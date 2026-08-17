import os
import re
import time
import sqlite3
import logging
import asyncio
from collections import defaultdict, deque

from dotenv import load_dotenv
load_dotenv()

from telegram import Update, ChatPermissions
from telegram.constants import ChatMemberStatus, ChatAction, ChatType
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
from telegram.error import TelegramError

import detection
from security import security_db_init, write_audit_log
import gemini
from gemini import ask_gemini, split_telegram_message
from quota import quota_db_init, check_and_use_quota
from analytics import analytics_db_init, record_message_activity, get_group_summary
from news import news_db_init, run_news_check_cycle, news_background_loop
import coordinator

from dashboard import get_dashboard_data, format_dashboard_message
from security import write_audit_log
from telegram.constants import ParseMode

from scope_policy import (
    scope_policy_db_init, ProgramStatus,
    create_program, get_program, list_programs, set_program_status,
    import_authorization, list_authorizations, review_authorization, revoke_authorization,
    add_scope_rule, remove_scope_rule, list_scope_rules,
    evaluate_target, effective_authorization_status,
)
from bb_report import get_bb_report_data, format_bb_report_message
from findings import (
    findings_db_init, create_finding, get_finding, list_findings,
    update_finding_status, mark_duplicate,
    add_evidence, get_evidence, list_evidence, remove_evidence, verify_evidence,
    VALID_SEVERITIES, VALID_STATUSES, VALID_EVIDENCE_TYPES, MAX_EVIDENCE_BYTES,
)

BOT_TOKEN = os.getenv("BOT_TOKEN")
DB_PATH = "bot.db"

SPAM_MESSAGE_LIMIT = 5
SPAM_TIME_WINDOW = 10
MAX_WARNINGS = 3
DEFAULT_MUTE_SECONDS = 600
TELEGRAM_CAPTION_LIMIT = 1024  # Telegram Bot API: caption max length for send_photo

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("modbot")

spam_tracker = defaultdict(deque)

AUTO_REPLY_TRIGGERS = {
    "ควย": "ควยพ่อมึงอะ ไอ้ควาย",
    "ควยไรอะ": "แล้วมึงเป็นควยไรอะ",
    "ต่อยกับกูไหม": "มาดิ ไอ้ควาย อย่าท้า",
    "ฝอ.3": "ไอ้หม่ำหรอ กูให้ 3 ไอ้หม่ำเลย",
}
AUTO_REPLY_ANNOY_THRESHOLD = 3
AUTO_REPLY_ANGRY_THRESHOLD = 5
AUTO_REPLY_ANNOYED_TEXT = "มึงพิมพ์เหี้ยไรนักหนาวะ ว่างมากก็ไปกรอกน้ำให้แม่มึงไป ไอ้สัตว์นรก"
AUTO_REPLY_ANGRY_TEXT = "ยัง ยังไม่หยุดอีก กูรำคาญ ไอ้ควาย เดี๋ยวสะง่องหรอก"

DEFAULT_MEDIA_QUESTION = "ช่วยวิเคราะห์ไฟล์/รูปภาพที่แนบมาให้หน่อย อธิบายเป็นภาษาไทยอย่างละเอียด"

auto_reply_tracker = defaultdict(int)

# ---------------- Database ----------------

def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
    
def db_info():
    conn = db_conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS forbidden_words (
        chat_id INTEGER NOT NULL,
        word TEXT NOT NULL,
        PRIMARY KEY (chat_id, word)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS warnings (
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (chat_id, user_id)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS settings (
        chat_id INTEGER PRIMARY KEY,
        filter_on INTEGER NOT NULL DEFAULT 1,
        antispam_on INTEGER NOT NULL DEFAULT 1
    )""")
    conn.commit()
    conn.close()
    
def get_settings(chat_id):
    conn = db_conn()
    conn.execute(
        "INSERT OR IGNORE INTO settings (chat_id, filter_on, antispam_on) VALUES (?, 1, 1)",
        (chat_id,),
    )
    conn.commit()
    row = conn.execute(
        "SELECT filter_on, antispam_on FROM settings WHERE chat_id=?", (chat_id,)
    ).fetchone()
    conn.close()
    return {"filter_on": row["filter_on"], "antispam_on": row["antispam_on"]}
    
def set_filter_on(chat_id, enabled):
    conn = db_conn()
    conn.execute(
        "INSERT INTO settings (chat_id, filter_on) VALUES (?, ?) "
        "ON CONFLICT(chat_id) DO UPDATE SET filter_on = excluded.filter_on",
        (chat_id, int(enabled)),
    )
    conn.commit()
    conn.close()
    
def add_word(chat_id, word):
    conn = db_conn()
    conn.execute(
        "INSERT OR IGNORE INTO forbidden_words (chat_id, word) VALUES (?, ?)",
        (chat_id, word.lower()),
    )
    conn.commit()
    conn.close()
    
def del_word(chat_id, word):
    conn = db_conn()
    conn.execute("DELETE FROM forbidden_words WHERE chat_id=? AND word=?", (chat_id, word.lower()))
    conn.commit()
    conn.close()
    
def list_words(chat_id):
    conn = db_conn()
    rows = conn.execute("SELECT word FROM forbidden_words WHERE chat_id=?", (chat_id,)).fetchall()
    conn.close()
    return [r["word"] for r in rows]
    
def get_warning(chat_id, user_id):
    conn = db_conn()
    row = conn.execute(
        "SELECT count FROM warnings WHERE chat_id=? AND user_id=?", (chat_id, user_id)
    ).fetchone()
    conn.close()
    return row["count"] if row else 0
    
def add_warning(chat_id, user_id):
    conn = db_conn()
    conn.execute(
        "INSERT INTO warnings (chat_id, user_id, count) VALUES (?, ?, 1) "
        "ON CONFLICT(chat_id, user_id) DO UPDATE SET count = count + 1",
        (chat_id, user_id),
    )
    conn.commit()
    row = conn.execute(
        "SELECT count FROM warnings WHERE chat_id=? AND user_id=?", (chat_id, user_id)
    ).fetchone()
    conn.close()
    return row["count"]
    
def reset_warning(chat_id, user_id):
    conn = db_conn()
    conn.execute(
        "INSERT OR REPLACE INTO warnings (chat_id, user_id, count) VALUES (?, ?, 0)",
        (chat_id, user_id),
    )
    conn.commit()
    conn.close()
    
# ---------------- Helpers ----------------

async def is_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    chat = update.effective_chat
    try:
        member = await context.bot.get_chat_member(chat.id, user.id)
        return member.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER)
    except TelegramError as e:
        logger.info(f"ADMIN CHECK ERROR: {e}")
        return False
        
async def check_bot_permissions(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    try:
        me = await context.bot.get_chat_member(chat.id, context.bot.id)
        can_delete = bool(getattr(me, "can_delete_messages", False))
        can_restrict = bool(getattr(me, "can_restrict_members", False))
        return can_delete, can_restrict
    except TelegramError as e:
        logger.info(f"PERMISSION CHECK ERROR: {e}")
        return False, False
        
def _find_bot_mention(entities: dict, bot_username: str):
    """entities is the dict returned by Message.parse_entities()/
    parse_caption_entities() — {MessageEntity: substring}. Returns the
    matched '@username' substring, or None."""
    target = f"@{bot_username.lower()}"
    for entity_text in entities.values():
        if entity_text.lower() == target:
            return entity_text
    return None
    
async def extract_media_from_message(message, context: ContextTypes.DEFAULT_TYPE):
    """ดาวน์โหลดรูปภาพ/เอกสารจาก Telegram message เพื่อส่งให้ GPT วิเคราะห์
    คืนค่า (bytes, mime_type, error_text):
      - ไม่มีรูป/เอกสารแนบเลย         -> (None, None, None)
      - มีแนบแต่ชนิดไฟล์ไม่รองรับ/ใหญ่เกิน -> (None, None, <ข้อความ error ภาษาไทย>)
      - ดาวน์โหลดสำเร็จ               -> (bytes, mime_type, None)
    ไม่เคยตัดข้อความ/ไฟล์ทิ้งเงียบๆ — ทุก error path คืนข้อความอธิบายกลับไปเสมอ"""
    file_id, mime_type, file_size = None, None, None
    
    if message.photo:
        largest = message.photo[-1]
        file_id, mime_type, file_size = largest.file_id, "image/jpeg", largest.file_size
    elif message.document:
        doc = message.document
        file_id, mime_type, file_size = doc.file_id, doc.mime_type or "", doc.file_size
        
    if not file_id:
        return None, None, None

    if not gemini.is_supported_media_mime(mime_type):
        return None, None, (
            f"❌ ไม่รองรับไฟล์ประเภทนี้ ({mime_type or 'ไม่ทราบชนิด'})\n"
            "รองรับ: รูปภาพ (JPEG/PNG/WebP), PDF, ไฟล์ข้อความล้วน (.txt)"
        )
        
    limit_mb = gemini.MAX_MEDIA_BYTES // (1024 * 1024)
    if file_size and file_size > gemini.MAX_MEDIA_BYTES:
        return None, None, f"❌ ไฟล์ใหญ่เกินไป (จำกัด {limit_mb}MB)"
        
    try:
        tg_file = await context.bot.get_file(file_id)
        file_bytes = bytes(await tg_file.download_as_bytearray())
    except TelegramError as e:
        logger.info(f"MEDIA DOWNLOAD ERROR: {e}")
        return None, None, "❌ ดาวน์โหลดไฟล์จาก Telegram ไม่สำเร็จ ลองใหม่อีกครั้ง"
        
    if len(file_bytes) > gemini.MAX_MEDIA_BYTES:
        return None, None, f"❌ ไฟล์ใหญ่เกินไป (จำกัด {limit_mb}MB)"
        
    return file_bytes, mime_type, None
        
async def parse_duration(text: str):
    match = re.fullmatch(r"(\d+)(s|m|h|d)", text.strip().lower())
    if not match:
        return None
    value, unit = int(match.group(1)), match.group(2)
    seconds = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return value * seconds
    
def contains_forbidden_word(text: str, words):
    lowered = text.lower()
    for w in words:
        if w in lowered:
           return w
    return None
    
async def apply_mute(update, context, target_user_id, seconds) -> bool:
    chat = update.effective_chat
    until = int(time.time()) + seconds
    try:
       await context.bot.restrict_chat_member(
            chat.id,
            target_user_id,
            permissions=ChatPermissions(can_send_message=False),
            until_date=until,
       )
       logger.info(f"MUTE SUCCESS user={target_user_id} seconds={seconds}")
       return True
    except TelegramError as e:
        logger.info(f"MUTE ERROR: {e}")
        await context.bot.send_message(chat.id, "Bot ไม่มีสิทธิ์ Restrict Members")
        return False
        
async def safe_delete(message, chat_id, context) -> bool:
    try:
        await context.bot.delete_message(chat_id, message.message_id)
        logger.info(f"MESSAGE DELETED | Chat ID: {chat_id} | Message ID: {message.message_id}")
        return True
    except TelegramError as e:
        logger.info(f"DELETE ERROR: {e}")
        return False
        
async def apply_warning_and_maybe_mute(update, context, user_id, reason):
    chat_id = update.effective_chat.id
    name = update.effective_user.first_name
    count = add_warning(chat_id, user_id)
    await context.bot.send_message(chat_id, f"{reason} | {name} Warning {count}/{MAX_WARNINGS}")
    if count >= MAX_WARNINGS:
        can_delete, can_restrict = await check_bot_permissions(update, context)
        if can_restrict:
            ok = await apply_mute(update, context, user_id, DEFAULT_MUTE_SECONDS)
            if ok:
                reset_warning(chat_id, user_id)
                await context.bot.send_message(
                    chat_id, f"🔇 ครบ {MAX_WARNINGS} Warning: Mute {DEFAULT_MUTE_SECONDS}s"
                )
        else:
            await context.bot.send_message(chat_id, "❌ Bot ไม่มีสิทธิ์ Restrict Members")
    return count
    
# ---------------- Commands ----------------

async def cmd_start(update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🤖 กูมาเพื่อช่วยเหลือพวกมึงแล้ว พวกเดนนรก\nพิมพ์ /help เพื่อดูคำสั่งทั้งหมด พัฒนาโดย @wissha_yosef พ่อกูเอง")
    
async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "/status - ดูสถานะบอท\n"
        "/filter_on /filter_off - เปิด/ปิดตัวกรองคำ\n"
        "/addword <คำ> - เพิ่มคำต้องห้าม\n"
        "/delword <คำ> - ลบคำต้องห้าม\n"
        "/listwords - แสดงคำต้องห้ามทั้งหมด\n"
        "/warnings - ดู Warning (Reply ข้อความ)\n"
        "/resetwarn - รีเซ็ต Warning (Reply ข้อความ)\n"
        "/mute 10m - Mute สมาชิก (Reply ข้อความ)\n"
        "/unmute - ปลด Mute (Reply ข้อความ)\n"
        "/id - ดู Chat ID\n"
        f"แท็ก @{context.bot.username} แล้วพิมพ์คำถาม - ถาม AI\n"
        f"ส่งรูปภาพ/ไฟล์ PDF/TXT พร้อม caption แท็ก @{context.bot.username} "
        f"(หรือ Reply รูป/ไฟล์เดิมแล้วแท็ก) - ให้ AI วิเคราะห์รูป/ไฟล์\n"
        "/imagine <คำอธิบาย> - ให้ AI สร้างรูปภาพแล้วส่งเข้าแชท"
    )
    await update.message.reply_text(text)
    
async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    settings = get_settings(chat_id)
    words_count = len(list_words(chat_id))
    can_delete, can_restrict = await check_bot_permissions(update, context)
    text = (
        f"Filter: {'ON' if settings['filter_on'] else 'OFF'}\n"
        f"Anti-Spam: {'ON' if settings['antispam_on'] else 'OFF'}\n"
        f"Forbidden Words: {words_count}\n"
        f"Bot Delete Permission: {'OK' if can_delete else 'MISSING'}\n"
        f"Bot Restrict Permission: {'OK' if can_restrict else 'MISSING'}"
    )
    await update.message.reply_text(text)
    
async def cmd_filter_on(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    set_filter_on(update.effective_chat.id, True)
    await update.message.reply_text("✅ เปิด Filter แล้ว")
    
async def cmd_filter_off(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    set_filter_on(update.effective_chat.id, False)
    await update.message.reply_text("✅ ปิด Filter แล้ว")
    
async def cmd_addword(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not context.args:
        return await update.message.reply_text("ใช้งาน: /addword คำ")
    word = " ".join(context.args)
    add_word(update.effective_chat.id, word)
    await update.message.reply_text(f"✅ เพิ่มคำต้องห้าม: {word}")
    
async def cmd_delword(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not context.args:
        return await update.message.reply_text("ใช้งาน: /delword คำ")
    word = " ".join(context.args)
    del_word(update.effective_chat.id, word)
    await update.message.reply_text(f"✅ ลบคำต้องห้าม: {word}")

async def cmd_listwords(update: Update, context: ContextTypes.DEFAULT_TYPE):
    words = list_words(update.effective_chat.id)
    if not words:
        return await update.message.reply_text("ยังไม่มีคำต้องห้าม")
    await update.message.reply_text("คำต้องห้าม:\n" + "\n".join(words))

async def cmd_warnings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not update.message.reply_to_message:
        return await update.message.reply_text("ใช้งาน: Reply ข้อความสมาชิกแล้วพิมพ์ /warnings")
    target = update.message.reply_to_message.from_user
    count = get_warning(update.effective_chat.id, target.id)
    await update.message.reply_text(f"{target.first_name}: Warning {count}/{MAX_WARNINGS}")

async def cmd_resetwarn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not update.message.reply_to_message:
        return await update.message.reply_text("ใช้งาน: Reply ข้อความสมาชิกแล้วพิมพ์ /resetwarn")
    target = update.message.reply_to_message.from_user
    reset_warning(update.effective_chat.id, target.id)
    await update.message.reply_text(f"✅ รีเซ็ต Warning ของ {target.first_name} แล้ว")

async def cmd_mute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not update.message.reply_to_message:
        return await update.message.reply_text("ใช้งาน: Reply ข้อความสมาชิกแล้วพิมพ์ /mute 10m")
    if not context.args:
        return await update.message.reply_text("ใช้งาน: /mute 10m (รองรับ s, m, h, d)")
    seconds = await parse_duration(context.args[0])
    if seconds is None:
        return await update.message.reply_text("รูปแบบเวลาไม่ถูกต้อง เช่น 10s 10m 1h 1d")
    can_delete, can_restrict = await check_bot_permissions(update, context)
    if not can_restrict:
        return await update.message.reply_text("❌ Bot ไม่มีสิทธิ์ Restrict Members")
    target = update.message.reply_to_message.from_user
    ok = await apply_mute(update, context, target.id, seconds)
    if ok:
        await update.message.reply_text(f"🔇 Mute {target.first_name} เป็นเวลา {context.args[0]}")

async def cmd_unmute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not update.message.reply_to_message:
        return await update.message.reply_text("ใช้งาน: Reply ข้อความสมาชิกแล้วพิมพ์ /unmute")
    target = update.message.reply_to_message.from_user
    chat = update.effective_chat
    try:
        chat_info = await context.bot.get_chat(chat.id)
        permissions = chat_info.permissions or ChatPermissions(can_send_messages=True)
        await context.bot.restrict_chat_member(chat.id, target.id, permissions=permissions)
        await update.message.reply_text(f"🔊 ปลด Mute {target.first_name} แล้ว")
        logger.info(f"UNMUTE SUCCESS user={target.id}")
    except TelegramError as e:
        logger.info(f"UNMUTE ERROR: {e}")
        await update.message.reply_text("❌ Bot ไม่มีสิทธิ์ Restrict Members")
        
async def cmd_announce(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """ส่งข้อความประกาศเข้ากลุ่ม สั่งได้เฉพาะในแชทส่วนตัวกับบอทเท่านั้น

    ใช้งาน:
      1) ข้อความอย่างเดียว:
         /announce <chat_id> <ข้อความ>

      2) รูปภาพ + ข้อความ:
         ส่งรูปภาพเข้าแชทส่วนตัวกับบอท (จะใส่ caption หรือไม่ก็ได้)
         แล้ว Reply รูปภาพนั้นด้วย /announce <chat_id> [ข้อความ]
         - ถ้าไม่พิมพ์ข้อความต่อท้าย chat_id จะใช้ caption ของรูปเป็นข้อความประกาศ
         - ถ้าพิมพ์ข้อความต่อท้าย chat_id ข้อความนั้นจะ override caption เดิม

    ผู้สั่งต้องเป็น Admin/Owner ของกลุ่มที่ระบุ chat_id นั้น"""
    if update.effective_chat.type != ChatType.PRIVATE:
        return await update.message.reply_text("คำสั่งนี้ใช้ได้เฉพาะในแชทส่วนตัวกับบอทเท่านั้น")

    reply_msg = update.message.reply_to_message
    is_photo_announce = bool(reply_msg and reply_msg.photo)

    if not context.args:
        return await update.message.reply_text(
            "ใช้งาน:\n"
            "1) /announce <chat_id> <ข้อความ>\n"
            "2) ส่งรูปภาพ (ใส่ caption ได้) แล้ว Reply รูปนั้นด้วย /announce <chat_id> [ข้อความ]\n"
            "ดู chat_id ของกลุ่มได้จาก /status ในกลุ่มนั้น"
        )

    try:
        target_chat_id = int(context.args[0])
    except ValueError:
        return await update.message.reply_text("chat_id ต้องเป็นตัวเลข")

    typed_text = " ".join(context.args[1:]).strip()

    if is_photo_announce:
        announce_text = typed_text or (reply_msg.caption or "").strip()
        if not announce_text:
            return await update.message.reply_text(
                "❌ ไม่มีข้อความประกาศ กรุณาใส่ caption ให้รูป หรือพิมพ์ข้อความต่อท้าย chat_id"
            )
        photo_file_id = reply_msg.photo[-1].file_id
    else:
        if len(context.args) < 2:
            return await update.message.reply_text(
                "ใช้งาน: /announce <chat_id> <ข้อความ>\nดู chat_id ของกลุ่มได้จาก /status ในกลุ่มนั้น"
            )
        announce_text = typed_text
        if not announce_text:
            return await update.message.reply_text("กรุณาพิมพ์ข้อความที่ต้องการประกาศต่อท้าย chat_id")

    user = update.effective_user
    try:
        member = await context.bot.get_chat_member(target_chat_id, user.id)
    except TelegramError as e:
        logger.info(f"ANNOUNCE ADMIN CHECK ERROR: {e}")
        return await update.message.reply_text("❌ ไม่พบกลุ่มนี้ หรือบอตไม่ได้อยู่ในกลุ่มนั้น")

    if member.status not in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin ของกลุ่มที่ระบุ")

    full_text = f"📢 ประกาศ\n\n{announce_text}"

    if is_photo_announce:
        if len(full_text) > TELEGRAM_CAPTION_LIMIT:
            return await update.message.reply_text(
                f"❌ ข้อความประกาศยาวเกินไปสำหรับ caption ของรูปภาพ "
                f"({len(full_text)}/{TELEGRAM_CAPTION_LIMIT} ตัวอักษร)\n"
                f"กรุณาย่อข้อความ หรือส่งแบบข้อความอย่างเดียวแทน"
            )
        try:
            await context.bot.send_photo(target_chat_id, photo=photo_file_id, caption=full_text)
        except TelegramError as e:
            logger.info(f"ANNOUNCE PHOTO SEND ERROR: {e}")
            return await update.message.reply_text(
                "❌ ส่งรูปภาพไม่สำเร็จ บอทอาจไม่มีสิทธิ์พูดในกลุ่มนั้น หรือรูปภาพมีปัญหา"
            )
        write_audit_log(target_chat_id, user.id, actor="admin", action="ANNOUNCE_PHOTO", detail=announce_text)
        logger.info(f"ANNOUNCE PHOTO SENT | Chat ID: {target_chat_id} | By User ID: {user.id}")
    else:
        try:
            await context.bot.send_message(target_chat_id, full_text)
        except TelegramError as e:
            logger.info(f"ANNOUNCE SEND ERROR: {e}")
            return await update.message.reply_text("❌ ส่งข้อความไม่สำเร็จ บอทอาจไม่มีสิทธิ์พูดในกลุ่มนั้น")
        write_audit_log(target_chat_id, user.id, actor="admin", action="ANNOUNCE_TEXT", detail=announce_text)
        logger.info(f"ANNOUNCE TEXT SENT | Chat ID: {target_chat_id} | By User ID: {user.id}")

    await update.message.reply_text("✅ ส่งประกาศเรียบร้อยแล้ว")

IMAGINE_CAPTION_RE = re.compile(r"^/imagine(@\w+)?\s*", re.IGNORECASE)

async def _run_imagine(update: Update, context: ContextTypes.DEFAULT_TYPE, prompt: str, image_message) -> None:
    """สร้าง/แก้ไขรูปภาพด้วย AI แล้วส่งเข้าแชท ใช้ร่วมกันทั้ง 3 ทาง:
    /imagine <ข้อความ> ธรรมดา (สร้างใหม่ไม่มีรูปอ้างอิง), Reply รูปเดิมด้วย
    /imagine (แก้ไขรูปนั้น), และส่งรูปใหม่พร้อม caption /imagine (แก้ไขรูปที่เพิ่งส่ง)
    image_message คือ message ที่คาดว่าจะมีรูป/เอกสารแนบ (หรือ None ถ้าไม่มี)"""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id

    if not prompt:
        return await update.message.reply_text(
            "ใช้งาน: /imagine <คำอธิบายรูปที่ต้องการ>\n"
            "เช่น /imagine แมวส้มใส่หมวกนักบินอวกาศ สไตล์การ์ตูน\n"
            "หรือ Reply รูป/ส่งรูปพร้อม caption /imagine <สิ่งที่ต้องการแก้ไข> เพื่อแก้ไขรูปเดิม"
        )

    image_bytes, image_mime, media_error = None, None, None
    if image_message and (image_message.photo or image_message.document):
        image_bytes, image_mime, media_error = await extract_media_from_message(image_message, context)
        if media_error:
            return await update.message.reply_text(media_error)
        if image_bytes and not image_mime.startswith("image/"):
            return await update.message.reply_text("❌ แก้ไขรูปได้เฉพาะไฟล์รูปภาพเท่านั้น (JPEG/PNG/WebP)")

    admin = await is_admin(update, context)
    allowed, used, limit = check_and_use_quota(chat_id, user_id, admin)
    if not allowed:
        return await update.message.reply_text(
            f"ใช้งานเกินโควตาวันนี้แล้ว ({used}/{limit} ครั้ง) ไว้มาใช้วันอื่นนะ หรือถ้ารีบก็ไปใช้งานบนเว็บไป ไอ้ควาย ไม่ต้องมาใช้กู นอกจากจะเปลือง Token แล้วยังเปลืองออกซิเจนเพราะมึงแย่งหายใจอีก🖕🏻"
        )

    mode = "edit" if image_bytes else "generate"
    logger.info(f"AI IMAGINE | Chat ID: {chat_id} | User ID: {user_id} | Mode: {mode} | Prompt: {prompt}")
    await context.bot.send_chat_action(chat_id, ChatAction.UPLOAD_PHOTO)

    if image_bytes:
        ok, result_bytes, error_text = await gemini.edit_image(prompt, image_bytes, image_mime)
        action_tag = "AI_IMAGE_EDITED"
    else:
        ok, result_bytes, error_text = await gemini.generate_image(prompt)
        action_tag = "AI_IMAGE_GENERATED"

    if not ok:
        return await update.message.reply_text(f"❌ {error_text}")

    caption = f"🎨 {prompt}"
    if len(caption) > TELEGRAM_CAPTION_LIMIT:
        caption = caption[: TELEGRAM_CAPTION_LIMIT - 1] + "…"

    try:
        await context.bot.send_photo(chat_id, photo=result_bytes, caption=caption)
    except TelegramError as e:
        logger.info(f"IMAGINE SEND ERROR: {e}")
        return await update.message.reply_text("❌ สร้างรูปสำเร็จแต่ส่งรูปเข้าแชทไม่สำเร็จ ลองใหม่อีกครั้ง")

    write_audit_log(chat_id, user_id, actor="user", action=action_tag, detail=prompt)


async def cmd_imagine(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """สั่ง AI สร้าง/แก้ไขรูปภาพแล้วส่งเข้าแชทนี้
    ใช้งาน: /imagine <คำอธิบาย> (สร้างรูปใหม่)
    หรือ Reply รูปเดิมด้วย /imagine <สิ่งที่ต้องการแก้ไข> (แก้ไขรูป)"""
    prompt = " ".join(context.args).strip()
    await _run_imagine(update, context, prompt, update.message.reply_to_message)


async def handle_imagine_caption(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """ส่งรูปพร้อม caption '/imagine <ข้อความ>' ในข้อความเดียว — แก้ไขรูปที่แนบมานั้น
    (คำสั่งใน caption ไม่ถูก CommandHandler จับ เพราะ CommandHandler อ่านจาก
    message.text เท่านั้น จึงต้องมี handler แยกที่จับจาก caption โดยตรง)"""
    message = update.effective_message
    prompt = IMAGINE_CAPTION_RE.sub("", message.caption or "", count=1).strip()
    await _run_imagine(update, context, prompt, message)
    
async def dashboard_command(update, context):
    chat, user = update.effective_chat, update.effective_user
    member = await context.bot.get_chat_member(chat.id, user.id)
    if member.status not in ("administrator", "creator"):
        await update.message.reply_text("คำสั่งนี้ใช้ได้เฉพาะแอดมินกลุ่มเท่านั้น")
        return
    text = format_dashboard_message(get_dashboard_data(chat.id, hours=24))
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)
    write_audit_log(chat.id, user.id, actor="admin", action="DASHBOARD_VIEW")
    
# ---------------- Anti-Link Commands ----------------

async def cmd_linkfilter_on(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    detection.enable_link_filter(update.effective_chat.id)
    await update.message.reply_text("✅ เปิด Link Filter แล้ว")
    
async def cmd_link_filter_off(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    detection.disable_link_filter(update.effective_chat.id)
    await update.message.reply_text("✅ ปิด Link Filter แล้ว")
    
async def cmd_adddomain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not context.args:
        return await update.message.reply_text("ใช้งาน: /adddomain example.com")
    domain = context.args[0]
    detection.add_domain(update.effective_chat.id, domain)
    await update.message.reply_text(f"✅ เพิ่ม Blocked Domain: {domain}")
    
async def cmd_deldomain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not context.args:
        return await update.message.reply_text("ใช้งาน: /deldomain example.com")
    domain = context.args[0]
    removed = detection.remove_domain(update.effective_chat.id, domain)
    if removed:
        await update.message.reply_text(f"✅ ลบ Blocked Domain: {domain}")
    else:
        await update.message.reply_text(f"ไม่พบ Domain นี้ในรายการ: {domain}")
        
async def cmd_listdomains(update: Update, context: ContextTypes.DEFAULT_TYPE):
    domains = detection.get_blocked_domains(update.effective_chat.id)
    if not domains:
        return await update.message.reply_text("ยังไม่มี Blocked Domain")
    await update.message.reply_text("Blocked Domains:\n" + "\n".join(domains))

# ---------------- Group Analytics ----------------

async def cmd_groupstats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """สรุปภาพรวมกลุ่ม (คำฮิต + ช่วงเวลาแอคทีฟ) แบบไม่แยกรายบุคคล — Admin เท่านั้น"""
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
        
    summary = get_group_summary(update.effective_chat.id)
    if summary["total_messages"] == 0:
        return await update.message.reply_text("ยังไม่มีข้อมูลสถิติของกลุ่มนี้")
        
    words_text = "\n".join(
        f"{i+1}. {w} ({c})" for i, (w, c) in enumerate(summary["top_words"])
    ) or "-"
    hours_text = "\n".join(
        f"{h:02d}:00-{h:02d}:59 UTC ({c} ข้อความ)" for h, c in summary["top_hours"]
    ) or "-"

    text = (
        f"📊 สรุปภาพรวมกลุ่ม\n"
        f"ข้อความทั้งหมดที่บันทึก: {summary['total_messages']}\n\n"
        f"คำฮิต:\n{words_text}\n\n"
        f"ช่วงเวลาแอคทีฟสุด:\n{hours_text}"
    )
    await update.message.reply_text(text)

# ---------------- Bug Bounty: Finding / Evidence Commands ----------------
#
# Telegram-facing surface for findings.py / scope_policy.py (Phase 4).
# Deliberately thin: every ALLOW/DENY decision and every state-machine
# rule lives in findings.py / scope_policy.py. This layer only does
# Telegram plumbing (parsing args, downloading replied-to files,
# formatting Thai replies) and decides which actions require chat-admin
# status.
#
# Permission model (see Phase 4 report for rationale): creating a
# Finding or attaching Evidence is treated like reporting a bug, not
# like moderating the chat -- so it is open to any chat member and the
# real gate is evaluate_target() (Program/Authorization/Scope), not
# Telegram role. Triage decisions that change a Finding's state
# (status transitions, duplicate marking) and destructive Evidence
# removal are admin-gated, matching this bot's existing convention for
# every other state-mutating command (/addword, /mute, etc.).
#
# Phase 5 adds /bbprogram, /bbauth, /bbscope, /bbcheck (below), so a
# program_id/authorization can now be obtained entirely through
# Telegram before /bbfinding new is used -- see those handlers for the
# same admin-gating rationale applied to Program/Authorization/Scope
# mutations.

_FINDING_DENY_TH = {
    "TITLE_REQUIRED": "กรุณาระบุชื่อเรื่อง (title)",
    "TITLE_TOO_LONG": "ชื่อเรื่องยาวเกินไป",
    "INVALID_SEVERITY": "ระดับความรุนแรงไม่ถูกต้อง (ใช้ได้: " + ", ".join(sorted(VALID_SEVERITIES)) + ")",
    "INVALID_STATUS": "สถานะไม่ถูกต้อง",
    "DESCRIPTION_TOO_LONG": "รายละเอียดยาวเกินไป",
    "TARGET_REQUIRED": "กรุณาระบุเป้าหมาย (target)",
    "PROGRAM_NOT_FOUND": "ไม่พบ Program นี้",
    "PROGRAM_NOT_ACTIVE": "Program นี้ยังไม่ ACTIVE",
    "AUTHORIZATION_NOT_FOUND": "Program นี้ยังไม่มี Authorization",
    "AUTHORIZATION_NOT_REVIEWED": "Authorization ยังไม่ผ่านการ review",
    "AUTHORIZATION_PENDING": "Authorization ยังรอ review อยู่",
    "AUTHORIZATION_EXPIRED": "Authorization หมดอายุแล้ว",
    "AUTHORIZATION_REVOKED": "Authorization ถูก revoke แล้ว",
    "AUTHORIZATION_REJECTED": "Authorization ถูก reject แล้ว",
    "AUTHORIZATION_NOT_EFFECTIVE": "Authorization ยังไม่ถึงวันมีผล",
    "TARGET_INVALID": "รูปแบบ target ไม่ถูกต้อง",
    "TARGET_OUT_OF_SCOPE": "target นี้ไม่อยู่ใน scope ของ Program",
    "TARGET_EXCLUDED": "target นี้ถูก EXCLUDE ออกจาก scope โดยเฉพาะ",
    "NO_INCLUDE_MATCH": "target นี้ไม่ตรงกับ INCLUDE rule ใดเลย",
    "POLICY_ERROR": "เกิดข้อผิดพลาดภายในระหว่างประเมินนโยบาย (fail-closed: DENY)",
    "FINDING_NOT_FOUND": "ไม่พบ Finding นี้",
    "INVALID_TRANSITION": "เปลี่ยนสถานะแบบนี้ไม่ได้จากสถานะปัจจุบัน",
    "USE_MARK_DUPLICATE": "ตั้งสถานะ DUPLICATE ตรงๆ ไม่ได้ ให้ใช้ /bbfinding duplicate แทน",
    "RESOLUTION_TOO_LONG": "ข้อความสรุปผลยาวเกินไป",
    "DUPLICATE_SELF_REFERENCE": "Finding อ้างอิงตัวเองเป็น duplicate ไม่ได้",
    "DUPLICATE_TARGET_NOT_FOUND": "ไม่พบ Finding ปลายทางที่จะ mark เป็น duplicate ของ",
}

_EVIDENCE_DENY_TH = {
    "FINDING_NOT_FOUND": "ไม่พบ Finding นี้",
    "INVALID_EVIDENCE_TYPE": "ประเภทหลักฐานไม่ถูกต้อง (ใช้ได้: " + ", ".join(sorted(VALID_EVIDENCE_TYPES)) + ")",
    "DESCRIPTION_TOO_LONG": "รายละเอียดยาวเกินไป",
    "UNSAFE_FILENAME": "ชื่อไฟล์ไม่ปลอดภัย/รูปแบบไม่ถูกต้อง",
    "FILE_TOO_LARGE": f"ไฟล์ใหญ่เกินไป (จำกัด {MAX_EVIDENCE_BYTES // (1024*1024)}MB)",
    "EVIDENCE_NOT_FOUND": "ไม่พบ Evidence นี้",
    "NO_STORED_HASH": "Evidence นี้ไม่มี hash ที่บันทึกไว้ให้เทียบ",
}


def _deny_text_finding(reason: str, detail: str = "") -> str:
    return "❌ " + _FINDING_DENY_TH.get(reason, reason)


def _deny_text_evidence(reason: str, detail: str = "") -> str:
    return "❌ " + _EVIDENCE_DENY_TH.get(reason, reason)


async def _reply_chunked(update: Update, text: str) -> None:
    """Sends `text` as one or more messages, splitting on
    gemini.py's existing split_telegram_message() when it exceeds
    Telegram's per-message length limit. Phase 6 fix: every /bb...list
    command previously used a single reply_text() call, so a Program/
    Authorization/Scope Rule/Finding/Evidence list long enough to pass
    ~4096 characters would raise a Telegram API error instead of
    sending. Reuses the exact splitter /ask already relies on --
    no new chunking logic is introduced."""
    for chunk in split_telegram_message(text):
        await update.message.reply_text(chunk)


async def _download_evidence_file(message, context: ContextTypes.DEFAULT_TYPE):
    """Downloads a photo/document attached to `message` for Evidence
    storage. Independent of gemini.py's mime allowlist on purpose --
    findings.py must stay usable even if the AI provider is down/
    removed, and evidence can legitimately be any file type (logs,
    HAR files, etc.), not just what the AI vision/PDF path accepts.
    Returns (bytes, filename, error_text); error_text is a ready-to-
    send Thai message on failure, None on success. All three are None
    if there is simply nothing attached to download."""
    file_id, filename, file_size = None, None, None
    if message.photo:
        largest = message.photo[-1]
        file_id, file_size = largest.file_id, largest.file_size
        filename = f"{largest.file_unique_id}.jpg"
    elif message.document:
        doc = message.document
        file_id, file_size, filename = doc.file_id, doc.file_size, doc.file_name

    if not file_id:
        return None, None, None

    if file_size and file_size > MAX_EVIDENCE_BYTES:
        return None, None, f"❌ ไฟล์ใหญ่เกินไป (จำกัด {MAX_EVIDENCE_BYTES // (1024*1024)}MB)"

    try:
        tg_file = await context.bot.get_file(file_id)
        file_bytes = bytes(await tg_file.download_as_bytearray())
    except TelegramError as e:
        logger.info(f"EVIDENCE DOWNLOAD ERROR: {e}")
        return None, None, "❌ ดาวน์โหลดไฟล์จาก Telegram ไม่สำเร็จ ลองใหม่อีกครั้ง"

    if len(file_bytes) > MAX_EVIDENCE_BYTES:
        return None, None, f"❌ ไฟล์ใหญ่เกินไป (จำกัด {MAX_EVIDENCE_BYTES // (1024*1024)}MB)"

    return file_bytes, filename, None


async def cmd_bbprogram(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/bbprogram new|active|pause|archive|list -- Program lifecycle.
    State machine (PAUSED<->ACTIVE, either ->ARCHIVED which is terminal)
    is enforced inside scope_policy.set_program_status(), not here --
    app.py only parses input, validates basic syntax, and calls the
    policy API, per the Phase 5 app.py/scope_policy.py split."""
    args = context.args or []
    if not args:
        return await update.message.reply_text(
            "ใช้งาน:\n"
            "/bbprogram new <ชื่อ...>\n"
            "/bbprogram active <program_id>\n"
            "/bbprogram pause <program_id>\n"
            "/bbprogram archive <program_id>\n"
            "/bbprogram list"
        )
    sub = args[0].lower()
    user = update.effective_user
    chat_id = update.effective_chat.id

    if sub == "new":
        if not await is_admin(update, context):
            return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
        if len(args) < 2:
            return await update.message.reply_text("ใช้งาน: /bbprogram new <ชื่อ...>")
        name = " ".join(args[1:])
        program_id = create_program(chat_id, name, created_by=user.id)
        await update.message.reply_text(
            f"✅ สร้าง Program #{program_id} แล้ว (สถานะ PAUSED)\n"
            f"ใช้ /bbprogram active {program_id} เพื่อเปิดใช้งาน"
        )

    elif sub in ("active", "pause", "archive"):
        if not await is_admin(update, context):
            return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text(f"ใช้งาน: /bbprogram {sub} <program_id>")
        program_id = int(args[1])
        program = get_program(program_id)
        if not program:
            return await update.message.reply_text("❌ ไม่พบ Program นี้")
        target_status = {
            "active": ProgramStatus.ACTIVE.value,
            "pause": ProgramStatus.PAUSED.value,
            "archive": ProgramStatus.ARCHIVED.value,
        }[sub]
        ok = set_program_status(program_id, target_status, user.id)
        if not ok:
            return await update.message.reply_text(
                f"❌ เปลี่ยนสถานะไม่ได้ ({program['status']} -> {target_status} ไม่ใช่ transition ที่อนุญาต)"
            )
        await update.message.reply_text(f"✅ Program #{program_id}: {program['status']} -> {target_status}")

    elif sub == "list":
        programs = list_programs(chat_id)
        if not programs:
            return await update.message.reply_text("ยังไม่มี Program ในกลุ่มนี้")
        lines = [f"#{p['program_id']} [{p['status']}] {p['name']}" for p in programs]
        await _reply_chunked(update, "Programs:\n" + "\n".join(lines))

    else:
        await update.message.reply_text("❌ subcommand ไม่ถูกต้อง (new/active/pause/archive/list)")


async def cmd_bbauth(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/bbauth import|review|revoke|list -- Authorization Artifact
    workflow. import always creates PENDING_REVIEW; only a separate,
    explicitly logged review_authorization() call (admin-only, below)
    can move it to ACTIVE/REJECTED. Being an admin never substitutes
    for this -- scope_policy.evaluate_target() has no is_admin input."""
    args = context.args or []
    if not args:
        return await update.message.reply_text(
            "ใช้งาน:\n"
            "/bbauth import <program_id> <source_type> [อ้างอิง...]\n"
            "/bbauth review <authorization_id> approve|reject [หมายเหตุ...]\n"
            "/bbauth revoke <authorization_id>\n"
            "/bbauth list <program_id>"
        )
    sub = args[0].lower()
    user = update.effective_user

    if sub == "import":
        if not await is_admin(update, context):
            return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
        if len(args) < 3 or not args[1].isdigit():
            return await update.message.reply_text(
                "ใช้งาน: /bbauth import <program_id> <source_type> [อ้างอิง...]"
            )
        program_id = int(args[1])
        source_type = args[2]
        source_reference = " ".join(args[3:])
        authorization_id = import_authorization(
            program_id, source_type, actor_user_id=user.id, source_reference=source_reference
        )
        if authorization_id is None:
            return await update.message.reply_text("❌ ไม่พบ Program นี้")
        await update.message.reply_text(
            f"✅ บันทึก Authorization #{authorization_id} แล้ว (สถานะ PENDING_REVIEW)\n"
            f"ใช้ /bbauth review {authorization_id} approve เพื่อ review"
        )

    elif sub == "review":
        if not await is_admin(update, context):
            return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
        if len(args) < 3 or not args[1].isdigit() or args[2].lower() not in ("approve", "reject"):
            return await update.message.reply_text(
                "ใช้งาน: /bbauth review <authorization_id> approve|reject [หมายเหตุ...]"
            )
        authorization_id = int(args[1])
        approve = args[2].lower() == "approve"
        notes = " ".join(args[3:])
        ok = review_authorization(authorization_id, approve, reviewer_user_id=user.id, notes=notes)
        if not ok:
            return await update.message.reply_text(
                "❌ Review ไม่สำเร็จ (ไม่พบ Authorization นี้ หรือสถานะไม่ใช่ PENDING_REVIEW)"
            )
        await update.message.reply_text(
            f"✅ Authorization #{authorization_id} -> {'ACTIVE' if approve else 'REJECTED'}"
        )

    elif sub == "revoke":
        if not await is_admin(update, context):
            return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text("ใช้งาน: /bbauth revoke <authorization_id>")
        authorization_id = int(args[1])
        ok = revoke_authorization(authorization_id, actor_user_id=user.id)
        if not ok:
            return await update.message.reply_text(
                "❌ Revoke ไม่สำเร็จ (ไม่พบ Authorization นี้ หรือสถานะถูก revoke/reject/expire ไปแล้ว)"
            )
        await update.message.reply_text(f"✅ Authorization #{authorization_id} -> REVOKED")

    elif sub == "list":
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text("ใช้งาน: /bbauth list <program_id>")
        authorizations = list_authorizations(int(args[1]))
        if not authorizations:
            return await update.message.reply_text("ยังไม่มี Authorization ใน Program นี้")
        lines = [
            f"#{a['authorization_id']} [{effective_authorization_status(a)}] "
            f"source={a['source_type']} ref={a['source_reference'] or '-'}"
            for a in authorizations
        ]
        await _reply_chunked(update, "Authorizations:\n" + "\n".join(lines))

    else:
        await update.message.reply_text("❌ subcommand ไม่ถูกต้อง (import/review/revoke/list)")


async def cmd_bbscope(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/bbscope add|remove|list -- Scope Rule management. Only ever
    calls scope_policy.add_scope_rule/remove_scope_rule/list_scope_rules
    -- no domain/IP/CIDR matching logic lives in app.py; that stays
    solely inside scope_policy.py's evaluate_target()/_rule_matches()."""
    args = context.args or []
    if not args:
        return await update.message.reply_text(
            "ใช้งาน:\n"
            "/bbscope add <program_id> include|exclude domain|url|ip|cidr <pattern>\n"
            "/bbscope remove <rule_id>\n"
            "/bbscope list <program_id>"
        )
    sub = args[0].lower()
    user = update.effective_user

    if sub == "add":
        if not await is_admin(update, context):
            return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
        if len(args) < 5 or not args[1].isdigit():
            return await update.message.reply_text(
                "ใช้งาน: /bbscope add <program_id> include|exclude domain|url|ip|cidr <pattern>"
            )
        program_id = int(args[1])
        rule_type = args[2].upper()
        target_type = args[3].upper()
        pattern = args[4]
        rule_id = add_scope_rule(program_id, rule_type, target_type, pattern, actor_user_id=user.id)
        if rule_id is None:
            return await update.message.reply_text(
                "❌ เพิ่ม Scope Rule ไม่สำเร็จ (ไม่พบ Program, rule_type/target_type ไม่ถูกต้อง, "
                "หรือ pattern ไม่ถูกต้อง)"
            )
        await update.message.reply_text(f"✅ เพิ่ม Scope Rule #{rule_id}: {rule_type} {target_type} {pattern}")

    elif sub == "remove":
        if not await is_admin(update, context):
            return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text("ใช้งาน: /bbscope remove <rule_id>")
        rule_id = int(args[1])
        ok = remove_scope_rule(rule_id, actor_user_id=user.id)
        if not ok:
            return await update.message.reply_text("❌ ไม่พบ Scope Rule นี้")
        await update.message.reply_text(f"✅ ลบ Scope Rule #{rule_id} แล้ว")

    elif sub == "list":
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text("ใช้งาน: /bbscope list <program_id>")
        rules = list_scope_rules(int(args[1]))
        if not rules:
            return await update.message.reply_text("ยังไม่มี Scope Rule ใน Program นี้")
        lines = [f"#{r['rule_id']} {r['rule_type']} {r['target_type']} {r['pattern']}" for r in rules]
        await _reply_chunked(update, "Scope Rules:\n" + "\n".join(lines))

    else:
        await update.message.reply_text("❌ subcommand ไม่ถูกต้อง (add/remove/list)")


async def cmd_bbcheck(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/bbcheck <program_id> <target> -- read-only scope-policy query,
    open to any chat member (no mutation happens here, so no is_admin
    gate). Calls the exact same evaluate_target() gate create_finding()
    uses, so a target can be checked before attempting /bbfinding new.
    Reuses _deny_text_finding()'s Thai reason mapping for DENY text --
    the Reason space evaluate_target() returns is identical either way,
    so this does not duplicate that mapping."""
    args = context.args or []
    if len(args) < 2 or not args[0].isdigit():
        return await update.message.reply_text("ใช้งาน: /bbcheck <program_id> <target>")
    program_id = int(args[0])
    target = " ".join(args[1:])
    decision = evaluate_target(program_id, target)
    if decision.allowed:
        detail = f" ({decision.detail})" if decision.detail else ""
        return await update.message.reply_text(f"✅ ALLOW{detail}")
    await update.message.reply_text(_deny_text_finding(decision.reason, decision.detail))


async def cmd_bbreport(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/bbreport <program_id> -- read-only aggregate summary (counts
    only: Authorization by effective status, Scope Rule by type,
    Finding by status/severity, Evidence total) for one Program.
    Admin-gated to match dashboard_command's existing precedent for
    aggregate reports (distinct from the open-to-all per-item
    /bbfinding list /bbauth list etc.). get_bb_report_data() only
    calls existing scope_policy.py/findings.py read APIs -- no new
    scope-matching/ALLOW-DENY logic is introduced by this command."""
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    args = context.args or []
    if not args or not args[0].isdigit():
        return await update.message.reply_text("ใช้งาน: /bbreport <program_id>")
    program_id = int(args[0])
    data = get_bb_report_data(program_id)
    if data is None:
        return await update.message.reply_text("❌ ไม่พบ Program นี้")
    await _reply_chunked(update, format_bb_report_message(data))
    write_audit_log(update.effective_chat.id, update.effective_user.id, actor="admin",
                     action="BB_REPORT_VIEW", detail=f"program_id={program_id}")


async def cmd_bbfinding(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/bbfinding new|list|show|status|duplicate -- see Phase 4 report
    for the exact argument syntax of each subcommand."""
    args = context.args or []
    if not args:
        return await update.message.reply_text(
            "ใช้งาน:\n"
            "/bbfinding new <program_id> <target> <severity> <หัวข้อ...>\n"
            "/bbfinding list <program_id>\n"
            "/bbfinding show <finding_id>\n"
            "/bbfinding status <finding_id> <สถานะใหม่> [สรุปผล...]\n"
            "/bbfinding duplicate <finding_id> <duplicate_of>"
        )
    sub = args[0].lower()
    user = update.effective_user

    if sub == "new":
        if len(args) < 5:
            return await update.message.reply_text(
                "ใช้งาน: /bbfinding new <program_id> <target> <severity> <หัวข้อ...>"
            )
        if not args[1].isdigit():
            return await update.message.reply_text("❌ program_id ต้องเป็นตัวเลข")
        program_id = int(args[1])
        target = args[2]
        severity = args[3].upper()
        title = " ".join(args[4:])
        result = create_finding(program_id, target, title, created_by=user.id, severity=severity)
        if not result.ok:
            return await update.message.reply_text(_deny_text_finding(result.reason, result.detail))
        await update.message.reply_text(
            f"✅ สร้าง Finding #{result.finding_id} แล้ว (สถานะ OPEN, severity {severity})"
        )

    elif sub == "list":
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text("ใช้งาน: /bbfinding list <program_id>")
        findings = list_findings(int(args[1]))
        if not findings:
            return await update.message.reply_text("ยังไม่มี Finding ใน Program นี้")
        lines = [f"#{f['finding_id']} [{f['status']}] {f['title']} ({f['severity']})" for f in findings]
        await _reply_chunked(update, "Findings:\n" + "\n".join(lines))

    elif sub == "show":
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text("ใช้งาน: /bbfinding show <finding_id>")
        finding = get_finding(int(args[1]))
        if not finding:
            return await update.message.reply_text("❌ ไม่พบ Finding นี้")
        evidence_count = len(list_evidence(finding["finding_id"]))
        text = (
            f"Finding #{finding['finding_id']} [{finding['status']}]\n"
            f"หัวข้อ: {finding['title']}\n"
            f"Target: {finding['target']}\n"
            f"Severity: {finding['severity']}\n"
            f"รายละเอียด: {finding['description'] or '-'}\n"
            f"Evidence: {evidence_count} รายการ"
        )
        if finding["status"] == "DUPLICATE":
            text += f"\nDuplicate of: #{finding['duplicate_of']}"
        if finding["resolution"]:
            text += f"\nสรุปผล: {finding['resolution']}"
        await update.message.reply_text(text)

    elif sub == "status":
        if not await is_admin(update, context):
            return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
        if len(args) < 3 or not args[1].isdigit():
            return await update.message.reply_text(
                "ใช้งาน: /bbfinding status <finding_id> <สถานะใหม่> [สรุปผล...]"
            )
        finding_id = int(args[1])
        new_status = args[2].upper()
        resolution = " ".join(args[3:])
        result = update_finding_status(finding_id, new_status, actor_user_id=user.id, resolution=resolution)
        if not result.ok:
            return await update.message.reply_text(_deny_text_finding(result.reason, result.detail))
        await update.message.reply_text(f"✅ Finding #{finding_id} -> {new_status}")

    elif sub == "duplicate":
        if not await is_admin(update, context):
            return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
        if len(args) < 3 or not args[1].isdigit() or not args[2].isdigit():
            return await update.message.reply_text("ใช้งาน: /bbfinding duplicate <finding_id> <duplicate_of>")
        finding_id, duplicate_of = int(args[1]), int(args[2])
        result = mark_duplicate(finding_id, duplicate_of, actor_user_id=user.id)
        if not result.ok:
            return await update.message.reply_text(_deny_text_finding(result.reason, result.detail))
        await update.message.reply_text(f"✅ Finding #{finding_id} ถูก mark เป็น duplicate ของ #{duplicate_of}")

    else:
        await update.message.reply_text("❌ subcommand ไม่ถูกต้อง (new/list/show/status/duplicate)")


async def cmd_bbevidence(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/bbevidence add|list|verify|remove -- see Phase 4 report for the
    exact argument syntax of each subcommand."""
    args = context.args or []
    if not args:
        return await update.message.reply_text(
            "ใช้งาน:\n"
            "/bbevidence add <finding_id> <ประเภท> [รายละเอียด...] (Reply ไฟล์/รูปได้)\n"
            "/bbevidence list <finding_id>\n"
            "/bbevidence verify <evidence_id> (Reply ไฟล์/รูปที่จะเทียบ)\n"
            "/bbevidence remove <evidence_id>"
        )
    sub = args[0].lower()
    user = update.effective_user
    reply_msg = update.message.reply_to_message

    if sub == "add":
        if len(args) < 3:
            return await update.message.reply_text(
                "ใช้งาน: /bbevidence add <finding_id> <ประเภท> [รายละเอียด...] "
                "(ใช้ได้: " + ", ".join(sorted(VALID_EVIDENCE_TYPES)) + ")"
            )
        if not args[1].isdigit():
            return await update.message.reply_text("❌ finding_id ต้องเป็นตัวเลข")
        finding_id = int(args[1])
        evidence_type = args[2].upper()
        description = " ".join(args[3:])

        content_bytes, filename = None, None
        if reply_msg and (reply_msg.photo or reply_msg.document):
            content_bytes, filename, err = await _download_evidence_file(reply_msg, context)
            if err:
                return await update.message.reply_text(err)

        result = add_evidence(finding_id, evidence_type, created_by=user.id,
                               description=description, filename=filename,
                               content_bytes=content_bytes)
        if not result.ok:
            return await update.message.reply_text(_deny_text_evidence(result.reason, result.detail))
        text = f"✅ เพิ่ม Evidence #{result.evidence_id} ให้ Finding #{finding_id} แล้ว"
        if result.sha256:
            text += f"\nSHA-256: {result.sha256}"
        await update.message.reply_text(text)

    elif sub == "list":
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text("ใช้งาน: /bbevidence list <finding_id>")
        evidence = list_evidence(int(args[1]))
        if not evidence:
            return await update.message.reply_text("ยังไม่มี Evidence สำหรับ Finding นี้")
        lines = []
        for e in evidence:
            label = e["filename"] or e["evidence_type"]
            hash_note = f" sha256={e['sha256'][:12]}..." if e["sha256"] else ""
            lines.append(f"#{e['evidence_id']} [{e['evidence_type']}] {label}{hash_note}")
        await _reply_chunked(update, "Evidence:\n" + "\n".join(lines))

    elif sub == "verify":
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text(
                "ใช้งาน: Reply ไฟล์/รูปที่จะเทียบแล้วพิมพ์ /bbevidence verify <evidence_id>"
            )
        if not reply_msg or not (reply_msg.photo or reply_msg.document):
            return await update.message.reply_text(
                "ใช้งาน: Reply ไฟล์/รูปที่จะเทียบแล้วพิมพ์ /bbevidence verify <evidence_id>"
            )
        content_bytes, _filename, err = await _download_evidence_file(reply_msg, context)
        if err:
            return await update.message.reply_text(err)
        result = verify_evidence(int(args[1]), content_bytes)
        if not result.ok:
            return await update.message.reply_text(_deny_text_evidence(result.reason))
        if result.match:
            await update.message.reply_text(f"✅ ตรงกัน (SHA-256: {result.recalculated_sha256})")
        else:
            await update.message.reply_text(
                f"⚠️ ไม่ตรงกัน\nที่บันทึกไว้: {result.stored_sha256}\nไฟล์นี้: {result.recalculated_sha256}"
            )

    elif sub == "remove":
        if not await is_admin(update, context):
            return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text("ใช้งาน: /bbevidence remove <evidence_id>")
        ok = remove_evidence(int(args[1]), actor_user_id=user.id)
        if not ok:
            return await update.message.reply_text("❌ ไม่พบ Evidence นี้")
        await update.message.reply_text(f"✅ ลบ Evidence #{args[1]} แล้ว")

    else:
        await update.message.reply_text("❌ subcommand ไม่ถูกต้อง (add/list/verify/remove)")

# ---------------- Message Handler ----------------

async def check_auto_reply(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> bool:
    """Auto-reply เมื่อข้อความตรงกับ AUTO_REPLY_TRIGGERS
    - พิมพ์ครั้งที่ 1-3: ตอบข้อความปกติ
    - เกิน AUTO_REPLY_ANNOY_THRESHOLD (ครั้งที่ 4-5): ตอบข้อความรำคาญ
    - เกิน AUTO_REPLY_ANGRY_THRESHOLD (ครั้งที่ 6+): ตอบข้อความไม่สุภาพ
    นับโควต้าแยกตาม (chat_id, user_id, trigger) คนละคนคนละโควต้า
    คืนค่า True หากมีการตอบกลับแล้ว (handle_message ควร return ทันที)
    """
    trigger = text.strip()
    reply_text = AUTO_REPLY_TRIGGERS.get(trigger)
    if reply_text is None:
        return False
        
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    key = (chat_id, user_id, trigger)
    
    auto_reply_tracker[key] += 1
    count = auto_reply_tracker[key]
    
    if count > AUTO_REPLY_ANGRY_THRESHOLD:
        await update.message.reply_text(AUTO_REPLY_ANGRY_TEXT)
    elif count > AUTO_REPLY_ANNOY_THRESHOLD:
        await update.message.reply_text(AUTO_REPLY_ANNOYED_TEXT)
    else:
        await update.message.reply_text(reply_text)
        
    logger.info(
        f"AUTO REPLY | Chat ID: {chat_id} | User ID: {user_id} | "
        f"Trigger: {trigger!r} | Count: {count}"
    )
    return True
    
async def _run_ai_question(update: Update, context: ContextTypes.DEFAULT_TYPE, question: str,
                            reply_msg, media) -> None:
    """ตรวจโควตา เรียก coordinator แล้วตอบกลับผู้ใช้ — ใช้ร่วมกันทั้ง
    check_gemini_mention (แท็กบอทเป็นข้อความ) และ handle_media_message
    (แท็กบอทใน caption ของรูป/ไฟล์) เพื่อไม่ให้ logic โควตา/quota-message/
    error-handling สองที่เพี้ยนไปจากกัน"""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    
    admin = await is_admin(update, context)
    allowed, used, limit = check_and_use_quota(chat_id, user_id, admin)
    if not allowed:
        await update.message.reply_text(
            f"ใช้งานเกินโควตาวันนี้แล้ว ({used}/{limit} ครั้ง) ไว้มาใช้วันอื่นนะ หรือถ้ารีบก็ไปใช้งานบนเว็บไป ไอ้ควาย ไม่ต้องมาใช้กู นอกจากจะเปลือง Token แล้วยังเปลืองออกซิเจนเพราะมึงแย่งหายใจอีก🖕🏻"
        )
        return
        
    logger.info(
        f"GEMINI MENTION | Chat ID: {chat_id} | User ID: {user_id} | "
        f"Question: {question} | Media: {'yes' if media else 'no'}"
    )
    await context.bot.send_chat_action(chat_id, ChatAction.TYPING)
    
    reply_user_id = reply_msg.from_user.id if reply_msg and reply_msg.from_user else None
    reply_text = reply_msg.text if reply_msg and reply_msg.text else None
    ok, result = await coordinator.handle_request(
        chat_id=chat_id,
        user_id=user_id,
        is_admin=admin,
        question=question,
        reply_user_id=reply_user_id,
        reply_text=reply_text,
        media=media,
    )
    if not ok:
        await update.message.reply_text(result)
        return
    for chunk in split_telegram_message(result):
        await update.message.reply_text(chunk)
    
async def check_gemini_mention(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> bool:
    """ถาม AI เมื่อมีคนแท็กบอท เช่น '@ชื่อบอท คำถาม' ในแชท
    รองรับแนบรูปภาพ/ไฟล์ (PDF/TXT) ได้ด้วยการ Reply ข้อความที่มีรูป/เอกสารนั้น
    แล้วแท็กบอทพร้อมคำถาม — หรือแท็กเฉยๆ ก็ได้ถ้ามีรูป/ไฟล์แนบ (จะใช้คำถามเริ่มต้น)
    คืนค่า True หากมีการตอบกลับแล้ว (handle_message ควร return ทันที)"""
    message = update.effective_message
    bot_username = context.bot.username
    if not bot_username:
        return False
        
    entities = message.parse_entities(types=["mention"])
    mention_text = _find_bot_mention(entities, bot_username)
    if mention_text is None:
        return False
        
    question = text.replace(mention_text, "", 1).strip()
    
    reply_msg = update.message.reply_to_message
    media = None
    if reply_msg and (reply_msg.photo or reply_msg.document):
        media_bytes, media_mime, media_error = await extract_media_from_message(reply_msg, context)
        if media_error:
            await update.message.reply_text(media_error)
            return True
        if media_bytes:
            media = [(media_bytes, media_mime)]
            
    if not question:
        if media:
            question = DEFAULT_MEDIA_QUESTION
        else:
             await update.message.reply_text(
                f"พิมพ์คำถามต่อท้าย {mention_text} ได้เลย เช่น {mention_text} วันนี้พ่อกับแม่มึงเย็ดกันหรือยัง"
             )
             return True
            
    await _run_ai_question(update, context, question, reply_msg, media)
    return True
    
async def handle_media_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """แท็กบอทพร้อมแนบรูปภาพ/ไฟล์ในข้อความเดียว เช่น ส่งรูปแล้วใส่ caption
    '@ชื่อบอท นี่คือรูปอะไร' — ทำงานคู่กับ check_gemini_mention ซึ่งรองรับ
    กรณี Reply รูป/ไฟล์ที่ส่งไปก่อนหน้าแล้วแท็กบอทเป็นข้อความแยกต่างหาก"""
    message = update.effective_message
    if message is None or not message.caption:
        return
        
    bot_username = context.bot.username
    if not bot_username:
        return
        
    entities = message.parse_caption_entities(types=["mention"])
    mention_text = _find_bot_mention(entities, bot_username)
    if mention_text is None:
        return
        
    media_bytes, media_mime, media_error = await extract_media_from_message(message, context)
    if media_error:
        await update.message.reply_text(media_error)
        return
    if not media_bytes:
        return 
        
    question = message.caption.replace(mention_text, "", 1).strip() or DEFAULT_MEDIA_QUESTION
    await _run_ai_question(update, context, question, reply_msg=None, media=[(media_bytes, media_mime)])
    
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    message = update.effective_message
    if message is None or not message.text:
        return
    chat = update.effective_chat
    user = update.effective_user
    text = message.text
        
    logger.info(f"MESSAGE RECEIVED | Chat ID: {chat.id} | User ID: {user.id} | Text: {text}")
    if chat.type in (ChatType.GROUP, ChatType.SUPERGROUP):
        record_message_activity(chat.id, text)
        detection_results = detection.analyze_message(chat.id, user.id, text)
        if detection_results:
            worst = max(
                detection_results,
                key=lambda r: {"low": 0, "medium": 1, "high": 2}.get(r.severity, 0),
            )
            await safe_delete(message, chat.id, context)
            await apply_warning_and_maybe_mute(update, context, user.id, f"⚠️ {worst.reason}")
            return
    if await check_auto_reply(update, context, text):
            return
            
    if await check_gemini_mention(update, context, text):
            return
        
    settings = get_settings(chat.id)
        
    if settings["antispam_on"]:
        now = time.time()
        dq = spam_tracker[(chat.id, user.id)]
        dq.append(now)
        while dq and now - dq[0] > SPAM_TIME_WINDOW:
            dq.popleft()
        if len(dq) > SPAM_MESSAGE_LIMIT:
            logger.info(f"SPAM DETECTED | Chat ID: {chat.id} | User ID: {user.id}")
            await safe_delete(message, chat.id, context)
            await apply_warning_and_maybe_mute(update, context, user.id, "⚠️ ส่งข้อความเหี้ยไรบ่อยนักหนา ไอ้นรก")
            dq.clear()
            return
        
        chat_id = update.effective_chat.id
        user_id = update.effective_user.id
            
    logger.info(f"FILTER: {'ON' if settings['filter_on'] else 'OFF'}")
    if settings["filter_on"]:
        words = list_words(chat.id)
        matched = contains_forbidden_word(text, words)
        if matched:
            logger.info(f"MATCHED WORD: {matched}\nACTION: DELETE")
            await safe_delete(message, chat.id, context)
            await apply_warning_and_maybe_mute(update, context, user.id, "🚫 ตรวจพบพวกลาบใช้คำต้องห้าม")
        else:
            logger.info("MATCHED WORD: NONE\nACTION: IGNORE")

async def error_handler(update, context):
    logger.error("UNHANDLED ERROR", exc_info=context.error)
    
async def post_init(app):
    app.bot_data["news_task"] = asyncio.create_task(news_background_loop(app.bot))
    
async def post_shutdown(app):
    task = app.bot_data.get("news_task")
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    
# ---------------- Main ----------------

def main():
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is not set. Please check .env file")
        
    logger.info("BOT STARTING")
    db_info()
    quota_db_init()
    security_db_init()
    analytics_db_init()
    news_db_init()
    detection.detection_db_init()
    scope_policy_db_init()
    findings_db_init()
    logger.info("DATABASE: OK")
    
    app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )
    
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("filter_on", cmd_filter_on))
    app.add_handler(CommandHandler("filter_off", cmd_filter_off))
    app.add_handler(CommandHandler("addword", cmd_addword))
    app.add_handler(CommandHandler("delword", cmd_delword))
    app.add_handler(CommandHandler("listwords", cmd_listwords))
    app.add_handler(CommandHandler("warnings", cmd_warnings))
    app.add_handler(CommandHandler("resetwarn", cmd_resetwarn))
    app.add_handler(CommandHandler("mute", cmd_mute))
    app.add_handler(CommandHandler("unmute", cmd_unmute))
    app.add_handler(CommandHandler("announce", cmd_announce))
    app.add_handler(CommandHandler("imagine", cmd_imagine))
    app.add_handler(CommandHandler("groupstats", cmd_groupstats))
    app.add_handler(CommandHandler("dashboard", dashboard_command))
    app.add_handler(CommandHandler("id", chat_id_command))
    app.add_handler(CommandHandler("bbprogram", cmd_bbprogram))
    app.add_handler(CommandHandler("bbauth", cmd_bbauth))
    app.add_handler(CommandHandler("bbscope", cmd_bbscope))
    app.add_handler(CommandHandler("bbcheck", cmd_bbcheck))
    app.add_handler(CommandHandler("bbreport", cmd_bbreport))
    app.add_handler(CommandHandler("bbfinding", cmd_bbfinding))
    app.add_handler(CommandHandler("bbevidence", cmd_bbevidence))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(
        filters.PHOTO & filters.CaptionRegex(IMAGINE_CAPTION_RE),
        handle_imagine_caption,
    ))
    app.add_handler(MessageHandler(
        (filters.PHOTO | filters.Document.ALL) & filters.CAPTION
        & ~filters.CaptionRegex(IMAGINE_CAPTION_RE) & ~filters.COMMAND,
        handle_media_message,
    ))
    app.add_error_handler(error_handler)

    logger.info("HANDLERS: OK")
    logger.info("POLLING: STARTED")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()