#!/usr/bin/env python3
'''
 ████ █   █  ███  █████ █████ █████ ████  .
█     █   █ █   █   █     █   █     █   █ .
█     █████ █████   █     █   █████ ████  .
█     █   █ █   █   █     █   █     █   █ .
 ████ █   █ █   █   █     █   █████ █   █ .

Chatter: Real-time messaging without the need to reload.

CODE TABLE OF CONTENTS
1. Importing
2. Languages
3. Optional conversion of time zone
4. Group data tables database (DO NOT DELETE OR UR COOKED)
5. 
'''
# Importing

import os
import re
import io
import json
import time
import random
import string
import sqlite3
from datetime import datetime, timedelta, timezone, timezone
from werkzeug.security import generate_password_hash
from functools import wraps
from collections import defaultdict
import secrets
import threading

from flask import (
    Flask,
    request,
    jsonify,
    session,
    send_from_directory,
    render_template_string,
    abort,
    redirect,
    url_for,
    g,
    Response
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room, leave_room
import html as _html
import hmac
import hashlib
import base64 as _b64
import shutil

import sqlite3
import csv
import io
import json
import markdown
import bleach
import secrets
import string
import requests
import difflib
import zlib
import base64, os
import uuid
from cryptography.fernet import Fernet
from flask_cors import CORS

# Languages

SUPPORTED_LANGUAGES = [
    ("en", "English"),
    ("es", "Spanish"),
    ("fr", "French"),
    ("de", "German"),
    ("it", "Italian"),
    ("pt", "Portuguese"),
    ("ru", "Russian"),
    ("ja", "Japanese"),
    ("ko", "Korean"),
    ("zh-CN", "Chinese (Simplified)"),
    ("zh-TW", "Chinese (Traditional)"),
    ("hi", "Hindi"),
    ("ar", "Arabic"),
]
SUPPORTED_LANGUAGE_CODES = {code for code, _ in SUPPORTED_LANGUAGES}

# Optional timezone conversion to America/New_York
try:
    from zoneinfo import ZoneInfo
    NY_TZ = ZoneInfo("America/New_York")
except Exception:
    NY_TZ = None

def to_ny_time(dt):
    if not dt:
        return None
    try:
        if NY_TZ is None:
            return dt.isoformat()
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(NY_TZ).isoformat()
    except Exception:
        return dt.isoformat()

def _client_id_from_request() -> str:
    try:
        cid = (request.cookies.get('client_id') or '').strip()
        if not cid:
            cid = (request.headers.get('X-Client-ID') or '').strip()
        return cid
    except Exception:
        return ''

def _is_device_banned(cid: str) -> bool:
    if not cid:
        return False

def _b64u(data: bytes) -> str:
    return _b64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

def _b64ud(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return _b64.urlsafe_b64decode(s + pad)

def _issue_dbx_token(user: str, ttl_seconds: int = 600) -> str:
    try:
        exp = int(time.time()) + int(ttl_seconds)
        payload = json.dumps({'u': user, 'exp': exp}, separators=(',',':')).encode('utf-8')
        sig = hmac.new(app.secret_key.encode('utf-8'), payload, hashlib.sha256).digest()
        return _b64u(payload) + '.' + _b64u(sig)
    except Exception:
        return ''

def _verify_dbx_token(token: str) -> str:
    try:
        if not token or '.' not in token:
            return ''
        p_b64, s_b64 = token.split('.', 1)
        payload = _b64ud(p_b64)
        sig = _b64ud(s_b64)
        good = hmac.compare_digest(hmac.new(app.secret_key.encode('utf-8'), payload, hashlib.sha256).digest(), sig)
        if not good:
            return ''
        obj = json.loads(payload.decode('utf-8'))
        if int(obj.get('exp') or 0) < int(time.time()):
            return ''
        return str(obj.get('u') or '')
    except Exception:
        return ''

def _dbx_user() -> str:
    try:
        u = session.get('username') or ''
        if u:
            return u
        tok = (
            request.headers.get('X-DBX')
            or (request.cookies.get('dbx') or '')
            or (request.args.get('dbx') or '')
        )
        return _verify_dbx_token(tok) or ''
    except Exception:
        return ''
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT 1 FROM device_bans WHERE client_id=? LIMIT 1', (cid,))
        return cur.fetchone() is not None
    except Exception:
        return False

# ============================================================================
# Group data database (IMPORTANT DO NOT DELETE)
def _ensure_gdm_schema():
    try:
        db = get_db(); cur = db.cursor()
        # Base tables
        cur.execute('CREATE TABLE IF NOT EXISTS group_threads (id INTEGER PRIMARY KEY, name TEXT, created_by TEXT, created_at TIMESTAMP, invite_code TEXT)')
        cur.execute('CREATE TABLE IF NOT EXISTS group_members (thread_id INTEGER, username TEXT)')
        cur.execute('CREATE TABLE IF NOT EXISTS group_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, thread_id INTEGER, username TEXT, text TEXT, attachment TEXT, created_at TIMESTAMP, edited INTEGER DEFAULT 0)')
        # Optional tables used by features
        try: cur.execute('CREATE TABLE IF NOT EXISTS group_bans (thread_id INTEGER, username TEXT)')
        except Exception: pass
        try: cur.execute('CREATE TABLE IF NOT EXISTS group_timeouts (thread_id INTEGER, username TEXT, until_ts INTEGER)')
        except Exception: pass
        # Columns that may be missing on older installs
        for col, default in (('locked', '0'),):
            try:
                cur.execute(f'ALTER TABLE group_threads ADD COLUMN {col} INTEGER DEFAULT {default}')
                db.commit()
            except Exception:
                pass
        # Add invite_code column if missing
        try:
            cur.execute('ALTER TABLE group_threads ADD COLUMN invite_code TEXT')
            db.commit()
        except Exception:
            pass
        
        # Generate invite codes for existing groups that don't have one
        try:
            import random, string
            cur.execute('SELECT id FROM group_threads WHERE invite_code IS NULL OR invite_code = ""')
            rows = cur.fetchall()
            for row in rows:
                thread_id = row[0]
                invite_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
                cur.execute('UPDATE group_threads SET invite_code = ? WHERE id = ?', (invite_code, thread_id))
            if rows:
                db.commit()
        except Exception:
            pass
        db.commit()
    except Exception:
        try:
            get_db().rollback()
        except Exception:
            pass

# Ensure Doc schema exists
def get_doc_role(doc_id, username):
    """Get the role of a user in a doc"""
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT role FROM doc_members WHERE doc_id=? AND username=?', (doc_id, username))
        r = cur.fetchone()
        return r[0] if r else None
    except Exception:
        return None

def can_view_doc(doc_id, username):
    """Check if user can view a doc"""
    role = get_doc_role(doc_id, username)
    return role is not None  # All members can view

def can_edit_doc(doc_id, username):
    """Check if user can edit a doc"""
    role = get_doc_role(doc_id, username)
    return role == 'editor'

def is_doc_creator(doc_id, username):
    """Check if user is the doc creator"""
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT created_by FROM docs WHERE id=?', (doc_id,))
        r = cur.fetchone()
        return r and (r[0] if not isinstance(r, sqlite3.Row) else r['created_by']) == username
    except Exception:
        return False

def _ensure_doc_schema():
    try:
        db = get_db(); cur = db.cursor()
        # Docs table
        cur.execute('''CREATE TABLE IF NOT EXISTS docs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            content TEXT DEFAULT '',
            last_edited_by TEXT,
            last_edited_at TIMESTAMP,
            tmpweb_url TEXT,
            tmpweb_expires_at TIMESTAMP,
            last_local_save TIMESTAMP,
            last_tmpweb_save TIMESTAMP
        )''')
        # Doc members table (like group_members) with permissions
        cur.execute('''CREATE TABLE IF NOT EXISTS doc_members (
            doc_id INTEGER,
            username TEXT,
            role TEXT DEFAULT 'viewer',
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (doc_id, username)
        )''')

        # Add role column if it doesn't exist (for existing installations)
        try:
            cur.execute("PRAGMA table_info(doc_members)")
            columns = [col[1] for col in cur.fetchall()]
            if 'role' not in columns:
                cur.execute("ALTER TABLE doc_members ADD COLUMN role TEXT DEFAULT 'viewer'")
        except Exception:
            pass
        db.commit()
    except Exception:
        try:
            get_db().rollback()
        except Exception:
            pass

def _seed_defaults_if_needed():
    try:
        if str(get_setting('DEFAULTS_SEEDED','0')) == '1':
            return
        defaults_on = [
            'PUBLIC_ENABLED','DM_ENABLED','GDM_ENABLED',
            'UM_BAN_USER','UM_TIMEOUT_USER','UM_SEARCH_USER','UM_TEMP_BAN','UM_GLOBAL_WARNING','UM_SHADOW_BAN',
            'MC_DELETE_MESSAGES','MC_EDIT_MESSAGES','MC_VIEW_HISTORY','MC_SEARCH_MESSAGES','MC_BROADCAST_MESSAGE','MC_PIN_MESSAGE',
            'GD_LOCK_GROUP','GD_UNLOCK_GROUP','GD_REMOVE_USER','GD_TRANSFER_OWNERSHIP','GD_DELETE_GROUP','GD_CLOSE_ALL_DMS','GD_DM_AS_SYSTEM','GD_SAVE_DM_LOGS','GD_FORCE_LEAVE_GROUP',
            'SEC_DEVICE_BAN_ON_LOGIN','SEC_REG_BAN_SIMILAR_CID'
        ]
        for k in defaults_on:
            try:
                set_setting(k, '1')
            except Exception:
                pass
        try:
            set_setting('DEFAULTS_SEEDED', '1')
        except Exception:
            pass
    except Exception:
        pass

def _log_incident(kind: str, meta: dict | None = None):
    """Append a structured incident line to the log file.

    """
    try:
        ts = _format_web_timestamp(datetime.utcnow())
        payload = {
            'kind': kind,
            'time': ts,
        }
        try:
            if isinstance(meta, dict):
                payload.update(meta)
        except Exception:
            pass
        _append_log_line(json.dumps(payload, ensure_ascii=False))
    except Exception:
        pass

# ============================================================================
    except Exception:
        pass

# ============================================================================
# COMPREHENSIVE ANTI-SPAM SYSTEM
# ============================================================================

import hashlib
import difflib
from collections import defaultdict, deque
import gzip

# Anti-spam system state - tracks user behavior patterns and sanctions
antispam_system_state = {
    'user_behavior': defaultdict(lambda: {
        'message_history': deque(maxlen=50),  # Recent messages for duplicate detection
        'message_times': deque(maxlen=100),   # Timestamps for rate analysis
        'message_lengths': deque(maxlen=20),  # Recent message lengths
        'sanction_level': 0,                  # 0=none, 1=warning, 2=slow_mode, 3=restricted
        'sanction_count': defaultdict(int),   # Count of each sanction type
        'last_sanction_time': 0,              # When last sanction was applied
        'slow_mode_until': 0,                 # Timestamp when slow mode expires
        'last_message_time': 0,               # For individual slow mode enforcement
        'pattern_violations': defaultdict(int), # Track specific pattern violations
        'warning_count': 0,                   # Number of warnings issued
    }),
    'global_stats': {
        'total_messages_blocked': 0,
        'total_warnings_issued': 0,
        'total_slow_modes_applied': 0,
        'total_restrictions_applied': 0,
        'last_cleanup_time': time.time(),
    },
    'settings_cache': {},  # Cache for anti-spam settings
    'message_hashes': deque(maxlen=1000),  # Global recent message hashes for duplicate detection
}

def _get_antispam_setting(key, default='0'):
    """Get anti-spam setting with caching"""
    try:
        cache_key = f'ANTISPAM_{key}'
        if cache_key in antispam_system_state['settings_cache']:
            return antispam_system_state['settings_cache'][cache_key]

        value = get_setting(cache_key, default)
        antispam_system_state['settings_cache'][cache_key] = value
        return value
    except Exception:
        return default

def _clear_antispam_settings_cache():
    """Clear settings cache to force reload"""
    antispam_system_state['settings_cache'].clear()

def _cleanup_antispam_memory():
    """Clean up old data to prevent memory leaks"""
    try:
        now = time.time()
        # Only cleanup every 10 minutes
        if now - antispam_system_state['global_stats']['last_cleanup_time'] < 600:
            return

        # Clean up old user behavior data
        cutoff_time = now - 3600  # 1 hour ago
        users_to_remove = []

        for username, data in antispam_system_state['user_behavior'].items():
            # Remove old timestamps
            while data['message_times'] and data['message_times'][0] < cutoff_time:
                data['message_times'].popleft()

            # If user has no recent activity, mark for removal
            if not data['message_times'] and data['last_message_time'] < cutoff_time:
                users_to_remove.append(username)

        # Remove inactive users
        for username in users_to_remove:
            del antispam_system_state['user_behavior'][username]

        antispam_system_state['global_stats']['last_cleanup_time'] = now
    except Exception:
        pass

def _calculate_message_hash(text, username):
    """Calculate hash for duplicate detection"""
    try:
        # Normalize text for comparison
        normalized = re.sub(r'\s+', ' ', (text or '').strip().lower())
        content = f"{username}:{normalized}"
        return hashlib.md5(content.encode('utf-8')).hexdigest()
    except Exception:
        return None

def _fuzzy_similarity(text1, text2):
    """Calculate fuzzy similarity between two texts (0.0 to 1.0)"""
    try:
        if not text1 or not text2:
            return 0.0

        # Normalize texts
        norm1 = re.sub(r'\s+', ' ', text1.strip().lower())
        norm2 = re.sub(r'\s+', ' ', text2.strip().lower())

        if norm1 == norm2:
            return 1.0

        # Use difflib for similarity
        similarity = difflib.SequenceMatcher(None, norm1, norm2).ratio()
        return similarity
    except Exception:
        return 0.0

def _is_near_duplicate(text, username, threshold=0.85):
    """Check if message is a near-duplicate of recent messages"""
    try:
        user_data = antispam_system_state['user_behavior'][username]

        # Check against user's recent messages
        for recent_msg in list(user_data['message_history'])[-10:]:  # Check last 10 messages
            similarity = _fuzzy_similarity(text, recent_msg)
            if similarity >= threshold:
                return True, similarity

        return False, 0.0
    except Exception:
        return False, 0.0

def _compress_and_measure(text):
    """Compress text and measure payload size"""
    try:
        if not text:
            return 0, 0

        original_size = len(text.encode('utf-8'))
        compressed = gzip.compress(text.encode('utf-8'))
        compressed_size = len(compressed)

        return original_size, compressed_size
    except Exception:
        return 0, 0

def _detect_suspicious_patterns(text):
    """Detect suspicious content patterns"""
    try:
        if not text:
            return []

        violations = []

        # Excessive whitespace
        whitespace_ratio = len(re.findall(r'\s', text)) / max(len(text), 1)
        if whitespace_ratio > 0.7:
            violations.append('excessive_whitespace')

        # HTML/CSS patterns
        html_tags = len(re.findall(r'<[^>]+>', text))
        if html_tags > 10:
            violations.append('excessive_html')

        # Repeated structures
        div_count = len(re.findall(r'<div[^>]*>', text, re.IGNORECASE))
        script_count = len(re.findall(r'<script[^>]*>', text, re.IGNORECASE))
        br_count = len(re.findall(r'<br[^>]*>', text, re.IGNORECASE))

        if div_count > 5:
            violations.append('excessive_divs')
        if script_count > 0:
            violations.append('script_tags')
        if br_count > 20:
            violations.append('excessive_breaks')

        # Code block patterns
        code_blocks = len(re.findall(r'```[\s\S]*?```', text))
        if code_blocks > 3:
            violations.append('excessive_code_blocks')

        return violations
    except Exception:
        return []

def _split_message_intelligently(text, max_length=800):
    """Split message by paragraphs and line breaks"""
    try:
        if not text or len(text) <= max_length:
            return [text] if text else []

        parts = []

        # First try splitting by double newlines (paragraphs)
        paragraphs = text.split('\n\n')
        current_part = ""

        for paragraph in paragraphs:
            if len(current_part + paragraph) <= max_length:
                current_part += paragraph + '\n\n'
            else:
                if current_part:
                    parts.append(current_part.strip())
                    current_part = ""

                # If paragraph itself is too long, split by single newlines
                if len(paragraph) > max_length:
                    lines = paragraph.split('\n')
                    for line in lines:
                        if len(current_part + line) <= max_length:
                            current_part += line + '\n'
                        else:
                            if current_part:
                                parts.append(current_part.strip())
                            current_part = line + '\n'
                else:
                    current_part = paragraph + '\n\n'

        if current_part:
            parts.append(current_part.strip())

        return parts
    except Exception:
        return [text] if text else []

def _apply_progressive_sanction(username, violation_type):
    """Apply progressive sanctions based on user behavior"""
    try:
        user_data = antispam_system_state['user_behavior'][username]
        now = time.time()

        # Increment violation count
        user_data['sanction_count'][violation_type] += 1
        total_violations = sum(user_data['sanction_count'].values())

        # Determine sanction level based on total violations
        if total_violations == 1:
            # First violation - warning
            user_data['sanction_level'] = 1
            user_data['warning_count'] += 1
            user_data['last_sanction_time'] = now
            antispam_system_state['global_stats']['total_warnings_issued'] += 1
            return 'warning', "⚠️ Warning: Please avoid spamming. Continued violations may result in restrictions."

        elif total_violations <= 3:
            # Second/third violation - slow mode
            user_data['sanction_level'] = 2
            slow_duration = min(10 + (total_violations * 5), 60)  # 10-60 seconds
            user_data['slow_mode_until'] = now + slow_duration
            user_data['last_sanction_time'] = now
            antispam_system_state['global_stats']['total_slow_modes_applied'] += 1
            return 'slow_mode', f"🐌 Slow mode applied for {slow_duration} seconds. Please wait before sending another message."

        else:
            # Fourth+ violation - restricted state
            user_data['sanction_level'] = 3
            restriction_duration = min(300 + (total_violations * 60), 1800)  # 5-30 minutes
            user_data['slow_mode_until'] = now + restriction_duration
            user_data['last_sanction_time'] = now
            antispam_system_state['global_stats']['total_restrictions_applied'] += 1
            return 'restricted', f"🚫 Restricted for {restriction_duration//60} minutes due to repeated violations. Please review chat guidelines."

    except Exception:
        return 'warning', "⚠️ Please avoid spamming."

def _is_user_in_slow_mode(username):
    """Check if user is currently in slow mode"""
    try:
        user_data = antispam_system_state['user_behavior'][username]
        now = time.time()

        if user_data['slow_mode_until'] > now:
            remaining = int(user_data['slow_mode_until'] - now)
            return True, remaining

        return False, 0
    except Exception:
        return False, 0

def _should_apply_individual_slow_mode(username):
    """Check if individual slow mode should be applied based on behavior"""
    try:
        user_data = antispam_system_state['user_behavior'][username]
        now = time.time()

        # Check recent message frequency
        recent_messages = [t for t in user_data['message_times'] if now - t < 60]  # Last minute

        if len(recent_messages) >= 10:  # 10+ messages in last minute
            return True, "🐌 Automatic slow mode: Too many messages in a short time."

        # Check for rapid large messages
        recent_large = 0
        for i, length in enumerate(list(user_data['message_lengths'])[-5:]):
            if length > 500:  # Large message
                recent_large += 1

        if recent_large >= 3:  # 3+ large messages recently
            return True, "🐌 Automatic slow mode: Multiple large messages detected."

        return False, ""
    except Exception:
        return False, ""

def antispam_check_message(username, text, message_type="public", has_attachment=False):
    """
    Main anti-spam check function - returns (allowed, message, split_parts)

    This is the core function called by the message pipeline to check if a message
    should be allowed, blocked, or split. Implements all 7 anti-spam features.
    """
    try:
        # Clean up memory periodically
        _cleanup_antispam_memory()

        # Check if anti-spam is enabled
        if _get_antispam_setting('ENABLED', '1') != '1':
            return True, "", [text] if text else []

        # Skip checks for superadmins if configured
        try:
            if _get_antispam_setting('SKIP_SUPERADMINS', '1') == '1' and is_superadmin(username):
                return True, "", [text] if text else []
        except Exception:
            pass

        user_data = antispam_system_state['user_behavior'][username]
        now = time.time()

        # Update user activity
        user_data['last_message_time'] = now
        user_data['message_times'].append(now)
        if text:
            user_data['message_lengths'].append(len(text))

        # 1. CHECK SLOW MODE STATUS
        in_slow_mode, remaining_time = _is_user_in_slow_mode(username)
        if in_slow_mode:
            antispam_system_state['global_stats']['total_messages_blocked'] += 1
            return False, f"🐌 You are in slow mode. Please wait {remaining_time} more seconds.", []

        # 2. CHECK INDIVIDUAL SLOW MODE TRIGGERS
        should_slow, slow_msg = _should_apply_individual_slow_mode(username)
        if should_slow:
            user_data['slow_mode_until'] = now + 10  # 10 second cooldown
            antispam_system_state['global_stats']['total_messages_blocked'] += 1
            return False, slow_msg, []

        # Skip further checks for empty messages with attachments
        if not text and has_attachment:
            return True, "", []

        if not text:
            return True, "", []

        # 3. MESSAGE LENGTH LIMITS
        max_length = int(_get_antispam_setting('MAX_MESSAGE_LENGTH', '1000'))
        if len(text) > max_length:
            # Check if auto-split is enabled
            if _get_antispam_setting('AUTO_SPLIT_ENABLED', '1') == '1':
                split_parts = _split_message_intelligently(text, max_length)
                if len(split_parts) > 1:
                    return True, f"Message will be split into {len(split_parts)} parts.", split_parts

            # Apply sanction for oversized message
            sanction_type, sanction_msg = _apply_progressive_sanction(username, 'message_too_long')
            antispam_system_state['global_stats']['total_messages_blocked'] += 1
            return False, f"❌ Message too long (max {max_length} characters). {sanction_msg}", []

        # 4. DUPLICATE & NEAR-DUPLICATE DETECTION
        if _get_antispam_setting('DUPLICATE_DETECTION', '1') == '1':
            is_duplicate, similarity = _is_near_duplicate(text, username)
            if is_duplicate:
                sanction_type, sanction_msg = _apply_progressive_sanction(username, 'duplicate_message')
                antispam_system_state['global_stats']['total_messages_blocked'] += 1
                return False, f"❌ Duplicate or very similar message detected. {sanction_msg}", []

        # 5. PAYLOAD SIZE MONITORING
        if _get_antispam_setting('PAYLOAD_MONITORING', '1') == '1':
            original_size, compressed_size = _compress_and_measure(text)
            max_payload = int(_get_antispam_setting('MAX_PAYLOAD_SIZE', '10000'))

            if original_size > max_payload:
                sanction_type, sanction_msg = _apply_progressive_sanction(username, 'payload_too_large')
                antispam_system_state['global_stats']['total_messages_blocked'] += 1
                return False, f"❌ Message payload too large. {sanction_msg}", []

        # 6. CONTENT PATTERN ANALYSIS
        if _get_antispam_setting('PATTERN_ANALYSIS', '1') == '1':
            violations = _detect_suspicious_patterns(text)
            if violations:
                # Track pattern violations
                for violation in violations:
                    user_data['pattern_violations'][violation] += 1

                # Apply sanction if too many pattern violations
                total_pattern_violations = sum(user_data['pattern_violations'].values())
                if total_pattern_violations >= 3:
                    sanction_type, sanction_msg = _apply_progressive_sanction(username, 'suspicious_patterns')
                    antispam_system_state['global_stats']['total_messages_blocked'] += 1
                    return False, f"❌ Suspicious content patterns detected. {sanction_msg}", []

        # Store message in history for future duplicate detection
        user_data['message_history'].append(text)

        # Calculate and store message hash
        msg_hash = _calculate_message_hash(text, username)
        if msg_hash:
            antispam_system_state['message_hashes'].append(msg_hash)

        # Message passed all checks
        return True, "", [text]

    except Exception as e:
        # On error, allow message but log the issue
        try:
            _log_incident('antispam_error', {'username': username, 'error': str(e)})
        except Exception:
            pass
        return True, "", [text] if text else []

# ---- Admins UI script injection (registered later to avoid NameError) ----
def _inject_admins_js(resp):
    # No-op: do not inject Admins section into right sidebar
    return resp

def admins_js():
    js = r'''(() => {
const SELS=['#rightOnlineList','#usersList','#users','.users-list','.usersPane','.right-col .users','.users','.users-container','.sidebar .users','#right .users'];
function bySel(){ for(const s of SELS){ const el=document.querySelector(s); if(el) return el; } return null; }
function findUsersHeading(){
  const cands = Array.from(document.querySelectorAll('h1,h2,h3,div,span'));
  for(const el of cands){
    const t = (el.textContent||'').trim();
    if(/^users\b/i.test(t)) return el;
  }
  return null;
}
function hostOrFallback(){
  const host = bySel(); if(host) return host.parentNode || host;
  const hdr = findUsersHeading(); if(hdr) return hdr.parentNode || document.body;
  return document.querySelector('.right-col') || document.querySelector('#right') || document.querySelector('.sidebar') || document.body;
}
function badge(role){ return role==='superadmin' ? '<span style="margin-left:6px;padding:2px 6px;border-radius:10px;background:#7c3aed;color:#fff;font-size:10px">SUPER</span>' : '<span style="margin-left:6px;padding:2px 6px;border-radius:10px;background:#2563eb;color:#fff;font-size:10px">ADMIN</span>'; }
function render(list){
  const host=bySel(); const target=hostOrFallback(); if(!target) return;
  let sec=document.getElementById('admins-section');
  if(!sec){
    sec=document.createElement('div'); sec.id='admins-section'; sec.style.margin='0 0 8px 0';
    if(host){ host.prepend(sec); }
    else if(target){ target.insertBefore(sec, target.firstChild); }
  }
  const items=(list||[]).map(function(a){ return '<div class="admin-item" style="display:flex;align-items:center;gap:6px;padding:4px 0"><span class="dot" style="width:8px;height:8px;border-radius:50%;background:#22c55e;display:inline-block"></span><span>'+a.username+'</span>'+badge(a.role)+'</div>'; }).join('');
  sec.innerHTML = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px"><strong>Admins</strong><span style="font-size:12px;color:#9ca3af">(' + (list||[]).length + ' online)</span></div>' + items;
}
function mirror(list){ const host=bySel(); if(!host) return; host.querySelectorAll('.admin-mirror').forEach(function(el){ el.remove(); }); (list||[]).forEach(function(a){ const el=document.createElement('div'); el.className='admin-mirror'; el.style.display='flex'; el.style.alignItems='center'; el.style.gap='6px'; el.style.padding='4px 0'; el.innerHTML = '<span class="dot" style="width:8px;height:8px;border-radius:50%;background:#22c55e;display:inline-block"></span><span>'+a.username+'</span>'+badge(a.role); host.appendChild(el); }); }
function cleanStatuses(){
  const root = bySel() || document;
  const words=new Set(['ONLINE','DND','IDLE','OFFLINE','AWAY','BUSY']);
  const isHeader = (t) => /(ONLINE|OFFLINE)\s*—/i.test(t);
  const wipe = (node) => { if(node) node.textContent=''; };
  ['.status','.user-status','.presence','.presence-text','.status-text'].forEach(function(q){ root.querySelectorAll(q).forEach(wipe); });
  root.querySelectorAll('span,small,div,p').forEach(function(el){
    if(el.childElementCount===0){
      const t=(el.textContent||'').trim();
      if(!t) return;
      if(isHeader(t)) return; // keep section headers
      if(words.has(t.toUpperCase())) el.textContent='';
      else if(/^(ONLINE|DND|IDLE|OFFLINE|AWAY|BUSY)\b/i.test(t)) el.textContent='';
    }
  });
}
function observeStatuses(){
  try{
    const root = bySel() || document.body; if(!root) return;
    const mo = new MutationObserver(()=>cleanStatuses());
    mo.observe(root, {subtree:true, childList:true, characterData:true});
  }catch(e){}
}
async function tick(){ try{ const r=await fetch('/api/admins/online',{credentials:'same-origin'}); const j=await r.json(); if(r.ok&&j&&j.ok){ const list=j.admins||[]; render(list); mirror(list); cleanStatuses(); } }catch(e){} }
function ensureAdminDropdown(){ if(document.getElementById('admin-dropdown')) return; const b=document.createElement('div'); b.id='admin-dropdown'; b.style.position='fixed'; b.style.top='12px'; b.style.right='12px'; b.style.zIndex='9999'; b.innerHTML = '\
<div style="position:relative">\
  <button id="admBtn" style="background:#111827;color:#e5e7eb;border:1px solid #374151;border-radius:8px;padding:8px 10px;cursor:pointer">Admin ▾</button>\
  <div id="admMenu" style="position:absolute;right:0;margin-top:6px;background:#0b1020;border:1px solid #374151;border-radius:8px;display:none;min-width:180px;box-shadow:0 10px 20px rgba(0,0,0,0.4)">\
    <a href="/admin/create_user" style="display:block;padding:8px 10px;color:#e5e7eb;text-decoration:none">Create User</a>\
    <a href="/admin/dbsafe" style="display:block;padding:8px 10px;color:#e5e7eb;text-decoration:none">DB Safe</a>\
    <a href="/dbx" style="display:block;padding:8px 10px;color:#e5e7eb;text-decoration:none">DBX Unlock</a>\
  </div>\
</div>'; document.body.appendChild(b); const btn=b.querySelector('#admBtn'); const menu=b.querySelector('#admMenu'); btn.addEventListener('click',function(){ menu.style.display = (menu.style.display==='none'||!menu.style.display) ? 'block':'none'; }); document.addEventListener('click',function(e){ if(!b.contains(e.target)){ menu.style.display='none'; } }); }
async function maybeShowAdminDropdown(){ try{ const r=await fetch('/api/me/role',{credentials:'same-origin'}); const j=await r.json(); if(r.ok && j && j.ok && (j.is_superadmin || j.is_admin)) { ensureAdminDropdown(); } }catch(e){} }
tick(); setInterval(tick, 5000); maybeShowAdminDropdown(); observeStatuses();
})();
'''
    from flask import make_response
    resp = make_response(js)
    resp.headers['Content-Type'] = 'application/javascript; charset=utf-8'
    return resp

def _rand_code(n=16):
    try:
        alphabet = string.ascii_uppercase + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(n))
    except Exception:
        return 'X'*n

def _get_downtime_code():
    try:
        code = get_setting('DOWNTIME_CODE','') or ''
        if not code:
            code = _rand_code(16)
            set_setting('DOWNTIME_CODE', code)
        return code
    except Exception:
        return _rand_code(16)

# ===================== Superadmin: Create User =====================
def admin_create_user():
    u = session.get('username') or ''
    if not is_superadmin(u):
        return redirect('/')
    if request.method == 'GET':
        html = (
            "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>Create User</title><style>body{font-family:system-ui,Segoe UI,Arial;margin:0;background:#0f172a;color:#e5e7eb} .card{max-width:520px;margin:24px auto;background:#111827;border:1px solid #1f2937;border-radius:12px;padding:16px} input,select,button{background:#0b1020;color:#e5e7eb;border:1px solid #374151;border-radius:6px;padding:8px;width:100%;box-sizing:border-box} label{display:block;margin:10px 0 6px} button{cursor:pointer} button:hover{filter:brightness(1.1)}</style></head><body>"
            "<div class='card'><h3 style='margin:0 0 12px'>Create User</h3>"
            "<form method='POST'><label>Username</label><input name='username' placeholder='username' required>"
            "<label>Password</label><input type='password' name='password' placeholder='password' required>"
            "<label>Role (optional)</label><input name='role' placeholder='role e.g. admin or user'>"
            "<div style='height:12px'></div><button type='submit'>Create</button></form>"
            "<div style='height:8px'></div><a href='/' style='color:#93c5fd'>Back</a></div></body></html>"
        )
        return html
    # POST
    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    role = (request.form.get('role') or '').strip() or None
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    try:
        db = get_db(); cur = db.cursor()
        # Users table schema
        cols, pk, has_rowid = _dbx_schema(cur, 'users')
        colnames = {c['name'] for c in cols}
        # Check uniqueness
        try:
            cur.execute('SELECT 1 FROM users WHERE username=? LIMIT 1', (username,))
            if cur.fetchone():
                return jsonify({'error': 'username already exists'}), 409
        except Exception:
            pass
        # Hash password
        try:
            from werkzeug.security import generate_password_hash
            pwh = generate_password_hash(password)
        except Exception:
            pwh = password
        values = {}
        # Required fields based on available columns
        if 'username' in colnames:
            values['username'] = username
        if 'password_hash' in colnames:
            values['password_hash'] = pwh
        elif 'password' in colnames:
            values['password'] = pwh
        if role and 'role' in colnames:
            values['role'] = role
        if 'language' in colnames and 'language' not in values:
            values['language'] = 'en'
        # created_at if present
        if 'created_at' in colnames:
            try:
                values['created_at'] = to_ny_time(datetime.now(timezone.utc))
            except Exception:
                values['created_at'] = datetime.utcnow().isoformat()
        if not values:
            return jsonify({'error': 'users table does not have supported columns'}), 500
        ks = list(values.keys())
        cur.execute(
            f"INSERT INTO users (" + ','.join(ks) + ") VALUES (" + ','.join(['?']*len(ks)) + ")",
            [values[k] for k in ks]
        )
        db.commit()
        try:
            log_admin_action(u, 'create_user', target=username, details={'via':'page','is_admin': bool(role and role.lower()=='admin')})
        except Exception:
            pass
        return redirect('/'), 302
    except Exception as e:
        try:
            get_db().rollback()
        except Exception:
            pass
        return jsonify({'error': str(e)}), 500

def _ensure_dbx_code():
    try:
        db = get_db(); cur = db.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)")
        cur.execute("SELECT value FROM app_settings WHERE key='DBX_CODE'")
        row = cur.fetchone()
        if row and row[0]:
            return row[0]
        code = _rand_code(24)
        try:
            cur.execute("INSERT OR REPLACE INTO app_settings(key,value) VALUES('DBX_CODE',?)", (code,))
            db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
        return code
    except Exception:
        return _rand_code(24)

def _get_dbx_code():
    try:
        db = get_db(); cur = db.cursor()
        cur.execute("SELECT value FROM app_settings WHERE key='DBX_CODE'")
        row = cur.fetchone()
        if row and row[0]:
            return row[0]
        return _ensure_dbx_code()
    except Exception:
        return _ensure_dbx_code()


# ---- Auth decorator (must be defined before any @login_required usage) ----
from functools import wraps as _wraps_login
def login_required(fn=None):
    def decorator(f):
        @_wraps_login(f)
        def wrapper(*args, **kwargs):
            try:
                u = session.get('username') or _verify_dbx_token(request.headers.get('X-DBX') or '')
                if not u:
                    wants_json = 'application/json' in (request.headers.get('Accept','') or '') or (request.path or '').startswith('/api/')
                    return (jsonify({'error': 'not logged in'}), 401) if wants_json else redirect('/')
                g.username = u
                return f(*args, **kwargs)
            except Exception:
                return jsonify({'error': 'not logged in'}), 401
        return wrapper
    return decorator(fn) if fn else decorator

# Also expose to builtins for modules pasted without import ordering
try:
    import builtins as _bi
    if not getattr(_bi, 'login_required', None):
        _bi.login_required = login_required
except Exception:
    pass

# -------- Admin helpers for main UI --------
def _admins_from_settings():
    try:
        db = get_db(); cur = db.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)")
        cur.execute("SELECT value FROM app_settings WHERE key='ADMINS'")
        row = cur.fetchone()
        if not row or not row[0]:
            return set()
        raw = str(row[0])
        return set([x.strip() for x in raw.split(',') if x.strip()])
    except Exception:
        return set()

def _is_adminish(username: str) -> bool:
    try:
        if not username:
            return False
        s = username.lower()
        # Baseline default sets
        try:
            if any((u == username) or (getattr(u, 'lower', lambda: u)() == s) for u in SUPERADMINS):
                return True
        except Exception:
            pass
        try:
            if any((u == username) or (getattr(u, 'lower', lambda: u)() == s) for u in ADMINS):
                return True
        except Exception:
            pass
        # DB-backed roles and extra table
        try:
            db = get_db(); cur = db.cursor()
            try:
                cur.execute('CREATE TABLE IF NOT EXISTS extra_admins (username TEXT PRIMARY KEY, created_at TEXT, created_by TEXT)')
            except Exception:
                pass
            try:
                cur.execute('SELECT role FROM users WHERE lower(username)=? LIMIT 1', (s,))
                r = cur.fetchone()
                if r:
                    role = r[0] if not isinstance(r, sqlite3.Row) else r['role']
                    if (role or '').lower() in ('admin','superadmin'):
                        return True
            except Exception:
                pass
            try:
                cur.execute('SELECT 1 FROM extra_admins WHERE lower(username)=? LIMIT 1', (s,))
                if cur.fetchone():
                    return True
            except Exception:
                pass
        except Exception:
            pass
        return False
    except Exception:
        return False

def api_admins_online():
    try:
        # Stealth mode: hide admins from online list entirely when enabled
        try:
            if get_setting('ADMINS_STEALTH','0') == '1':
                return jsonify({'ok': True, 'admins': []})
        except Exception:
            pass
        db = get_db(); cur = db.cursor()
        # Load extra_admins set for origin tagging
        extra_set = set()
        try:
            cur.execute('CREATE TABLE IF NOT EXISTS extra_admins (username TEXT PRIMARY KEY, created_at TEXT, created_by TEXT)')
            cur.execute('SELECT username FROM extra_admins')
            for r in cur.fetchall() or []:
                try:
                    extra_set.add(r[0] if not isinstance(r, sqlite3.Row) else r['username'])
                except Exception:
                    pass
        except Exception:
            pass
        online = set()
        # 1) DB table chatter_online if present
        try:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chatter_online'")
            if cur.fetchone():
                try:
                    cur.execute("SELECT DISTINCT username FROM chatter_online")
                    online.update([r[0] for r in cur.fetchall() if r and r[0]])
                except Exception:
                    try:
                        cur.execute("SELECT DISTINCT user FROM chatter_online")
                        online.update([r[0] for r in cur.fetchall() if r and r[0]])
                    except Exception:
                        pass
        except Exception:
            pass
        # 2) In-memory trackers
        try:
            online.update(list(getattr(globals().get('online_users', {}), 'keys', lambda: [])()))
        except Exception:
            try:
                online.update(list(online_users.keys()))
            except Exception:
                pass
        try:
            vals = list(getattr(globals().get('connected_sockets', {}), 'values', lambda: [])())
            if vals:
                online.update([v for v in vals if v])
        except Exception:
            try:
                online.update(list(connected_sockets.values()))
            except Exception:
                pass
        # 3) Current session user
        try:
            u = session.get('username')
            if u:
                online.add(u)
        except Exception:
            pass
        out = []
        for u in sorted(list(online)):
            try:
                if _is_adminish(u):
                    role = 'superadmin' if (("is_superadmin" in globals()) and is_superadmin(u)) else 'admin'
                    out.append({'username': u, 'role': role, 'extra': (False if role=='superadmin' else (u in extra_set))})
            except Exception:
                pass
        return jsonify({'ok': True, 'admins': out})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Flask app setup (moved here to fix app not defined error)
app = Flask(__name__, static_folder=os.path.dirname(os.path.abspath(__file__)))
app.secret_key = "dev-secret-key-change-this-in-production"

@app.route('/api/admin/create_user', methods=['POST'])
@login_required
def api_admin_create_user():
    try:
        me = session.get('username')
        if not me or not (('is_superadmin' in globals()) and is_superadmin(me)):
            return jsonify({'error': 'forbidden'}), 403
        data = request.get_json(silent=True) or {}
        username = (data.get('username') or '').strip()
        password = (data.get('password') or '').strip()
        is_admin_flag = True if data.get('is_admin') in (True, '1', 1, 'true', 'on') else False
        try:
            username = sanitize_username(username)
        except Exception:
            pass
        # Mirror register() validations
        if not username or len(username) > 20:
            return jsonify({'error': 'Invalid username (max 20 characters)'}), 400
        if not password:
            return jsonify({'error': 'Provide password'}), 400
        if username.lower() == 'system':
            return jsonify({'error': 'Reserved username'}), 400
        # Hash like register()
        try:
            from werkzeug.security import generate_password_hash as _gph
            pw_hash = _gph(password)
        except Exception:
            pw_hash = generate_password_hash(password)  # type: ignore

        db = get_db(); cur = db.cursor()
        try:
            cur.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, theme TEXT, avatar TEXT, bio TEXT, status TEXT, language TEXT DEFAULT \'en\', allow_dm_nonfriends INTEGER DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        except Exception:
            pass
        
        # Check if user already exists
        cur.execute('SELECT username FROM users WHERE username = ?', (username,))
        if cur.fetchone():
            return jsonify({'error': 'Username taken'}), 409
        
        # INSERT only (no replace) to avoid clobbering existing users
        try:
            try:
                cur.execute('INSERT INTO users (username, password_hash, language) VALUES (?, ?, ?)', (username, pw_hash, 'en'))
                print(f"DEBUG: Inserted user {username} into users table")
            except sqlite3.OperationalError:
                cur.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, pw_hash))
                print(f"DEBUG: Inserted user {username} into users table (fallback)")
        except sqlite3.IntegrityError as e:
            print(f"DEBUG: IntegrityError: {e}")
            return jsonify({'error': 'Username taken'}), 409
        except Exception as e:
            print(f"DEBUG: Insert error: {e}")
            return jsonify({'error': f'Database error: {str(e)}'}), 500
            
        if is_admin_flag:
            try:
                cur.execute('CREATE TABLE IF NOT EXISTS extra_admins (username TEXT PRIMARY KEY, created_at TEXT, created_by TEXT)')
                cur.execute('INSERT OR REPLACE INTO extra_admins(username, created_at, created_by) VALUES (?,?,?)', (username, datetime.utcnow(), me))
                print(f"DEBUG: Added {username} to extra_admins table")
            except Exception as e:
                print(f"DEBUG: Admin table error: {e}")
                pass
        
        # Commit transaction
        try:
            db.commit()
            print(f"DEBUG: Database committed successfully")
        except Exception as e:
            print(f"DEBUG: Commit error: {e}")
            db.rollback()
            return jsonify({'error': 'Failed to save user to database'}), 500
            
        # Verify user was created
        cur.execute('SELECT username FROM users WHERE username = ?', (username,))
        verification = cur.fetchone()
        if not verification:
            print(f"DEBUG: Verification failed - user not found after insert")
            return jsonify({'error': 'Failed to verify user creation'}), 500
            
        print(f"DEBUG: User {username} created and verified successfully")
        
        try:
            log_admin_action(me, 'create_user', target=username, details={'via':'api','is_admin': bool(is_admin_flag)})
        except Exception:
            pass
        try:
            socketio.emit('user_list_refresh', {'new_user': username})
        except Exception:
            pass
        return jsonify({'ok': True, 'username': username})
    except Exception as e:
        print(f"DEBUG: Create user error: {e}")
        import traceback
        traceback.print_exc()
        try:
            get_db().rollback()
        except Exception:
            pass
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/banned_users', methods=['GET'])
@login_required
def api_admin_banned_users():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT username FROM banned_users ORDER BY username ASC')
        banned_users = [row[0] for row in cur.fetchall()]
        return jsonify({'banned_users': banned_users})
    except Exception as e:
        print(f"Error fetching banned users: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/request_password_reset', methods=['POST'])
def api_request_password_reset():
    """Request a password reset token"""
    try:
        data = request.get_json(silent=True) or {}
        username = (data.get('username') or '').strip()
        email = (data.get('email') or '').strip()
        
        if not username or not email:
            return jsonify({'error': 'Username and email are required'}), 400
        
        # Validate username format
        try:
            username = sanitize_username(username)
        except Exception:
            return jsonify({'error': 'Invalid username format'}), 400
        
        # Validate email format
        if '@' not in email or '.' not in email:
            return jsonify({'error': 'Invalid email format'}), 400
        
        db = get_db()
        cur = db.cursor()
        
        # Check if user exists and email matches
        cur.execute('SELECT username, email FROM users WHERE username=?', (username,))
        user = cur.fetchone()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        stored_email = user[1] if not isinstance(user, sqlite3.Row) else user['email']
        if not stored_email or stored_email.lower() != email.lower():
            return jsonify({'error': 'Email does not match our records'}), 400
        
        # Generate reset token
        import secrets
        token = secrets.token_urlsafe(32)
        expiry = datetime.now(timezone.utc) + timedelta(hours=1)  # Token expires in 1 hour
        
        # Store reset token
        cur.execute('CREATE TABLE IF NOT EXISTS password_reset_tokens (username TEXT PRIMARY KEY, token TEXT, expires_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        cur.execute('INSERT OR REPLACE INTO password_reset_tokens (username, token, expires_at) VALUES (?, ?, ?)', 
                   (username, token, expiry))
        db.commit()
        
        # Log the reset request
        try:
            log_admin_action('system', 'password_reset_requested', target=username, details={'email': email})
        except Exception:
            pass
        
        # Send reset email
        try:
            # Get frontend URL (port 8080) instead of backend URL (port 5000)
            frontend_url = request.headers.get('Origin') or request.host_url.replace('5000', '8080')
            reset_link = f"{frontend_url}/reset-password?token={token}&username={username}"
            email_subject = "Password Reset - Chatter"
            email_body = f"""
Hello {username},

You requested a password reset for your Chatter account.

Click the link below to reset your password:
{reset_link}

This link will expire in 1 hour.

If you didn't request this password reset, you can safely ignore this email.

Thanks,
Chatter Team
            """
            
            # Actual email sending using Gmail SMTP
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            msg = MIMEMultipart()
            msg['From'] = 'wholeworldcoding@gmail.com'
            msg['To'] = email
            msg['Subject'] = email_subject
            msg.attach(MIMEText(email_body, 'plain'))
            
            # Gmail SMTP configuration with app password
            try:
                server = smtplib.SMTP('smtp.gmail.com', 587)
                server.starttls()
                # Use app-specific password for Gmail
                server.login('wholeworldcoding@gmail.com', 'akbg qacz meal bijl')
                server.send_message(msg)
                server.quit()
                print(f"Password reset email sent successfully to {email}")
            except smtplib.SMTPAuthenticationError as auth_error:
                print(f"Gmail authentication failed: {auth_error}")
                print("Make sure to:")
                print("1. Enable 2-factor authentication on the Gmail account")
                print("2. Generate an app-specific password")
                print("3. Use the app password instead of the regular password")
                raise auth_error
            
        except Exception as e:
            print(f"Failed to send reset email: {e}")
            # Continue with the flow even if email fails
            # In development, still show the reset info
            print(f"=== PASSWORD RESET EMAIL (FALLBACK) ===")
            print(f"To: {email}")
            print(f"Subject: {email_subject}")
            print(f"Body: {email_body}")
            print(f"==========================")
        
        return jsonify({
            'ok': True, 
            'message': 'Password reset instructions sent to your email',
            # Only include token in development for testing
            'token': token if app.debug else None
        })
        
    except Exception as e:
        print(f"Password reset request error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/reset_password', methods=['POST'])
def api_reset_password():
    """Reset password using token"""
    try:
        data = request.get_json(silent=True) or {}
        username = (data.get('username') or '').strip()
        token = (data.get('token') or '').strip()
        new_password = (data.get('password') or '').strip()
        confirm_password = (data.get('confirm_password') or '').strip()
        
        if not username or not token or not new_password:
            return jsonify({'error': 'Username, token, and new password are required'}), 400
        
        # Validate passwords match
        if new_password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        # Validate password
        if len(new_password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400
        
        db = get_db()
        cur = db.cursor()
        
        # Verify token and check expiry
        cur.execute('SELECT token, expires_at FROM password_reset_tokens WHERE username=?', (username,))
        token_data = cur.fetchone()
        
        if not token_data:
            return jsonify({'error': 'Invalid or expired reset token'}), 400
        
        stored_token = token_data[0] if not isinstance(token_data, sqlite3.Row) else token_data['token']
        expires_at = token_data[1] if not isinstance(token_data, sqlite3.Row) else token_data['expires_at']
        
        if stored_token != token:
            return jsonify({'error': 'Invalid reset token'}), 400
        
        if datetime.utcnow() > expires_at:
            # Clean up expired token
            cur.execute('DELETE FROM password_reset_tokens WHERE username=?', (username,))
            db.commit()
            return jsonify({'error': 'Reset token has expired'}), 400
        
        # Hash new password
        try:
            from werkzeug.security import generate_password_hash as _gph
            pw_hash = _gph(new_password)
        except Exception:
            pw_hash = generate_password_hash(new_password)
        
        # Update password
        cur.execute('UPDATE users SET password_hash=? WHERE username=?', (pw_hash, username))
        
        # Clean up reset token
        cur.execute('DELETE FROM password_reset_tokens WHERE username=?', (username,))
        
        db.commit()
        
        # Log the password reset
        try:
            log_admin_action('system', 'password_reset_completed', target=username)
        except Exception:
            pass
        
        # Invalidate user sessions (optional security measure)
        try:
            # You might want to implement session invalidation here
            pass
        except Exception:
            pass
        
        return jsonify({'ok': True, 'message': 'Password reset successfully'})
        
    except Exception as e:
        print(f"Password reset error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/admin/reset_password', methods=['POST'])
@login_required
def api_admin_reset_password():
    try:
        me = session.get('username')
        if not me or not (('is_superadmin' in globals()) and is_superadmin(me)):
            return jsonify({'error': 'forbidden'}), 403
        data = request.get_json(silent=True) or {}
        username = sanitize_username((data.get('username') or '').strip())
        new_pw = (data.get('password') or '').strip()
        if not username or not new_pw:
            return jsonify({'error': 'missing username or password'}), 400
        # Guard: superadmins cannot reset other superadmins' passwords
        try:
            if username in SUPERADMINS and username != me:
                try:
                    log_admin_action(me, 'reset_password_blocked', target=username)
                except Exception:
                    pass
                return jsonify({'error': 'cannot reset password for another superadmin'}), 403
        except Exception:
            pass
        try:
            from werkzeug.security import generate_password_hash as _gph
            pw_hash = _gph(new_pw)
        except Exception:
            try:
                pw_hash = generate_password_hash(new_pw)  # type: ignore
            except Exception:
                pw_hash = new_pw
        db = get_db(); cur = db.cursor()
        try:
            cur.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT, created_at TEXT)')
        except Exception:
            pass
        # Update if exists; otherwise create user with current timestamp
        cur.execute('INSERT OR REPLACE INTO users(username, password_hash, created_at) VALUES (?,?,COALESCE((SELECT created_at FROM users WHERE username=?),?))', (username, pw_hash, username, datetime.utcnow()))
        db.commit()
        try:
            log_admin_action(me, 'reset_password', target=username)
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        try:
            get_db().rollback()
        except Exception:
            pass
        return jsonify({'error': str(e)}), 500

def api_pinned():
    try:
        kind = (request.args.get('type') or 'public').lower()
        all_pins = request.args.get('all', '').lower() == 'true'
        if kind not in ('public','gdm'):
            return jsonify({'error':'bad params'}), 400
        db = get_db(); cur = db.cursor()
        _ensure_pin_table()
        if kind == 'public':
            if all_pins:
                # Return all pinned messages, ordered by created_at DESC
                cur.execute('SELECT message_id, created_at FROM pinned_messages WHERE kind=? ORDER BY created_at DESC', ('public',))
                rows = cur.fetchall()
                messages = []
                for row in rows:
                    mid = row[0]
                    try:
                        cur.execute('SELECT id, username, text, attachment, created_at FROM messages WHERE id=?', (mid,))
                        r = cur.fetchone()
                        if r:
                            messages.append({'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4]) if r[4] else None, 'pinned_at': to_ny_time(row[1]) if row[1] else None})
                    except Exception:
                        pass
                return jsonify({'ok': True, 'messages': messages})
            else:
                # Return latest pinned message
                cur.execute('SELECT message_id FROM pinned_messages WHERE kind=? ORDER BY created_at DESC LIMIT 1', ('public',))
                row = cur.fetchone(); mid = row[0] if row else None
                if not mid:
                    return jsonify({'ok': True, 'message': None})
                try:
                    cur.execute('SELECT id, username, text, attachment, created_at FROM messages WHERE id=?', (mid,))
                    r = cur.fetchone()
                    if not r:
                        return jsonify({'ok': True, 'message': None})
                    msg = {'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4]) if r[4] else None}
                    return jsonify({'ok': True, 'message': msg})
                except Exception:
                    return jsonify({'ok': True, 'message': None})
        else:
            try:
                tid = int(request.args.get('thread_id') or 0)
            except Exception:
                tid = 0
            if not tid:
                return jsonify({'error':'bad params'}), 400
            if all_pins:
                # Return all pinned messages for this thread
                cur.execute('SELECT message_id, created_at FROM pinned_messages WHERE kind=? AND thread_id=? ORDER BY created_at DESC', ('gdm', tid))
                rows = cur.fetchall()
                messages = []
                for row in rows:
                    mid = row[0]
                    try:
                        cur.execute('SELECT id, username, text, attachment, created_at FROM group_messages WHERE id=?', (mid,))
                        r = cur.fetchone()
                        if r:
                            messages.append({'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4]) if r[4] else None, 'thread_id': tid, 'pinned_at': to_ny_time(row[1]) if row[1] else None})
                    except Exception:
                        pass
                return jsonify({'ok': True, 'messages': messages})
            else:
                # Return latest pinned message for this thread
                cur.execute('SELECT message_id FROM pinned_messages WHERE kind=? AND thread_id=? ORDER BY created_at DESC LIMIT 1', ('gdm', tid))
                row = cur.fetchone(); mid = row[0] if row else None
                if not mid:
                    return jsonify({'ok': True, 'message': None})
                try:
                    cur.execute('SELECT id, username, text, attachment, created_at FROM group_messages WHERE id=?', (mid,))
                    r = cur.fetchone()
                    if not r:
                        return jsonify({'ok': True, 'message': None})
                    msg = {'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4]) if r[4] else None, 'thread_id': tid}
                    return jsonify({'ok': True, 'message': msg})
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def api_me_role():
    try:
        u = session.get('username') or ''
        is_sup = False
        is_adm = False
        try:
            is_sup = is_superadmin(u)
        except Exception:
            is_sup = False
        try:
            if 'is_admin' in globals() and callable(globals().get('is_admin')):
                is_adm = globals()['is_admin'](u)
            else:
                is_adm = (not is_sup) and _is_adminish(u)
        except Exception:
            is_adm = (not is_sup) and _is_adminish(u)
        return jsonify({'ok': True, 'username': u, 'is_superadmin': bool(is_sup), 'is_admin': bool(is_adm)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def _bool_from_setting(v: str) -> bool:
    try:
        return str(v).strip().lower() in ('1','true','yes','on')
    except Exception:
        return False

def api_admins_resets():
    try:
        me = session.get('username') or ''
        is_sa = bool(me and (('is_superadmin' in globals()) and is_superadmin(me)))
        is_ad = False
        try:
            if 'is_admin' in globals() and callable(globals().get('is_admin')):
                is_ad = globals()['is_admin'](me)
            else:
                is_ad = _is_adminish(me)
        except Exception:
            is_ad = _is_adminish(me)
        # Allow GET for admins and superadmins; restrict POST to superadmins
        if request.method == 'GET':
            if not (is_sa or is_ad):
                return jsonify({'error': 'forbidden'}), 403
            settings = {
                # Default to ON if not set, so toggles don't appear all off on first load
                'reset_public': _bool_from_setting(get_setting('RESET_PUBLIC_IDS','1')),
                'reset_dm': _bool_from_setting(get_setting('RESET_DM_IDS','1')),
                'reset_gdm': _bool_from_setting(get_setting('RESET_GDM_IDS','1')),
                'reset_group_threads': _bool_from_setting(get_setting('RESET_GROUP_THREADS_IDS','1')),
            }
            return jsonify({'ok': True, 'settings': settings})
        else:
            if not is_sa:
                return jsonify({'error': 'forbidden'}), 403
            data = request.get_json(silent=True) or {}
            try: set_setting('RESET_PUBLIC_IDS', '1' if (data.get('reset_public') in (True, '1', 1, 'true', 'on')) else '0')
            except Exception: pass
            try: set_setting('RESET_DM_IDS', '1' if (data.get('reset_dm') in (True, '1', 1, 'true', 'on')) else '0')
            except Exception: pass
            try: set_setting('RESET_GDM_IDS', '1' if (data.get('reset_gdm') in (True, '1', 1, 'true', 'on')) else '0')
            except Exception: pass
            try: set_setting('RESET_GROUP_THREADS_IDS', '1' if (data.get('reset_group_threads') in (True, '1', 1, 'true', 'on')) else '0')
            except Exception: pass
            return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def api_admins_resets_get():
    # Compatibility alias returning same as GET /api/admins/resets
    try:
        request.method = 'GET'  # hint for tooling
    except Exception:
        pass
    return api_admins_resets()

# ---------- DB Safe: generic key/value editor ----------
@login_required
def admin_dbsafe():
    me = session.get('username') or ''
    if not is_superadmin(me):
        return redirect('/')
    try:
        tbl = (request.args.get('table') or 'app_settings').strip()
        kcol = (request.args.get('key_col') or 'key').strip()
        vcol = (request.args.get('val_col') or 'value').strip()
        import re
        safe = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
        if not (safe.match(tbl) and safe.match(kcol) and safe.match(vcol)):
            return "Bad table or column name", 400
        if tbl == 'app_settings':
            _ensure_app_settings()
        db = get_db(); cur = db.cursor()
        cur.execute(f'SELECT {kcol}, {vcol} FROM {tbl} ORDER BY {kcol} ASC')
        rows = cur.fetchall() or []
        pairs = [(r[0] if not isinstance(r, sqlite3.Row) else r[kcol], r[1] if not isinstance(r, sqlite3.Row) else r[vcol]) for r in rows]
    except Exception:
        pairs = []
        tbl = (request.args.get('table') or 'app_settings').strip()
        kcol = (request.args.get('key_col') or 'key').strip()
        vcol = (request.args.get('val_col') or 'value').strip()
    html = [
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>DB Safe – {tbl}</title>",
        "<style>body{font-family:system-ui,Segoe UI,Arial;margin:0;background:#0f172a;color:#e5e7eb}",
        ".wrap{max-width:900px;margin:24px auto;padding:0 12px}",
        ".card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:16px}",
        "input.k,input.v{width:100%;box-sizing:border-box;background:#0b1020;color:#e5e7eb;border:1px solid #374151;border-radius:6px;padding:8px}",
        ".btn{padding:8px 12px;border-radius:8px;border:1px solid #374151;background:#2563eb;color:#fff;cursor:pointer}",
        ".row{display:grid;grid-template-columns:240px 1fr;gap:10px;align-items:center}",
        ".muted{color:#9ca3af;font-size:12px}",
        "a{color:#93c5fd}",
        "</style></head><body>",
        "<div class='wrap'><div class='card'>",
        f"<h3 style='margin:0 0 12px'>DB Safe – {tbl}</h3>",
        "<div class='muted'>Edit values and click Save All. Adds new rows if key is new.</div>",
        "<div id='rows'>",
    ]
    for k, v in pairs:
        try:
            html.append(f"<div class='row'><input class='k' value='{_html.escape(str(k))}' /><input class='v' value='{_html.escape(str(v or ''))}' /></div>")
        except Exception:
            pass
    html.append("<div class='row'><input class='k' placeholder='new key' /><input class='v' placeholder='value' /></div>")
    html += [
        "</div>",
        "<div style='display:flex;gap:8px;margin-top:12px'><button id='add' class='btn' type='button' style='background:#374151'>Add Row</button><button id='saveAll' class='btn' type='button'>Save All</button><a href='/' style='margin-left:auto;text-decoration:underline'>Back</a></div>",
        "<div id='note' class='muted' style='margin-top:8px'></div>",
        "</div></div>",
        "<script>(function(){\n",
        "const rows = document.getElementById('rows');\n",
        "document.getElementById('add').onclick = ()=>{ const d=document.createElement('div'); d.className='row'; d.innerHTML=\"<input class='k' placeholder='new key'/><input class='v' placeholder='value'/>\"; rows.appendChild(d); };\n",
        "document.getElementById('saveAll').onclick = async ()=>{\n",
        "  const data = {}; rows.querySelectorAll('.row').forEach(r=>{ const k=r.querySelector('.k').value.trim(); const v=r.querySelector('.v').value; if(k) data[k]=v; });\n",
        "  try{ const res = await fetch('/api/admin/dbsafe/save_all'+(window.location.search||''), { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) }); const j = await res.json();\n",
        "    document.getElementById('note').textContent = (res.ok && j && j.ok) ? 'Saved.' : (j && j.error ? j.error : 'Failed');\n",
        "  }catch(e){ document.getElementById('note').textContent = 'Failed'; }\n",
        "};\n",
        "})();</script>",
        "</body></html>"
    ]
    return ''.join(html)

@login_required
def api_admin_dbsafe_save_all():
    try:
        me = session.get('username') or ''
        if not is_superadmin(me):
            return jsonify({'error': 'forbidden'}), 403
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({'error': 'bad payload'}), 400
        tbl = (request.args.get('table') or 'app_settings').strip()
        kcol = (request.args.get('key_col') or 'key').strip()
        vcol = (request.args.get('val_col') or 'value').strip()
        import re
        safe = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
        if not (safe.match(tbl) and safe.match(kcol) and safe.match(vcol)):
            return jsonify({'error': 'bad table or column'}), 400
        if tbl == 'app_settings':
            _ensure_app_settings()
        db = get_db(); cur = db.cursor()
        ok = True
        for k, v in data.items():
            try:
                try:
                    cur.execute(f"INSERT INTO {tbl} ({kcol}, {vcol}) VALUES (?, ?) ON CONFLICT({kcol}) DO UPDATE SET {vcol}=excluded.{vcol}", (str(k), str(v)))
                except Exception:
                    try:
                        cur.execute(f"REPLACE INTO {tbl} ({kcol}, {vcol}) VALUES (?, ?)", (str(k), str(v)))
                    except Exception:
                        cur.execute(f"SELECT 1 FROM {tbl} WHERE {kcol}=? LIMIT 1", (str(k),))
                        if cur.fetchone():
                            cur.execute(f"UPDATE {tbl} SET {vcol}=? WHERE {kcol}=?", (str(v), str(k)))
                        else:
                            cur.execute(f"INSERT INTO {tbl} ({kcol}, {vcol}) VALUES (?, ?)", (str(k), str(v)))
            except Exception:
                ok = False
        try:
            db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
            ok = False
        return jsonify({'ok': ok})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def _register_admins_routes(a):
    try:
        a.add_url_rule('/api/admins/online', 'api_admins_online', api_admins_online, methods=['GET'])
        a.add_url_rule('/api/me/role', 'api_me_role', api_me_role, methods=['GET'])
        a.add_url_rule('/api/pinned', 'api_pinned', api_pinned, methods=['GET'])
        a.add_url_rule('/admins.js', 'admins_js', admins_js, methods=['GET'])
        # DB Safe routes (guarded)
        # Register legacy key/value editor at a non-conflicting path so /admin/dbsafe maps to the full tables UI below
        try:
            if 'admin_dbsafe_kv' not in a.view_functions:
                a.add_url_rule('/admin/dbsafe/kv', 'admin_dbsafe_kv', admin_dbsafe, methods=['GET'])
        except Exception:
            pass
        try:
            if 'api_admin_dbsafe_save_all' not in a.view_functions:
                a.add_url_rule('/api/admin/dbsafe/save_all', 'api_admin_dbsafe_save_all', api_admin_dbsafe_save_all, methods=['POST'])
        except Exception:
            pass
        # ID Reset toggles
        a.add_url_rule('/api/admins/resets', 'api_admins_resets', api_admins_resets, methods=['GET','POST'])
        a.add_url_rule('/api/admins/resets/get', 'api_admins_resets_get', api_admins_resets_get, methods=['GET'])
        # after_request must be registered per-app
        try:
            a.after_request(_inject_admins_js)
        except Exception:
            pass
        # Superadmin create-user routes
        a.add_url_rule('/admin/create_user', 'admin_create_user', admin_create_user, methods=['GET','POST'])
        a.add_url_rule('/api/admin/create_user', 'api_admin_create_user', api_admin_create_user, methods=['POST'])
        a.add_url_rule('/api/admin/reset_password', 'api_admin_reset_password', api_admin_reset_password, methods=['POST'])
        # Pinned messages API
        a.add_url_rule('/api/pinned', 'api_pinned', api_pinned, methods=['GET'])
    except Exception:
        pass

# Best-effort auto-register if app is already defined in this module
try:
    if 'app' in globals() and app:
        _register_admins_routes(app)
except Exception:
    pass

# Final safety: bind admin/pinned routes just before first request, in case
# the earlier auto-register ran before `app` existed.
try:
    @app.before_first_request
    def __bind_admin_routes_once():
        try:
            if not getattr(app, '_admins_routes_bound', False):
                _register_admins_routes(app)
                setattr(app, '_admins_routes_bound', True)
        except Exception:
            pass
        return None
except Exception:
    pass

def _rotate_downtime_code():
    try:
        set_setting('DOWNTIME_CODE', _rand_code(16))
    except Exception:
        pass

def enforce_device_ban():
    try:
        # Allow login, static and recovery always
        path = request.path or ''
        if path.startswith('/static/') or path.startswith('/preview/') or path.startswith('/uploads/'):
            return
        # Allow downtime unlock and smite always
        if path.startswith('/api/downtime/unlock') or path.rstrip('/') == '/smite':
            return
        # Superadmins bypass
        u = session.get('username')
        if u and is_superadmin(u):
            return
        cid = _client_id_from_request()
        if cid and _is_device_banned(cid):
            # Return JSON for API endpoints
            if path.startswith('/api/'):
                return jsonify({'error': 'device banned'}), 403
            return ("Forbidden: device banned", 403)
    except Exception:
        return

# File upload defaults
try:
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
except Exception:
    UPLOAD_FOLDER = 'uploads'
try:
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', str(20*1024*1024)))
except Exception:
    MAX_CONTENT_LENGTH = 20*1024*1024

app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.before_request(enforce_device_ban)

CORS(app, 
     supports_credentials=True, 
     origins=["http://localhost:8080", "http://127.0.0.1:8080", "http://localhost:3000", "http://127.0.0.1:3000"])

# Global error handler for API endpoints
@app.errorhandler(Exception)
def handle_exception(e):
    # If the request is for an API endpoint, return JSON
    if request.path.startswith('/api/'):
        return jsonify({'error': str(e)}), 500
    # For non-API endpoints, let Flask handle the error normally
    return e

# SocketIO initialization - only one instance
socketio = SocketIO(app, 
                    cors_allowed_origins=["http://localhost:8080", "http://127.0.0.1:8080", "http://localhost:3000", "http://127.0.0.1:3000"],
                    manage_session=False,
                    logger=True,
                    engineio_logger=True)

# Ensure self-contained app setup
try:
    if not getattr(app, 'secret_key', None):
        app.secret_key = os.environ.get('SECRET_KEY') or 'devkey'
except Exception:
    pass
try:
    _register_admins_routes(app)
except Exception:
    pass
    # File upload defaults
    try:
        UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    except Exception:
        UPLOAD_FOLDER = 'uploads'
    try:
        MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', str(20*1024*1024)))
    except Exception:
        MAX_CONTENT_LENGTH = 20*1024*1024
    try:
        app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
    except Exception:
        pass

# Helper: sanitize usernames to plain text (no HTML). Markdown punctuation is allowed.
def sanitize_username(u: str) -> str:
    try:
        import re
        # Strip HTML entirely then allow only a safe charset (no markdown semantics)
        text = _html.unescape(bleach.clean(u or '', tags=[], attributes={}, styles=[], strip=True))
        # Keep letters, numbers, space, underscore, hyphen, and dot
        text = re.sub(r"[^A-Za-z0-9._\- ]+", "", text)
        # Collapse multiple spaces
        text = re.sub(r"\s+", " ", text).strip()
        # Limit length to 20 characters
        if len(text) > 20:
            text = text[:20].rstrip()
        return text
    except Exception:
        return (u or '').strip()

def is_gdm_owner(tid: int, user: str) -> bool:
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
        row = cur.fetchone()
        owner = (row[0] if row and not isinstance(row, sqlite3.Row) else (row['created_by'] if row else None))
        return owner == user
    except Exception:
        return False

def is_superadmin(user: str = None) -> bool:
    try:
        u = user or session.get('username') or _verify_dbx_token(request.headers.get('X-DBX') or '')
        return u in SUPERADMINS
    except Exception:
        return False

# Ensure a consistent admin checker for all permission gates (override any legacy one)
def is_admin(user: str = None) -> bool:
    try:
        u = user or session.get('username') or ''
        if not u:
            return False
        # Recognize DB role admins and extra_admins as admins; superadmins are handled by is_superadmin
        if is_superadmin(u):
            return False
        return _is_adminish(u)
    except Exception:
        return False

def _list_all_admin_usernames() -> list:
    try:
        db = get_db(); cur = db.cursor()
        names = set()
        # Defaults
        try:
            for x in SUPERADMINS:
                try: names.add(str(x))
                except Exception: pass
        except Exception:
            pass
        try:
            for x in ADMINS:
                try: names.add(str(x))
                except Exception: pass
        except Exception:
            pass
        # DB roles
        try:
            cur.execute("SELECT username FROM users WHERE lower(role) IN ('admin','superadmin')")
            for r in cur.fetchall() or []:
                try:
                    names.add(r[0] if not isinstance(r, sqlite3.Row) else r['username'])
                except Exception:
                    pass
        except Exception:
            pass
        # Extra admins table
        try:
            cur.execute('CREATE TABLE IF NOT EXISTS extra_admins (username TEXT PRIMARY KEY, created_at TEXT, created_by TEXT)')
            cur.execute('SELECT username FROM extra_admins')
            for r in cur.fetchall() or []:
                try:
                    names.add(r[0] if not isinstance(r, sqlite3.Row) else r['username'])
                except Exception:
                    pass
        except Exception:
            pass
        return sorted([n for n in names if n])
    except Exception:
        return []

def migrate_avatars_to_folder():
    """Migration: Move all avatar files from uploads/ to uploads/avatars/"""
    try:
        db = get_db()
        cur = db.cursor()

        # Get all users with avatars
        cur.execute("SELECT id, username, avatar FROM users WHERE avatar IS NOT NULL AND avatar != ''")
        users = cur.fetchall()

        moved_count = 0
        for user_id, username, avatar in users:
            if avatar and not avatar.startswith('avatars/'):
                old_path = os.path.join(UPLOAD_FOLDER, avatar)
                new_filename = f"avatars/{avatar}"
                new_path = os.path.join(UPLOAD_FOLDER, new_filename)

                # Move file if it exists in old location
                if os.path.exists(old_path) and not os.path.exists(new_path):
                    try:
                        shutil.move(old_path, new_path)
                        # Update database record
                        cur.execute("UPDATE users SET avatar=? WHERE id=?", (new_filename, user_id))
                        moved_count += 1
                        print(f"Moved avatar for {username}: {avatar} -> {new_filename}")
                    except Exception as e:
                        print(f"Failed to move avatar for {username}: {e}")
                elif os.path.exists(new_path):
                    # File already in correct location, just update DB
                    cur.execute("UPDATE users SET avatar=? WHERE id=?", (new_filename, user_id))

        db.commit()
        print(f"Avatar migration completed. Moved {moved_count} avatars to avatars/ folder.")
        return moved_count
    except Exception as e:
        print(f"Avatar migration failed: {e}")
        return 0

# Configuration
DB_PATH = "chatter.db"
UPLOAD_FOLDER = "uploads"
AVATAR_FOLDER = os.path.join(UPLOAD_FOLDER, "avatars")
LOG_UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(AVATAR_FOLDER, exist_ok=True)
MAX_UPLOAD_MB = 200
MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024
ADMINS = {"SpyDrone", "octolinkyt", "swim67667"}
SUPERADMINS = {"SpyDrone", "octolinkyt", "buster427", "P7MJ"}
PREVIEW_EXTS = {"png", "jpg", "jpeg", "gif", "mp4", "webm", "html"}
ZIP_EXT = "zip"
DEFAULT_SYS_AVATAR = "sys_pfp.png"
DEFAULT_AVATAR = "default_pfp.png"  # Update this path if you change the default avatar asset
APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# Tor exit node blocking
_TOR_CACHE = {"ips": set(), "fetched_at": 0}
_TOR_URL = "https://check.torproject.org/torbulkexitlist"
_TOR_TTL = 15 * 60  # seconds

def _refresh_tor_ips():
    try:
        now = time.time()
        if now - _TOR_CACHE["fetched_at"] < _TOR_TTL:
            return
        r = requests.get(_TOR_URL, timeout=5)
        r.raise_for_status()
        _TOR_CACHE["ips"] = {
            line.strip()
            for line in r.text.splitlines()
            if line.strip() and not line.startswith("#")
        }
        _TOR_CACHE["fetched_at"] = now
    except Exception:
        pass  # keep last good cache

def _client_ip_for_tor():
    try:
        xff = request.headers.get("X-Forwarded-For") or request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        return request.remote_addr or ""
    except Exception:
        return ""

def _block_tor():
    _refresh_tor_ips()
    try:
        ip = _client_ip_for_tor()
    except Exception:
        ip = ""
    if ip in _TOR_CACHE["ips"]:
        return Response("You can't access Chatter with Tor.", status=403, mimetype="text/plain")

try:
    app.before_request(_block_tor)
except Exception:
    pass

# Server-side anti-duplicate guard (per-user recent send)
user_last_send = {}

# ---------- File/Attachment helpers ----------
def _safe_ext(name: str) -> str:
    try:
        ext = (name.rsplit('.', 1)[-1] or '').lower()
        return ext
    except Exception:
        return ''

def _unique_name(base: str) -> str:
    try:
        base = secure_filename(base or 'file')
        if not base:
            base = 'file'
        root, ext = os.path.splitext(base)
        ts = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        rand = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
        return f"{root}_{ts}_{rand}{ext}"
    except Exception:
        return f"file_{int(time.time())}.bin"

def safe_save_file_from_b64(filename: str, content_b64: str) -> str | None:
    try:
        if not content_b64:
            return None
        data = content_b64.strip()
        # Strip data URL prefix if present
        try:
            if data.lower().startswith('data:'):
                # form: data:<mime>;base64,<payload>
                comma = data.find(',')
                if comma != -1:
                    data = data[comma+1:]
        except Exception:
            pass
        # Normalize padding for base64 variants
        def _b64_decode_any(s: str) -> bytes:
            s = s.strip()
            # First try standard base64
            try:
                pad = '=' * (-len(s) % 4)
                return _b64.b64decode(s + pad, validate=False)
            except Exception:
                pass
            # Try urlsafe (replace -_ to +/)
            try:
                s2 = s.replace('-', '+').replace('_', '/')
                pad = '=' * (-len(s2) % 4)
                return _b64.b64decode(s2 + pad, validate=False)
            except Exception:
                pass
            # Last resort: urlsafe decoder directly
            try:
                pad = '=' * (-len(s) % 4)
                return _b64.urlsafe_b64decode(s + pad)
            except Exception:
                raise
        raw = _b64_decode_any(data)
        # Enforce size limit
        try:
            max_bytes = int(MAX_CONTENT_LENGTH)
            if max_bytes and len(raw) > max_bytes:
                return None
        except Exception:
            pass
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        name = _unique_name(filename or 'upload')
        fpath = os.path.join(UPLOAD_FOLDER, name)
        print(f"Saving file to: {fpath}")
        with open(fpath, 'wb') as f:
            f.write(raw)
        print(f"File saved successfully: {name}")
        return name
    except Exception:
        return None

# Preserve reference to robust implementation for any legacy wrappers
SAFE_SAVE_FILE_B64_IMPL = safe_save_file_from_b64

def safe_save_file(file, folder=None) -> str | None:
    try:
        if not file:
            return None
        fname = secure_filename(file.filename or 'upload')
        if not fname:
            fname = 'upload'
        # Enforce max size if possible
        try:
            file.stream.seek(0, os.SEEK_END)
            size = file.stream.tell()
            file.stream.seek(0)
            max_bytes = int(MAX_CONTENT_LENGTH)
            if max_bytes and size > max_bytes:
                return None
        except Exception:
            pass
        # Use specified folder or default UPLOAD_FOLDER
        target_folder = folder or UPLOAD_FOLDER
        os.makedirs(target_folder, exist_ok=True)
        name = _unique_name(fname)
        dest = os.path.join(target_folder, name)
        file.save(dest)
        return name
    except Exception:
        return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            u = session.get('username') or _verify_dbx_token(request.headers.get('X-DBX') or '')
            if not u:
                return jsonify({'error': 'not logged in'}), 401
            g.username = u
            return f(*args, **kwargs)
        except Exception:
            return jsonify({'error': 'not logged in'}), 401
    return decorated

# Make decorator available as a builtin so modules that don't import it explicitly (e.g., chatter.py)
# can still resolve @login_required without NameError.
try:
    import builtins as _bi
    if not getattr(_bi, 'login_required', None):
        _bi.login_required = login_required
except Exception:
    pass

# App settings helpers
def _ensure_app_settings():
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )''')
        db.commit()
    except Exception:
        pass

# Pins table for messages
def _ensure_pin_table():
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS pinned_messages (
            kind TEXT,        -- 'public' or 'gdm'
            message_id INTEGER,
            thread_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(kind, message_id)
        )''')
        db.commit()
    except Exception:
        pass

def get_setting(key: str, default=None):
    try:
        _ensure_app_settings()
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT value FROM app_settings WHERE key=?', (key,))
        row = cur.fetchone()
        if not row:
            return default
        v = row[0] if not isinstance(row, sqlite3.Row) else row['value']
        return v
    except Exception:
        return default

def set_setting(key: str, value: str):
    try:
        _ensure_app_settings()
        db = get_db(); cur = db.cursor()
        cur.execute("INSERT OR REPLACE INTO app_settings(key,value) VALUES(?,?)", (key, value))
        db.commit()
        return True
    except Exception:
        return False


# Message/activity log file
LOG_FILE = "chat_messages.txt"

def _plain_text_from_html(html_text: str) -> str:
    try:
        # Remove all tags, keep text content
        stripped = bleach.clean(html_text or "", tags=[], attributes={}, styles=[], strip=True)
        return _html.unescape(stripped).strip()
    except Exception:
        return (html_text or "").strip()

def _append_log_line(line: str):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line.rstrip("\n") + "\n")
    except Exception:
        pass

def _format_web_timestamp(dt: datetime) -> str:
    try:
        d = dt
        if NY_TZ is not None:
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            d = d.astimezone(NY_TZ)
        # Example wanted: Fri Oct 31 2025 7:12:23 PM
        s = d.strftime('%a %b %d %Y %I:%M:%S %p')
        # remove leading zero from hour
        # split before AM/PM
        try:
            prefix, ampm = s.rsplit(' ', 1)
            head, timepart = prefix.rsplit(' ', 1)
            timepart = timepart.lstrip('0') or '0'
            s = f"{head} {timepart} {ampm}"
        except Exception:
            pass
        # remove leading zero from day (e.g., 'Oct 03' -> 'Oct 3')
        # pattern: '... %b %d %Y ...'
        # We'll rebuild that part roughly
        try:
            parts = s.split(' ')
            # parts: [Fri, Oct, 31, 2025, 7:12:23, PM]
            if len(parts) >= 6:
                day = parts[2].lstrip('0') or '0'
                parts[2] = day
                s = ' '.join(parts)
        except Exception:
            pass
        return s
    except Exception:
        # fallback to ISO if anything fails
        return to_ny_time(dt)

# Serve resources folder like GitHub Pages
_resources_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resources')
if os.path.isdir(_resources_path):
    @app.route('/', defaults={'path': 'index.html'})
    @app.route('/<path:path>')
    def serve_resources(path):
        """Serve resources folder like GitHub Pages - subfolders become top-level routes"""
        try:
            full_path = os.path.join(_resources_path, path)

            # If it's a directory, try to serve index.html from it
            if os.path.isdir(full_path):
                index_path = os.path.join(full_path, 'index.html')
                if os.path.isfile(index_path):
                    return send_from_directory(_resources_path, os.path.join(path, 'index.html'))
                abort(404)

            # If it's a file, serve it
            if os.path.isfile(full_path):
                return send_from_directory(_resources_path, path)

            # Try appending index.html if path doesn't have extension
            if '.' not in os.path.basename(path):
                index_path = os.path.join(full_path, 'index.html')
                if os.path.isfile(index_path):
                    return send_from_directory(_resources_path, os.path.join(path, 'index.html'))

            abort(404)
        except Exception:
            abort(404)


# Seed defaults eagerly at startup (Flask 3 removed before_first_request)
try:
    _ensure_app_settings()
    _seed_defaults_if_needed()
    _ensure_gdm_schema()
except Exception:
    pass

# Socket.IO is already initialized above - no need for duplicate initialization

# Register admin routes on the main app
try:
    _register_admins_routes(app)
except Exception:
    pass

# Global state
try:
    app.add_url_rule('/api/admins/online', view_func=api_admins_online, methods=['GET'])
except Exception:
    pass

# Superadmin-only: toggle stealth mode for admins list
def api_admins_set_stealth():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get('enabled'))
    try:
        set_setting('ADMINS_STEALTH', '1' if enabled else '0')
        return jsonify({'ok': True, 'enabled': enabled})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

try:
    app.add_url_rule('/api/admins/stealth', view_func=api_admins_set_stealth, methods=['POST'])
except Exception:
    pass

# Superadmin-only: get stealth mode state
def api_admins_get_stealth():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    try:
        enabled = (get_setting('ADMINS_STEALTH','0') == '1')
        return jsonify({'ok': True, 'enabled': enabled})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

try:
    app.add_url_rule('/api/admins/stealth', view_func=api_admins_get_stealth, methods=['GET'])
except Exception:
    pass

# Superadmin-only: get/set ID reset toggles
def api_admins_resets_get():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    try:
        return jsonify({'ok': True,
                        'public': get_setting('RESET_ID_PUBLIC','0')=='1',
                        'dm': get_setting('RESET_ID_DM','0')=='1',
                        'gdm': get_setting('RESET_ID_GDM','0')=='1',
                        'group_threads': get_setting('RESET_ID_GROUP_THREADS','0')=='1'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def api_admins_resets_set():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    try:
        if 'public' in data:
            set_setting('RESET_ID_PUBLIC','1' if data.get('public') else '0')
        if 'dm' in data:
            set_setting('RESET_ID_DM','1' if data.get('dm') else '0')
        if 'gdm' in data:
            set_setting('RESET_ID_GDM','1' if data.get('gdm') else '0')
        if 'group_threads' in data:
            set_setting('RESET_ID_GROUP_THREADS','1' if data.get('group_threads') else '0')
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

try:
    app.add_url_rule('/api/admins/reset_ids', view_func=api_admins_resets_get, methods=['GET'])
    app.add_url_rule('/api/admins/reset_ids', view_func=api_admins_resets_set, methods=['POST'])
except Exception:
    pass

# Superadmin-only: clear ALL DMs globally (includes system messages) and optionally reset sequence
def api_admin_dm_clear_all():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    db = get_db(); cur = db.cursor()
    try:
        cur.execute('DELETE FROM direct_messages')
        try:
            if get_setting('RESET_ID_DM','0')=='1':
                try:
                    cur.execute("DELETE FROM sqlite_sequence WHERE name='direct_messages'")
                except Exception:
                    pass
        except Exception:
            pass
        db.commit()
        try:
            socketio.emit('dm_cleared', {'global': True})
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

try:
    app.add_url_rule('/api/admin/dm_clear_all', view_func=api_admin_dm_clear_all, methods=['POST'])
except Exception:
    pass

# Superadmin-only: reset all autoincrement IDs (messages, direct_messages, group_messages, group_threads)
@app.route('/api/admins/reset_all_ids', methods=['POST'])
@login_required
def api_admins_reset_all_ids():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    try:
        db = get_db(); cur = db.cursor()
        try:
            cur.execute("DELETE FROM sqlite_sequence WHERE name IN ('messages','direct_messages','group_messages','group_threads')")
        except Exception:
            # sqlite_sequence may not exist or tables may not use AUTOINCREMENT; ignore
            pass
        try:
            set_setting('RESET_ID_PUBLIC','1')
            set_setting('RESET_ID_DM','1')
            set_setting('RESET_ID_GDM','1')
            set_setting('RESET_ID_GROUP_THREADS','1')
            # Also maintain legacy/alternate keys used elsewhere
            set_setting('RESET_PUBLIC_IDS','1')
            set_setting('RESET_DM_IDS','1')
            set_setting('RESET_GDM_IDS','1')
            set_setting('RESET_GROUP_THREADS_IDS','1')
        except Exception:
            pass
        db.commit()
        return jsonify({'ok': True})
    except Exception as e:
        try:
            get_db().rollback()
        except Exception:
            pass
        return jsonify({'error': str(e)}), 500
online_users = defaultdict(lambda: 0)
user_timeouts = {}
last_timeout = {}  # Track last timeout for undo functionality
banned_users = set()
banned_ips = set()  # Track banned IP addresses
user_ips = {}  # Track username -> IP mapping
connected_sockets = {}  # Track connected sockets for better message delivery
typing_users = {}  # username -> expiry timestamp
voice_channels = defaultdict(set)  # channel -> set(usernames)
call_sessions = {}  # call_id -> {'type': 'dm'|'gdm', 'peer'|'thread_id': value, 'initiator': username, 'created_at': timestamp}
doc_sessions = {}  # doc_id -> {'content': str, 'last_edit_time': timestamp, 'users': set(usernames), 'tmpweb_url': str, 'tmpweb_expires': timestamp, 'idle_timer': threading.Timer}
doc_idle_timers = {}  # doc_id -> threading.Timer for 5-minute auto-save

# ============================================================================
# COMPREHENSIVE ANTI-SPAM SYSTEM
# ============================================================================

# Anti-spam tracking data structures
antispam_user_data = defaultdict(lambda: {
    'message_history': [],  # [(timestamp, channel_type), ...]
    'content_hashes': [],   # [(timestamp, content_hash), ...]
    'recent_messages': [],  # [(timestamp, normalized_content, channel_type), ...]
    'violation_count': 0,
    'violation_timestamp': 0,
    'slow_mode_until': 0,
    'block_until': 0,
    'last_message_time': 0,
    'consecutive_large_messages': 0,
    'pattern_violations': 0
})

# Anti-spam configuration with defaults
ANTISPAM_CONFIG = {
    'MAX_MESSAGE_LENGTH': 1000,
    'MAX_MESSAGE_BYTES': 4000,
    'RATE_LIMIT_WINDOW': 10.0,
    'RATE_LIMIT_MAX_MESSAGES': 8,
    'MIN_MESSAGE_GAP': 0.7,
    'DUPLICATE_WINDOW': 60.0,
    'SIMILARITY_THRESHOLD': 0.85,
    'SLOW_MODE_DURATION': 10.0,
    'BLOCK_DURATION_SHORT': 30.0,
    'BLOCK_DURATION_LONG': 300.0,
    'VIOLATION_DECAY_TIME': 300.0,
    'AUTO_SPLIT_THRESHOLD': 500,
    'AUTO_SPLIT_MAX_PARTS': 5,
    'PATTERN_HTML_TAG_LIMIT': 10,
    'PATTERN_BR_TAG_LIMIT': 20,
    'PATTERN_NEWLINE_LIMIT': 50,
    'PATTERN_WHITESPACE_RATIO': 0.7
}

def _load_antispam_config():
    """Load anti-spam configuration from settings with fallbacks"""
    config = ANTISPAM_CONFIG.copy()
    try:
        config['MAX_MESSAGE_LENGTH'] = int(get_setting('ANTISPAM_MAX_LENGTH', str(config['MAX_MESSAGE_LENGTH'])))
        config['MAX_MESSAGE_BYTES'] = int(get_setting('ANTISPAM_MAX_BYTES', str(config['MAX_MESSAGE_BYTES'])))
        config['RATE_LIMIT_WINDOW'] = float(get_setting('ANTISPAM_RATE_WINDOW', str(config['RATE_LIMIT_WINDOW'])))
        config['RATE_LIMIT_MAX_MESSAGES'] = int(get_setting('ANTISPAM_RATE_MAX', str(config['RATE_LIMIT_MAX_MESSAGES'])))
        config['MIN_MESSAGE_GAP'] = float(get_setting('ANTISPAM_MIN_GAP', str(config['MIN_MESSAGE_GAP'])))
        config['SLOW_MODE_DURATION'] = float(get_setting('ANTISPAM_SLOW_DURATION', str(config['SLOW_MODE_DURATION'])))
    except Exception:
        pass
    return config

def _normalize_content(text):
    """Normalize text content for comparison, avoiding over-normalization"""
    if not text:
        return ""

    # Basic normalization - preserve structure but normalize whitespace
    normalized = ' '.join(text.strip().split())

    # Don't normalize single characters or very short messages to avoid blocking common letters
    if len(normalized) <= 3:
        return normalized

    return normalized.lower()

def _generate_content_hash(content):
    """Generate a hash for content deduplication"""
    if not content:
        return ""
    normalized = _normalize_content(content)
    return hashlib.md5(normalized.encode('utf-8')).hexdigest()

def _check_message_length(content, config):
    """Check if message exceeds length limits"""
    if not content:
        return True, None

    char_count = len(content)
    byte_count = len(content.encode('utf-8'))

    if char_count > config['MAX_MESSAGE_LENGTH']:
        return False, f"Message too long ({char_count} characters). Maximum allowed: {config['MAX_MESSAGE_LENGTH']} characters."

    if byte_count > config['MAX_MESSAGE_BYTES']:
        return False, f"Message too large ({byte_count} bytes). Maximum allowed: {config['MAX_MESSAGE_BYTES']} bytes."

    return True, None

def _check_payload_size(content, config):
    """Check payload size using compression to detect encoded spam"""
    if not content or len(content) < 200:
        return True, None

    try:
        # Compress content to detect large encoded payloads
        compressed = zlib.compress(content.encode('utf-8'), level=3)
        if len(compressed) > config['MAX_MESSAGE_BYTES']:
            return False, "Message appears to contain large encoded data. Please send as a file instead."
    except Exception:
        pass

    return True, None

def _check_rate_limiting(username, channel_type, config):
    """Check if user is sending messages too quickly"""
    user_data = antispam_user_data[username]
    now = time.time()

    # Clean old history
    window = config['RATE_LIMIT_WINDOW']
    user_data['message_history'] = [
        (ts, ch) for ts, ch in user_data['message_history']
        if now - ts <= window
    ]

    # Check minimum gap between messages
    if user_data['last_message_time'] and (now - user_data['last_message_time']) < config['MIN_MESSAGE_GAP']:
        return False, f"Please wait {config['MIN_MESSAGE_GAP']} seconds between messages."

    # Check maximum messages per window
    recent_count = len(user_data['message_history'])
    if recent_count >= config['RATE_LIMIT_MAX_MESSAGES']:
        return False, f"Too many messages in {window} seconds. Please slow down."

    return True, None

def _check_duplicate_content(username, content, channel_type, config):
    """Check for duplicate or near-duplicate content"""
    if not content or len(content) <= 10:  # Skip very short messages
        return True, None

    user_data = antispam_user_data[username]
    now = time.time()
    normalized = _normalize_content(content)

    # Clean old content history
    window = config['DUPLICATE_WINDOW']
    user_data['recent_messages'] = [
        (ts, msg, ch) for ts, msg, ch in user_data['recent_messages']
        if now - ts <= window
    ]

    # Check for exact duplicates
    for ts, prev_content, prev_channel in user_data['recent_messages']:
        if normalized == prev_content:
            return False, "Duplicate message detected. Please avoid repeating the same content."

    # Check for near-duplicates (only for longer messages to avoid false positives)
    if len(normalized) >= 20:
        for ts, prev_content, prev_channel in user_data['recent_messages']:
            if len(prev_content) >= 20:
                try:
                    similarity = difflib.SequenceMatcher(None, normalized, prev_content).ratio()
                    if similarity > config['SIMILARITY_THRESHOLD']:
                        return False, "Very similar message detected. Please avoid minor variations of the same content."
                except Exception:
                    pass

    return True, None

def _check_content_patterns(content, config):
    """Analyze content for suspicious patterns"""
    if not content:
        return True, None

    lower_content = content.lower()

    # Check for HTML/script injection patterns
    html_tags = ['<div', '<script', '<style', '<html', '<body', '<iframe', '<object', '<embed']
    tag_count = sum(lower_content.count(tag) for tag in html_tags)

    if tag_count >= config['PATTERN_HTML_TAG_LIMIT']:
        return False, "Message contains too many HTML tags. Please send as a file or remove HTML content."

    # Check for excessive line breaks
    br_count = lower_content.count('<br')
    newline_count = content.count('\n')

    if br_count >= config['PATTERN_BR_TAG_LIMIT'] or newline_count >= config['PATTERN_NEWLINE_LIMIT']:
        return False, "Message contains excessive line breaks. Please format your content more concisely."

    # Check for excessive whitespace (but not single character repetition)
    if len(content) > 50:  # Only check longer messages
        whitespace_count = sum(1 for c in content if c.isspace())
        whitespace_ratio = whitespace_count / len(content)

        if whitespace_ratio > config['PATTERN_WHITESPACE_RATIO']:
            return False, "Message contains excessive whitespace. Please format your content properly."

    return True, None

def _auto_split_message(content, config):
    """Automatically split large messages if appropriate"""
    if not content or len(content) <= config['AUTO_SPLIT_THRESHOLD']:
        return [content] if content else []

    # Try to split by paragraphs first
    paragraphs = [p.strip() for p in content.split('\n\n') if p.strip()]
    if len(paragraphs) > 1 and len(paragraphs) <= config['AUTO_SPLIT_MAX_PARTS']:
        # Check if each part is reasonable size
        if all(len(p) <= config['MAX_MESSAGE_LENGTH'] for p in paragraphs):
            return paragraphs

    # Try to split by sentences
    sentences = [s.strip() + '.' for s in content.split('.') if s.strip()]
    if len(sentences) > 1 and len(sentences) <= config['AUTO_SPLIT_MAX_PARTS']:
        if all(len(s) <= config['MAX_MESSAGE_LENGTH'] for s in sentences):
            return sentences

    # Try to split by lines
    lines = [line.strip() for line in content.split('\n') if line.strip()]
    if len(lines) > 1 and len(lines) <= config['AUTO_SPLIT_MAX_PARTS']:
        if all(len(line) <= config['MAX_MESSAGE_LENGTH'] for line in lines):
            return lines

    # If can't split reasonably, return as single message (will be rejected by length check)
    return [content]

def _apply_progressive_sanctions(username, violation_type, config):
    """Apply progressive sanctions based on violation history"""
    user_data = antispam_user_data[username]
    now = time.time()

    # Decay old violations
    if user_data['violation_timestamp'] and (now - user_data['violation_timestamp']) > config['VIOLATION_DECAY_TIME']:
        user_data['violation_count'] = max(0, user_data['violation_count'] - 1)

    # Record new violation
    user_data['violation_count'] += 1
    user_data['violation_timestamp'] = now

    violation_count = user_data['violation_count']

    if violation_count >= 3:
        # Third violation: Temporary block
        user_data['block_until'] = now + config['BLOCK_DURATION_LONG']
        return False, f"You have been temporarily blocked for {config['BLOCK_DURATION_LONG']/60:.1f} minutes due to repeated violations."
    elif violation_count >= 2:
        # Second violation: Slow mode
        user_data['slow_mode_until'] = now + config['SLOW_MODE_DURATION']
        return False, f"Slow mode enabled for {config['SLOW_MODE_DURATION']} seconds. Please wait before sending another message."
    else:
        # First violation: Warning
        return False, f"Warning: Please follow the chat guidelines. Further violations may result in restrictions."

def _check_user_restrictions(username, config):
    """Check if user is currently under restrictions"""
    user_data = antispam_user_data[username]
    now = time.time()

    # Check temporary block
    if user_data['block_until'] > now:
        remaining = int(user_data['block_until'] - now)
        return False, f"You are temporarily blocked. Time remaining: {remaining} seconds."
    elif user_data['block_until'] > 0:
        user_data['block_until'] = 0  # Clear expired block

    # Check slow mode
    if user_data['slow_mode_until'] > now:
        remaining = int(user_data['slow_mode_until'] - now)
        return False, f"Slow mode active. Please wait {remaining} seconds before sending another message."
    elif user_data['slow_mode_until'] > 0:
        user_data['slow_mode_until'] = 0  # Clear expired slow mode

    return True, None

def antispam_check_message(username, content, channel_type='public', has_attachment=False):
    """
    Main anti-spam checking function that coordinates all checks

    Args:
        username: Username of the sender
        content: Message content to check
        channel_type: Type of channel ('public', 'dm', 'gdm')
        has_attachment: Whether message has an attachment

    Returns:
        tuple: (allowed: bool, message: str or None, split_parts: list or None)
    """
    try:
        # Superadmins bypass all checks
        if username in SUPERADMINS:
            return True, None, None

        if not username:
            return False, "Invalid user.", None

        config = _load_antispam_config()
        now = time.time()

        # Check user restrictions first
        allowed, msg = _check_user_restrictions(username, config)
        if not allowed:
            return False, msg, None

        # For attachment-only messages, only apply rate limiting
        if not content and has_attachment:
            allowed, msg = _check_rate_limiting(username, channel_type, config)
            if not allowed:
                _apply_progressive_sanctions(username, 'rate_limit', config)
                return False, msg, None

            # Update tracking
            user_data = antispam_user_data[username]
            user_data['message_history'].append((now, channel_type))
            user_data['last_message_time'] = now
            return True, None, None

        if not content:
            return True, None, None

        # 1. Message Length Limits
        allowed, msg = _check_message_length(content, config)
        if not allowed:
            # Try auto-splitting for large messages
            split_parts = _auto_split_message(content, config)
            if len(split_parts) > 1 and len(split_parts) <= config['AUTO_SPLIT_MAX_PARTS']:
                # Check if all parts are valid
                all_valid = True
                for part in split_parts:
                    part_allowed, _ = _check_message_length(part, config)
                    if not part_allowed:
                        all_valid = False
                        break

                if all_valid:
                    return True, f"Message will be split into {len(split_parts)} parts.", split_parts

            _apply_progressive_sanctions(username, 'length', config)
            return False, msg, None

        # 2. Payload Size Monitoring
        allowed, msg = _check_payload_size(content, config)
        if not allowed:
            _apply_progressive_sanctions(username, 'payload', config)
            return False, msg, None

        # 3. Rate Limiting
        allowed, msg = _check_rate_limiting(username, channel_type, config)
        if not allowed:
            _apply_progressive_sanctions(username, 'rate_limit', config)
            return False, msg, None

        # 4. Duplicate Detection
        allowed, msg = _check_duplicate_content(username, content, channel_type, config)
        if not allowed:
            _apply_progressive_sanctions(username, 'duplicate', config)
            return False, msg, None

        # 5. Content Pattern Analysis
        allowed, msg = _check_content_patterns(content, config)
        if not allowed:
            _apply_progressive_sanctions(username, 'pattern', config)
            return False, msg, None

        # All checks passed - update tracking data
        user_data = antispam_user_data[username]
        user_data['message_history'].append((now, channel_type))
        user_data['recent_messages'].append((now, _normalize_content(content), channel_type))
        user_data['content_hashes'].append((now, _generate_content_hash(content)))
        user_data['last_message_time'] = now

        # Clean up old data to prevent memory leaks
        window = max(config['RATE_LIMIT_WINDOW'], config['DUPLICATE_WINDOW'])
        user_data['message_history'] = [(ts, ch) for ts, ch in user_data['message_history'] if now - ts <= window]
        user_data['recent_messages'] = [(ts, msg, ch) for ts, msg, ch in user_data['recent_messages'] if now - ts <= window]
        user_data['content_hashes'] = [(ts, h) for ts, h in user_data['content_hashes'] if now - ts <= window]

        return True, None, None

    except Exception as e:
        # Fail open on unexpected errors to avoid breaking chat
        return True, None, None

def antispam_get_user_status(username):
    """Get current anti-spam status for a user"""
    try:
        if username in SUPERADMINS:
            return {"status": "superadmin", "restrictions": None}

        user_data = antispam_user_data[username]
        now = time.time()

        status = {"status": "normal", "restrictions": []}

        if user_data['block_until'] > now:
            remaining = int(user_data['block_until'] - now)
            status["status"] = "blocked"
            status["restrictions"].append(f"Blocked for {remaining} seconds")

        if user_data['slow_mode_until'] > now:
            remaining = int(user_data['slow_mode_until'] - now)
            if status["status"] == "normal":
                status["status"] = "slow_mode"
            status["restrictions"].append(f"Slow mode for {remaining} seconds")

        if user_data['violation_count'] > 0:
            status["violation_count"] = user_data['violation_count']

        return status
    except Exception:
        return {"status": "unknown", "restrictions": None}

# Initialize anti-spam defaults in settings
def _init_antispam_settings():
    """Initialize anti-spam settings with defaults"""
    try:
        defaults = {
            'ANTISPAM_MAX_LENGTH': '1000',
            'ANTISPAM_MAX_BYTES': '4000',
            'ANTISPAM_RATE_WINDOW': '10.0',
            'ANTISPAM_RATE_MAX': '8',
            'ANTISPAM_MIN_GAP': '0.7',
            'ANTISPAM_SLOW_DURATION': '10.0',
        }

        for key, value in defaults.items():
            if not get_setting(key):
                set_setting(key, value)
    except Exception:
        pass

# Initialize settings on module load
_init_antispam_settings()

# ============================================================================
# END ANTI-SPAM SYSTEM
# ============================================================================


# ============================================================================
# FILE MANAGEMENT API
# ============================================================================

@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    """Upload a file for chat attachments"""
    try:
        me = session.get('username')

        if 'file' not in request.files:
            return jsonify({'error': 'no file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'no file selected'}), 400

        # Read file content
        file_content = file.read()
        filename = secure_filename(file.filename)
        
        # Generate unique ID
        file_id = str(uuid.uuid4())[:8]
        
        # Create uploads directory if it doesn't exist
        uploads_dir = os.path.join(os.path.dirname(__file__), 'uploads')
        os.makedirs(uploads_dir, exist_ok=True)
        
        # Save file
        file_path = os.path.join(uploads_dir, f"{file_id}_{filename}")
        with open(file_path, 'wb') as f:
            f.write(file_content)
        
        # Return file info
        return jsonify({
            'ok': True,
            'file_id': file_id,
            'filename': filename,
            'size': len(file_content),
            'url': f"/uploads/{file_id}_{filename}"
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/upload', methods=['POST'])
@login_required
def api_file_upload():
    """Upload a file to tmpweb storage"""
    try:
        me = session.get('username')

        if 'file' not in request.files:
            return jsonify({'error': 'no file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'no file selected'}), 400

        # Read file content
        file_content = file.read()
        filename = secure_filename(file.filename)
        
        # Generate unique ID
        file_id = str(uuid.uuid4())[:8]
        
        # Store in database
        db = get_db()
        cur = db.cursor()
        cur.execute('''INSERT INTO file_storage (id, filename, content, size, mime_type, uploaded_by, uploaded_at)
                      VALUES (?, ?, ?, ?, ?, ?, ?)''',
                   (file_id, filename, file_content, len(file_content), file.mimetype, me, datetime.utcnow()))
        db.commit()
        
        return jsonify({'ok': True, 'id': file_id, 'filename': filename, 'size': len(file_content)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/upload-url', methods=['POST'])
@login_required
def api_file_upload_url():
    """Upload a file from URL to tmpweb storage"""
    try:
        me = session.get('username')
        data = request.get_json(silent=True) or {}
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'url required'}), 400
        
        # Download file from URL
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # Get filename from URL or Content-Disposition
        filename = url.split('/')[-1].split('?')[0]
        if 'content-disposition' in response.headers:
            cd = response.headers['content-disposition']
            if 'filename=' in cd:
                filename = cd.split('filename=')[-1].strip('"')
        
        if not filename:
            filename = 'downloaded_file'
            
        filename = secure_filename(filename)
        
        # Generate unique ID
        file_id = str(uuid.uuid4())[:8]
        
        # Store in database
        db = get_db()
        cur = db.cursor()
        cur.execute('''INSERT INTO file_storage (id, filename, content, size, mime_type, uploaded_by, uploaded_at, source_url)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                   (file_id, filename, response.content, len(response.content), 
                    response.headers.get('content-type', 'application/octet-stream'), 
                    me, datetime.utcnow(), url))
        db.commit()
        
        return jsonify({'ok': True, 'id': file_id, 'filename': filename, 'size': len(response.content)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/list', methods=['GET'])
@login_required
def api_file_list():
    """List all uploaded files"""
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute('''SELECT id, filename, size, mime_type, uploaded_by, uploaded_at, expires_at
                      FROM file_storage 
                      WHERE uploaded_by = ? OR (expires_at IS NULL OR expires_at > ?)
                      ORDER BY uploaded_at DESC''', 
                   (session.get('username'), datetime.utcnow()))
        
        files = []
        for row in cur.fetchall():
            files.append({
                'id': row[0],
                'filename': row[1],
                'size': row[2],
                'mime_type': row[3],
                'uploaded_by': row[4],
                'uploaded': row[5].isoformat() if row[5] else None,
                'expires': row[6].isoformat() if row[6] else None
            })
        
        return jsonify({'ok': True, 'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/<file_id>', methods=['GET', 'DELETE'])
@login_required
def api_file_detail(file_id):
    """Get file info or delete file"""
    try:
        me = session.get('username')
        db = get_db()
        cur = db.cursor()
        
        if request.method == 'GET':
            cur.execute('''SELECT id, filename, size, mime_type, uploaded_by, uploaded_at, expires_at
                          FROM file_storage WHERE id = ?''', (file_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({'error': 'file not found'}), 404
            
            file_data = {
                'id': row[0],
                'filename': row[1],
                'size': row[2],
                'mime_type': row[3],
                'uploaded_by': row[4],
                'uploaded': row[5].isoformat() if row[5] else None,
                'expires': row[6].isoformat() if row[6] else None
            }
            
            return jsonify({'ok': True, 'file': file_data})
            
        elif request.method == 'DELETE':
            # Check ownership or admin
            cur.execute('SELECT uploaded_by FROM file_storage WHERE id = ?', (file_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({'error': 'file not found'}), 404
            
            uploaded_by = row[0]
            if uploaded_by != me and not (is_admin(me) or is_superadmin(me)):
                return jsonify({'error': 'forbidden'}), 403
            
            cur.execute('DELETE FROM file_storage WHERE id = ?', (file_id,))
            db.commit()
            
            return jsonify({'ok': True})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<username>', methods=['GET'])
@login_required
def api_user_info(username):
    """Get user information"""
    try:
        me = session.get('username')
        
        # Users can only see their own full info, others get limited info
        is_self = me == username
        is_admin_user = is_admin(me) or is_superadmin(me)
        
        if not is_self and not is_admin_user:
            return jsonify({'error': 'forbidden'}), 403
        
        db = get_db()
        cur = db.cursor()
        cur.execute('''SELECT username, role, created_at, last_seen, avatar_url
                      FROM users WHERE username = ?''', (username,))
        row = cur.fetchone()
        
        if not row:
            return jsonify({'error': 'user not found'}), 404
        
        user_data = {
            'username': row[0],
            'role': row[1],
            'created': row[2].isoformat() if row[2] else None,
            'last_seen': row[3].isoformat() if row[3] else None,
            'avatar': row[4]
        }
        
        return jsonify({'ok': True, 'user': user_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/online', methods=['GET'])
@login_required
def api_users_online():
    """List online users"""
    try:
        # This is a simplified version - in a real app you'd track actual online status
        db = get_db()
        cur = db.cursor()
        cur.execute('''SELECT username, role, last_seen
                      FROM users 
                      WHERE last_seen > datetime('now', '-5 minutes')
                      ORDER BY last_seen DESC''')
        
        users = []
        for row in cur.fetchall():
            users.append({
                'username': row[0],
                'role': row[1],
                'last_seen': row[2].isoformat() if row[2] else None
            })
        
        return jsonify({'ok': True, 'users': users})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users_all')
@login_required
def api_users_all():
    """List all users with their status"""
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute('''SELECT username, avatar, bio, status
                      FROM users 
                      ORDER BY username ASC''')
        
        users = []
        
        for row in cur.fetchall():
            users.append({
                'username': row[0],
                'role': 'user',  # Default role since role column doesn't exist
                'last_seen': None,  # Not selected in query for now
                'avatar': row[1],
                'bio': row[2],  # Include bio
                'status': row[3],  # Include status
                'is_online': False  # Will be updated based on online users
            })
        
        return jsonify({'ok': True, 'users': users})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/edit_message', methods=['POST'])
@login_required
def api_admin_edit_message():
    """Allow superadmin to edit any message"""
    try:
        me = session.get('username')
        if not me:
            return jsonify({'error': 'Not authenticated'}), 401
        
        # Check if user is superadmin
        db = get_db()
        cur = db.cursor()
        cur.execute('SELECT role FROM users WHERE username=?', (me,))
        user_row = cur.fetchone()
        
        if not user_row or (user_row[0] if not isinstance(user_row, sqlite3.Row) else user_row['role']) != 'superadmin':
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        data = request.get_json(silent=True) or {}
        message_id = data.get('message_id')
        new_content = data.get('content', '').strip()
        
        if not message_id or not new_content:
            return jsonify({'error': 'Message ID and content are required'}), 400
        
        # Get the message to edit
        cur.execute('SELECT * FROM messages WHERE id=?', (message_id,))
        message = cur.fetchone()
        
        if not message:
            return jsonify({'error': 'Message not found'}), 404
        
        # Update the message
        cur.execute('UPDATE messages SET text=?, edited_at=CURRENT_TIMESTAMP WHERE id=?', 
                   (new_content, message_id))
        db.commit()
        
        # Log the action
        log_admin_action(me, 'edit_message', target=str(message_id), 
                     details={'original_content': message[2], 'new_content': new_content})
        
        # Emit the edited message to all connected clients
        socketio.emit('message_edited', {
            'id': message_id,
            'content': new_content,
            'edited_at': datetime.now(timezone.utc).isoformat(),
            'edited_by': me
        })
        
        return jsonify({'ok': True, 'message': 'Message edited successfully'})
        
    except Exception as e:
        print(f"Error editing message: {e}")
        return jsonify({'error': 'Failed to edit message'}), 500

@app.route('/api/admin/delete_message', methods=['POST'])
@login_required
def api_admin_delete_message():
    """Allow superadmin to delete any message"""
    try:
        me = session.get('username')
        if not me:
            return jsonify({'error': 'Not authenticated'}), 401
        
        # Check if user is superadmin
        db = get_db()
        cur = db.cursor()
        cur.execute('SELECT role FROM users WHERE username=?', (me,))
        user_row = cur.fetchone()
        
        if not user_row or (user_row[0] if not isinstance(user_row, sqlite3.Row) else user_row['role']) != 'superadmin':
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        data = request.get_json(silent=True) or {}
        message_id = data.get('message_id')
        
        if not message_id:
            return jsonify({'error': 'Message ID is required'}), 400
        
        # Get the message to delete
        cur.execute('SELECT * FROM messages WHERE id=?', (message_id,))
        message = cur.fetchone()
        
        if not message:
            return jsonify({'error': 'Message not found'}), 404
        
        # Delete the message
        cur.execute('DELETE FROM messages WHERE id=?', (message_id,))
        db.commit()
        
        # Log the action
        log_admin_action(me, 'delete_message', target=str(message_id), 
                     details={'deleted_content': message[2]})
        
        # Emit the deletion to all connected clients
        socketio.emit('message_deleted', {
            'id': message_id,
            'deleted_by': me
        })
        
        return jsonify({'ok': True, 'message': 'Message deleted successfully'})
        
    except Exception as e:
        print(f"Error deleting message: {e}")
        return jsonify({'error': 'Failed to delete message'}), 500

@app.route('/api/users/<username>')
@login_required
def api_get_user_profile(username):
    """Get user profile information"""
    try:
        me = session.get('username')
        if not me:
            return jsonify({'error': 'Not authenticated'}), 401
        
        db = get_db()
        cur = db.cursor()
        
        # Get user profile
        cur.execute('''SELECT username, role, bio, status, avatar, last_seen, language, 
                           COALESCE(allow_dm_nonfriends, 1) AS allow_dm_nonfriends,
                           created_at
                      FROM users WHERE username=?''', (username,))
        user = cur.fetchone()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get user statistics
        cur.execute('''SELECT COUNT(*) as message_count FROM messages 
                      WHERE username=? AND deleted_at IS NULL''', (username,))
        message_stats = cur.fetchone()
        
        cur.execute('''SELECT COUNT(*) as dm_count FROM messages 
                      WHERE (to_user=? OR username=?) AND channel LIKE 'dm:%' 
                      AND deleted_at IS NULL''', (username, username))
        dm_stats = cur.fetchone()
        
        # Check if user is online
        is_online = username in online_users
        
        user_data = {
            'username': user[0] if not isinstance(user, sqlite3.Row) else user['username'],
            'role': user[1] if not isinstance(user, sqlite3.Row) else user['role'],
            'bio': user[2] if not isinstance(user, sqlite3.Row) else user['bio'],
            'status': user[3] if not isinstance(user, sqlite3.Row) else user['status'],
            'avatar': user[4] if not isinstance(user, sqlite3.Row) else user['avatar'],
            'last_seen': user[5] if not isinstance(user, sqlite3.Row) else user['last_seen'],
            'language': user[6] if not isinstance(user, sqlite3.Row) else user['language'],
            'allow_dm_nonfriends': bool(user[7] if not isinstance(user, sqlite3.Row) else user['allow_dm_nonfriends']),
            'created_at': user[8] if not isinstance(user, sqlite3.Row) else user['created_at'],
            'is_online': is_online,
            'message_count': message_stats[0] if not isinstance(message_stats, sqlite3.Row) else message_stats['message_count'],
            'dm_count': dm_stats[0] if not isinstance(dm_stats, sqlite3.Row) else dm_stats['dm_count'],
            'is_me': username == me
        }
        
        return jsonify({'ok': True, 'user': user_data})
        
    except Exception as e:
        print(f"Error getting user profile: {e}")
        return jsonify({'error': 'Failed to get user profile'}), 500

@app.route('/api/messages/send', methods=['POST'])
@login_required
def api_message_send():
    """Send a message to a channel"""
    try:
        me = session.get('username')
        data = request.get_json(silent=True) or {}
        channel = data.get('channel', '').strip()
        text = data.get('text', '').strip()
        
        if not channel or not text:
            return jsonify({'error': 'channel and text required'}), 400
        
        # For now, this is a placeholder - you'd implement actual channel messaging
        # This could integrate with existing message system or external APIs
        
        return jsonify({'ok': True, 'message': 'Message sent to ' + channel})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# MAIN APPLICATION ROUTES
# ============================================================================
    try:
        me = session.get('username')
        db = get_db(); cur = db.cursor()

        # List only user's own files
        cur.execute('''SELECT id, filename, size_bytes, uploaded_at, expires_at
                      FROM file_storage
                      WHERE uploaded_by=?
                      ORDER BY uploaded_at DESC
                      LIMIT 50''', (me,))

        files = []
        for row in cur.fetchall():
            files.append({
                'id': row[0],
                'name': row[1],
                'size': row[2],
                'uploaded_at': to_ny_time(row[3]) if row[3] else None,
                'expires_at': to_ny_time(row[4]) if row[4] else None,
                'url': f'/api/files/download/{row[0]}'
            })

        return jsonify({'ok': True, 'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Socket.IO connection management
@socketio.on('connect')
def _on_connect():
    try:
        u = session.get('username') or ''
        if not u:
            # reject anonymous socket connections for chat
            return False
        sid = request.sid
        connected_sockets[sid] = u
        try:
            join_room('chat_room')
        except Exception:
            pass
        try:
            join_room(f'user:{u}')
        except Exception:
            pass
        # If user is currently timed out, remind client
        try:
            until = user_timeouts.get(u) or 0
            if until and time.time() < float(until):
                emit('timeout_set', { 'until': int(until) }, room=sid)
        except Exception:
            pass
    except Exception:
        return False

@socketio.on('disconnect')
def _on_disconnect():
    try:
        sid = request.sid
        try:
            connected_sockets.pop(sid, None)
        except Exception:
            pass
        try:
            # Remove from any voice channel memberships
            u = None
            try:
                u = session.get('username') or ''
            except Exception:
                u = None
            if u:
                for ch in list(voice_channels.keys()):
                    if u in voice_channels[ch]:
                        try:
                            voice_channels[ch].discard(u)
                            leave_room(f"voice:{ch}")
                            socketio.emit('voice_participants', {'channel': ch, 'participants': sorted(list(voice_channels[ch]))}, room=f"voice:{ch}")
                        except Exception:
                            pass
        except Exception:
            pass
    except Exception:
        pass

# WebRTC Voice channel signaling and presence
@socketio.on('voice_join')
def _voice_join(data):
    try:
        ch = (data or {}).get('channel') or ''
        u = session.get('username') or ''
        if not ch or not u:
            return
        join_room(f"voice:{ch}")
        voice_channels[ch].add(u)
        socketio.emit('voice_participants', {'channel': ch, 'participants': sorted(list(voice_channels[ch]))}, room=f"voice:{ch}")
    except Exception:
        pass

@socketio.on('voice_leave')
def _voice_leave(data):
    try:
        ch = (data or {}).get('channel') or ''
        u = session.get('username') or ''
        if not ch or not u:
            return
        try:
            voice_channels[ch].discard(u)
        except Exception:
            pass
        leave_room(f"voice:{ch}")
        socketio.emit('voice_participants', {'channel': ch, 'participants': sorted(list(voice_channels[ch]))}, room=f"voice:{ch}")
    except Exception:
        pass

@socketio.on('voice_mute')
def _voice_mute(data):
    try:
        ch = (data or {}).get('channel') or ''
        muted = bool((data or {}).get('muted'))
        u = session.get('username') or ''
        if not ch or not u:
            return
        socketio.emit('voice_mute', {'channel': ch, 'user': u, 'muted': muted}, room=f"voice:{ch}")
    except Exception:
        pass

@socketio.on('voice_offer')
def _voice_offer(data):
    try:
        ch = (data or {}).get('channel') or ''
        u = session.get('username') or ''
        if not ch or not u:
            return
        payload = {'channel': ch, 'from': u, 'sdp': (data or {}).get('sdp')}
        emit('voice_offer', payload, room=f"voice:{ch}", include_self=False)
    except Exception:
        pass

@socketio.on('voice_answer')
def _voice_answer(data):
    try:
        ch = (data or {}).get('channel') or ''
        u = session.get('username') or ''
        if not ch or not u:
            return
        payload = {'channel': ch, 'from': u, 'sdp': (data or {}).get('sdp')}
        emit('voice_answer', payload, room=f"voice:{ch}", include_self=False)
    except Exception:
        pass

@socketio.on('voice_ice')
def _voice_ice(data):
    try:
        ch = (data or {}).get('channel') or ''
        u = session.get('username') or ''
        if not ch or not u:
            return
        payload = {'channel': ch, 'from': u, 'candidate': (data or {}).get('candidate')}
        emit('voice_ice', payload, room=f"voice:{ch}", include_self=False)
    except Exception:
        pass

# Call initiation handlers for DMs and GDMs
# WebRTC Calling System - Enhanced
@socketio.on('call_user')
def handle_call_user(data):
    """Handle initiating a call to another user"""
    try:
        from_user = session.get('username')
        to_user = data.get('to_user')
        call_type = data.get('call_type', 'voice')  # 'voice' or 'video'
        
        if not from_user or not to_user:
            return
        
        if from_user == to_user:
            emit('call_error', {'error': 'Cannot call yourself'})
            return
        
        # Check if target user is online
        if to_user not in online_users:
            emit('call_error', {'error': 'User is not online'})
            return
        
        # Store call info
        call_id = f"{from_user}_{to_user}_{int(time.time())}"
        call_info = {
            'call_id': call_id,
            'from_user': from_user,
            'to_user': to_user,
            'call_type': call_type,
            'status': 'ringing',
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        call_sessions[call_id] = call_info
        
        # Send call request to target user
        socketio.emit('incoming_call', {
            'call_id': call_id,
            'from_user': from_user,
            'call_type': call_type
        }, room=online_users[to_user])
        
        # Confirm to caller
        emit('call_initiated', {'call_id': call_id, 'to_user': to_user})
        
        print(f"Call initiated: {from_user} -> {to_user} ({call_type})")
        
    except Exception as e:
        print(f"Call initiation error: {e}")
        emit('call_error', {'error': 'Failed to initiate call'})

@socketio.on('answer_call')
def handle_answer_call(data):
    """Handle answering an incoming call"""
    try:
        username = session.get('username')
        call_id = data.get('call_id')
        answer = data.get('answer')  # True for accept, False for decline
        
        if not username or not call_id:
            return
        
        # Find the call and notify the other party
        call_info = call_sessions.get(call_id)
        if call_info:
            other_user = call_info.get('to_user') if call_info.get('from_user') == username else call_info.get('from_user')
            
            if other_user and other_user in online_users:
                socketio.emit('call_answered', {
                    'call_id': call_id,
                    'by_user': username,
                    'answer': answer
                }, room=online_users[other_user])
        
        if answer:
            print(f"Call accepted: {call_id} by {username}")
        else:
            print(f"Call declined: {call_id} by {username}")
            # Clean up declined call
            if call_id in call_sessions:
                del call_sessions[call_id]
        
    except Exception as e:
        print(f"Call answer error: {e}")

@socketio.on('end_call')
def handle_end_call(data):
    """Handle ending a call"""
    try:
        username = session.get('username')
        call_id = data.get('call_id')
        
        if not username or not call_id:
            return
        
        # Find the call and notify the other party
        call_info = call_sessions.get(call_id)
        if call_info:
            other_user = call_info.get('to_user') if call_info.get('from_user') == username else call_info.get('from_user')
            
            if other_user and other_user in online_users:
                socketio.emit('call_ended', {
                    'call_id': call_id,
                    'by_user': username
                }, room=online_users[other_user])
        
        # Clean up call
        if call_id in call_sessions:
            del call_sessions[call_id]
        
        print(f"Call ended: {call_id} by {username}")
        
    except Exception as e:
        print(f"Call end error: {e}")

@socketio.on('webrtc_signal')
def handle_webrtc_signal(data):
    """Handle WebRTC signaling messages"""
    try:
        from_user = session.get('username')
        to_user = data.get('to_user')
        signal_type = data.get('type')
        signal_data = data.get('data')
        
        if not from_user or not to_user or not signal_type:
            return
        
        # Forward the signaling message to the target user
        if to_user in online_users:
            socketio.emit('webrtc_signal', {
                'from_user': from_user,
                'type': signal_type,
                'data': signal_data
            }, room=online_users[to_user])
        
    except Exception as e:
        print(f"WebRTC signaling error: {e}")

@socketio.on('call_start_dm')
def _call_start_dm(data):
    try:
        u = session.get('username') or ''
        to_user = (data or {}).get('to_user') or ''
        if not u or not to_user:
            return
        # Generate unique call ID
        call_id = f"dm_{u}_{to_user}_{int(time.time()*1000)}"
        call_sessions[call_id] = {
            'type': 'dm',
            'peer': to_user,
            'initiator': u,
            'created_at': time.time()
        }
        # Emit system message to both users
        sys_msg = f"Voice call started by {u}. <a href='/call/{call_id}' style='color:#3b82f6;text-decoration:underline'>Click here to join!</a>"
        payload = {
            'id': int(time.time()*1000)%2147483647,
            'from_user': 'System',
            'to_user': to_user,
            'text': sys_msg,
            'attachment': None,
            'created_at': to_ny_time(datetime.utcnow()),
            'avatar': '/sys_pfp.png'
        }
        emit('dm_new', payload, room=f'user:{to_user}')
        emit('dm_new', payload, room=f'user:{u}')
        # Emit call_started event with call_id
        emit('call_started', {'call_id': call_id, 'type': 'dm', 'peer': to_user}, room=f'user:{u}')
        emit('call_started', {'call_id': call_id, 'type': 'dm', 'peer': u}, room=f'user:{to_user}')
    except Exception:
        pass

@socketio.on('call_start_gdm')
def _call_start_gdm(data):
    try:
        u = session.get('username') or ''
        try:
            tid = int((data or {}).get('thread_id', 0))
        except Exception:
            tid = 0
        if not u or not tid:
            return
        # Generate unique call ID
        call_id = f"gdm_{tid}_{int(time.time()*1000)}"
        call_sessions[call_id] = {
            'type': 'gdm',
            'thread_id': tid,
            'initiator': u,
            'created_at': time.time()
        }
        # Get group name
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT name FROM group_threads WHERE id=?', (tid,))
        row = cur.fetchone()
        group_name = (row[0] if row else f'Group {tid}') if not isinstance(row, sqlite3.Row) else (row['name'] if row else f'Group {tid}')
        # Emit system message to all members
        sys_msg = f"Voice call started by {u}. <a href='/call/{call_id}' style='color:#3b82f6;text-decoration:underline'>Click here to join!</a>"
        cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
        members = [r[0] for r in cur.fetchall()]
        payload = {
            'id': int(time.time()*1000)%2147483647,
            'thread_id': tid,
            'username': 'System',
            'text': sys_msg,
            'attachment': None,
            'created_at': to_ny_time(datetime.utcnow()),
            'avatar': '/sys_pfp.png'
        }
        for member in members:
            socketio.emit('gdm_new', payload, room=f'user:{member}')
        # Emit call_started event with call_id
        emit('call_started', {'call_id': call_id, 'type': 'gdm', 'thread_id': tid, 'group_name': group_name}, room=f'gdm:{tid}')
    except Exception:
        pass

def _session_user_valid() -> bool:
    try:
        uid = session.get('user_id')
        uname = session.get('username')
        if not uid or not uname:
            return False
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT username FROM users WHERE id=?', (uid,))
        row = cur.fetchone()
        if not row:
            return False
        db_uname = row[0] if not isinstance(row, sqlite3.Row) else row['username']
        return db_uname == uname
    except Exception:
        return False

@app.before_request
def _enforce_bans_global():
    try:
        ep = (request.endpoint or '')
        if ep and (ep.startswith('static') or ep in ('healthcheck',)):
            return
        # Enforce IP bans using private first, then public
        u = session.get('username') or ''
        priv, pub = detect_client_ips()
        if u:
            _update_user_ips(u, priv, pub)
            if _is_ip_blocked_for(u, priv, pub):
                # Return JSON for API endpoints
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'IP address banned'}), 403
                return ("Your IP address is banned", 403)
        else:
            # Anonymous access: block by public/private as available
            if (priv and is_ip_banned(priv)) or (pub and is_ip_banned(pub)):
                # Return JSON for API endpoints
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'IP address banned'}), 403
                return ("Your IP address is banned", 403)
        u = session.get('username')
        if u and is_banned(u):
            session.clear()
            # Return JSON for API endpoints
            if request.path.startswith('/api/'):
                return jsonify({'error': 'user banned'}), 403
            return redirect(url_for('login'))
        # If a session exists but the user row is missing, force logout
        if session.get('user_id'):
            try:
                db = get_db(); cur = db.cursor()
                cur.execute('SELECT 1 FROM users WHERE id=?', (session['user_id'],))
                if not cur.fetchone():
                    session.clear()
                    return redirect(url_for('login'))
            except Exception:
                pass
    except Exception:
        pass

# ============================================================================
# DOC CHANNEL SOCKET HANDLERS
# ============================================================================

def _reset_doc_idle_timer(doc_id):
    """Reset the 5-minute idle timer for a doc"""
    global doc_idle_timers
    if doc_id in doc_idle_timers:
        doc_idle_timers[doc_id].cancel()

    def save_to_tmpweb():
        """Auto-save to tmpweb.net after 5 minutes of inactivity"""
        try:
            if doc_id not in doc_sessions:
                return
            session_data = doc_sessions[doc_id]
            content = session_data.get('content', '')

            # POST to tmpweb.net
            response = requests.post('https://tmpweb.net/api/create',
                                   json={'content': content},
                                   timeout=10)
            if response.status_code == 200:
                data = response.json()
                url = data.get('url')
                expires_at = datetime.utcnow() + timedelta(days=7)

                # Update session and database
                session_data['tmpweb_url'] = url
                session_data['tmpweb_expires'] = expires_at.timestamp()

                db = get_db(); cur = db.cursor()
                cur.execute('UPDATE docs SET tmpweb_url=?, tmpweb_expires_at=? WHERE id=?',
                           (url, expires_at, doc_id))
                db.commit()

                # Notify all users in the doc
                socketio.emit('doc_saved_to_tmpweb', {'doc_id': doc_id, 'url': url, 'expires_at': to_ny_time(expires_at)},
                            room=f'doc:{doc_id}')
        except Exception as e:
            print(f"Error saving doc {doc_id} to tmpweb: {e}")

    timer = threading.Timer(300.0, save_to_tmpweb)  # 5 minutes
    timer.daemon = True
    timer.start()
    doc_idle_timers[doc_id] = timer

def _check_doc_expiration_warnings():
    """Check for docs expiring in 1 day and send warnings"""
    try:
        _ensure_doc_schema()
        db = get_db(); cur = db.cursor()
        now = datetime.utcnow()
        one_day_from_now = now + timedelta(days=1)

        # Find docs with tmpweb_expires_at between now and 1 day from now
        cur.execute('''SELECT id, tmpweb_expires_at FROM docs
                       WHERE tmpweb_expires_at IS NOT NULL
                       AND tmpweb_expires_at > ?
                       AND tmpweb_expires_at <= ?''',
                   (now, one_day_from_now))

        for r in cur.fetchall():
            doc_id = r[0] if not isinstance(r, sqlite3.Row) else r['id']
            expires_at = r[1] if not isinstance(r, sqlite3.Row) else r['tmpweb_expires_at']

            # Get all members of this doc
            cur.execute('SELECT username FROM doc_members WHERE doc_id=?', (doc_id,))
            members = [m[0] for m in cur.fetchall()]

            # Send DM from System to each member
            for member in members:
                try:
                    sys_msg = f"Your collaborative doc will be automatically deleted tomorrow. Make an edit before then to preserve it."
                    cur.execute('''INSERT INTO direct_messages (from_user, to_user, text, created_at)
                                   VALUES (?, ?, ?, ?)''',
                               ('System', member, sys_msg, datetime.utcnow()))
                    db.commit()

                    # Emit socket event
                    payload = {
                        'id': int(time.time()*1000) % 2147483647,
                        'from_user': 'System',
                        'to_user': member,
                        'text': sys_msg,
                        'attachment': None,
                        'created_at': to_ny_time(datetime.utcnow()),
                        'avatar': '/sys_pfp.png'
                    }
                    socketio.emit('dm_new', payload, room=f'user:{member}')
                except Exception:
                    pass
    except Exception as e:
        print(f"Error checking doc expiration: {e}")

@socketio.on('doc_join')
def _doc_join(data):
    try:
        u = session.get('username') or ''
        doc_id = int((data or {}).get('doc_id', 0))
        if not u or not doc_id:
            return

        _ensure_doc_schema()
        db = get_db(); cur = db.cursor()

        # Verify user has access
        if not can_view_doc(doc_id, u):
            emit('error', {'message': 'access denied'})
            return

        # Load doc if not in session
        if doc_id not in doc_sessions:
            cur.execute('SELECT content, tmpweb_url, tmpweb_expires_at FROM docs WHERE id=?', (doc_id,))
            r = cur.fetchone()
            if r:
                content = r[0] if not isinstance(r, sqlite3.Row) else r['content'] or ''
                tmpweb_url = r[1] if not isinstance(r, sqlite3.Row) else r['tmpweb_url']
                tmpweb_expires = r[2] if not isinstance(r, sqlite3.Row) else r['tmpweb_expires_at']
                doc_sessions[doc_id] = {
                    'content': content,
                    'last_edit_time': time.time(),
                    'users': {u},
                    'tmpweb_url': tmpweb_url,
                    'tmpweb_expires': tmpweb_expires.timestamp() if tmpweb_expires else None,
                    'idle_timer': None
                }
                _reset_doc_idle_timer(doc_id)
        else:
            doc_sessions[doc_id]['users'].add(u)

        join_room(f'doc:{doc_id}')
        # Send doc content to the joining user
        emit('doc_content', {'content': doc_sessions[doc_id]['content'], 'doc_id': doc_id})
        # Notify others that user joined
        socketio.emit('doc_user_joined', {'username': u, 'doc_id': doc_id}, room=f'doc:{doc_id}', skip_sid=request.sid)
    except Exception:
        pass

@socketio.on('doc_edit')
def _doc_edit(data):
    try:
        u = session.get('username') or ''
        doc_id = int((data or {}).get('doc_id', 0))
        content = (data or {}).get('content', '')
        if not u or not doc_id:
            return

        # Check edit permission
        if not can_edit_doc(doc_id, u):
            emit('error', {'message': 'edit access denied'})
            return

        if doc_id not in doc_sessions:
            return

        # Update session
        doc_sessions[doc_id]['content'] = content
        doc_sessions[doc_id]['last_edit_time'] = time.time()

        # Reset idle timer for auto-save
        _reset_doc_idle_timer(doc_id)

        # Broadcast to all users in the doc
        socketio.emit('doc_content_updated', {'content': content, 'edited_by': u}, room=f'doc:{doc_id}')

        # Update database with edit info
        try:
            db = get_db(); cur = db.cursor()
            cur.execute('UPDATE docs SET content=?, last_edited_by=?, last_edited_at=? WHERE id=?',
                       (content, u, datetime.utcnow(), doc_id))
            db.commit()
        except Exception:
            pass
    except Exception:
        pass

@socketio.on('doc_leave')
def _doc_leave(data):
    try:
        u = session.get('username') or ''
        doc_id = int((data or {}).get('doc_id', 0))
        if not u or not doc_id:
            return

        if doc_id in doc_sessions:
            doc_sessions[doc_id]['users'].discard(u)
            if not doc_sessions[doc_id]['users']:
                # Last user left, save to DB
                try:
                    db = get_db(); cur = db.cursor()
                    cur.execute('UPDATE docs SET content=? WHERE id=?',
                               (doc_sessions[doc_id]['content'], doc_id))
                    db.commit()
                except Exception:
                    pass

        leave_room(f'doc:{doc_id}')
        socketio.emit('doc_user_left', {'username': u}, room=f'doc:{doc_id}')
    except Exception:
        pass

# Database helpers
def get_db():
    """Get a database connection for the current context."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
        db.row_factory = sqlite3.Row
        try:
            # Improve concurrency and durability/perf tradeoff for chat workloads
            db.execute('PRAGMA journal_mode=WAL;')
            db.execute('PRAGMA synchronous=NORMAL;')
            db.execute('PRAGMA temp_store=MEMORY;')
            db.execute('PRAGMA mmap_size=268435456;')  # 256MB
            db.execute('PRAGMA cache_size=-65536;')     # ~64MB page cache
        except Exception:
            pass
    return db

def get_db_socket():
    """Get a dedicated database connection for Socket.IO events."""
    db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    db.row_factory = sqlite3.Row
    try:
        # Improve concurrency and durability/perf tradeoff for chat workloads
        db.execute('PRAGMA journal_mode=WAL;')
        db.execute('PRAGMA synchronous=NORMAL;')
        db.execute('PRAGMA temp_store=MEMORY;')
        db.execute('PRAGMA mmap_size=268435456;')  # 256MB
        db.execute('PRAGMA cache_size=-65536;')     # ~64MB page cache
    except Exception:
        pass
    return db

@app.teardown_appcontext
def close_connection(exc):
    db = getattr(g, "_database", None)
    if db:
        db.close()

# Helper functions for admin commands
def save_uploaded_file(file_data, filename, uploader):
    """Save an uploaded file and return its ID"""
    try:
        # Create uploads directory if it doesn't exist
        os.makedirs('uploads', exist_ok=True)
        
        # Generate a unique ID for the file
        file_id = str(uuid.uuid4())
        file_path = os.path.join('uploads', file_id)
        
        # Save the file
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        # Store file metadata in database
        db = get_db()
        cur = db.cursor()
        cur.execute('''
            INSERT INTO file_uploads 
            (id, filename, uploader, upload_time, size) 
            VALUES (?, ?, ?, datetime('now'), ?)
        ''', (file_id, filename, uploader, len(file_data)))
        db.commit()
        
        return file_id
    except Exception as e:
        print(f"Error saving file: {e}")
        return None

def get_file_info(file_id):
    """Get information about an uploaded file"""
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute('''
            SELECT id, filename, uploader, upload_time, size 
            FROM file_uploads 
            WHERE id = ?
        ''', (file_id,))
        return cur.fetchone()
    except Exception:
        return None

def list_files(uploader=None):
    """List all uploaded files, optionally filtered by uploader"""
    try:
        db = get_db()
        cur = db.cursor()
        if uploader:
            cur.execute('''
                SELECT id, filename, uploader, upload_time, size 
                FROM file_uploads 
                WHERE uploader = ?
                ORDER BY upload_time DESC
            ''', (uploader,))
        else:
            cur.execute('''
                SELECT id, filename, uploader, upload_time, size 
                FROM file_uploads 
                ORDER BY upload_time DESC
            ''')
        return cur.fetchall()
    except Exception as e:
        print(f"Error listing files: {e}")
        return []

def delete_file(file_id, requester):
    """Delete a file if the requester has permission"""
    try:
        db = get_db()
        cur = db.cursor()
        
        # Check if file exists and get uploader
        file_info = get_file_info(file_id)
        if not file_info:
            return False, "File not found"
            
        # Only allow deletion by uploader or admin
        if file_info['uploader'] != requester and not is_admin(requester):
            return False, "Permission denied"
            
        # Delete file from filesystem
        file_path = os.path.join('uploads', file_id)
        if os.path.exists(file_path):
            os.remove(file_path)
            
        # Delete from database
        cur.execute('DELETE FROM file_uploads WHERE id = ?', (file_id,))
        db.commit()
        
        return True, "File deleted successfully"
    except Exception as e:
        print(f"Error deleting file: {e}")
        return False, f"Error: {str(e)}"

def is_channel_member(channel_id, user_id):
    """Check if a user is a member of a channel."""
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute('''
            SELECT 1 FROM channel_members 
            WHERE channel_id = ? AND user_id = ?
        ''', (channel_id, user_id))
        return cur.fetchone() is not None
    except Exception:
        return False

def get_channel_by_name(channel_name):
    """Get a channel by its name."""
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute('SELECT * FROM channels WHERE name = ?', (channel_name,))
        return cur.fetchone()
    except Exception:
        return None

def get_user_channel_status(user_id, channel_id):
    """Get a user's status in a channel."""
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute('''
            SELECT is_admin FROM channel_members 
            WHERE user_id = ? AND channel_id = ?
        ''', (user_id, channel_id))
        result = cur.fetchone()
        return {
            'is_member': result is not None,
            'is_admin': result['is_admin'] if result else False
        }
    except Exception:
        return {'is_member': False, 'is_admin': False}

def add_user_to_channel(user_id, username, channel_id, is_admin=False):
    """Add a user to a channel."""
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute('''
            INSERT OR REPLACE INTO channel_members 
            (channel_id, user_id, joined_at, is_admin)
            VALUES (?, ?, datetime('now'), ?)
        ''', (channel_id, user_id, 1 if is_admin else 0))
        db.commit()
        return True
    except Exception as e:
        print(f"Error adding user to channel: {e}")
        return False

def get_channel_members(channel_id):
    """Get all members of a channel."""
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute('''
            SELECT u.username, u.id, cm.is_admin, cm.joined_at
            FROM channel_members cm
            JOIN users u ON cm.user_id = u.id
            WHERE cm.channel_id = ?
            ORDER BY cm.joined_at
        ''', (channel_id,))
        return cur.fetchall()
    except Exception as e:
        print(f"Error getting channel members: {e}")
        return []

def get_current_channel():
    """Get the current channel for the user."""
    try:
        db = get_db()
        cur = db.cursor()
        # Get the first channel as default
        cur.execute('SELECT * FROM channels LIMIT 1')
        return cur.fetchone()
    except Exception:
        return None

# Downtime allowlist table
def _ensure_downtime_table():
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('CREATE TABLE IF NOT EXISTS downtime_ip_allow (ip TEXT PRIMARY KEY)')
        db.commit()
    except Exception:
        pass

def _get_ip():
    try:
        return request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or request.remote_addr or ''
    except Exception:
        return request.remote_addr or ''

def _is_ip_allowed_during_downtime(ip: str) -> bool:
    try:
        _ensure_downtime_table()
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT 1 FROM downtime_ip_allow WHERE ip=?', (ip,))
        return cur.fetchone() is not None
    except Exception:
        return False

def _allow_ip_during_downtime(ip: str):
    try:
        _ensure_downtime_table()
        db = get_db(); cur = db.cursor()
        cur.execute('INSERT OR IGNORE INTO downtime_ip_allow(ip) VALUES(?)', (ip,))
        db.commit()
    except Exception:
        pass

def _clear_downtime_ips():
    try:
        _ensure_downtime_table()
        db = get_db(); cur = db.cursor()
        cur.execute('DELETE FROM downtime_ip_allow')
        db.commit()
    except Exception:
        pass


@app.before_request
def _downtime_gate():
    try:
        if str(get_setting('DOWNTIME_ENABLED','0')) != '1':
            # reset allowlist when downtime ends ()
            try: _clear_downtime_ips()
            except: pass
            return
        # Always allow unlock API, /smite, and static/media so admins can generate/use codes
        path = request.path or ''
        if path.startswith('/api/downtime/unlock') or path.startswith('/smite') or path.startswith('/uploads/') or path.startswith('/static/'):
            return
        # Allow superadmins
        u = session.get('username') or ''
        if u and (u in SUPERADMINS):
            return
        # Allow whitelisted IPs
        ip = _get_ip()
        if ip and _is_ip_allowed_during_downtime(ip):
            return
        # Return downtime page
        reason = get_setting('DOWNTIME_REASON','') or ''
        # Return downtime page
        if not reason:
            reason = 'No reason provided'
            try:
                set_setting('DOWNTIME_REASON', reason)
            except Exception:
                pass
        
        # Return JSON for API endpoints
        if request.path.startswith('/api/'):
            return jsonify({'error': 'server in maintenance', 'reason': reason}), 503
            
        reason_html = ("<div style='height:10px'></div><div class='reason'>Reason: " + reason + "</div>")
        heading = 'Chatter is temporarily unavailable'
        sub = 'We are performing maintenance. Please check back later.'
        html = (
            "<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>\n"
            "<title>Chatter Down</title>\n"
            "<style>body{margin:0;font-family:system-ui,Segoe UI,Arial;background:#0f172a;color:#e5e7eb;display:flex;align-items:center;justify-content:center;min-height:100vh} .card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:20px;max-width:640px;margin:16px;box-shadow:0 10px 30px rgba(0,0,0,.3)} .muted{color:#9ca3af} .reason{white-space:pre-wrap;word-break:break-word} .modal{position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;align-items:center;justify-content:center;z-index:10000} .modal>.box{background:#111827;border:1px solid #374151;border-radius:12px;padding:16px;max-width:360px;width:92%} .input{width:100%;padding:10px;border-radius:8px;border:1px solid #374151;background:#0b1020;color:#e5e7eb} .btn{padding:8px 10px;border-radius:8px;border:1px solid #374151;background:#2563eb;color:#fff}</style>\n"
            "</head><body>\n"
            "  <div class='card'>\n"
            f"    <h2 style='margin:0 0 6px'>{heading}</h2>\n"
            f"    <div class='muted'>{sub}</div>\n"
            + reason_html +
            "    <div style='height:14px'></div>\n"
            "    <div class='muted' id='hint'></div>\n"
            "  </div>\n"
            "  <div class='modal' id='dtModal'><div class='box'>\n"
            "    <div style='font-weight:600;margin-bottom:6px'>Enter access code</div>\n"
            "    <input id='dtCode' type='password' class='input' placeholder='16-character code' autocomplete='off'/>\n"
            "    <div style='display:flex;gap:8px;justify-content:flex-end;margin-top:10px'>\n"
            "      <button id='dtCancel' class='btn' style='background:#374151'>Cancel</button>\n"
            "      <button id='dtSubmit' class='btn'>Unlock</button>\n"
            "    </div>\n"
            "  </div></div>\n"
            "<script>\n"
            "(function(){\n"
            "  let pressed = new Set();\n"
            "  document.addEventListener('keydown', async (e)=>{\n"
            "    pressed.add(e.key.toLowerCase());\n"
            "    if (pressed.has('control') && pressed.has('shift') && pressed.has('u')){\n"
            "      pressed.clear();\n"
            "      try{\n"
            "        const m = prompt('Enter master code'); if (!m) return;\n"
            "        const r = await fetch('/smite', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ master: m })});\n"
            "        const j = await r.json().catch(()=>({}));\n"
            "        if (r.ok && j && j.ok && j.code){\n"
            "          const modal = document.getElementById('dtModal'); const codeInput = document.getElementById('dtCode');\n"
            "          try{ codeInput.value = ''; modal.style.display='flex'; codeInput.focus(); }catch(e){ }\n"
            "          alert('Code copied to clipboard. Paste it into the box to unlock.');\n"
            "          try{ navigator.clipboard.writeText(j.code); }catch(e){ }\n"
            "        } else { alert((j&&j.error)||'Invalid'); }\n"
            "      }catch(e){ alert('Failed'); }\n"
            "    }\n"
            "  });\n"
            "  document.addEventListener('keyup', (e)=>{ pressed.delete(e.key.toLowerCase()); });\n"
            "  try{ document.getElementById('hint').textContent = ''; }catch(error){ }\n"
            "  try{\n"
            "    const modal = document.getElementById('dtModal');\n"
            "    const codeInput = document.getElementById('dtCode');\n"
            "    const cancelBtn = document.getElementById('dtCancel');\n"
            "    const submitBtn = document.getElementById('dtSubmit');\n"
            "    cancelBtn.onclick = ()=>{ modal.style.display='none'; codeInput.value=''; };\n"
            "    async function submit(){\n"
            "      const pass = (codeInput.value||'').trim(); if (!pass) return;\n"
            "      try{ const r = await fetch('/api/downtime/unlock', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ code: pass })}); if (r.ok){ codeInput.value=''; location.reload(); } else { alert('Invalid code'); } }catch(e){ alert('Failed'); }\n"
            "    }\n"
            "    submitBtn.onclick = submit; codeInput.onkeydown = (e)=>{ if (e.key==='Enter') submit(); };\n"
            "  }catch(e){ }\n"
            "})();\n"
            "</script>\n"
            "</body></html>\n"
        )
        return html
    except Exception:
        pass

# ===================== Datasette Reverse Proxy (superadmin only) =====================
def _proxy_filter_headers(src):
    # Remove hop-by-hop headers
    excluded = {
        'connection','keep-alive','proxy-authenticate','proxy-authorization',
        'te','trailers','transfer-encoding','upgrade','content-length'
    }
    return {k: v for k, v in src.items() if k.lower() not in excluded}
@app.route('/admin/sqlite', defaults={'subpath': ''}, methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS'])
@app.route('/admin/sqlite/<path:subpath>', methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS'])
@login_required
def admin_sqlite_proxy(subpath: str):
    return abort(404)

@app.route('/admin/datasette')
@login_required
def admin_datasette_helper():
    return abort(404)

# Proxy py4web DB admin under this Flask app
@app.route('/db_admin', defaults={'subpath': ''}, methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS'])
@app.route('/db_admin/<path:subpath>', methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS'])
def proxy_db_admin(subpath: str):
    try:
        base = 'http://127.0.0.1:8000/db_admin'
        qs = (request.query_string or b'').decode('utf-8', 'ignore')
        url = base + ('/' + subpath if subpath else '') + (('?' + qs) if qs else '')
        headers = _proxy_filter_headers(request.headers)
        # Forward request body and cookies
        r = requests.request(
            request.method,
            url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=True,
            timeout=30,
        )
        resp = Response(r.content, status=r.status_code)
        for k, v in r.headers.items():
            kl = k.lower()
            if kl in ('connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailers','transfer-encoding','upgrade','content-length'):
                continue
            resp.headers[k] = v
        return resp
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/api/downtime/unlock', methods=['POST'])
def api_downtime_unlock():
    try:
        data = request.get_json(silent=True) or {}
        code = (data.get('code') or data.get('passcode') or '').strip()
        if not code:
            return jsonify({'error':'missing'}), 400
        # Compare in a case-insensitive safe way
        cur_code = _get_downtime_code()
        if code and cur_code and secrets.compare_digest(code.upper(), cur_code.upper()):
            _allow_ip_during_downtime(_get_ip())
            _rotate_downtime_code()
            return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ======== DBX code-gate helpers ========
def _get_dbx_code():
    try:
        code = get_setting('DBX_CODE','') or ''
        if not code:
            code = _rand_code(8)
            set_setting('DBX_CODE', code)
        return code
    except Exception:
        return _rand_code(8)

def _make_dbxok_cookie() -> str:
    try:
        payload = json.dumps({'ok': True, 'ts': int(time.time())}, separators=(',',':')).encode('utf-8')
        sig = hmac.new(app.secret_key.encode('utf-8'), payload, hashlib.sha256).digest()
        return _b64u(payload) + '.' + _b64u(sig)
    except Exception:
        return ''

def _verify_dbxok_cookie(val: str) -> bool:
    try:
        if not val or '.' not in val:
            return False
        p, s = val.split('.',1)
        payload = _b64ud(p); sig = _b64ud(s)
        good = hmac.compare_digest(hmac.new(app.secret_key.encode('utf-8'), payload, hashlib.sha256).digest(), sig)
        return bool(good)
    except Exception:
        return False

def _dbx_ok() -> bool:
    try:
        # superadmin always ok
        if is_superadmin():
            return True
        # code cookie
        v = request.cookies.get('dbxok') or ''
        if _verify_dbxok_cookie(v):
            return True
        return False
    except Exception:
        return False
    return jsonify({'error':'invalid'}), 403

# Alerts API
@app.route('/api/alerts')
def api_alerts():
    try:
        enabled = str(get_setting('ALERTS_ENABLED','0'))=='1'
        text = get_setting('ALERTS_TEXT','') or ''
        return jsonify({'enabled': enabled, 'text': text})
    except Exception:
        return jsonify({'enabled': False, 'text': ''})

# Admin settings for downtime and alerts
@app.route('/api/admin/settings', methods=['POST'])
@login_required
def api_admin_settings():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    keys = ['DOWNTIME_ENABLED','DOWNTIME_REASON','ALERTS_ENABLED','ALERTS_TEXT']
    try:
        for k in keys:
            if k in data:
                set_setting(k, str(data[k]))
        try:
            if str(get_setting('DOWNTIME_ENABLED','0')) != '1':
                _clear_downtime_ips()
                set_setting('DOWNTIME_CODE','')
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/whoami')
def api_whoami():
    try:
        sess = session.get('username') or ''
        hdr = request.headers.get('X-DBX') or ''
        q = request.args.get('dbx') or ''
        cook = request.cookies.get('dbx') or ''
        hdr_u = _verify_dbx_token(hdr)
        q_u = _verify_dbx_token(q)
        c_u = _verify_dbx_token(cook)
        eff = sess or hdr_u or q_u or c_u
        
        # Get user data if user is authenticated
        avatar = None
        bio = None
        status = None
        if eff:
            try:
                db = get_db()
                cur = db.cursor()
                cur.execute('SELECT avatar, bio, status FROM users WHERE username=?', (eff,))
                row = cur.fetchone()
                if row:
                    avatar = row[0]
                    bio = row[1]
                    status = row[2]
                cur.close()
            except Exception:
                pass
        
        return jsonify({ 
            'session': sess, 
            'x_dbx_user': hdr_u, 
            'q_dbx_user': q_u, 
            'cookie_dbx_user': c_u, 
            'effective': eff, 
            'is_superadmin': bool(eff in SUPERADMINS),
            'avatar': avatar,
            'bio': bio,
            'status': status
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/smite', methods=['GET','POST'])
def api_smite():
    if request.method == 'GET':
        # If redirected after a successful POST, show the code once and then clear it
        show = (request.args.get('show') or '').lower()
        if show == 'code':
            code_once = session.pop('smite_code', None)
            if code_once:
                return (
                    "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "<title>Downtime Code</title>"
                    "<style>body{margin:0;font-family:system-ui,Segoe UI,Arial;background:#0f172a;color:#e5e7eb;display:flex;align-items:center;justify-content:center;min-height:100vh}"
                    ".card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:20px;max-width:480px;margin:16px;box-shadow:0 10px 30px rgba(0,0,0,.3)}"
                    ".muted{color:#9ca3af}.code{font-size:20px;letter-spacing:2px;background:#0b1020;border:1px solid #374151;padding:10px;border-radius:8px;display:flex;gap:8px;align-items:center;justify-content:space-between}"
                    ".btn{padding:8px 10px;border-radius:8px;border:1px solid #374151;background:#2563eb;color:#fff}</style></head><body>"
                    "<div class='card'><h3 style='margin-top:0'>Current downtime code</h3>"
                    "<div class='code'><span>••••••••••••••••</span> "
                    f"<button class='btn' onclick=\"navigator.clipboard.writeText('{code_once}')\">Copy</button></div>"
                    "<div class='muted' style='margin-top:8px'>Code rotates after each successful unlock.</div>"
                    "</div></body></html>"
                )
        # Default: Simple HTML form (available even during downtime)
        return ("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
                "<title>/smite</title>"
                "<style>body{margin:0;font-family:system-ui,Segoe UI,Arial;background:#0f172a;color:#e5e7eb;display:flex;align-items:center;justify-content:center;min-height:100vh}"
                ".card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:20px;max-width:480px;margin:16px;box-shadow:0 10px 30px rgba(0,0,0,.3)}"
                ".input{width:100%;padding:10px;border-radius:8px;border:1px solid #374151;background:#0b1020;color:#e5e7eb}"
                ".btn{padding:8px 10px;border-radius:8px;border:1px solid #374151;background:#2563eb;color:#fff}</style></head><body>"
                "<div class='card'><h3 style='margin-top:0'>/smite</h3>"
                "<form method='post'><input name='master' type='password' placeholder='Master code' class='input' style='margin-bottom:8px' autocomplete='off'>"
                "<button type='submit' class='btn'>Get current downtime code</button></form>"
                "</div></body></html>")
    # POST (form or JSON)
    try:
        is_json = bool(request.is_json)
        master_form = (request.form.get('master') if not is_json else None)
        master_json = ((request.get_json(silent=True) or {}).get('master') if is_json else None)
        master = (master_form or master_json or '').strip()
        if master == 'Smite6741':
            code = _get_downtime_code()
            if not is_json and (master_form is not None):
                # Store code for one-time display on redirected GET
                try:
                    session['smite_code'] = code
                except Exception:
                    pass
                return redirect(url_for('api_smite', show='code'))
            # JSON client (Ctrl+Shift+U flow)
            return jsonify({'ok': True, 'code': code})
        return jsonify({'error':'invalid'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Back-compat: Admin app settings endpoint used by some clients
@app.route('/api/admin/app_settings', methods=['GET','POST'])
@login_required
def api_admin_app_settings_v2():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    if request.method == 'GET':
        try:
            _seed_defaults_if_needed()
            db = get_db(); cur = db.cursor()
            try:
                cur.execute('SELECT key, value FROM app_settings')
            except Exception:
                _ensure_app_settings(); cur.execute('SELECT key, value FROM app_settings')
            out = {}
            for row in cur.fetchall():
                k = row[0] if not isinstance(row, sqlite3.Row) else row['key']
                v = row[1] if not isinstance(row, sqlite3.Row) else row['value']
                out[k] = v
            return jsonify({'ok': True, 'settings': out})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    # POST
    data = request.get_json(silent=True) or {}
    settings = data.get('settings') if isinstance(data.get('settings'), dict) else data
    try:
        # Ensure table exists before writes
        try:
            _ensure_app_settings()
        except Exception:
            pass
        for k, v in (settings or {}).items():
            set_setting(str(k), str(v))
        try:
            if str(get_setting('DOWNTIME_ENABLED','0')) != '1':
                _clear_downtime_ips()
                set_setting('DOWNTIME_CODE','')
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Admin toggles: accept flat or {settings:{}} payload
@app.route('/api/admin/toggles', methods=['POST'])
@login_required
def api_admin_toggles():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    settings = data.get('settings') if isinstance(data.get('settings'), dict) else data
    try:
        keys = set([
            # Global/chat
            'PUBLIC_ENABLED','DM_ENABLED','GDM_ENABLED','MAINTENANCE_MODE','INVITE_ONLY_MODE','ANNOUNCEMENTS_ONLY',
            # User management
            'UM_BAN_USER','UM_TIMEOUT_USER','UM_SEARCH_USER','UM_TEMP_BAN','UM_GLOBAL_WARNING','UM_SHADOW_BAN',
            # Message controls
            'MC_DELETE_MESSAGES','MC_EDIT_MESSAGES','MC_SEARCH_MESSAGES','MC_PURGE_CHANNEL','MC_PIN_MESSAGE','MC_BROADCAST_MESSAGE','MC_VIEW_HISTORY','MC_MESSAGE_LIFESPAN','MC_MESSAGE_LIFESPAN_DAYS',
            # Group tools
            'GD_LOCK_GROUP','GD_UNLOCK_GROUP','GD_REMOVE_USER','GD_TRANSFER_OWNERSHIP','GD_DELETE_GROUP','GD_CLOSE_ALL_DMS','GD_DM_AS_SYSTEM','GD_SAVE_DM_LOGS','GD_FORCE_LEAVE_GROUP',
            # Admin tools
            'ADMIN_SYNC_PERMS','ADMIN_VIEW_ACTIVE','ADMIN_STEALTH_MODE',
            # Downtime & Alerts
            'DOWNTIME_ENABLED','DOWNTIME_REASON','ALERTS_ENABLED','ALERTS_TEXT',
            # Security
            'SEC_STRICT_ASSOCIATED_BAN','SEC_DEVICE_BAN_ON_LOGIN','SEC_REG_BAN_SIMILAR_CID',
        ])
        for k, v in (settings or {}).items():
            if k not in keys:
                continue
            if k == 'MC_MESSAGE_LIFESPAN_DAYS':
                try:
                    v = str(max(0, int(str(v).strip() or '0')))
                except Exception:
                    v = '0'
            else:
                v = str(v)
            set_setting(k, v)
        # Clear downtime allowlist if downtime disabled and reset code
        try:
            if str(get_setting('DOWNTIME_ENABLED','0')) != '1':
                _clear_downtime_ips()
                set_setting('DOWNTIME_CODE','')
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Undo last timeout
@app.route('/api/admin/undo_timeout', methods=['POST'])
@login_required
def api_admin_undo_timeout():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    try:
        if not last_timeout or 'user' not in last_timeout:
            return jsonify({'error':'no timeout to undo'}), 400
        
        user = last_timeout['user']
        if user not in user_timeouts:
            return jsonify({'error':'user not timed out'}), 400
        
        # Remove the timeout
        user_timeouts.pop(user)
        
        # Send notification
        emit("system_message", store_system_message(f"{user} timeout removed by {me}"))
        try:
            emit('timeout_removed', {}, room=f'user:{user}')
        except Exception:
            pass
        
        # Log the action
        try:
            log_admin_action(me, 'untimeout', target=user, details={'undo': True})
        except Exception:
            pass
        
        # Clear last timeout
        last_timeout.clear()
        
        return jsonify({'ok': True, 'user': user})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Get all groups (including deleted)
@app.route('/api/admin/all_groups', methods=['GET'])
@login_required
def api_admin_all_groups():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    try:
        db = get_db()
        cur = db.cursor()
        
        # Get all group threads including deleted ones
        cur.execute('''
            SELECT gt.id, gt.name, gt.created_at, gt.deleted_at, gt.created_by,
                   COUNT(gm.id) as message_count,
                   u.username as creator_name
            FROM group_threads gt
            LEFT JOIN group_messages gm ON gt.id = gm.thread_id
            LEFT JOIN users u ON gt.created_by = u.username
            GROUP BY gt.id, gt.name, gt.created_at, gt.deleted_at, gt.created_by, u.username
            ORDER BY gt.created_at DESC
        ''')
        
        groups = []
        for row in cur.fetchall():
            groups.append({
                'id': row[0],
                'name': row[1],
                'created_at': row[2],
                'deleted_at': row[3],
                'created_by': row[4],
                'message_count': row[5],
                'creator_name': row[6],
                'is_deleted': row[3] is not None
            })
        
        return jsonify({'ok': True, 'groups': groups})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Get group message logs
@app.route('/api/admin/group_messages/<int:thread_id>', methods=['GET'])
@login_required
def api_admin_group_messages(thread_id):
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    try:
        db = get_db()
        cur = db.cursor()
        
        # Get all messages for this group
        cur.execute('''
            SELECT gm.id, gm.text, gm.username, gm.created_at, gm.attachment,
                   gm.reply_to, gm.edited_by, gm.edited_at
            FROM group_messages gm
            WHERE gm.thread_id = ?
            ORDER BY gm.created_at ASC
        ''', (thread_id,))
        
        messages = []
        for row in cur.fetchall():
            messages.append({
                'id': row[0],
                'text': row[1],
                'username': row[2],
                'created_at': row[3],
                'attachment': row[4],
                'reply_to': row[5],
                'edited_by': row[6],
                'edited_at': row[7]
            })
        
        return jsonify({'ok': True, 'messages': messages})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Superadmin DB editor
@app.route('/api/admin/sql_run', methods=['POST'])
@login_required
def api_admin_sql_run():
    me = session.get('username')
    if not (me in SUPERADMINS):
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    sql = (data.get('sql') or '').strip()
    if not sql:
        return jsonify({'error':'missing sql'}), 400
    try:
        db = get_db(); cur = db.cursor()
        cur.execute(sql)
        rows = cur.fetchall() if sql.strip().lower().startswith('select') else []
        db.commit()
        out = []
        for r in rows:
            if isinstance(r, sqlite3.Row):
                out.append({ k:r[k] for k in r.keys() })
            else:
                out.append(list(r))
        return jsonify({'ok': True, 'rows': out})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ===================== New DB Browser (from scratch) =====================
def _dbx_tables(cur):
    cur.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name")
    return [ (r[0] if not isinstance(r, sqlite3.Row) else r['name']) for r in cur.fetchall() ]

def _dbx_schema(cur, table):
    # Use tuple-based PRAGMA to avoid any row_factory/keys() nuances
    c2 = cur.connection.cursor()
    c2.execute(f"PRAGMA table_info({table})")
    cols = []
    for r in c2.fetchall():
        # PRAGMA table_info returns: (cid, name, type, notnull, dflt_value, pk)
        try:
            name = r[1]
            pkflag = r[5]
            cols.append({'name': name, 'pk': pkflag})
        except Exception:
            pass
    pk = [ c['name'] for c in cols if c.get('pk') ]
    # detect rowid availability
    has_rowid = False
    try:
        cur.execute(f"SELECT rowid FROM {table} LIMIT 1")
        cur.fetchone(); has_rowid = True
    except Exception:
        has_rowid = False
    return cols, pk, has_rowid

def _dbx_select(cur, table, limit=100, offset=0, search=None, sort=None, desc=False):
    cols, pk, has_rowid = _dbx_schema(cur, table)
    names = [c['name'] for c in cols]
    where = []
    params = []
    if search:
        like_clause = ' OR '.join([f"CAST({n} AS TEXT) LIKE ?" for n in names])
        where.append(f"({like_clause})")
        params.extend([f"%{search}%"]*len(names))
    where_sql = (" WHERE "+" AND ".join(where)) if where else ""
    order_sql = f" ORDER BY {sort} {'DESC' if desc else 'ASC'}" if sort and sort in names else ""
    # Use a fresh connection without detect_types to avoid sqlite's timestamp
    # auto-decoder raising "too many values to unpack" on non-standard values.
    try:
        tmp_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    except Exception:
        tmp_conn = cur.connection
    c2 = tmp_conn.cursor()
    sel = f"SELECT {'rowid AS rid, ' if has_rowid else ''}* FROM {table}{where_sql}{order_sql} LIMIT ? OFFSET ?"
    c2.execute(sel, params + [limit, offset])
    # Build dicts from cursor.description to avoid row_factory quirks
    cols_meta = c2.description or []
    colnames = [d[0] for d in cols_meta]
    rows = []
    for tup in c2.fetchall():
        obj = {}
        for i, k in enumerate(colnames):
            try:
                v = tup[i]
            except Exception:
                v = None
            # Coerce datetimes to string for JSON
            try:
                from datetime import datetime as _dt
                if isinstance(v, _dt):
                    v = to_ny_time(v)
            except Exception:
                pass
            # Coerce bytes-like to base64 string
            try:
                if isinstance(v, (bytes, bytearray, memoryview)):
                    v = _b64u(bytes(v))
            except Exception:
                pass
            obj[k] = v
        rows.append(obj)
    try:
        if tmp_conn is not cur.connection:
            tmp_conn.close()
    except Exception:
        pass
    return { 'columns': cols, 'pk': (['rid'] if has_rowid else pk), 'has_rowid': has_rowid, 'rows': rows }

@app.route('/api/admin/dbx/tables')
def api_admin_dbx_tables():
    return abort(404)

@app.route('/api/admin/dbx/table')
def api_admin_dbx_table():
    return abort(404)

@app.route('/api/admin/dbx/save', methods=['POST'])
def api_admin_dbx_save():
    return abort(404)

@app.route('/dbx')
def dbx_unlock_ui():
    # Show unlock UI always so superadmins can view/copy the code
    code_hint = '[code set]'
    if is_superadmin(session.get('username') or ''):
        try:
            code_hint = _ensure_dbx_code()
        except Exception:
            pass
    html = (
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>DBX Unlock</title><style>body{margin:0;font-family:system-ui,Segoe UI,Arial;background:#0f172a;color:#e5e7eb;display:flex;align-items:center;justify-content:center;min-height:100vh} .card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:20px;max-width:520px;margin:16px} .label{font-size:12px;color:#9ca3af} .input{width:100%;padding:10px;border-radius:8px;border:1px solid #374151;background:#0b1020;color:#e5e7eb} .btn{padding:8px 10px;border-radius:8px;border:1px solid #374151;background:#2563eb;color:#fff}</style></head><body>"
        f"<div class='card'><h3>Enter DB Admin Code</h3><div style='height:8px'></div><input id='code' class='input' placeholder='Enter code'/>"
        f"<div style='height:8px'></div><button id='go' class='btn'>Unlock</button>"
        f"<div style='height:12px'></div><div class='label'>Current code (visible to superadmins only):</div><input class='input' value='{code_hint}' readonly onclick=\"this.select();document.execCommand('copy');\" title='Click to copy'/>"
        "</div><script>document.getElementById('go').onclick=async()=>{const v=(document.getElementById('code').value||'').trim(); if(!v) return; const r=await fetch('/api/dbx/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:v})}); if(r.ok){ location.href='/admin/dbsafe'; } else { alert('Invalid code'); } };</script></body></html>"
    )
    return html

# ===================== Single-file Safe DB Admin (superadmin-only) =====================
@app.route('/admin/dbsafe')
def admin_dbsafe_index():
    if not _dbx_ok():
        return redirect('/dbx')
    db = get_db(); cur = db.cursor()
    tables = _dbx_tables(cur)
    items = ''.join([f"<li><a href='/admin/dbsafe/table?name={_html.escape(t)}'>{_html.escape(t)}</a></li>" for t in tables])
    html = (
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>DB Safe Admin</title><style>body{font-family:system-ui,Segoe UI,Arial;margin:0;background:#0f172a;color:#e5e7eb} .wrap{display:flex;min-height:100vh} .side{width:260px;border-right:1px solid #1f2937;padding:12px;background:#111827} .main{flex:1;padding:16px} a{color:#93c5fd;text-decoration:none} ul{list-style:none;margin:0;padding:0} li{margin:6px 0} input,select,button{background:#0b1020;color:#e5e7eb;border:1px solid #374151;border-radius:6px;padding:6px} button{cursor:pointer} button:hover{filter:brightness(1.1)} .toolbar{display:flex;gap:8px;align-items:center;margin-bottom:12px} .toast{position:fixed;right:12px;top:12px;background:#1f2937;color:#e5e7eb;border:1px solid #374151;border-radius:8px;padding:10px 12px;z-index:9999;display:none}</style></head><body>"
        "<div class='wrap'><div class='side'><b>Tables</b><ul>"+items+"</ul></div><div class='main'>"
        "<div class='toolbar'><h3 style='margin:0'>DB Safe Admin</h3>"
        "<button onclick=\"if(confirm('Delete ALL rows from ALL tables except app_settings?')) fetch('/admin/dbsafe/clear_all',{method:'POST'}).then(r=>r.json()).then(()=>location.reload()).catch(()=>alert('Failed'));\">Clear All (keep app_settings)</button>"
        "<button onclick=\"saveAllForms()\">Save All</button>"
        "</div><p>Select a table from the left.</p><div id='toast' class='toast'></div>"
        "</div></div><script>function showToast(t){try{const el=document.getElementById('toast'); el.textContent=t; el.style.display='block'; setTimeout(()=>{el.style.display='none'}, 1600);}catch(_){}} async function saveAllForms(){ const forms=[...document.querySelectorAll('tbody form[action=\"/admin/dbsafe/apply\"]')]; if(!forms.length){ showToast('Nothing to save'); return;} for(const f of forms){ const fd=new FormData(f); fd.set('action','update'); try{ await fetch('/admin/dbsafe/apply',{method:'POST', body: fd}); }catch(e){} } location.reload(); }</script></body></html>"
    )
    return html

@app.route('/dbsafe')
def dbsafe_alias_root():
    if not _dbx_ok():
        return redirect('/dbx')
    return redirect('/admin/dbsafe')

@app.route('/admin/dbsafe/table')
def admin_dbsafe_table():
    if not _dbx_ok():
        return redirect('/dbx')
    name = (request.args.get('name') or '').strip()
    if not name:
        return redirect('/admin/dbsafe')
    try:
        limit = max(1, min(200, int(request.args.get('limit') or '50')))
    except Exception:
        limit = 50
    try:
        offset = max(0, int(request.args.get('offset') or '0'))
    except Exception:
        offset = 0
    search = (request.args.get('search') or '').strip() or None
    sort = (request.args.get('sort') or '').strip() or None
    desc = (request.args.get('desc') or '').strip() == '1'
    db = get_db(); cur = db.cursor()
    cols, pk, has_rowid = _dbx_schema(cur, name)
    data = _dbx_select(cur, name, limit=limit, offset=offset, search=search, sort=sort, desc=desc)
    rows = data.get('rows') or []
    # Header
    ths = ''.join([f"<th style='padding:6px;border-bottom:1px solid #1f2937;text-align:left'>{_html.escape(c['name'])}</th>" for c in cols])
    # Rows with update/delete forms
    trs = []
    for r in rows:
        inputs = []
        for c in cols:
            v = r.get(c['name'])
            sval = '' if v is None else str(v)
            inputs.append(f"<td style='padding:6px;border-top:1px solid #1f2937'><input name='val_{_html.escape(c['name'])}' value='{_html.escape(sval)}' /></td>")
        # Identity hidden fields
        hidden = []
        if has_rowid and ('rid' in r):
            hidden.append(f"<input type='hidden' name='rid' value='{_html.escape(str(r['rid']))}'>")
        for k in (pk or []):
            if k in r and r[k] is not None:
                hidden.append(f"<input type='hidden' name='pk_{_html.escape(k)}' value='{_html.escape(str(r[k]))}'>")
        form_update = (
            "<form method='POST' action='/admin/dbsafe/apply' style='display:inline'>"
            f"<input type='hidden' name='table' value='{_html.escape(name)}'>"
            + ''.join(hidden) + ''.join(inputs) +
            "<td style='padding:6px;border-top:1px solid #1f2937'>"
            "<button name='action' value='update'>Save</button> "
            "<button name='action' value='delete' onclick=\"return confirm('Delete row?')\">Delete</button>"
            "</td></form>"
        )
        trs.append(f"<tr>{form_update}</tr>")
    body = ''.join(trs) or "<tr><td colspan='99' style='padding:8px;color:#9ca3af'>No rows</td></tr>"
    # Insert form
    ins_inputs = ''.join([f"<td style='padding:6px;border-top:1px solid #1f2937'><input name='val_{_html.escape(c['name'])}' placeholder='{_html.escape(c['name'])}' /></td>" for c in cols if not c.get('pk')])
    insert_form = (
        "<form method='POST' action='/admin/dbsafe/apply'><tr>"
        f"<input type='hidden' name='table' value='{_html.escape(name)}'>"
        + ins_inputs +
        "<td style='padding:6px;border-top:1px solid #1f2937'><button name='action' value='insert'>Insert</button></td>"
        "</tr></form>"
    )
    # Sidebar tables
    tables = _dbx_tables(cur)
    links = ''.join([f"<li><a href='/admin/dbsafe/table?name={_html.escape(t)}'>{_html.escape(t)}</a></li>" for t in tables])
    # Controls
    controls = (
        "<form method='GET' action='/admin/dbsafe/table' style='margin-bottom:10px'>"
        f"<input type='hidden' name='name' value='{_html.escape(name)}'>"
        f"<input name='search' placeholder='Search' value='{_html.escape(request.args.get('search') or '')}' /> "
        f"<input name='limit' type='number' min='1' max='200' value='{limit}' /> "
        f"<input name='offset' type='number' min='0' value='{offset}' /> "
        "<button type='submit'>Apply</button>"
        "</form>"
    )
    # Build an insert row with inputs for ALL columns, including id/key/etc.
    try:
        insert_cells = ''.join([
            (lambda cn: f"<td><input name='val_{_html.escape(cn)}' placeholder='{_html.escape(cn)}' /></td>")(c['name']) for c in cols
        ])
        insert_form = (
            "<tr>"
            "<form method='POST' action='/admin/dbsafe/apply'>"
            f"<input type='hidden' name='table' value='{_html.escape(name)}'>"
            "<input type='hidden' name='action' value='insert'>"
            + insert_cells +
            "<td><button type='submit'>Insert</button></td>"
            "</form>"
            "</tr>"
        )
    except Exception:
        insert_form = ""
    html = (
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>DB Safe Admin - { _html.escape(name) }</title>"
        "<style>body{font-family:system-ui,Segoe UI,Arial;margin:0;background:#0f172a;color:#e5e7eb} .wrap{display:flex;min-height:100vh} .side{width:260px;border-right:1px solid #1f2937;padding:12px;background:#111827} .main{flex:1;padding:16px} a{color:#93c5fd;text-decoration:none} ul{list-style:none;margin:0;padding:0} li{margin:6px 0} table{border-collapse:collapse;width:100%} thead th{position:sticky;top:0;background:#0b1327;z-index:1} tbody tr:nth-child(odd){background:#0e1730} tbody tr:nth-child(even){background:#0b1327} td,th{border-bottom:1px solid #1f2937} input,button{background:#0b1020;color:#e5e7eb;border:1px solid #374151;border-radius:6px;padding:6px} button{cursor:pointer} button:hover{filter:brightness(1.1)} .toolbar{display:flex;gap:8px;align-items:center;margin-bottom:12px} .toast{position:fixed;right:12px;top:12px;background:#1f2937;color:#e5e7eb;border:1px solid #374151;border-radius:8px;padding:10px 12px;z-index:9999;display:none}</style></head><body>"
        "<div class='wrap'>"
        f"<div class='side'><b>Tables</b><ul>{links}</ul><div style='margin-top:12px'><a href='/admin/dbsafe'>Home</a></div></div>"
        f"<div class='main'><div class='toolbar'><h3 style='margin:0'>{_html.escape(name)}</h3>"
        "<button onclick=\"saveAllForms()\">Save All</button>"
        f"<form method='POST' action='/admin/dbsafe/clear_table' style='display:inline;margin-left:8px'><input type='hidden' name='name' value='{_html.escape(name)}'><button onclick=\"return confirm('Clear this table?')\">Clear This Table</button></form>"
        f"<a href='/admin/dbsafe/export?name={_html.escape(name)}' style='margin-left:8px'><button type='button'>Export CSV</button></a>"
        f"<form method='POST' action='/admin/dbsafe/import' enctype='multipart/form-data' style='display:inline;margin-left:8px'><input type='hidden' name='name' value='{_html.escape(name)}'><input type='file' name='file' accept='.csv' required><button type='submit'>Import CSV</button></form>"
        "</div>" + controls + f"<div id='toast' class='toast'></div><table><thead><tr>{ths}<th>Actions</th></tr></thead><tbody>" + body + insert_form + "</tbody></table>"
        "</div></div><script>function showToast(t){try{const el=document.getElementById('toast'); el.textContent=t; el.style.display='block'; setTimeout(()=>{el.style.display='none'}, 1600);}catch(_){}} async function saveAllForms(){ const forms=[...document.querySelectorAll('tbody form[action=\"/admin/dbsafe/apply\"]')]; if(!forms.length){ showToast('Nothing to save'); return;} for(const f of forms){ const fd=new FormData(f); if(!fd.get('action')){ fd.set('action','update'); } try{ await fetch('/admin/dbsafe/apply',{method:'POST', body: fd}); }catch(e){} } location.reload(); }</script></body></html>"
    )
    return html

@app.route('/dbsafe/table')
def dbsafe_alias_table():
    if not _dbx_ok():
        return redirect('/dbx')
    # preserve query string (name, limit, offset, etc.)
    qs = (request.query_string or b'').decode('utf-8', 'ignore')
    return redirect('/admin/dbsafe/table' + (('?' + qs) if qs else ''))

@app.route('/admin/dbsafe/apply', methods=['POST'])
def admin_dbsafe_apply():
    if not _dbx_ok():
        return redirect('/dbx')
    name = (request.form.get('table') or '').strip()
    action = (request.form.get('action') or '').strip()
    if not name or action not in ('insert','update','delete'):
        return redirect('/admin/dbsafe')
    db = get_db(); cur = db.cursor()
    cols, pk, has_rowid = _dbx_schema(cur, name)
    # Build value dict from form
    values = {}
    for c in cols:
        k = f"val_{c['name']}"
        if k in request.form:
            values[c['name']] = request.form.get(k)
    new_dbx_after = False
    try:
        if action == 'insert':
            if values:
                ks = list(values.keys())
                cur.execute(f"INSERT INTO {name} ("+','.join(ks)+") VALUES ("+','.join(['?']*len(ks))+")", [values[k] for k in ks])
                if name == 'app_settings':
                    try:
                        if (values.get('key') == 'DBX_CODE') or (request.form.get('val_key') == 'DBX_CODE'):
                            new_dbx_after = True
                    except Exception:
                        pass
        elif action in ('update','delete'):
            where_sql = ''
            where_params = []
            # Prefer rowid if present
            rid = request.form.get('rid')
            if has_rowid and rid not in (None, ''):
                where_sql = 'rowid = ?'; where_params = [rid]
            elif pk:
                parts = []
                for k in pk:
                    parts.append(f"{k}=?"); where_params.append(request.form.get(f'pk_{k}'))
                where_sql = ' AND '.join(parts)
            else:
                return redirect(f"/admin/dbsafe/table?name={name}")
            if action == 'update':
                set_ks = [k for k in values.keys()]
                if set_ks:
                    cur.execute(f"UPDATE {name} SET " + ','.join([f"{k}=?" for k in set_ks]) + f" WHERE {where_sql}", [values[k] for k in set_ks] + where_params)
                    if name == 'app_settings':
                        try:
                            # If editing the DBX_CODE row and value provided, refresh cookie after commit
                            target_key = request.form.get('pk_key') or request.form.get('val_key')
                            if (target_key == 'DBX_CODE') and ('value' in values or 'val_value' in request.form):
                                new_dbx_after = True
                        except Exception:
                            pass
            else:
                cur.execute(f"DELETE FROM {name} WHERE {where_sql}", where_params)
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    # Build redirect response; if DBX_CODE changed, refresh dbxok cookie so user stays authorized
    from flask import make_response
    resp = make_response(redirect(f"/admin/dbsafe/table?name={name}"))
    if new_dbx_after:
        try:
            resp.set_cookie('dbxok', _make_dbxok_cookie(), max_age=3600, secure=True, httponly=True, samesite='Lax', path='/')
        except Exception:
            pass
    return resp

@app.route('/admin/dbsafe/clear_all', methods=['POST'])
def admin_dbsafe_clear_all():
    if not _dbx_ok():
        return jsonify({'error':'forbidden'}), 403
    try:
        db = get_db(); cur = db.cursor()
        tables = _dbx_tables(cur)
        protected = {'app_settings'}
        cleared = []
        skipped = []
        try:
            cur.execute('BEGIN')
        except Exception:
            pass
        for t in tables:
            if t in protected:
                skipped.append(t)
                continue
            try:
                cur.execute(f'DELETE FROM {t}')
                # Reset AUTOINCREMENT sequence if present
                try:
                    cur.execute('DELETE FROM sqlite_sequence WHERE name=?', (t,))
                except Exception:
                    pass
                cleared.append(t)
            except Exception:
                # Skip tables we cannot delete from (e.g., views)
                skipped.append(t)
        try:
            db.commit()
        except Exception:
            pass
        try:
            actor = session.get('username') or ''
            details = {'cleared': cleared, 'skipped': skipped}
            try:
                details['audit_ids_reset'] = bool('admin_audit' in cleared)
            except Exception:
                pass
            log_admin_action(actor, 'dbsafe_clear_all', details=details)
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        try:
            get_db().rollback()
        except Exception:
            pass
        return jsonify({'error': str(e)}), 500
    return redirect(f"/admin/dbsafe/table?name={name}")

@app.route('/admin/dbsafe/clear_table', methods=['POST'])
def admin_dbsafe_clear_table():
    if not _dbx_ok():
        return redirect('/dbx')
    name = (request.form.get('name') or '').strip()
    if not name:
        return redirect('/admin/dbsafe')
    try:
        db = get_db(); cur = db.cursor()
        cur.execute(f'DELETE FROM {name}')
        # Reset AUTOINCREMENT sequence if present
        try:
            cur.execute('DELETE FROM sqlite_sequence WHERE name=?', (name,))
        except Exception:
            pass
        db.commit()
    except Exception:
        try: get_db().rollback()
        except Exception: pass
    try:
        actor = session.get('username') or ''
        det = {}
        try:
            det['audit_ids_reset'] = bool(name == 'admin_audit')
        except Exception:
            pass
        log_admin_action(actor, 'dbsafe_clear_table', target=name, details=det)
    except Exception:
        pass
    return redirect(f"/admin/dbsafe/table?name={name}")

@app.route('/admin/dbsafe/export')
def admin_dbsafe_export():
    if not _dbx_ok():
        return redirect('/dbx')
    name = (request.args.get('name') or '').strip()
    if not name:
        return redirect('/admin/dbsafe')
    # Use a fresh connection without detect_types to avoid sqlite converters
    # raising unpack errors on non-standard timestamps
    try:
        tmp_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    except Exception:
        tmp_conn = get_db()
    try:
        tmp_conn.row_factory = None
    except Exception:
        pass
    cur = tmp_conn.cursor()
    try:
        cur.execute(f'SELECT * FROM {name}')
        rows = cur.fetchall()
        desc = cur.description or []
        headers = [d[0] for d in desc]
        index_map = {h: i for i, h in enumerate(headers)}
        import io, csv
        buf = io.StringIO()
        w = csv.writer(buf)
        if headers:
            w.writerow(headers)
        from datetime import datetime as _dt
        for r in rows:
            out = []
            for h in headers:
                try:
                    v = r[index_map[h]]
                except Exception:
                    v = None
                # serialize bytes
                try:
                    if isinstance(v, (bytes, bytearray, memoryview)):
                        v = _b64u(bytes(v))
                except Exception:
                    pass
                # serialize datetimes
                try:
                    if isinstance(v, _dt):
                        v = to_ny_time(v)
                except Exception:
                    pass
                out.append(v)
            w.writerow(out)
        data = buf.getvalue().encode('utf-8')
        from flask import make_response
        resp = make_response(data)
        resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
        resp.headers['Content-Disposition'] = f"attachment; filename={name}.csv"
        return resp
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        try:
            if tmp_conn is not get_db():
                tmp_conn.close()
        except Exception:
            pass

@app.route('/admin/dbsafe/import', methods=['POST'])
def admin_dbsafe_import():
    if not _dbx_ok():
        return redirect('/dbx')
    name = (request.form.get('name') or '').strip()
    f = request.files.get('file')
    if not name or not f:
        return redirect('/admin/dbsafe')
    try:
        raw = f.read()
        import io, csv
        txt = raw.decode('utf-8-sig', errors='replace')
        reader = csv.DictReader(io.StringIO(txt))
        db = get_db(); cur = db.cursor()
        # determine table columns
        cols, pk, has_rowid = _dbx_schema(cur, name)
        table_cols = [c['name'] for c in cols]
        try:
            cur.execute('BEGIN')
        except Exception:
            pass
        count = 0
        for row in reader:
            vals = {k: v for k, v in (row or {}).items() if k in table_cols}
            if not vals:
                continue
            # normalize empties and 'NULL' to None, trim whitespace
            for k in list(vals.keys()):
                v = vals[k]
                if isinstance(v, str):
                    v2 = v.strip()
                    if v2 == '' or v2.upper() == 'NULL':
                        vals[k] = None
                    else:
                        vals[k] = v2
            # if id provided but blank/None, let sqlite autogenerate by removing it
            if 'id' in vals and (vals['id'] is None or str(vals['id']).strip() == ''):
                vals.pop('id', None)
            ks = list(vals.keys())
            vs = [vals[k] for k in ks]
            # Prefer ON CONFLICT upsert when table has a PK
            if pk:
                non_pk = [c for c in ks if c not in pk]
                if non_pk:
                    try:
                        set_sql = ', '.join([f"{c}=excluded.{c}" for c in non_pk])
                        conflict_sql = ','.join(pk)
                        cur.execute(
                            f"INSERT INTO {name} (" + ','.join(ks) + ") VALUES (" + ','.join(['?']*len(ks)) + ") "
                            f"ON CONFLICT(" + conflict_sql + ") DO UPDATE SET " + set_sql,
                            vs
                        )
                    except Exception:
                        # Fallback to REPLACE if SQLite is older
                        cur.execute(
                            f"INSERT OR REPLACE INTO {name} (" + ','.join(ks) + ") VALUES (" + ','.join(['?']*len(ks)) + ")",
                            vs
                        )
                else:
                    # Only PK columns present -> ensure row exists or noop
                    try:
                        placeholders = ','.join(['?']*len(ks))
                        cur.execute(f"INSERT OR IGNORE INTO {name} (" + ','.join(ks) + ") VALUES (" + placeholders + ")", vs)
                    except Exception:
                        pass
            else:
                cur.execute(
                    f"INSERT OR REPLACE INTO {name} (" + ','.join(ks) + ") VALUES (" + ','.join(['?']*len(ks)) + ")",
                    vs
                )
            count += 1
        db.commit()
        return redirect(f"/admin/dbsafe/table?name={name}")
    except Exception as e:
        try: get_db().rollback()
        except Exception: pass
        return jsonify({'error': str(e)}), 500

@app.route('/api/dbx/unlock', methods=['POST'])
def api_dbx_unlock():
    try:
        data = request.get_json(silent=True) or {}
        code = (data.get('code') or '').strip()
        if not code:
            return jsonify({'error':'missing'}), 400
        cur_code = _get_dbx_code()
        if cur_code and code and secrets.compare_digest(cur_code.upper(), code.upper()):
            from flask import make_response
            resp = make_response(jsonify({'ok': True}))
            resp.set_cookie('dbxok', _make_dbxok_cookie(), max_age=3600, secure=True, httponly=True, samesite='Lax', path='/')
            return resp
        return jsonify({'error':'invalid'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dbx/app')
def admin_db_new_ui():
    if not _dbx_ok():
        return redirect('/dbx')
    return redirect('/admin/dbsafe')

@app.route('/api/dbx/code')
def api_dbx_code():
    u = session.get('username')
    if not is_superadmin(u):
        return jsonify({'error': 'forbidden'}), 403
    return jsonify({'code': _get_dbx_code()})

def init_db():
    db = get_db()
    cur = db.cursor()
    # Users table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            avatar TEXT,
            theme TEXT DEFAULT 'light',
            bio TEXT,
            status TEXT,
            language TEXT DEFAULT 'en',
            allow_dm_nonfriends INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    
    # Add last_seen column if it doesn't exist
    try:
        cur.execute("ALTER TABLE users ADD COLUMN last_seen TIMESTAMP DEFAULT NULL")
        db.commit()
    except sqlite3.OperationalError:
        # Column already exists
        pass
    # Messages table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            text TEXT,
            attachment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    # Banned users table
    cur.execute("CREATE TABLE IF NOT EXISTS banned_users (username TEXT PRIMARY KEY)")
    cur.execute("CREATE TABLE IF NOT EXISTS banned_ips (ip_address TEXT PRIMARY KEY)")
    # Reactions table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS message_reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            message_type TEXT NOT NULL,
            username TEXT NOT NULL,
            emoji TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(message_id, message_type, username, emoji)
        )
        """
    )
    # Direct messages table (1:1)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS direct_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user TEXT NOT NULL,
            text TEXT,
            attachment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    # Group DMs (threads)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS group_threads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS group_members (
            thread_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (thread_id, username)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS group_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            thread_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            text TEXT,
            attachment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            edited INTEGER DEFAULT 0
        )
        """
    )
    # Optional reply_to columns (id of the message being replied to)
    try:
        cur.execute("ALTER TABLE messages ADD COLUMN reply_to INTEGER")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE direct_messages ADD COLUMN reply_to INTEGER")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE group_messages ADD COLUMN reply_to INTEGER")
    except Exception:
        pass
    db.commit()
    # Admin audit log (actor, action, optional target, optional details JSON)
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        db.commit()
    except Exception:
        pass
    # Attempt to add optional columns for profiles (ignore if already exist)
    try:
        cur.execute("ALTER TABLE users ADD COLUMN avatar TEXT")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN theme TEXT")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN bio TEXT")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN status TEXT")  # 'online' | 'idle' | 'dnd'
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN language TEXT DEFAULT 'en'")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN allow_dm_nonfriends INTEGER")
    except Exception:
        pass
    # friends feature removed: friendships table no longer created
    try:
        cur.execute("CREATE TABLE IF NOT EXISTS group_invites (token TEXT PRIMARY KEY, thread_id INTEGER NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL)")
    except Exception:
        pass
    try:
        cur.execute("CREATE TABLE IF NOT EXISTS group_bans (thread_id INTEGER NOT NULL, username TEXT NOT NULL, PRIMARY KEY(thread_id, username))")
    except Exception:
        pass
    try:
        cur.execute("CREATE TABLE IF NOT EXISTS group_timeouts (thread_id INTEGER NOT NULL, username TEXT NOT NULL, until_ts INTEGER NOT NULL, PRIMARY KEY(thread_id, username))")
    except Exception:
        pass
    # Device logs (username, client_id, public_ip, private_ips JSON, mdns JSON, remote_port, user_agent, created_at)
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS device_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                client_id TEXT NOT NULL,
                public_ip TEXT,
                private_ips TEXT,
                mdns TEXT,
                remote_port TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
    except Exception:
        pass
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS device_bans (
                client_id TEXT PRIMARY KEY,
                username TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
    except Exception:
        pass
    # Optional columns for IP/immunity; ignore if present
    try:
        cur.execute("ALTER TABLE users ADD COLUMN private_ip TEXT")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN public_ip TEXT")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN immune INTEGER DEFAULT 0")
    except Exception:
        pass
    # Username change history for rollback on crash/timeout
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS username_change_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                old_username TEXT NOT NULL,
                new_username TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                rolled_back INTEGER DEFAULT 0
            )
            """
        )
        db.commit()
    except Exception:
        pass

    # Reports table for user reporting system
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_type TEXT NOT NULL,  -- 'message' or 'user'
                target_id TEXT,             -- message_id for messages, username for users
                target_username TEXT,       -- username of reported user
                reason TEXT NOT NULL,       -- reason code (spam, harassment, etc.)
                details TEXT,               -- optional additional details
                reporter_username TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending',  -- pending, reviewed, resolved, dismissed
                admin_notes TEXT,
                resolved_at TIMESTAMP,
                resolved_by TEXT
            )
            """
        )
        db.commit()
    except Exception:
        pass

    db.commit()

    # Create file_uploads table
    try:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS file_uploads (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                uploader TEXT NOT NULL,
                upload_time TEXT NOT NULL,
                size INTEGER NOT NULL,
                FOREIGN KEY (uploader) REFERENCES users(username) ON DELETE CASCADE
            )
        ''')
    except Exception:
        pass
    
    # Create channels table
    try:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                topic TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_private INTEGER DEFAULT 0,
                FOREIGN KEY (created_by) REFERENCES users(username) ON DELETE SET NULL
            )
        ''')
    except Exception:
        pass
    
    # Create channel_members table
    try:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS channel_members (
                channel_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                joined_at TEXT NOT NULL,
                last_read_message_id TEXT,
                is_admin INTEGER DEFAULT 0,
                PRIMARY KEY (channel_id, user_id),
                FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
    except Exception:
        pass
    
    # Create default channels if they don't exist
    try:
        default_channels = [
            ('general', 'General discussion'),
            ('random', 'Random chat'),
            ('help', 'Get help here')
        ]
        
        for name, desc in default_channels:
            cur.execute('SELECT id FROM channels WHERE name = ?', (name,))
            if not cur.fetchone():
                channel_id = str(uuid.uuid4())
                cur.execute('''
                    INSERT INTO channels (id, name, description, created_by, created_at)
                    VALUES (?, ?, ?, 'system', datetime('now'))
                ''', (channel_id, name, desc))
    except Exception:
        pass
    
    db.commit()

def recover_failed_username_changes():
    """Recover from failed username changes by rolling back to old username if new username is invalid"""
    try:
        db = get_db(); cur = db.cursor()
        # Find recent username changes that haven't been rolled back and check if they're valid
        cur.execute('''
            SELECT id, user_id, old_username, new_username
            FROM username_change_history
            WHERE rolled_back = 0
            AND created_at > datetime('now', '-1 hour')
            ORDER BY id DESC
        ''')
        rows = cur.fetchall()
        for row in rows:
            hist_id = row[0] if not isinstance(row, sqlite3.Row) else row['id']
            user_id = row[1] if not isinstance(row, sqlite3.Row) else row['user_id']
            old_username = row[2] if not isinstance(row, sqlite3.Row) else row['old_username']
            new_username = row[3] if not isinstance(row, sqlite3.Row) else row['new_username']

            # Check if new username is too long or invalid
            if len(new_username) > 20:
                # Rollback to old username
                try:
                    cur.execute('UPDATE users SET username=? WHERE id=?', (old_username, user_id))
                    cur.execute('UPDATE messages SET username=? WHERE username=?', (old_username, new_username))
                    cur.execute('UPDATE direct_messages SET from_user=? WHERE from_user=?', (old_username, new_username))
                    cur.execute('UPDATE direct_messages SET to_user=? WHERE to_user=?', (old_username, new_username))
                    cur.execute('UPDATE group_members SET username=? WHERE username=?', (old_username, new_username))
                    cur.execute('UPDATE group_threads SET created_by=? WHERE created_by=?', (old_username, new_username))
                    cur.execute('UPDATE username_change_history SET rolled_back=1 WHERE id=?', (hist_id,))
                    db.commit()
                except Exception:
                    try:
                        db.rollback()
                    except Exception:
                        pass
    except Exception:
        pass

def log_admin_action(actor, action, target='', details=None):
    try:
        db = get_db(); cur = db.cursor()
        payload = None
        if details is not None:
            try:
                payload = json.dumps(details, ensure_ascii=False)
            except Exception:
                try:
                    payload = str(details)
                except Exception:
                    payload = None
        cur.execute('INSERT INTO admin_audit(actor, action, target, details) VALUES(?,?,?,?)', (actor or '', action or '', target or '', payload))
        db.commit()
    except Exception:
        pass

# Authentication helpers
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def is_ip_banned(ip_address):
    # Never ban loopback to avoid locking out all local users/admin
    if ip_address in ("127.0.0.1", "::1"):
        return False
    if ip_address in banned_ips:
        return True

"""Overseer for superadmin IP bans is stored in DB by user_id so renames do not break it."""
IPBAN_OVERSEER_USER_ID = None  # cached in-memory

def _ensure_settings_table(cur):
    try:
        cur.execute('CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)')
    except Exception:
        pass

def _get_overseer_user_id():
    global IPBAN_OVERSEER_USER_ID
    if IPBAN_OVERSEER_USER_ID is not None:
        return IPBAN_OVERSEER_USER_ID
    try:
        db = get_db(); cur = db.cursor()
        _ensure_settings_table(cur)
        cur.execute('SELECT value FROM app_settings WHERE key=?', ('ipban_overseer_user_id',))
        row = cur.fetchone()
        if row and row[0]:
            try:
                IPBAN_OVERSEER_USER_ID = int(row[0])
            except Exception:
                IPBAN_OVERSEER_USER_ID = None
        return IPBAN_OVERSEER_USER_ID
    except Exception:
        return None

def _set_overseer_by_username(username: str) -> bool:
    global IPBAN_OVERSEER_USER_ID
    if not username:
        return False
    try:
        db = get_db(); cur = db.cursor()
        _ensure_settings_table(cur)
        cur.execute('SELECT id FROM users WHERE username=?', (username,))
        r = cur.fetchone()
        if not r:
            return False
        uid = int(r[0])
        cur.execute('INSERT INTO app_settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                    ('ipban_overseer_user_id', str(uid)))
        db.commit()
        IPBAN_OVERSEER_USER_ID = uid
        return True
    except Exception:
        return False

def _issuer_user_id(issuer: str):
    if not issuer:
        return None
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT id FROM users WHERE username=?', (issuer,))
        r = cur.fetchone()
        return int(r[0]) if r else None
    except Exception:
        return None

def _can_ipban_superadmin_ips(issuer: str) -> bool:
    overseer_id = _get_overseer_user_id()
    if overseer_id is None:
        return False
    return _issuer_user_id(issuer) == overseer_id

def _can_unban(issuer: str, target: str) -> bool:
    # Mirror ban rules
    if not issuer or not target:
        return False
    if issuer not in ADMINS and issuer not in SUPERADMINS:
        return False
    if target in SUPERADMINS:
        return False
    if issuer in ADMINS and target in ADMINS:
        return False
    return True

def is_superadmin(username=None):
    if username is None:
        username = session.get("username")
    return username in SUPERADMINS

def _can_ban(issuer: str, target: str) -> bool:
    if not issuer or not target:
        return False
    if issuer not in ADMINS and issuer not in SUPERADMINS:
        return False
    if target in SUPERADMINS:
        return False
    # Admins cannot ban other admins
    if issuer in ADMINS and target in ADMINS:
        return False
    return True

def is_banned(username):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT 1 FROM banned_users WHERE username=?", (username,))
    return cur.fetchone() is not None

def load_banned_ips():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT ip_address FROM banned_ips")
    dirty = False
    for row in cur.fetchall():
        ip = row[0]
        if ip in ("127.0.0.1", "::1"):
            # Clean up accidental loopback bans
            cur.execute("DELETE FROM banned_ips WHERE ip_address=?", (ip,))
            dirty = True
            continue
        banned_ips.add(ip)
    if dirty:
        try:
            db.commit()
        except Exception:
            pass

def _is_private_ip(ip: str) -> bool:
    try:
        if not ip:
            return False
        ip = ip.strip()
        if ip.startswith('127.') or ip == '::1':
            return True
        if ip.startswith('10.'):
            return True
        if ip.startswith('192.168.'):
            return True
        if ip.startswith('172.'):
            try:
                second = int(ip.split('.')[1])
                return 16 <= second <= 31
            except Exception:
                return False
        # IPv6 ULA fc00::/7
        if ':' in ip:
            try:
                h = ip.lower()
                return h.startswith('fc') or h.startswith('fd') or h == '::1'
            except Exception:
                return False
        return False
    except Exception:
        return False

def _is_loopback_ip(ip: str) -> bool:
    try:
        if not ip:
            return False
        ip = ip.strip()
        return ip.startswith('127.') or ip == '::1'
    except Exception:
        return False

def _first_rfc1918(ips) -> str:
    try:
        for p in ips or []:
            if isinstance(p, str) and p.strip() and _is_private_ip(p) and not _is_loopback_ip(p):
                return p.strip()
    except Exception:
        pass
    return None

def get_client_ip():
    try:
        xff = request.headers.get('X-Forwarded-For', '')
        if xff:
            parts = [p.strip() for p in xff.split(',') if p.strip()]
            # Prefer private/local IPs if present (first match)
            for p in parts:
                if _is_private_ip(p):
                    return p
            # Otherwise take first valid public IP
            for p in parts:
                if not _is_private_ip(p):
                    return p
            # Fallback to last entry
            if parts:
                return parts[-1]
        xri = request.headers.get('X-Real-IP')
        if xri:
            return xri
        return request.remote_addr
    except Exception:
        return request.remote_addr

def detect_client_ips():
    """Return (private_ip_or_None, public_ip_or_None) from headers safely."""
    try:
        private_ip = None
        public_ip = None
        loopback_ip = None
        xff = request.headers.get('X-Forwarded-For', '')
        if xff:
            parts = [p.strip() for p in xff.split(',') if p.strip()]
            for p in parts:
                if _is_private_ip(p):
                    if p in ("127.0.0.1", "::1"):
                        loopback_ip = loopback_ip or p
                    else:
                        private_ip = private_ip or p
                else:
                    public_ip = public_ip or p
        xri = (request.headers.get('X-Real-IP') or '').strip()
        if xri:
            if _is_private_ip(xri):
                if xri in ("127.0.0.1", "::1"):
                    loopback_ip = loopback_ip or xri
                else:
                    private_ip = private_ip or xri
            else:
                public_ip = public_ip or xri
        ra = (request.remote_addr or '').strip()
        if ra:
            if _is_private_ip(ra):
                if ra in ("127.0.0.1", "::1"):
                    loopback_ip = loopback_ip or ra
                else:
                    private_ip = private_ip or ra
            else:
                public_ip = public_ip or ra
        # Only use loopback as private if no better private was found and there is no public
        if not private_ip and not public_ip and loopback_ip:
            private_ip = loopback_ip
        return (private_ip, public_ip)
    except Exception:
        return (None, request.remote_addr)

def _user_immune(username: str) -> bool:
    try:
        if username in SUPERADMINS:
            return True
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT COALESCE(immune,0) FROM users WHERE username=?', (username,))
        r = cur.fetchone()
        return bool((r[0] if r and not isinstance(r, sqlite3.Row) else (r['COALESCE(immune,0)'] if r else 0)))
    except Exception:
        return False

def _update_user_ips(username: str, private_ip: str, public_ip: str):
    try:
        db = get_db(); cur = db.cursor()
        try:
            cur.execute('UPDATE users SET private_ip=?, public_ip=?, immune=CASE WHEN ? IN (SELECT username FROM users WHERE username IN (%s)) THEN 1 ELSE COALESCE(immune,0) END WHERE username=?' % (','.join('?'*len(SUPERADMINS)) if SUPERADMINS else "''"),
                        (private_ip, public_ip, username, *list(SUPERADMINS), username))
        except Exception:
            # Fallback: set columns if exist
            try:
                cur.execute('UPDATE users SET private_ip=?, public_ip=? WHERE username=?', (private_ip, public_ip, username))
            except Exception:
                pass
        db.commit()
    except Exception:
        pass
    try:
        user_ips[username] = { 'private': private_ip, 'public': public_ip, 'immune': _user_immune(username) }
    except Exception:
        user_ips[username] = { 'private': private_ip, 'public': public_ip, 'immune': False }

def _is_ip_blocked_for(username: str, private_ip: str, public_ip: str) -> bool:
    try:
        if username in SUPERADMINS:
            # Superadmins bypass IP bans silently to avoid log spam
            return False
        if _user_immune(username):
            return False
        # Prefer private IP ban
        if private_ip and is_ip_banned(private_ip):
            return True
        # Fallback to public IP ban
        if public_ip and is_ip_banned(public_ip):
            return True
        return False
    except Exception:
        return False

def safe_save_file(file, folder):
    if not file or not file.filename:
        return None

    os.makedirs(folder, exist_ok=True)

    prefix = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    filename = secure_filename(file.filename)
    saved = f"{prefix}_{filename}"

    file.save(os.path.join(folder, saved))
    return saved


def user_exists(username: str) -> bool:
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT 1 FROM users WHERE username=?', (username,))
        return cur.fetchone() is not None
    except Exception:
        return False

@app.route('/api/admin/delete_user', methods=['POST'])
def api_admin_delete_user():
    me = session.get('username')
    if not me or not is_superadmin(me):
        return jsonify({'error': 'Forbidden'}), 403
    try:
        data = request.get_json(silent=True) or {}
        target = (data.get('username') or '').strip()
        if not target:
            return jsonify({'error': 'Username required'}), 400
        if target in SUPERADMINS:
            try:
                log_admin_action(me, 'delete_user_blocked', target=target)
            except Exception:
                pass
            return jsonify({'error': 'Cannot delete another superadmin'}), 400
        db = get_db(); cur = db.cursor()
        # Find user id
        cur.execute('SELECT id FROM users WHERE username=?', (target,))
        row = cur.fetchone()
        if not row:
            return jsonify({'ok': True, 'note': 'User not found (already deleted)'}), 200
        uid = row['id']
        # Remove memberships
        try:
            cur.execute('DELETE FROM group_members WHERE username=?', (target,))
        except Exception:
            pass
        # Remove DMs involving user
        try:
            cur.execute('DELETE FROM direct_messages WHERE from_user=? OR to_user=?', (target, target))
        except Exception:
            pass
        # Remove messages by user (public and group)
        try:
            cur.execute('DELETE FROM messages WHERE user_id=?', (uid,))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM group_messages WHERE username=?', (target,))
        except Exception:
            pass
        # Finally delete user
        cur.execute('DELETE FROM users WHERE id=?', (uid,))
        db.commit()
        # Disconnect live sockets
        for sid, uname in list(connected_sockets.items()):
            if uname == target:
                try:
                    socketio.server.disconnect(sid)
                except Exception:
                    pass
                try:
                    del connected_sockets[sid]
                except Exception:
                    pass
        try:
            online_users.pop(target, None)
            user_ips.pop(target, None)
        except Exception:
            pass
        # Broadcast updates
        try:
            socketio.emit('user_list_refresh', {'deleted': target})
            socketio.emit('system_message', store_system_message(f"{target} was deleted by {me}"))
        except Exception:
            pass
        try:
            log_admin_action(me, 'delete_user', target=target)
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/gdm/transfer', methods=['POST'])
@login_required
def api_gdm_transfer():
    me = session.get('username')
    # Toggle gate
    try:
        if get_setting('GD_TRANSFER_OWNERSHIP','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    new_owner = sanitize_username((data.get('new_owner') or '').strip())
    if not tid or not new_owner:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'not found'}), 404
    owner = row[0] if not isinstance(row, sqlite3.Row) else row['created_by']
    if not (me == owner or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    # Ensure new owner exists
    cur.execute('SELECT 1 FROM users WHERE username=? LIMIT 1', (new_owner,))
    if not cur.fetchone():
        return jsonify({'error':'user not found'}), 404
    # Make sure new owner is a member
    try:
        cur.execute('INSERT OR IGNORE INTO group_members(thread_id, username) VALUES (?,?)', (tid, new_owner))
    except Exception:
        pass
    cur.execute('UPDATE group_threads SET created_by=? WHERE id=?', (new_owner, tid))
    db.commit()
    # notify all members to refresh
    try:
        cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
        members = [r[0] for r in cur.fetchall()]
        for u in members:
            socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{u}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/account/delete', methods=['POST'])
@login_required
def api_account_delete():
    me = session.get('username')
    uid = session.get('user_id')
    if not me or not uid:
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    password = (data.get('password') or '').strip()
    if not password:
        return jsonify({'error': 'password required'}), 400
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT id, password_hash FROM users WHERE id=?', (uid,))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'not found'}), 404
        if not check_password_hash(row['password_hash'], password):
            return jsonify({'error': 'invalid password'}), 400
        # Remove memberships and content authored by this user
        try:
            cur.execute('DELETE FROM group_members WHERE username=?', (me,))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM direct_messages WHERE from_user=? OR to_user=?', (me, me))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM messages WHERE user_id=?', (uid,))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM group_messages WHERE username=?', (me,))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM device_logs WHERE username=?', (me,))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM device_bans WHERE username=?', (me,))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM banned_users WHERE username=?', (me,))
        except Exception:
            pass
        try:
            cur.execute('DELETE FROM users WHERE id=?', (uid,))
        except Exception:
            pass
        try:
            db.commit()
        except Exception:
            pass
        # Disconnect sockets
        try:
            for sid, uname in list(connected_sockets.items()):
                if uname == me:
                    try: socketio.server.disconnect(sid)
                    except Exception: pass
        except Exception:
            pass
        # Clear session last
        try:
            session.clear()
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# True Ban: ban user + device + IPs in one action
@app.route('/api/admin/true_ban', methods=['POST'])
@login_required
def api_admin_true_ban():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    user = sanitize_username((data.get('user') or '').strip())
    client_id = (data.get('client_id') or '').strip()
    if not user:
        return jsonify({'error': 'bad params'}), 400
    if not _can_ban(me, user):
        return jsonify({'error':'not allowed'}), 403
    db = get_db(); cur = db.cursor()
    # Ban user
    try:
        cur.execute('INSERT OR IGNORE INTO banned_users(username) VALUES(?)', (user,))
    except Exception:
        pass
    # Resolve client id if missing
    if not client_id:
        try:
            cur.execute('SELECT client_id FROM device_logs WHERE username=? AND client_id IS NOT NULL ORDER BY created_at DESC LIMIT 1', (user,))
            r = cur.fetchone()
            if r:
                client_id = r[0] if not isinstance(r, sqlite3.Row) else r['client_id']
        except Exception:
            client_id = ''
    # Ban device
    try:
        if client_id:
            cur.execute('INSERT OR IGNORE INTO device_bans(client_id, username) VALUES(?,?)', (client_id, user))
    except Exception:
        pass
    # Ban IPs (private+public best-effort)
    ips_to_ban = set()
    try:
        cur.execute('SELECT private_ip, public_ip FROM device_logs WHERE username=? ORDER BY created_at DESC LIMIT 1', (user,))
        r = cur.fetchone()
        if r:
            priv = r[0] if not isinstance(r, sqlite3.Row) else r['private_ip']
            pub = r[1] if not isinstance(r, sqlite3.Row) else r['public_ip']
            if priv: ips_to_ban.add(priv)
            if pub and not _is_loopback_ip(pub): ips_to_ban.add(pub)
    except Exception:
        pass
    try:
        info = user_ips.get(user) if isinstance(user_ips.get(user), dict) else {}
        if info.get('private'): ips_to_ban.add(info.get('private'))
        if info.get('public') and not _is_loopback_ip(info.get('public')): ips_to_ban.add(info.get('public'))
    except Exception:
        pass
    for ip in ips_to_ban:
        try:
            cur.execute('INSERT OR IGNORE INTO banned_ips(ip_address) VALUES(?)', (ip,))
        except Exception:
            pass
    try: db.commit()
    except Exception: pass
    # Disconnect active sockets of the user
    for sid, uname in list(connected_sockets.items()):
        if uname == user:
            try: socketio.server.disconnect(sid)
            except Exception: pass
    return jsonify({'ok': True, 'banned_ips': list(ips_to_ban), 'client_id': client_id})

# True Unban: remove user ban + device ban(s) + relevant IPs
@app.route('/api/admin/true_unban', methods=['POST'])
@login_required
def api_admin_true_unban():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    user = sanitize_username((data.get('user') or '').strip())
    client_id = (data.get('client_id') or '').strip()
    if not user:
        return jsonify({'error': 'bad params'}), 400
    if not _can_unban(me, user):
        return jsonify({'error':'not allowed'}), 403
    db = get_db(); cur = db.cursor()
    # Remove user ban
    try:
        cur.execute('DELETE FROM banned_users WHERE username=?', (user,))
    except Exception:
        pass
    # Determine client ids to clear
    cids = set()
    if client_id: cids.add(client_id)
    try:
        cur.execute('SELECT DISTINCT client_id FROM device_logs WHERE username=? AND client_id IS NOT NULL ORDER BY created_at DESC LIMIT 3', (user,))
        for r in cur.fetchall():
            cids.add(r[0] if not isinstance(r, sqlite3.Row) else r['client_id'])
    except Exception:
        pass
    for cid in cids:
        try:
            cur.execute('DELETE FROM device_bans WHERE client_id=?', (cid,))
        except Exception:
            pass
    # Remove IP bans best-effort (latest known + in-memory)
    ips_to_unban = set()
    try:
        cur.execute('SELECT private_ip, public_ip FROM device_logs WHERE username=? ORDER BY created_at DESC LIMIT 3', (user,))
        for r in cur.fetchall():
            priv = r[0] if not isinstance(r, sqlite3.Row) else r['private_ip']
            pub = r[1] if not isinstance(r, sqlite3.Row) else r['public_ip']
            if priv: ips_to_unban.add(priv)
            if pub: ips_to_unban.add(pub)
    except Exception:
        pass
    try:
        info = user_ips.get(user) if isinstance(user_ips.get(user), dict) else {}
        if info.get('private'): ips_to_unban.add(info.get('private'))
        if info.get('public'): ips_to_unban.add(info.get('public'))
    except Exception:
        pass
    for ip in ips_to_unban:
        try:
            cur.execute('DELETE FROM banned_ips WHERE ip_address=?', (ip,))
        except Exception:
            pass
    try: db.commit()
    except Exception: pass
    return jsonify({'ok': True, 'unbanned_ips': list(ips_to_unban), 'cleared_client_ids': list(cids)})

# Device logging endpoint (expects JSON with client_id, private_ips, mdns)
@app.route('/api/device_log', methods=['POST'])
@login_required
def api_device_log():
    try:
        u = session.get('username') or ''
        if not u:
            return jsonify({'error': 'forbidden'}), 403
        data = request.get_json(silent=True) or {}
        client_id = (data.get('client_id') or '').strip()
        private_ips = data.get('private_ips') or []
        mdns = data.get('mdns') or []
        if not isinstance(private_ips, list):
            private_ips = []
        if not isinstance(mdns, list):
            mdns = []
        # Try to record the real public IP, not loopback
        try:
            _priv, _pub = detect_client_ips()
        except Exception:
            _priv, _pub = (None, None)
        pub_ip = _pub if (_pub and not _is_loopback_ip(_pub)) else (request.headers.get('CF-Connecting-IP') or request.headers.get('X-Real-IP') or request.remote_addr)
        if _is_loopback_ip(pub_ip or ''):
            pub_ip = ''
        rport = str(request.environ.get('REMOTE_PORT') or '')
        ua = request.headers.get('User-Agent') or ''
        try:
            db = get_db(); cur = db.cursor()
            cur.execute(
                'INSERT INTO device_logs(username, client_id, public_ip, private_ips, mdns, remote_port, user_agent) VALUES(?,?,?,?,?,?,?)',
                (u, client_id, pub_ip, json.dumps(private_ips), json.dumps(mdns), rport, ua)
            )
            db.commit()
        except Exception:
            pass
        # If user is banned, also ban this device id to follow the account (toggleable)
        try:
            if u and is_banned(u):
                db = get_db(); cur = db.cursor()
                if client_id and get_setting('SEC_DEVICE_BAN_ON_LOGIN','1')=='1':
                    cur.execute('INSERT OR IGNORE INTO device_bans(client_id, username) VALUES(?,?)', (client_id, u))
                # Strict associated ban: also ban public IP if toggle enabled
                try:
                    if (_pub and not _is_loopback_ip(_pub)) and get_setting('SEC_STRICT_ASSOCIATED_BAN','0')=='1':
                        cur.execute('INSERT OR IGNORE INTO banned_ips(ip_address) VALUES(?)', (_pub,))
                except Exception:
                    pass
                db.commit()
        except Exception:
            pass
        # Update in-memory private/public for admin dashboard
        try:
            info = user_ips.get(u) if isinstance(user_ips.get(u), dict) else {}
            first_private = next((p for p in private_ips if isinstance(p, str) and p), None)
            merged = {
                'private': first_private or info.get('private'),
                'public': (info.get('public') or pub_ip),
                'immune': info.get('immune', _user_immune(u)),
                'client_id': client_id or info.get('client_id')
            }
            user_ips[u] = merged
        except Exception:
            pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Simple logs view for current user
@app.route('/logs')
@login_required
def view_logs():
    try:
        u = session.get('username')
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT id, client_id, public_ip, private_ips, mdns, remote_port, user_agent, created_at FROM device_logs WHERE username=? ORDER BY created_at DESC', (u,))
        rows = cur.fetchall() or []
        out = [
            '<html><body><h3>Your Devices</h3><table border="1" cellspacing="0" cellpadding="4">',
            '<tr><th>When</th><th>Client ID</th><th>Public IP</th><th>Private IPs</th><th>mDNS</th><th>Remote Port</th><th>User Agent</th></tr>'
        ]
        for r in rows:
            when = r['created_at'] if isinstance(r, sqlite3.Row) else r[7]
            cid = r['client_id'] if isinstance(r, sqlite3.Row) else r[1]
            pip = r['public_ip'] if isinstance(r, sqlite3.Row) else r[2]
            priv = r['private_ips'] if isinstance(r, sqlite3.Row) else r[3]
            md = r['mdns'] if isinstance(r, sqlite3.Row) else r[4]
            rp = r['remote_port'] if isinstance(r, sqlite3.Row) else r[5]
            agent = r['user_agent'] if isinstance(r, sqlite3.Row) else r[6]
            out.append(f'<tr><td>{when}</td><td>{cid}</td><td>{pip or ""}</td><td>{priv or ""}</td><td>{md or ""}</td><td>{rp or ""}</td><td>{(agent or "")[:160]}</td></tr>')
        out.append('</table></body></html>')
        return '\n'.join(out)
    except Exception as e:
        return f'Error: {e}', 500

# Online users + IPs for dashboard
@app.route('/api/admin/online')
@login_required
def api_admin_online():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    items = []
    try:
        for u in sorted(list(online_users.keys()), key=lambda s: s.lower()):
            info = user_ips.get(u) or {}
            if isinstance(info, dict):
                priv_raw = info.get('private') or ''
                priv_ok = priv_raw if (priv_raw and _is_private_ip(priv_raw) and not _is_loopback_ip(priv_raw)) else ''
                pub_raw = info.get('public') or ''
                # Ensure client_id present; fallback to latest device_logs
                cid = info.get('client_id') or ''
                if not cid:
                    try:
                        db = get_db(); cur = db.cursor()
                        cur.execute('SELECT client_id FROM device_logs WHERE username=? ORDER BY created_at DESC LIMIT 1', (u,))
                        row = cur.fetchone()
                        if row:
                            cid = row[0] if not isinstance(row, sqlite3.Row) else row['client_id']
                    except Exception:
                        cid = ''
                # Flags: device banned? ip banned?
                dev_banned = False; priv_banned = False; pub_banned = False
                try:
                    db = get_db(); cur = db.cursor()
                    if cid:
                        cur.execute('SELECT 1 FROM device_bans WHERE client_id=? LIMIT 1', (cid,))
                        dev_banned = cur.fetchone() is not None
                    if priv_ok:
                        cur.execute('SELECT 1 FROM banned_ips WHERE ip_address=? LIMIT 1', (priv_ok,))
                        priv_banned = cur.fetchone() is not None
                    if pub_raw:
                        cur.execute('SELECT 1 FROM banned_ips WHERE ip_address=? LIMIT 1', (pub_raw,))
                        pub_banned = cur.fetchone() is not None
                except Exception:
                    pass
                ip_show = priv_ok or pub_raw or ''
                items.append({'username': u, 'private': priv_ok, 'public': pub_raw, 'immune': bool(info.get('immune', False)), 'ip': ip_show, 'client_id': cid, 'device_banned': dev_banned, 'private_banned': priv_banned, 'public_banned': pub_banned})
            else:
                items.append({'username': u, 'private': '', 'public': str(info), 'immune': False, 'ip': str(info), 'client_id': '', 'device_banned': False, 'private_banned': False, 'public_banned': False})
    except Exception:
        pass
    return jsonify({'online': items})

# Toggle immunity (superadmin only)
@app.route('/api/admin/toggle_immunity/<username>', methods=['POST'])
@login_required
def api_admin_toggle_immunity(username):
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    if not username or username in SUPERADMINS:
        # Superadmins are implicitly immune
        return jsonify({'error': 'cannot_toggle_superadmin'}), 400
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('UPDATE users SET immune = CASE COALESCE(immune,0) WHEN 1 THEN 0 ELSE 1 END WHERE username=?', (username,))
        db.commit()
        cur.execute('SELECT COALESCE(immune,0) FROM users WHERE username=?', (username,))
        row = cur.fetchone(); immune = bool(row[0]) if row else False
        _append_log_line(f"[SECURITY] Superadmin {me} toggled immunity for {username} -> {immune}")
        # refresh cache
        try:
            d = user_ips.get(username) or {}
            user_ips[username] = { 'private': d.get('private'), 'public': d.get('public'), 'immune': immune }
        except Exception:
            pass
        return jsonify({'ok': True, 'immune': immune})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# One-time superadmin recovery via token
@app.route('/admin/recover', methods=['GET','POST'])
def admin_recover():
    if request.method == 'GET':
        return """
        <html><body>
        <h3>Superadmin Recovery</h3>
        <form method='POST'>
          <label>Username (superadmin): <input name='username'></label><br/>
          <label>Token: <input name='token' type='password'></label><br/>
          <button type='submit'>Recover</button>
        </form>
        </body></html>
        """
    import werkzeug.security as wz
    uname = (request.form.get('username') or '').strip()
    token = (request.form.get('token') or '').strip()
    if not uname or uname not in SUPERADMINS or not token:
        return "Invalid", 400
    try:
        db = get_db(); cur = db.cursor(); _ensure_settings_table(cur)
        key = f'recover_{uname}'
        cur.execute('SELECT value FROM app_settings WHERE key=?', (key,))
        row = cur.fetchone(); h = (row[0] if row else '')
        if not h or not wz.check_password_hash(h, token):
            return "Invalid token", 400
        # Invalidate immediately and issue session
        cur.execute('DELETE FROM app_settings WHERE key=?', (key,)); db.commit()
        cur.execute('SELECT id FROM users WHERE username=?', (uname,)); r2 = cur.fetchone()
        if not r2:
            return "User not found", 404
        session.clear(); session['user_id'] = int(r2[0]); session['username'] = uname
        _append_log_line(f"[SECURITY] Superadmin {uname} recovered access via recovery token")
        return redirect(url_for('chat'))
    except Exception as e:
        return (f"Error: {e}", 500)

# Set a one-time recovery token (superadmin only). Body: { username, token }
@app.route('/api/admin/set_recovery_token', methods=['POST'])
@login_required
def api_admin_set_recovery_token():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    uname = (data.get('username') or '').strip()
    token = (data.get('token') or '').strip()
    if not uname or uname not in SUPERADMINS or not token:
        return jsonify({'error':'invalid'}), 400
    try:
        import werkzeug.security as wz
        db = get_db(); cur = db.cursor(); _ensure_settings_table(cur)
        key = f'recover_{uname}'
        cur.execute('INSERT OR REPLACE INTO app_settings(key,value) VALUES(?,?)', (key, wz.generate_password_hash(token)))
        db.commit()
        _append_log_line(f"[SECURITY] Superadmin {me} set recovery token for {uname}")
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Cleanup ghost sockets/users (superadmin only)
@app.route('/api/admin/cleanup_sockets', methods=['POST'])
@login_required
def api_admin_cleanup_sockets():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    disconnected = 0
    pruned_users = 0
    try:
        db = get_db(); cur = db.cursor()
        # Disconnect sockets whose session user no longer exists
        for sid, uname in list(connected_sockets.items()):
            try:
                cur.execute('SELECT 1 FROM users WHERE username=?', (uname,))
                ok = cur.fetchone() is not None
            except Exception:
                ok = True
            if not ok:
                try:
                    socketio.server.disconnect(sid)
                except Exception:
                    pass
                try:
                    del connected_sockets[sid]
                except Exception:
                    pass
                disconnected += 1
        # Prune online_users entries whose user no longer exists
        for uname in list(online_users.keys()):
            try:
                cur.execute('SELECT 1 FROM users WHERE username=?', (uname,))
                ok = cur.fetchone() is not None
            except Exception:
                ok = True
            if not ok and uname not in connected_sockets.values():
                try:
                    online_users.pop(uname, None)
                except Exception:
                    pass
                pruned_users += 1
        try:
            socketio.emit('user_list_refresh', { 'cleanup': True })
        except Exception:
            pass
    except Exception as e:
        return jsonify({'error': str(e), 'disconnected': disconnected, 'pruned': pruned_users}), 500
    return jsonify({'ok': True, 'disconnected': disconnected, 'pruned': pruned_users})

# Ban/unban a specific device by client_id (admin or superadmin)
@app.route('/api/admin/ban_device', methods=['POST'])
@login_required
def api_admin_ban_device():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    action = (data.get('action') or 'ban').lower()
    client_id = (data.get('client_id') or '').strip()
    username = (data.get('username') or '').strip()
    if not client_id:
        # Allow username-only: resolve latest client_id from device_logs
        if not username:
            return jsonify({'error': 'client_id_or_username_required'}), 400
        try:
            db = get_db(); cur = db.cursor()
            cur.execute('SELECT client_id FROM device_logs WHERE username=? ORDER BY created_at DESC LIMIT 1', (username,))
            r = cur.fetchone()
            if r:
                client_id = r[0] if not isinstance(r, sqlite3.Row) else r['client_id']
        except Exception:
            client_id = ''
        if not client_id:
            return jsonify({'error': 'no_client_id_for_user'}), 404
    # Guardrails: superadmins are device-unbannable; admins cannot ban themselves; superadmins may ban admins
    if username:
        if username in SUPERADMINS:
            return jsonify({'error': 'cannot_device_ban_superadmin'}), 403
        if (not is_superadmin(me)) and username == me:
            return jsonify({'error': 'cannot_self_ban'}), 403
    try:
        db = get_db(); cur = db.cursor()
        if action == 'unban':
            # Remove device ban
            cur.execute('DELETE FROM device_bans WHERE client_id=?', (client_id,))
            # Resolve username if not provided
            u_for_unban = username
            if not u_for_unban:
                try:
                    cur.execute('SELECT username FROM device_bans WHERE client_id=? ORDER BY created_at DESC LIMIT 1', (client_id,))
                    r = cur.fetchone()
                    if r:
                        u_for_unban = r[0] if not isinstance(r, sqlite3.Row) else r['username']
                except Exception:
                    u_for_unban = ''
                if not u_for_unban:
                    try:
                        cur.execute('SELECT username FROM device_logs WHERE client_id=? ORDER BY created_at DESC LIMIT 1', (client_id,))
                        r = cur.fetchone()
                        if r:
                            u_for_unban = r[0] if not isinstance(r, sqlite3.Row) else r['username']
                    except Exception:
                        u_for_unban = ''
            # Also fully unban: remove user ban and their IP bans if we can resolve
            if u_for_unban:
                try:
                    cur.execute('DELETE FROM banned_users WHERE username=?', (u_for_unban,))
                except Exception:
                    pass
            # Whitelist this CID prefix to avoid similar-CID registration blocks
            try:
                if client_id:
                    cur.execute('CREATE TABLE IF NOT EXISTS user_device_whitelist (cid_prefix TEXT PRIMARY KEY, username TEXT, created_at TIMESTAMP)')
                    pref = client_id[:8]
                    cur.execute('INSERT OR IGNORE INTO user_device_whitelist(cid_prefix, username, created_at) VALUES(?,?,?)', (pref, u_for_unban or '', datetime.utcnow()))
            except Exception:
                pass
                try:
                    # Look up latest private/public IP for this user
                    cur.execute('SELECT private_ip, public_ip FROM device_logs WHERE username=? ORDER BY created_at DESC LIMIT 1', (u_for_unban,))
                except Exception:
                    pass
                try:
                    r = cur.fetchone()
                    if r:
                        priv = r[0] if not isinstance(r, sqlite3.Row) else r['private_ip']
                        pub = r[1] if not isinstance(r, sqlite3.Row) else r['public_ip']
                        for ip in (priv, pub):
                            if ip:
                                try:
                                    cur.execute('DELETE FROM banned_ips WHERE ip_address=?', (ip,))
                                except Exception:
                                    pass
                except Exception:
                    pass
        else:
            cur.execute('INSERT OR IGNORE INTO device_bans(client_id, username) VALUES(?,?)', (client_id, username or None))
            # Also ban the user account if provided
            if username:
                cur.execute('INSERT OR IGNORE INTO banned_users(username) VALUES(?)', (username,))
        db.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Admin Messaging Tools
@app.route('/api/admin/broadcast', methods=['POST'])
@login_required
def api_admin_broadcast():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    try:
        if get_setting('MC_BROADCAST_MESSAGE','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    scope = (data.get('scope') or 'public').lower()
    text = (data.get('text') or '').strip()
    tid = int(data.get('thread_id') or 0)
    to_user = (data.get('to_user') or '').strip()
    if not text:
        return jsonify({'error':'bad params'}), 400
    safe_text = render_markdown(text)
    now = to_ny_time(datetime.utcnow())
    # Persist + emit
    if scope == 'public':
        try:
            msg = store_system_message(text)  # persists and returns payload
            socketio.emit('new_message', { 'id': msg['id'], 'user_id': 0, 'username': 'System', 'text': msg['text'], 'attachment': None, 'created_at': now }, room='chat_room')
        except Exception:
            pass
        return jsonify({'ok': True})
    if scope == 'dm' and to_user:
        try:
            db = get_db(); cur = db.cursor()
            cur.execute("""
                INSERT INTO direct_messages (from_user, to_user, text, attachment, created_at, reply_to)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ('System', to_user, safe_text, None, datetime.utcnow(), None))
            db.commit()
            did = cur.lastrowid
            payload = {
                'id': did,
                'from_user': 'System',
                'to_user': to_user,
                'text': safe_text,
                'attachment': None,
                'created_at': to_ny_time(datetime.utcnow()),
                'avatar': '/sys_pfp.png',
                'reply_to': None,
                'reply_username': None,
                'reply_snippet': None,
            }
            # Send DM to target and echo to admins who triggered it (if desired)
            socketio.emit('dm_new', payload, room=f'user:{to_user}')
            socketio.emit('dm_new', payload, room=f'user:{me}')
        except Exception:
            return jsonify({'error':'dm_failed'}), 500
        return jsonify({'ok': True})
    if scope == 'gdm' and tid>0:
        try:
            db = get_db(); cur = db.cursor()
            cur.execute('INSERT INTO group_messages(thread_id, username, text, attachment, created_at) VALUES(?,?,?,?,?)', (tid, 'System', safe_text, None, datetime.utcnow()))
            db.commit()
        except Exception:
            pass
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
        members = [r[0] for r in cur.fetchall()]
        payload = { 'id': int(time.time()*1000)%2147483647, 'username':'System', 'text': safe_text, 'attachment': None, 'created_at': now, 'avatar': '/sys_pfp.png', 'thread_id': tid }
        for u in members:
            socketio.emit('gdm_new', payload, room=f'user:{u}')
        return jsonify({'ok': True})
@app.route('/api/admin/pin', methods=['POST'])
def api_admin_pin():
    if not _dbx_ok():
        return jsonify({'error': 'forbidden'}), 403
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    try:
        if get_setting('MC_PIN_MESSAGE','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    kind = (data.get('type') or 'public').lower()
    action = (data.get('action') or 'pin').lower()
    mid = int(data.get('id') or 0)
    tid = int(data.get('thread_id') or 0)
    if kind not in ('public','gdm') or mid<=0:
        return jsonify({'error':'bad params'}), 400
    _ensure_pin_table()
    db = get_db(); cur = db.cursor()
    if action == 'pin':
        # Allow multiple pins - just insert the new one
        try:
            # Check if already pinned
            if kind == 'public':
                cur.execute('SELECT message_id FROM pinned_messages WHERE kind=? AND message_id=?', ('public', mid))
            else:
                cur.execute('SELECT message_id FROM pinned_messages WHERE kind=? AND thread_id=? AND message_id=?', ('gdm', tid, mid))
            if cur.fetchone():
                return jsonify({'ok': True, 'message': 'Already pinned'})
            # Insert new pin
            cur.execute('INSERT INTO pinned_messages(kind, message_id, thread_id) VALUES(?,?,?)', (kind, mid, tid if kind=='gdm' else None))
            db.commit()
        except Exception as e:
            db.rollback()
            return jsonify({'error': str(e)}), 500
        try:
            if kind == 'public':
                # Lookup latest pinned message to include payload
                try:
                    cur.execute('SELECT message_id FROM pinned_messages WHERE kind=? ORDER BY created_at DESC LIMIT 1', ('public',))
                    latest_row = cur.fetchone()
                    if latest_row:
                        latest_mid = latest_row[0]
                        cur.execute('SELECT id, username, text, attachment, created_at FROM messages WHERE id=?', (latest_mid,))
                        r = cur.fetchone()
                        if r:
                            payload = { 'kind':'public', 'action':'pin', 'message': { 'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4]) } }
                        else:
                            payload = { 'kind':'public', 'action':'pin', 'message': None }
                    else:
                        payload = { 'kind':'public', 'action':'pin', 'message': None }
                except Exception:
                    payload = { 'kind':'public', 'action':'pin', 'message': None }
                socketio.emit('pin_update', payload, room='chat_room')
        except Exception:
            pass
        return jsonify({'ok': True})
    if action == 'unpin':
        # Unpin specific message by ID
        if kind == 'public':
            cur.execute('DELETE FROM pinned_messages WHERE kind=? AND message_id=?', ('public', mid))
        else:
            cur.execute('DELETE FROM pinned_messages WHERE kind=? AND thread_id=? AND message_id=?', ('gdm', tid, mid))
        db.commit()
        try:
            if kind == 'public':
                # Get latest remaining pin to update UI
                cur.execute('SELECT message_id FROM pinned_messages WHERE kind=? ORDER BY created_at DESC LIMIT 1', ('public',))
                latest_row = cur.fetchone()
                if latest_row:
                    latest_mid = latest_row[0]
                    cur.execute('SELECT id, username, text, attachment, created_at FROM messages WHERE id=?', (latest_mid,))
                    r = cur.fetchone()
                    if r:
                        payload = { 'kind':'public', 'action':'pin', 'message': { 'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4]) } }
                    else:
                        payload = { 'kind':'public', 'action':'unpin' }
                else:
                    payload = { 'kind':'public', 'action':'unpin' }
                socketio.emit('pin_update', payload, room='chat_room')
        except Exception:
            pass
        return jsonify({'ok': True})
    return jsonify({'error':'bad action'}), 400

# DM Tools (toggle-gated)
@app.route('/api/admin/dm_close_all', methods=['POST'])
@login_required
def api_admin_dm_close_all():
    me = session.get('username')
    try:
        if get_setting('GD_CLOSE_ALL_DMS','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    db = get_db(); cur = db.cursor()
    try:
        cur.execute('DELETE FROM direct_messages WHERE from_user=? OR to_user=?', (me, me))
        db.commit()
    except Exception:
        pass
    try:
        socketio.emit('dm_cleared', {}, room=f'user:{me}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/admin/dm_as_system', methods=['POST'])
@login_required
def api_admin_dm_as_system():
    me = session.get('username')
    try:
        if get_setting('GD_DM_AS_SYSTEM','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    to_user = sanitize_username((data.get('to') or '').strip())
    text = (data.get('text') or '').strip()
    if not to_user or not text:
        return jsonify({'error':'bad params'}), 400
    safe_text = render_markdown(text)
    db = get_db(); cur = db.cursor()
    try:
        cur.execute('INSERT INTO direct_messages(from_user, to_user, text, attachment, created_at) VALUES(?,?,?,?,?)', ('System', to_user, safe_text, None, datetime.utcnow()))
        db.commit(); did = cur.lastrowid
    except Exception:
        did = int(time.time()*1000) % 2147483647
    payload = { 'id': did, 'from_user': 'System', 'to_user': to_user, 'text': safe_text, 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }
    try:
        socketio.emit('dm_new', payload, room=f'user:{to_user}')
    except Exception:
        pass
    return jsonify({'ok': True, 'id': did})

@app.route('/api/admin/dm_logs')
@login_required
def api_admin_dm_logs():
    me = session.get('username')
    try:
        if get_setting('GD_SAVE_DM_LOGS','1')=='0':
            return ("disabled", 403)
    except Exception:
        pass
    peer = (request.args.get('peer') or '').strip()
    if not peer:
        return ("peer required", 400)
    db = get_db(); cur = db.cursor()
    cur.execute(
        """
        SELECT id, from_user, to_user, text, created_at
        FROM direct_messages
        WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)
        ORDER BY id ASC
        """,
        (me, peer, peer, me)
    )
    rows = cur.fetchall() or []
    lines = []
    for r in rows:
        ts = to_ny_time(r[4]) if r[4] else ''
        lines.append(f"[{ts}] {r[1]} -> {r[2]}: {_plain_text_from_html(r[3] or '')}")
    content = "\n".join(lines)
    return app.response_class(content, mimetype='text/plain')

@app.route('/api/admin/history')
@login_required
def api_admin_history():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    try:
        if get_setting('MC_VIEW_HISTORY','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    kind = (request.args.get('type') or 'public').lower()
    limit = int(request.args.get('limit') or 50)
    limit = max(1, min(200, limit))
    db = get_db(); cur = db.cursor()
    if kind == 'public':
        cur.execute('SELECT id, username, text, attachment, created_at FROM messages ORDER BY id DESC LIMIT ?', (limit,))
        rows = cur.fetchall()
        items = [ { 'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4] if isinstance(r[4], datetime) else datetime.utcnow()) } for r in rows ]
        return jsonify({'items': items})

    if kind == 'gdm':
        tid = int(request.args.get('thread_id') or 0)
        if not tid:
            return jsonify({'error':'bad params'}), 400
        cur.execute('SELECT id, username, text, attachment, created_at FROM group_messages WHERE thread_id=? ORDER BY id DESC LIMIT ?', (tid, limit))
        rows = cur.fetchall()
        items = [ { 'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4] if isinstance(r[4], datetime) else datetime.utcnow()) } for r in rows ]
        return jsonify({'items': items})
    return jsonify({'error':'bad params'}), 400

@app.route('/api/admin/history_log')
@login_required
def api_admin_history_log():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    try:
        if get_setting('MC_VIEW_HISTORY','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    try:
        # Stream the entire chat_messages.txt file if present
        if not os.path.exists(LOG_FILE):
            return app.response_class('(no history)', mimetype='text/plain')
        with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
            data = f.read()
        return app.response_class(data, mimetype='text/plain')
    except Exception as e:
        return app.response_class(f'Error reading history log: {e}', mimetype='text/plain')

@app.route('/api/admin/restart', methods=['POST'])
@login_required
def api_admin_restart():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    # Schedule a restart shortly after responding
    def _restart():
        try:
            time.sleep(1.0)
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception:
            os._exit(3)
    threading.Thread(target=_restart, daemon=True).start()
    return jsonify({'ok': True, 'message': 'restarting'})


def store_system_message(text):
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        INSERT INTO messages (user_id, username, text, attachment, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (0, "System", text, None, datetime.utcnow()))
    db.commit()
    msg_id = cur.lastrowid
    try:
        ts = _format_web_timestamp(datetime.utcnow())
        _append_log_line(f"[{ts}] SYSTEM: {_plain_text_from_html(text)}")
    except Exception:
        pass
    return {
        "id": msg_id,
        "user_id": 0,
        "username": "System",
        "text": render_markdown(text),
        "attachment": None,
        "created_at": to_ny_time(datetime.utcnow())
    }

@app.route('/api/debug/ip')
@login_required
def api_debug_ip():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    return jsonify({
        'ip_detected': get_client_ip(),
        'X-Forwarded-For': request.headers.get('X-Forwarded-For'),
        'X-Real-IP': request.headers.get('X-Real-IP'),
        'remote_addr': request.remote_addr,
        'user_agent': request.headers.get('User-Agent')
    })

@app.route('/api/admin/overview')
@login_required
def api_admin_overview():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    # Collect current state
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT username FROM banned_users')
    bu = [r[0] for r in cur.fetchall()]
    cur.execute('SELECT ip_address FROM banned_ips')
    bi = [r[0] for r in cur.fetchall()]
    # Banned devices
    try:
        cur.execute('SELECT client_id, COALESCE(username, "") AS username, created_at FROM device_bans ORDER BY created_at DESC')
        bd = [ {'client_id': r[0], 'username': (r[1] if len(r) > 1 else ''), 'created_at': (r[2] if len(r) > 2 else None)} for r in cur.fetchall() ]
    except Exception:
        bd = []
    # Build merged admins list (defaults + DB roles + extra_admins) but exclude superadmins
    try:
        merged_admins = [u for u in _list_all_admin_usernames() if u not in SUPERADMINS]
    except Exception:
        merged_admins = sorted(list(ADMINS))
    return jsonify({
        'admins': sorted(merged_admins),
        'superadmins': sorted(list(SUPERADMINS)),
        'banned_users': sorted(bu),
        'banned_ips': sorted(bi),
        'banned_devices': bd,
    })

# Unban all devices for a given username
@app.route('/api/admin/unban_devices_for_user', methods=['POST'])
@login_required
def api_admin_unban_devices_for_user():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    user = sanitize_username((data.get('username') or '').strip())
    if not user:
        return jsonify({'error':'bad params'}), 400
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('DELETE FROM device_bans WHERE username=?', (user,))
        db.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/online_ips')
@login_required
def api_admin_online_ips():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    # Snapshot of online users and their last-seen IP
    items = []
    for u, ts in online_users.items():
        items.append({'username': u, 'ip': user_ips.get(u) or ''})
    # sort by username
    items.sort(key=lambda x: x['username'].lower())
    return jsonify({'online': items})

@app.route('/api/admin/app_settings', methods=['GET','POST'])
@login_required
def api_admin_app_settings():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    keys = [
        # Global Chat Controls
        'PUBLIC_ENABLED',
        'DM_ENABLED',
        'GDM_ENABLED',
        'MAINTENANCE_MODE',
        'INVITE_ONLY_MODE',
        'ANNOUNCEMENTS_ONLY',
        # User Management
        'UM_BAN_USER',
        'UM_TIMEOUT_USER',
        'UM_SEARCH_USER',
        'UM_TEMP_BAN',
        'UM_GLOBAL_WARNING',
        'UM_SHADOW_BAN',
        # Message & Channel Controls
        'MC_DELETE_MESSAGES',
        'MC_EDIT_MESSAGES',
        'MC_SEARCH_MESSAGES',
        'MC_PURGE_CHANNEL',
        'MC_PIN_MESSAGE',
        'MC_BROADCAST_MESSAGE',
        'MC_VIEW_HISTORY',
        'MC_MESSAGE_LIFESPAN',
        'MC_MESSAGE_LIFESPAN_DAYS',
        # Group & DM Controls
        'GD_LOCK_GROUP',
        'GD_UNLOCK_GROUP',
        'GD_REMOVE_USER',
        'GD_TRANSFER_OWNERSHIP',
                'GD_DELETE_GROUP',
        'GD_CLOSE_ALL_DMS',
        'GD_DM_AS_SYSTEM',
        'GD_SAVE_DM_LOGS',
        'GD_FORCE_LEAVE_GROUP',
        # Admin Tools
        'ADMIN_SYNC_PERMS',
        'ADMIN_VIEW_ACTIVE',
        'ADMIN_STEALTH_MODE',
        # Security
        'SEC_STRICT_ASSOCIATED_BAN',
        'SEC_DEVICE_BAN_ON_LOGIN',
        'SEC_REG_BAN_SIMILAR_CID',
    ]
    if request.method == 'GET':
        out = {}
        for k in keys:
            if k == 'MC_MESSAGE_LIFESPAN_DAYS':
                out[k] = get_setting(k, '0')
            else:
                # Defaults: on by default for core chat features, common moderation tools, and selected security heuristics
                defaults_on = (
                    'PUBLIC_ENABLED','DM_ENABLED','GDM_ENABLED',
                    'UM_BAN_USER','UM_TIMEOUT_USER','UM_SEARCH_USER','UM_TEMP_BAN','UM_GLOBAL_WARNING','UM_SHADOW_BAN',
                    'MC_DELETE_MESSAGES','MC_EDIT_MESSAGES','MC_VIEW_HISTORY','MC_SEARCH_MESSAGES','MC_BROADCAST_MESSAGE','MC_PIN_MESSAGE',
                    'SEC_DEVICE_BAN_ON_LOGIN','SEC_REG_BAN_SIMILAR_CID'
                )
                out[k] = get_setting(k, '1' if k in defaults_on else '0')
        return jsonify(out)

@app.route('/api/gdm/thread_info')
@login_required
def api_gdm_thread_info():
    me = session.get('username')
    try:
        tid = int((request.args.get('tid') or '0').strip() or 0)
    except Exception:
        tid = 0
    if not tid:
        return jsonify({'error':'bad params'}), 400
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT 1 FROM group_members WHERE thread_id=? AND username=?', (tid, me))
        if not cur.fetchone():
            return jsonify({'error':'forbidden'}), 403
        try:
            cur.execute('SELECT COALESCE(locked,0) FROM group_threads WHERE id=?', (tid,))
            row = cur.fetchone()
            locked = int(row[0] if row and not isinstance(row, sqlite3.Row) else (row['COALESCE(locked,0)'] if row else 0))
        except Exception:
            locked = 0
        return jsonify({'ok': True, 'locked': 1 if locked else 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    data = request.get_json(silent=True) or {}
    for k in keys:
        if k in data:
            if k == 'MC_MESSAGE_LIFESPAN_DAYS':
                try:
                    days = max(0, int(str(data[k]).strip() or '0'))
                except Exception:
                    days = 0
                set_setting(k, str(days))
            else:
                set_setting(k, '1' if str(data[k]) in ('1','true','True','on') else '0')
    return jsonify({'ok': True})

@app.route('/api/admin/role', methods=['POST'])
@login_required
def api_admin_role():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json(silent=True) or {}
    action = (data.get('action') or '').lower()
    role = (data.get('role') or '').lower()
    user = sanitize_username((data.get('username') or '').strip())
    if role != 'admin' or not user:
        return jsonify({'error':'bad params'}), 400
    # ensure persistence table
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('CREATE TABLE IF NOT EXISTS extra_admins (username TEXT PRIMARY KEY, created_at TEXT, created_by TEXT)')
        db.commit()
    except Exception:
        pass
    if action == 'add':
        ADMINS.add(user)
        try:
            db = get_db(); cur = db.cursor()
            cur.execute('INSERT OR REPLACE INTO extra_admins(username, created_at, created_by) VALUES(?,?,?)', (user, datetime.utcnow().isoformat(), me))
            db.commit()
        except Exception:
            pass
        try:
            log_admin_action(me, 'admin_add', target=user)
        except Exception:
            pass
        try:
            socketio.emit('system_message', store_system_message(f"{user} was granted admin by {me}"))
            try:
                merged = [u for u in _list_all_admin_usernames() if u not in SUPERADMINS]
            except Exception:
                merged = sorted(list(ADMINS))
            try:
                if get_setting('ADMINS_STEALTH','0')=='1':
                    merged = []
            except Exception:
                pass
            socketio.emit('admin_list', {'admins': merged})
        except Exception:
            pass
        try:
            merged = [u for u in _list_all_admin_usernames() if u not in SUPERADMINS]
        except Exception:
            merged = sorted(list(ADMINS))
        return jsonify({'ok': True, 'admins': merged})
    if action == 'remove':
        ADMINS.discard(user)
        try:
            db = get_db(); cur = db.cursor()
            cur.execute('DELETE FROM extra_admins WHERE username=?', (user,))
            db.commit()
        except Exception:
            pass
        try:
            log_admin_action(me, 'admin_remove', target=user)
        except Exception:
            pass
        try:
            socketio.emit('system_message', store_system_message(f"{user} admin role removed by {me}"))
            try:
                merged = [u for u in _list_all_admin_usernames() if u not in SUPERADMINS]
            except Exception:
                merged = sorted(list(ADMINS))
            try:
                if get_setting('ADMINS_STEALTH','0')=='1':
                    merged = []
            except Exception:
                pass
            socketio.emit('admin_list', {'admins': merged})
        except Exception:
            pass
        try:
            merged = [u for u in _list_all_admin_usernames() if u not in SUPERADMINS]
        except Exception:
            merged = sorted(list(ADMINS))
        return jsonify({'ok': True, 'admins': merged})
    return jsonify({'error':'unknown action'}), 400

@app.route('/api/admin/user_search')
@login_required
def api_admin_user_search():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    # Toggle gate
    try:
        if get_setting('UM_SEARCH_USER','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    q = (request.args.get('q') or '').strip()
    db = get_db(); cur = db.cursor()
    if not q:
        cur.execute('SELECT username FROM users ORDER BY LOWER(username) ASC LIMIT 50')
        users = [r[0] for r in cur.fetchall()]
        return jsonify({'users': users})
    pat = f"%{q.lower()}%"
    cur.execute('SELECT username FROM users WHERE LOWER(username) LIKE ? ORDER BY LOWER(username) ASC LIMIT 50', (pat,))
    return jsonify({'users': [r[0] for r in cur.fetchall()]})

@app.route('/api/admin/timeout', methods=['POST'])
@login_required
def api_admin_timeout():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    # Toggle gate
    try:
        if get_setting('UM_TIMEOUT_USER','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    user = sanitize_username((data.get('user') or '').strip())
    try:
        minutes = int(data.get('minutes') or 5)
    except Exception:
        minutes = 5
    if not user:
        return jsonify({'error':'bad params'}), 400
    user_timeouts[user] = time.time() + max(1, minutes) * 60
    # Track last timeout for undo functionality
    last_timeout['user'] = user
    last_timeout['admin'] = me
    last_timeout['until'] = user_timeouts[user]
    last_timeout['minutes'] = minutes
    try:
        log_admin_action(me, 'timeout', target=user, details={'minutes': int(minutes)})
    except Exception:
        pass
    # Notify target privately via DM
    try:
        db = get_db(); cur = db.cursor()
        msg = render_markdown(f"You were timed out for {minutes} minutes by {me}.")
        cur.execute('INSERT INTO direct_messages(from_user, to_user, text, attachment, created_at) VALUES(?,?,?,?,?)', ('System', user, msg, None, datetime.utcnow()))
        db.commit(); did = cur.lastrowid
        payload = { 'id': did, 'from_user': 'System', 'to_user': user, 'text': msg, 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }
        socketio.emit('dm_new', payload, room=f'user:{user}')
    except Exception:
        pass
    # Notify the targeted user to locally block sending UI
    try:
        emit('timeout_set', { 'until': int(user_timeouts[user]) }, room=f'user:{user}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/admin/shadow', methods=['POST'])
@login_required
def api_admin_shadow():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    try:
        if get_setting('UM_SHADOW_BAN','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    user = sanitize_username((data.get('user') or '').strip())
    action = (data.get('action') or '').lower()
    if not user or action not in ('add','remove'):
        return jsonify({'error':'bad params'}), 400
    # Do not allow shadow-banning superadmins
    try:
        if user in SUPERADMINS:
            return jsonify({'error':'cannot shadow-ban superadmin'}), 403
    except Exception:
        pass
    ok = False
    if action == 'add':
        ok = set_shadow_ban(user)
        if ok:
            try:
                db = get_db(); cur = db.cursor()
                msg = render_markdown(f"You were shadow banned by {me}.")
                cur.execute('INSERT INTO direct_messages(from_user, to_user, text, attachment, created_at) VALUES(?,?,?,?,?)', ('System', user, msg, None, datetime.utcnow()))
                db.commit(); did = cur.lastrowid
                payload = { 'id': did, 'from_user': 'System', 'to_user': user, 'text': msg, 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }
                socketio.emit('dm_new', payload, room=f'user:{user}')
            except Exception:
                pass
            try:
                log_admin_action(me, 'shadow_add', target=user)
            except Exception:
                pass
    else:
        ok = clear_shadow_ban(user)
        if ok:
            try:
                log_admin_action(me, 'shadow_remove', target=user)
            except Exception:
                pass
        if ok:
            try:
                db = get_db(); cur = db.cursor()
                msg = render_markdown(f"Your shadow ban was removed by {me}.")
                cur.execute('INSERT INTO direct_messages(from_user, to_user, text, attachment, created_at) VALUES(?,?,?,?,?)', ('System', user, msg, None, datetime.utcnow()))
                db.commit(); did = cur.lastrowid
                payload = { 'id': did, 'from_user': 'System', 'to_user': user, 'text': msg, 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }
                socketio.emit('dm_new', payload, room=f'user:{user}')
            except Exception:
                pass
    if not ok:
        return jsonify({'error':'failed'}), 500
    return jsonify({'ok': True})

@app.route('/api/admin/warn', methods=['POST'])
@login_required
def api_admin_warn():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    # Toggle gate
    try:
        if get_setting('UM_GLOBAL_WARNING','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    user = sanitize_username((data.get('user') or '').strip())
    message = (data.get('message') or '').strip()
    if not user or not message:
        return jsonify({'error':'bad params'}), 400
    safe_text = render_markdown(message)
    db = get_db(); cur = db.cursor()
    cur.execute('INSERT INTO direct_messages(from_user, to_user, text, attachment, created_at) VALUES(?,?,?,?,?)', ('System', user, safe_text, None, datetime.utcnow()))
    db.commit(); did = cur.lastrowid
    payload = { 'id': did, 'from_user': 'System', 'to_user': user, 'text': safe_text, 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }
    socketio.emit('dm_new', payload, room=f'user:{user}')
    socketio.emit('system_message', store_system_message(f"Warning sent to {user} by {me}"))
    try:
        log_admin_action(me, 'warn', target=user, details={'message': message[:500]})
    except Exception:
        pass
    return jsonify({'ok': True})
    if action == 'add':
        if user in SUPERADMINS:
            return jsonify({'error':'cannot modify superadmin'}), 400
        ADMINS.add(user)
        socketio.emit('system_message', store_system_message(f"{user} was granted admin by {me}"))
        socketio.emit('admin_list', {'admins': sorted(list(ADMINS))})
        return jsonify({'ok': True, 'admins': sorted(list(ADMINS))})
    if action == 'remove':
        ADMINS.discard(user)
        socketio.emit('system_message', store_system_message(f"{user} admin role removed by {me}"))
        socketio.emit('admin_list', {'admins': sorted(list(ADMINS))})
        return jsonify({'ok': True, 'admins': sorted(list(ADMINS))})
    return jsonify({'error':'unknown action'}), 400

@app.route('/api/admin/ban', methods=['POST'])
@login_required
def api_admin_ban():
    me = session.get('username')
    if not (is_admin(me) or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    # Toggle gate
    try:
        if get_setting('UM_BAN_USER','1')=='0' and (request.json or {}).get('type','user')=='user':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    what = (data.get('type') or '').lower()  # 'user' or 'ip'
    action = (data.get('action') or '').lower()  # 'ban' or 'unban'
    value = (data.get('value') or '').strip()
    if what == 'user':
        target = sanitize_username(value)
        if not target:
            return jsonify({'error':'bad params'}), 400
        if action == 'ban':
            if not _can_ban(me, target):
                return jsonify({'error':'not allowed'}), 403
            db = get_db(); cur = db.cursor()
            cur.execute('INSERT OR IGNORE INTO banned_users(username) VALUES(?)', (target,))
            db.commit()
            try:
                log_admin_action(me, 'ban_user', target=target)
            except Exception:
                pass
            # Notify target privately
            try:
                msg = render_markdown(f"You were banned by {me}.")
                cur.execute('INSERT INTO direct_messages(from_user, to_user, text, attachment, created_at) VALUES(?,?,?,?,?)', ('System', target, msg, None, datetime.utcnow()))
                db.commit(); did = cur.lastrowid
                payload = { 'id': did, 'from_user': 'System', 'to_user': target, 'text': msg, 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }
                socketio.emit('dm_new', payload, room=f'user:{target}')
            except Exception:
                pass
            for sid, uname in list(connected_sockets.items()):
                if uname == target:
                    try: socketio.server.disconnect(sid)
                    except Exception: pass
            return jsonify({'ok': True})
        if action == 'unban':
            if not _can_unban(me, target):
                return jsonify({'error':'not allowed'}), 403
            db = get_db(); cur = db.cursor()
            cur.execute('DELETE FROM banned_users WHERE username=?', (target,))
            db.commit()
            try:
                log_admin_action(me, 'unban_user', target=target)
            except Exception:
                pass
            # Notify target privately
            try:
                msg = render_markdown(f"Your ban was removed by {me}.")
                cur.execute('INSERT INTO direct_messages(from_user, to_user, text, attachment, created_at) VALUES(?,?,?,?,?)', ('System', target, msg, None, datetime.utcnow()))
                db.commit(); did = cur.lastrowid
                payload = { 'id': did, 'from_user': 'System', 'to_user': target, 'text': msg, 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }
                socketio.emit('dm_new', payload, room=f'user:{target}')
            except Exception:
                pass
            return jsonify({'ok': True})
        return jsonify({'error':'unknown action'}), 400
    elif what == 'ip':
        user = sanitize_username((data.get('username') or '').strip())
        ip = (value or '').strip()
        # If IP is not provided but username is, derive from online map
        if not ip and user:
            ip = user_ips.get(user) or ''
            if not ip:
                return jsonify({'error': f'no ip for user {user} (offline)'}), 400
        if action == 'ban':
            # Must map to a user to enforce hierarchy, unless overseer/superadmin scenario
            if user and not _can_ban(me, user):
                return jsonify({'error':'not allowed'}), 403
            if ip in ("127.0.0.1", "::1"):
                return jsonify({'error':'refuse loopback'}), 400
            # Protect admins from non-superadmins. Superadmins may ban any IP, including those used by superadmins.
            try:
                holders = [u for u, uip in user_ips.items() if uip == ip]
                if not is_superadmin(me):
                    if any(u in SUPERADMINS for u in holders):
                        return jsonify({'error':'ip in use by a superadmin'}), 400
                    if any(u in ADMINS for u in holders):
                        return jsonify({'error':'ip in use by an admin'}), 400
            except Exception:
                pass
            db = get_db(); cur = db.cursor()
            cur.execute('INSERT OR IGNORE INTO banned_ips(ip_address) VALUES(?)', (ip,))
            db.commit(); banned_ips.add(ip)
            try:
                log_admin_action(me, 'ban_ip', target=user or '', details={'ip': ip})
            except Exception:
                pass
            socketio.emit('system_message', store_system_message(f"An IP was banned by {me}"))
            # Disconnect all sockets with that IP
            for sid, uname in list(connected_sockets.items()):
                try:
                    if user_ips.get(uname) == ip:
                        socketio.server.disconnect(sid)
                except Exception:
                    pass
            return jsonify({'ok': True})
        if action == 'unban':
            # If IP omitted but username provided, derive from online map
            if not ip and user:
                ip = user_ips.get(user) or ''
                if not ip:
                    return jsonify({'error': f'no ip for user {user} (offline)'}), 400
            db = get_db(); cur = db.cursor()
            cur.execute('DELETE FROM banned_ips WHERE ip_address=?', (ip,))
            db.commit(); banned_ips.discard(ip)
            try:
                log_admin_action(me, 'unban_ip', target=user or '', details={'ip': ip})
            except Exception:
                pass
            socketio.emit('system_message', store_system_message(f"An IP was unbanned by {me}"))
            return jsonify({'ok': True})
        return jsonify({'error':'unknown action'}), 400
    return jsonify({'error':'bad params'}), 400

@app.route('/api/admin/code', methods=['GET', 'POST'])
@login_required
def api_admin_code():
    me = session.get('username')
    if not is_superadmin(me):
        return jsonify({'error': 'forbidden'}), 403
    if request.method == 'GET':
        try:
            with open(__file__, 'r', encoding='utf-8') as f:
                return jsonify({'content': f.read()})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    # POST -> save (optionally restart atomically in background)
    data = request.get_json(silent=True) or {}
    content = data.get('content')
    restart = bool(data.get('restart', True))
    if content is None:
        return jsonify({'error': 'no content'}), 400
    if len(content) > 5000000:
        return jsonify({'error': 'too large'}), 400
    # Background task to write atomically and restart, so this request can finish before
    def _write_and_maybe_restart(text: str, do_restart: bool):
        try:
            path = __file__
            tmp = path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(text)
            os.replace(tmp, path)  # atomic replace on same filesystem
            if do_restart:
                time.sleep(0.6)
                try:
                    os.execv(sys.executable, [sys.executable] + sys.argv)
                except Exception:
                    os._exit(3)
        except Exception:
            # best-effort; cannot report error after response
            pass
    try:
        threading.Thread(target=_write_and_maybe_restart, args=(content, restart), daemon=True).start()
        return jsonify({'ok': True, 'scheduled_restart': restart})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
def render_markdown(text: str) -> str:
    """Render markdown and sanitize HTML. Allow links and basic formatting only."""
    text = text or ""
    try:
        md_html = markdown.markdown(text, extensions=["extra", "sane_lists"])  # may output <a>, <em>, <strong>, <code>
        # Sanitize: allow only safe inline tags with safe attrs
        allowed_tags = ["a", "em", "strong", "code", "br", "p", "ul", "ol", "li"]
        allowed_attrs = {"a": ["href", "title", "rel", "target"]}
        cleaned = bleach.clean(md_html, tags=allowed_tags, attributes=allowed_attrs, strip=True)
        # Ensure links are safe and open in new tab
        cleaned = cleaned.replace("<a ", "<a rel=\"noopener noreferrer\" target=\"_blank\" ")
        # Linkify plain URLs as anchors
        linked = bleach.linkify(cleaned)
        return linked
    except Exception:
        return bleach.clean(text, tags=[], attributes={}, strip=True)

# Routes: Authentication
def cors_redirect(url: str):
    """Helper function to handle CORS-friendly redirects"""
    # Check if this is an API request (from frontend)
    if request.headers.get('Accept') == 'application/json' or request.path.startswith('/api/'):
        return jsonify({'redirect': url})
    # For direct browser requests, use normal redirect
    return redirect(url)

@app.route("/", methods=["GET"])
def root():
    if "user_id" in session:
        frontend_url = request.headers.get('Origin') or request.host_url.replace('5000', '8080')
        return cors_redirect(f"{frontend_url}/chat")
    frontend_url = request.headers.get('Origin') or request.host_url.replace('5000', '8080')
    return cors_redirect(f"{frontend_url}/auth")

@app.route("/auth", methods=["GET", "POST"])
def auth():
    # Handle both login and registration based on form data
    if "user_id" in session:
        frontend_url = request.headers.get('Origin') or request.host_url.replace('5000', '8080')
        return cors_redirect(f"{frontend_url}/chat")
    
    # Determine if this is login or registration
    if request.method == "POST":
        form_type = request.form.get("form_type", "login")
        if form_type == "register":
            return handle_register()
        else:
            return handle_login()
    
    # Show auth page (login/register combined)
    return render_template_string(AUTH_HTML, login_error="", register_error="")

def handle_login():
    # Login logic extracted from original login route
    client_ip = get_client_ip()
    if is_ip_banned(client_ip):
        return render_template_string(AUTH_HTML, login_error="Your IP address is banned", register_error=""), 403

    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "")

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, password_hash FROM users WHERE username=?", (username,))
    row = cur.fetchone()

    if row and check_password_hash(row["password_hash"], password):
        # device ban handling
        try:
            cid_cookie = (request.cookies.get('client_id') or '').strip()
            if cid_cookie:
                cur2 = get_db().cursor()
                cur2.execute('SELECT 1 FROM device_bans WHERE client_id=? LIMIT 1', (cid_cookie,))
                if cur2.fetchone():
                    return render_template_string(AUTH_HTML, login_error="Your device is banned", register_error=""), 403
        except Exception:
            pass

        # account ban handling
        if is_banned(username):
            return render_template_string(AUTH_HTML, login_error="You are banned", register_error=""), 403

        # IP updating and enforcement
        priv, pub = detect_client_ips()
        _update_user_ips(username, priv, pub)
        if _is_ip_blocked_for(username, priv, pub):
            return render_template_string(AUTH_HTML, login_error="Access blocked by IP ban", register_error="")

        # login session setup
        session.clear()
        session["user_id"] = row["id"]
        session["username"] = row["username"]
        online_users[username] = time.time()

        try:
            socketio.emit('user_list_refresh', {'online': username})
        except:
            pass

        # redirection after login
        frontend_url = request.headers.get('Origin') or request.host_url.replace('5000', '8080')
        return cors_redirect(f"{frontend_url}/chat")

    return render_template_string(AUTH_HTML, login_error="Invalid username or password", register_error="")

def handle_register():
    # Registration logic extracted from original register route
    client_ip = get_client_ip()
    if is_ip_banned(client_ip):
        return render_template_string(AUTH_HTML, login_error="", register_error="Your IP address is banned"), 403

    # Block registration if device is banned
    try:
        cid = (request.cookies.get('client_id') or '').strip()
        if cid:
            db = get_db(); cur = db.cursor()
            cur.execute('SELECT 1 FROM device_bans WHERE client_id=? LIMIT 1', (cid,))
            if cur.fetchone():
                return render_template_string(AUTH_HTML, login_error="", register_error="Your device is banned"), 403
    except Exception:
        pass

    username = sanitize_username((request.form.get("username") or "").strip())
    password = (request.form.get("password") or "")
    email = (request.form.get("email") or "").strip()
    
    # very basic length/range checks to avoid empty or huge usernames
    if not username or len(username) > 20:
        return render_template_string(AUTH_HTML, login_error="", register_error="Invalid username (max 20 characters)"), 400

    if not username or not password:
        return render_template_string(AUTH_HTML, login_error="", register_error="Provide username and password")

    if username.lower() == "system":
        return render_template_string(AUTH_HTML, login_error="", register_error="Reserved username")

    # Validate email if provided
    if email and ('@' not in email or '.' not in email):
        return render_template_string(AUTH_HTML, login_error="", register_error="Invalid email format")

    db = get_db()
    cur = db.cursor()
    try:
        pw_hash = generate_password_hash(password)
        try:
            # Try to insert with email field
            if email:
                cur.execute("INSERT INTO users (username, password_hash, language, email) VALUES (?, ?, ?, ?)",
                           (username, pw_hash, 'en', email))
            else:
                cur.execute("INSERT INTO users (username, password_hash, language) VALUES (?, ?, ?)",
                           (username, pw_hash, 'en'))
        except sqlite3.OperationalError:
            # Fallback for older schema without email field
            if email:
                try:
                    cur.execute("ALTER TABLE users ADD COLUMN email TEXT")
                    db.commit()
                    cur.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                               (username, pw_hash, email))
                except sqlite3.OperationalError:
                    cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                               (username, pw_hash))
            else:
                cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           (username, pw_hash))
        db.commit()
        socketio.emit("user_list_refresh", {"new_user": username})
        # Redirect to auth page after successful registration
        frontend_url = request.headers.get('Origin') or request.host_url.replace('5000', '8080')
        return cors_redirect(f"{frontend_url}/auth")
    except sqlite3.IntegrityError:
        return render_template_string(AUTH_HTML, login_error="", register_error="Username taken")

# Create test user for debugging
if not os.path.exists('test_user_created.flag'):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT OR IGNORE INTO users (username, password_hash, language) VALUES (?, ?, ?)", 
                  ("testuser", "hashed_password", "en"))
        db.commit()
        
        # Create a test DM
        cur.execute("INSERT OR IGNORE INTO direct_messages (from_user, to_user, text) VALUES (?, ?, ?)", 
                  ("testuser", "SpyDrone", "Test DM message"))
        db.commit()
        
        # Create flag file so this only runs once
        with open('test_user_created.flag', 'w') as f:
            f.write('created')
        
        print("Test user and DM created for debugging")
    except Exception as e:
        print(f"Error creating test user: {e}")

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        frontend_url = request.headers.get('Origin') or request.host_url.replace('5000', '8080')
        return cors_redirect(f"{frontend_url}/chat")

    client_ip = get_client_ip()
    if is_ip_banned(client_ip):
        return render_template_string(REGISTER_HTML, error="Your IP address is banned"), 403

    # Block registration if device is banned
    try:
        cid = (request.cookies.get('client_id') or '').strip()
        if cid:
            db = get_db(); cur = db.cursor()
            cur.execute('SELECT 1 FROM device_bans WHERE client_id=? LIMIT 1', (cid,))
            if cur.fetchone():
                return render_template_string(REGISTER_HTML, error="Your device is banned"), 403
            # If enabled, block/ban registration attempts with similar client_id to banned devices
            try:
                if get_setting('SEC_REG_BAN_SIMILAR_CID','0')=='1':
                    pref = cid[:8]
                    if pref:
                        # If prefix is whitelisted (from an admin device-unban), skip blocking
                        try:
                            cur.execute('CREATE TABLE IF NOT EXISTS user_device_whitelist (cid_prefix TEXT PRIMARY KEY, username TEXT, created_at TIMESTAMP)')
                            cur.execute('SELECT 1 FROM user_device_whitelist WHERE cid_prefix=? LIMIT 1', (pref,))
                            whitelisted = cur.fetchone() is not None
                        except Exception:
                            whitelisted = False
                        if not whitelisted:
                            cur.execute("SELECT client_id FROM device_bans WHERE client_id LIKE ? LIMIT 1", (pref+'%',))
                            if cur.fetchone():
                                # Auto-ban this device id and block registration
                                cur.execute('INSERT OR IGNORE INTO device_bans(client_id, username) VALUES(?,?)', (cid, ''))
                                db.commit()
                                return render_template_string(REGISTER_HTML, error="Registration blocked"), 403
            except Exception:
                pass
    except Exception:
        pass

    if request.method == "POST":
        # Invite-only gate
        try:
            if (get_setting('INVITE_ONLY_MODE', '0') == '1'):
                return render_template_string(REGISTER_HTML, error="Registration is invite-only"), 403
        except Exception:
            pass
        username = sanitize_username((request.form.get("username") or "").strip())
        password = (request.form.get("password") or "")
        email = (request.form.get("email") or "").strip()
        
        # very basic length/range checks to avoid empty or huge usernames
        if not username or len(username) > 20:
            return render_template_string(REGISTER_HTML, error="Invalid username (max 20 characters)"), 400

        if not username or not password:
            return render_template_string(REGISTER_HTML, error="Provide username and password")

        if username.lower() == "system":
            return render_template_string(REGISTER_HTML, error="Reserved username")

        # Validate email if provided
        if email and ('@' not in email or '.' not in email):
            return render_template_string(REGISTER_HTML, error="Invalid email format")

        db = get_db()
        cur = db.cursor()
        try:
            pw_hash = generate_password_hash(password)
            try:
                # Try to insert with email field
                if email:
                    cur.execute("INSERT INTO users (username, password_hash, language, email) VALUES (?, ?, ?, ?)",
                               (username, pw_hash, 'en', email))
                else:
                    cur.execute("INSERT INTO users (username, password_hash, language) VALUES (?, ?, ?)",
                               (username, pw_hash, 'en'))
            except sqlite3.OperationalError:
                # Fallback for older schema without email field
                if email:
                    # Try to add email column if it doesn't exist
                    try:
                        cur.execute("ALTER TABLE users ADD COLUMN email TEXT")
                        db.commit()
                        cur.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                                   (username, pw_hash, email))
                    except sqlite3.OperationalError:
                        # If email column can't be added, proceed without email
                        cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                                   (username, pw_hash))
                else:
                    cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                               (username, pw_hash))
            db.commit()
            socketio.emit("user_list_refresh", {"new_user": username})
            # Redirect directly to frontend after successful registration
            frontend_url = request.headers.get('Origin') or request.host_url.replace('5000', '8080')
            return redirect(f"{frontend_url}/login", code=303)
        except sqlite3.IntegrityError:
            return render_template_string(REGISTER_HTML, error="Username taken")

    return render_template_string(REGISTER_HTML, error="")

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        frontend_url = request.headers.get('Origin') or request.host_url.replace('5000', '8080')
        return cors_redirect(f"{frontend_url}/chat")

    client_ip = get_client_ip()
    if is_ip_banned(client_ip):
        return render_template_string(LOGIN_HTML, error="Your IP address is banned"), 403

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "")

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, username, password_hash FROM users WHERE username=?", (username,))
        row = cur.fetchone()

        if row and check_password_hash(row["password_hash"], password):

            # device ban handling
            try:
                cid_cookie = (request.cookies.get('client_id') or '').strip()
                if cid_cookie:
                    cur2 = get_db().cursor()
                    cur2.execute('SELECT 1 FROM device_bans WHERE client_id=? LIMIT 1', (cid_cookie,))
                    if cur2.fetchone():
                        return render_template_string(LOGIN_HTML, error="Your device is banned"), 403
            except Exception:
                pass

            # account ban handling
            if is_banned(username):
                try:
                    if get_setting('SEC_STRICT_ASSOCIATED_BAN', '0') == '1':
                        priv, pub = detect_client_ips()
                        if pub and not _is_loopback_ip(pub):
                            cur.execute('INSERT OR IGNORE INTO banned_ips(ip_address) VALUES(?)', (pub,))
                            get_db().commit()
                except:
                    pass

                try:
                    cid_cookie = (request.cookies.get('client_id') or '').strip()
                    if cid_cookie and get_setting('SEC_DEVICE_BAN_ON_LOGIN', '1') == '1':
                        cur.execute('INSERT OR IGNORE INTO device_bans(client_id, username) VALUES(?,?)',
                                    (cid_cookie, username))
                        get_db().commit()
                except:
                    pass

                return render_template_string(LOGIN_HTML, error="You are banned"), 403

            # IP updating and enforcement
            priv, pub = detect_client_ips()
            _update_user_ips(username, priv, pub)
            if _is_ip_blocked_for(username, priv, pub):
                return render_template_string(LOGIN_HTML, error="Access blocked by IP ban")

            # login session setup
            session.clear()
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            online_users[username] = time.time()

            try:
                cid = (request.cookies.get('client_id') or '').strip()
                info = user_ips.get(username) if isinstance(user_ips.get(username), dict) else {}
                if cid:
                    info = {
                        'private': info.get('private'),
                        'public': info.get('public'),
                        'immune': info.get('immune', _user_immune(username)),
                        'client_id': cid
                    }
                    user_ips[username] = info
            except:
                pass

            try:
                socketio.emit('user_list_refresh', {'online': username})
            except:
                pass

            # redirection after login
            frontend_url = request.headers.get('Origin') or request.host_url.replace('5000', '8080')
            redirect_url = request.args.get('redirect') or session.get('returnUrl') or f"{frontend_url}/chat"
            if 'returnUrl' in session:
                session.pop('returnUrl')

            return cors_redirect(redirect_url)

        return render_template_string(
            LOGIN_HTML,
            error="Invalid username or password. Your account may have been deleted in a recent update, try re-creating it."
        )

    return render_template_string(LOGIN_HTML, error="")
    
@app.route("/logout")
def logout():
    username = session.get("username")
    session.clear()
    if username in online_users:
        online_users.pop(username)
    try:
        socketio.emit('user_list_refresh', { 'offline': username })
    except Exception:
        pass
    return redirect(url_for("login"))

@app.route("/reset-password", methods=["GET"])
def reset_password_page():
    """Frontend route for password reset page"""
    token = request.args.get('token', '')
    username = request.args.get('username', '')
    
    # Render the password reset page
    return render_template_string(RESET_PASSWORD_HTML, 
                           token=token, 
                           username=username, 
                           error="")

# Routes: Chat
# Redirect to frontend - Node.js handles UI
@app.route("/chat")
@login_required
def chat():
    # Get the frontend URL from request or use default
    frontend_url = request.headers.get('Origin') or request.host_url.replace('5000', '8080')
    return redirect(f"{frontend_url}/chat")

@app.route('/call/<call_id>')
@login_required
def call_link(call_id: str):
    try:
        # Get the frontend URL from request or use default
        frontend_url = request.headers.get('Origin') or request.host_url.replace('5000', '8080')
        
        # Join a call by ID; if call exists, redirect to chat with call preselected
        cid = (call_id or '').strip()
        if cid and cid in call_sessions:
            return redirect(f"{frontend_url}/chat?call={cid}")
        # If call doesn't exist, still redirect to chat (user can create new call)
        return redirect(f"{frontend_url}/chat")
    except Exception:
        return redirect(f"{frontend_url}/chat")

@app.route("/api/messages")
@login_required
def api_messages():
    db = get_db()
    cur = db.cursor()
    me = session.get('username')
    cur.execute("SELECT * FROM messages ORDER BY id ASC")
    messages = []
    for row in cur.fetchall():
        author = row["username"] if isinstance(row, sqlite3.Row) else row[2]
        try:
            if author and author != me and is_shadow_banned(author):
                continue
        except Exception:
            pass
        # Reply preview
        rto = None; ruser=None; rsnip=None
        try:
            rto = (row["reply_to"] if isinstance(row, sqlite3.Row) else None)
        except Exception:
            rto = None
        if rto:
            try:
                cur2 = db.cursor(); cur2.execute('SELECT username, text FROM messages WHERE id=?', (rto,))
                rr = cur2.fetchone()
                if rr:
                    ruser = rr[0] if not isinstance(rr, sqlite3.Row) else rr['username']
                    rhtml = rr[1] if not isinstance(rr, sqlite3.Row) else rr['text']
                    try:
                        plain = re.sub(r'<[^>]+>', '', rhtml or '')
                    except Exception:
                        plain = (rhtml or '')
                    rsnip = (plain or '')[:140]
            except Exception:
                pass
        messages.append({
            "id": row["id"],
            "user_id": row["user_id"],
            "username": row["username"],
            "text": row["text"],
            "attachment": row["attachment"],
            "created_at": to_ny_time(row["created_at"]) if row["created_at"] else None,
            "reply_to": rto,
            "reply_username": ruser,
            "reply_snippet": rsnip
        })
    return jsonify(messages)

@app.route("/api/users/search")
@login_required
def api_users_search():
    """Search for users by username prefix"""
    query = request.args.get('q', '').strip()
    offset = int(request.args.get('offset', 0))
    limit = min(int(request.args.get('limit', 20)), 50)  # Max 50 results

    # Validate query
    if not query or len(query) < 2:
        return jsonify({"users": [], "has_more": False, "query": query})

    # Prevent overly broad searches
    if len(query) == 1 and query.isalpha():
        return jsonify({"users": [], "has_more": False, "query": query, "error": "Query too broad"})

    try:
        db = get_db()
        cur = db.cursor()

        # Search for users with username starting with query (case-insensitive)
        # Exclude banned users and get additional info
        cur.execute("""
            SELECT u.username, u.avatar, u.status, u.created_at, u.bio
            FROM users u
            LEFT JOIN banned_users b ON u.username = b.username
            WHERE LOWER(u.username) LIKE LOWER(?)
            AND b.username IS NULL
            ORDER BY LOWER(u.username) ASC
            LIMIT ? OFFSET ?
        """, (f"{query}%", limit + 1, offset))

        results = cur.fetchall()
        has_more = len(results) > limit
        users = results[:limit]

        # Format user data
        user_list = []
        for user in users:
            user_data = {
                "username": user[0],
                "avatar": user[1],
                "status": user[2] or "offline",
                "created_at": user[3],
                "bio": user[4] or ""
            }
            user_list.append(user_data)

        return jsonify({
            "users": user_list,
            "has_more": has_more,
            "query": query,
            "total_shown": len(user_list)
        })

    except Exception as e:
        return jsonify({"users": [], "has_more": False, "query": query, "error": "Search failed"}), 500


@app.route("/api/voice/channels")
@login_required
def api_voice_channels():
    try:
        chans = sorted([k for k,v in voice_channels.items() if v and len(v)>0])
        return jsonify({'ok': True, 'channels': chans})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e), 'channels': []}), 200

@app.route("/api/dm/peers")
@login_required
def api_dm_peers():
    me = session.get("username")
    db = get_db()
    cur = db.cursor()
    cur.execute(
        """
        SELECT DISTINCT CASE WHEN from_user=? THEN to_user ELSE from_user END AS peer
        FROM direct_messages
        WHERE from_user=? OR to_user=?
        ORDER BY LOWER(peer) ASC
        """,
        (me, me, me),
    )
    peers = [r[0] for r in cur.fetchall()]
    print(f"DM peers for {me}: {peers}")  # Debug log
    return jsonify(peers)

@app.route("/api/dm/messages")
@login_required
def api_dm_messages():
    me = session.get("username")
    peer = (request.args.get("peer") or "").strip()
    if not peer:
        return jsonify([])
    db = get_db()
    cur = db.cursor()
    cur.execute(
        """
        SELECT id, from_user, to_user, text, attachment, created_at, reply_to
        FROM direct_messages
        WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)
        ORDER BY id ASC
        """,
        (me, peer, peer, me),
    )
    rows = cur.fetchall()
    out = []
    for r in rows:
        # Hide messages authored by shadow-banned users (except my own)
        try:
            if r[1] and r[1] != me:
                try:
                    if is_shadow_banned(r[1]):
                        continue
                except Exception:
                    pass
        except Exception:
            pass
        # Reply preview
        rto = None; ruser=None; rsnip=None
        try:
            rto = r[6]
        except Exception:
            rto = None
        if rto:
            try:
                cur2 = db.cursor(); cur2.execute('SELECT from_user, text FROM direct_messages WHERE id=?', (rto,))
                rr = cur2.fetchone()
                if rr:
                    ruser = rr[0]
                    rhtml = rr[1]
                    try:
                        plain = re.sub(r'<[^>]+>', '', rhtml or '')
                    except Exception:
                        plain = (rhtml or '')
                    rsnip = (plain or '')[:140]
            except Exception:
                pass
        out.append(
            {
                "id": r[0],
                "from_user": r[1],
                "to_user": r[2],
                "text": r[3],
                "attachment": r[4],
                "created_at": to_ny_time(r[5]) if r[5] else None,
                "reply_to": rto,
                "reply_username": ruser,
                "reply_snippet": rsnip,
                "avatar": '/sys_pfp.png' if r[1] == 'System' else None,
            }
        )
    return jsonify(out)

# Group DM APIs
@app.route('/api/gdm/threads', methods=['GET','POST'])
@login_required
def api_gdm_threads():
    me = session.get('username')
    try:
        _ensure_gdm_schema()
    except Exception:
        pass
    db = get_db(); cur = db.cursor()
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        name = (data.get('name') or '').strip() or f"Group {datetime.utcnow().strftime('%H%M%S')}"
        members = list(set([(m or '').strip() for m in (data.get('members') or []) if m and m.strip()]))
        if me not in members:
            members.append(me)
        if not members or len(members) < 2:
            return jsonify({'error':'need at least 2 members'}), 400
        # Generate unique invite code
        import random, string
        invite_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        cur.execute('INSERT INTO group_threads (name, created_by, created_at, invite_code) VALUES (?, ?, ?, ?)', (name, me, datetime.utcnow(), invite_code))
        tid = cur.lastrowid
        for u in members:
            cur.execute('INSERT OR IGNORE INTO group_members (thread_id, username) VALUES (?,?)', (tid, u))
        db.commit()
        return jsonify({'ok': True, 'id': tid, 'name': name, 'invite_code': invite_code})
    # GET: list my group threads
    try:
        cur.execute("""
            SELECT t.id, t.name, t.created_by, t.created_at, t.invite_code
            FROM group_threads t JOIN group_members m ON t.id=m.thread_id
            WHERE m.username=?
            ORDER BY t.id ASC
        """, (me,))
        rows = cur.fetchall() or []
        out = []
        for r in rows:
            try:
                out.append({'id': r[0], 'name': r[1], 'created_by': r[2], 'created_at': to_ny_time(r[3]) if r[3] else None, 'invite_code': r[4]})
            except Exception:
                # Fallback if row is sqlite3.Row
                try:
                    out.append({'id': r['id'], 'name': r['name'], 'created_by': r['created_by'], 'created_at': to_ny_time(r['created_at']) if r['created_at'] else None, 'invite_code': r['invite_code']})
                except Exception:
                    pass
        return jsonify(out)
    except Exception:
        # Likely missing columns; retry without them
        try:
            cur.execute("""
                SELECT t.id, t.name, t.created_by, t.created_at
                FROM group_threads t JOIN group_members m ON t.id=m.thread_id
                WHERE m.username=?
                ORDER BY t.id ASC
            """, (me,))
            rows = cur.fetchall() or []
            out = [{'id': r[0], 'name': r[1], 'created_by': r[2], 'created_at': to_ny_time(r[3]) if r[3] else None} for r in rows]
            return jsonify(out)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/gdm/join', methods=['POST'])
@login_required
def api_gdm_join_invite():
    """Join a GDM using an invite code"""
    me = session.get('username')
    try:
        _ensure_gdm_schema()
    except Exception:
        return jsonify({'error':'database error'}), 500
    
    data = request.get_json(silent=True) or {}
    invite_code = data.get('invite_code', '').strip().upper()
    
    if not invite_code:
        return jsonify({'error':'invite code required'}), 400
    
    db = get_db(); cur = db.cursor()
    # Find thread by invite code
    cur.execute('SELECT id, name FROM group_threads WHERE invite_code=?', (invite_code,))
    thread = cur.fetchone()
    
    if not thread:
        return jsonify({'error':'invalid invite code'}), 404
    
    thread_id, thread_name = thread
    
    # Check if already a member
    cur.execute('SELECT COUNT(*) FROM group_members WHERE thread_id=? AND username=?', (thread_id, me))
    if cur.fetchone()[0] > 0:
        return jsonify({'error':'already a member'}), 400
    
    # Check if banned
    cur.execute('SELECT COUNT(*) FROM group_bans WHERE thread_id=? AND username=?', (thread_id, me))
    if cur.fetchone()[0] > 0:
        return jsonify({'error':'banned from this group'}), 403
    
    # Add as member
    cur.execute('INSERT INTO group_members (thread_id, username) VALUES (?,?)', (thread_id, me))
    db.commit()
    
    # Notify all members
    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (thread_id,))
    members = [r[0] for r in cur.fetchall()]
    for u in members:
        socketio.emit('gdm_threads_refresh', {'tid': thread_id}, room=f'user:{u}')
    
    return jsonify({'id': thread_id, 'name': thread_name, 'invite_code': invite_code})

@app.route('/api/gdm/messages')
@login_required
def api_gdm_messages():
    me = session.get('username')
    try:
        tid = int((request.args.get('tid') or '0'))
    except Exception:
        tid = 0
    if not tid:
        return jsonify([])
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT 1 FROM group_members WHERE thread_id=? AND username=?', (tid, me))
    if not cur.fetchone():
        return jsonify([])
    cur.execute('SELECT id, username, text, attachment, created_at, edited, reply_to FROM group_messages WHERE thread_id=? ORDER BY id ASC', (tid,))
    out=[]
    for r in cur.fetchall():
        try:
            author = r[1]
            if author and author != me:
                try:
                    if is_shadow_banned(author):
                        continue
                except Exception:
                    pass
        except Exception:
            pass
        rto=None; ruser=None; rsnip=None
        try:
            rto = r[6]
        except Exception:
            rto = None
        if rto:
            try:
                cur2 = db.cursor(); cur2.execute('SELECT username, text FROM group_messages WHERE id=?', (rto,))
                rr = cur2.fetchone()
                if rr:
                    ruser = rr[0] if not isinstance(rr, sqlite3.Row) else rr['username']
                    rhtml = rr[1] if not isinstance(rr, sqlite3.Row) else rr['text']
                    try:
                        plain = re.sub(r'<[^>]+>', '', rhtml or '')
                    except Exception:
                        plain = (rhtml or '')
                    rsnip = (plain or '')[:140]
            except Exception:
                pass
        out.append({'id': r[0], 'username': r[1], 'text': r[2], 'attachment': r[3], 'created_at': to_ny_time(r[4]) if r[4] else None, 'edited': r[5] or 0, 'reply_to': rto, 'reply_username': ruser, 'reply_snippet': rsnip})
    return jsonify(out)

@app.route('/api/gdm/rename', methods=['POST'])
@login_required
def api_gdm_rename():
    me = session.get('username')
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    name = (data.get('name') or '').strip()
    print(f"Rename attempt: user={me}, tid={tid}, name={name}")  # Debug
    if not tid or not name:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'not found'}), 404
    creator = row[0]
    if not (me == creator or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    
    print(f"Updating group {tid} to name '{name}'")  # Debug
    cur.execute('UPDATE group_threads SET name=? WHERE id=?', (name, tid))
    db.commit()
    print(f"Database updated, affected rows: {cur.rowcount}")  # Debug
    
    # notify all members to refresh
    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
    members = [r[0] for r in cur.fetchall()]
    for u in members:
        socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{u}')
    return jsonify({'ok': True})

# Group management endpoints (toggle-gated)
@app.route('/api/gdm/lock', methods=['POST'])
@login_required
def api_gdm_lock():
    me = session.get('username')
    try:
        if get_setting('GD_LOCK_GROUP','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    if not tid:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    r = cur.fetchone()
    if not r:
        return jsonify({'error':'not found'}), 404
    owner = r[0] if not isinstance(r, sqlite3.Row) else r['created_by']
    if not (me == owner or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    cur.execute('UPDATE group_threads SET locked=1 WHERE id=?', (tid,))
    db.commit()
    try:
        cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
        for u in [x[0] for x in cur.fetchall()]:
            socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{u}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/gdm/unlock', methods=['POST'])
@login_required
def api_gdm_unlock():
    me = session.get('username')
    try:
        if get_setting('GD_UNLOCK_GROUP','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    if not tid:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    r = cur.fetchone()
    if not r:
        return jsonify({'error':'not found'}), 404
    owner = r[0] if not isinstance(r, sqlite3.Row) else r['created_by']
    if not (me == owner or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    cur.execute('UPDATE group_threads SET locked=0 WHERE id=?', (tid,))
    db.commit()
    try:
        cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
        for u in [x[0] for x in cur.fetchall()]:
            socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{u}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/gdm/remove_member', methods=['POST'])
@login_required
def api_gdm_remove_member():
    me = session.get('username')
    try:
        if get_setting('GD_REMOVE_USER','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    user = sanitize_username((data.get('username') or '').strip())
    if not tid or not user:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    r = cur.fetchone()
    if not r:
        return jsonify({'error':'not found'}), 404
    owner = r[0] if not isinstance(r, sqlite3.Row) else r['created_by']
    if not (me == owner or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    if user == owner:
        return jsonify({'error':'cannot remove owner'}), 400
    cur.execute('DELETE FROM group_members WHERE thread_id=? AND username=?', (tid, user))
    db.commit()
    try:
        socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{user}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/gdm/delete', methods=['POST'])
@login_required
def api_gdm_delete_group():
    me = session.get('username')
    try:
        if get_setting('GD_DELETE_GROUP','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    if not tid:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    r = cur.fetchone()
    if not r:
        return jsonify({'error':'not found'}), 404
    owner = r[0] if not isinstance(r, sqlite3.Row) else r['created_by']
    if not (me == owner or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    try:
        cur.execute('DELETE FROM group_messages WHERE thread_id=?', (tid,))
    except Exception:
        pass
    try:
        cur.execute('DELETE FROM group_members WHERE thread_id=?', (tid,))
    except Exception:
        pass
    cur.execute('DELETE FROM group_threads WHERE id=?', (tid,))
    db.commit()
    # If this was the last group and toggle enabled, reset group id sequences
    try:
        cur.execute('SELECT COUNT(1) FROM group_threads')
        left = (cur.fetchone() or [0])[0]
        if int(left or 0) == 0 and get_setting('RESET_ID_GROUP_THREADS','0')=='1':
            try:
                cur.execute("DELETE FROM sqlite_sequence WHERE name IN ('group_threads','group_members','group_messages')")
                db.commit()
            except Exception:
                pass
    except Exception:
        pass
    # notify: users who had membership get a refresh (best-effort, using prior members is tricky after delete)
    try:
        socketio.emit('gdm_threads_refresh', {'deleted': tid})
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/gdm/force_leave', methods=['POST'])
@login_required
def api_gdm_force_leave():
    me = session.get('username')
    try:
        if get_setting('GD_FORCE_LEAVE_GROUP','1')=='0':
            return jsonify({'error':'disabled'}), 403
    except Exception:
        pass
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    user = sanitize_username((data.get('username') or '').strip())
    if not tid or not user:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    r = cur.fetchone()
    if not r:
        return jsonify({'error':'not found'}), 404
    owner = r[0] if not isinstance(r, sqlite3.Row) else r['created_by']
    if not (me == owner or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    if user == owner:
        return jsonify({'error':'cannot force owner'}), 400
    cur.execute('DELETE FROM group_members WHERE thread_id=? AND username=?', (tid, user))
    db.commit()
    try:
        socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{user}')
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/clear/all', methods=['POST'])
@login_required
def api_clear_all():
    me = session.get('username')
    if not me:
        return jsonify({'error': 'not logged in'}), 401
    db = get_db()
    cur = db.cursor()
    removed = {'public':0,'dm':0,'gdm':0}
    did_reset_public = False
    did_reset_gdm = False
    # Public: only superadmins can nuke all public messages
    if is_superadmin(me):
        try:
            cur.execute('DELETE FROM messages')
            removed['public'] = cur.rowcount if hasattr(cur, 'rowcount') else 0
            # Reset message IDs if toggle enabled
            try:
                if get_setting('RESET_PUBLIC_IDS','0')=='1':
                    try:
                        cur.execute("DELETE FROM sqlite_sequence WHERE name='messages'")
                        did_reset_public = True
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass
    # DMs: clear all DMs involving me
    try:
        cur.execute('DELETE FROM direct_messages WHERE from_user=? OR to_user=?', (me, me))
        removed['dm'] = cur.rowcount if hasattr(cur, 'rowcount') else 0
    except Exception:
        pass
    # Group messages: superadmin can nuke all, regular users only their authored messages
    try:
        if is_superadmin(me):
            cur.execute('DELETE FROM group_messages')
        else:
            cur.execute('DELETE FROM group_messages WHERE username=?', (me,))
        removed['gdm'] = cur.rowcount if hasattr(cur, 'rowcount') else 0
        # If SA cleared all, optionally reset GDM ids
        try:
            if is_superadmin(me) and get_setting('RESET_GDM_IDS','0')=='1':
                try:
                    cur.execute("DELETE FROM sqlite_sequence WHERE name='group_messages'")
                    did_reset_gdm = True
                except Exception:
                    pass
        except Exception:
            pass
    except Exception:
        pass
    try:
        db.commit()
    except Exception:
        pass
    # Audit: record ID resets if any occurred
    try:
        if did_reset_public or did_reset_gdm:
            log_admin_action(me, 'reset_ids', details={'public': bool(did_reset_public), 'gdm': bool(did_reset_gdm), 'removed': removed})
    except Exception:
        pass
    # Notify this user client to clear UI
    try:
        emit('clear_all', {}, room=f'user:{me}')
    except Exception:
        pass
    return jsonify({'ok': True, 'removed': removed})

@app.route('/api/gdm/kick', methods=['POST'])
@login_required
def api_gdm_kick():
    me = session.get('username')
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    user = sanitize_username((data.get('user') or '').strip())
    if not tid or not user:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    # Must be owner or superadmin
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'not found'}), 404
    creator = row[0]
    if not (me == creator or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    # Remove membership
    cur.execute('DELETE FROM group_members WHERE thread_id=? AND username=?', (tid, user))
    db.commit()
    # Notify
    emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{user}')
    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
    for r2 in cur.fetchall():
        emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{r2[0]}')
    return jsonify({'ok': True})

@app.route('/api/gdm/add_member', methods=['POST'])
@login_required
def api_gdm_add_member():
    me = session.get('username')
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    users = data.get('users') or []
    users = [ (u or '').strip() for u in users if u and u.strip() ]
    if not tid or not users:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'not found'}), 404
    creator = row[0]
    if not (me == creator or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    for u in users:
        cur.execute('INSERT OR IGNORE INTO group_members (thread_id, username) VALUES (?,?)', (tid, u))
    db.commit()
    # notify all existing and new members
    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
    members = [r[0] for r in cur.fetchall()]
    for u in members:
        socketio.emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{u}')
    return jsonify({'ok': True})

@app.route('/api/gdm/update', methods=['POST'])
@login_required
def api_gdm_update():
    """Update group name or description"""
    me = session.get('username')
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid', 0))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid thread ID'}), 400
    
    if not tid:
        return jsonify({'error': 'Thread ID required'}), 400
    
    # Check if user is owner or superadmin
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error': 'Group not found'}), 404
    
    owner = row[0] if not isinstance(row, sqlite3.Row) else row['created_by']
    if not (is_superadmin(me) or (owner and owner == me)):
        return jsonify({'error': 'Forbidden - only owner or superadmin can update group'}), 403
    
    # Update group information
    name = data.get('name')
    description = data.get('description')
    
    if name:
        cur.execute('UPDATE group_threads SET name=? WHERE id=?', (name, tid))
    
    # Note: description would need to be added to the database schema
    # For now, we'll just update the name
    
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/gdm/delete', methods=['POST'])
@login_required
def api_gdm_delete():
    me = session.get('username')
    data = request.get_json(silent=True) or {}
    try:
        tid = int(data.get('tid') or 0)
    except Exception:
        tid = 0
    if not tid:
        return jsonify({'error':'bad params'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT created_by FROM group_threads WHERE id=?', (tid,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'not found'}), 404
    creator = row[0]
    if not (me == creator or is_superadmin(me)):
        return jsonify({'error':'forbidden'}), 403
    # collect members for notification
    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
    members = [r[0] for r in cur.fetchall()]
    cur.execute('DELETE FROM group_messages WHERE thread_id=?', (tid,))
    cur.execute('DELETE FROM group_members WHERE thread_id=?', (tid,))
    cur.execute('DELETE FROM group_threads WHERE id=?', (tid,))
    db.commit()
    for u in set(members):
        socketio.emit('gdm_threads_refresh', {'deleted': tid}, room=f'user:{u}')
    return jsonify({'ok': True})

@app.route("/api/online")
@login_required
def api_online():
    cutoff = time.time() - 60
    return jsonify([u for u, t in online_users.items() if t > cutoff])

@app.route("/api/users_profiles")
@login_required
def api_users_profiles():
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT username, avatar, bio, status FROM users ORDER BY LOWER(username) ASC")
    now = time.time(); cutoff = now - 60; idle_cutoff = now - 20
    out=[]
    for r in cur.fetchall():
        u = r[0]
        avatar = r[1]
        bio = r[2] or ""
        pref_status = (r[3] or '').lower()
        last = online_users.get(u, 0)
        # Manual status override: always respected if set
        if pref_status in ('online','idle','dnd','offline'):
            presence = pref_status
        else:
            if last > cutoff:
                presence = 'online' if last >= idle_cutoff else 'idle'
            else:
                presence = 'offline'
        out.append({
            "username": u,
            "avatar": avatar,
            "avatar_url": (f"/uploads/{avatar}" if avatar else url_for('default_avatar')),
            "bio": bio,
            "status": pref_status or '',
            "presence": presence,
        })
    return jsonify(out)

@app.route('/default_avatar')
def default_avatar():
    return send_from_directory(APP_ROOT, DEFAULT_AVATAR)

@app.route('/default_sys_avatar')
def default_sys_avatar():
    return send_from_directory(APP_ROOT, DEFAULT_SYS_AVATAR)

@app.route('/api/gdm/members')
@login_required
def api_gdm_members():
    me = session.get('username')
    try:
        tid = int((request.args.get('tid') or '0'))
    except Exception:
        tid = 0
    if not tid:
        return jsonify([])
    db = get_db(); cur = db.cursor()
    # Only members can view the member list
    cur.execute('SELECT 1 FROM group_members WHERE thread_id=? AND username=?', (tid, me))
    if not cur.fetchone():
        return jsonify([])
    cur.execute('SELECT username FROM group_members WHERE thread_id=? ORDER BY LOWER(username) ASC', (tid,))
    return jsonify([r[0] for r in cur.fetchall()])

# Group DM Invite API
@app.route('/api/gdm/invite/create', methods=['POST'])
@login_required
def api_gdm_invite_create():
    me = session.get('username')
    data = request.get_json(silent=True) or {}
    try:
        tid = int((data.get('tid') or 0))
    except Exception:
        tid = 0
    if not tid:
        return jsonify({'error':'invalid tid'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT 1 FROM group_members WHERE thread_id=? AND username=?', (tid, me))
    if not cur.fetchone():
        return jsonify({'error':'not a member'}), 403
    token = secrets.token_urlsafe(16)
    cur.execute('INSERT INTO group_invites(token, thread_id, created_by, created_at) VALUES(?,?,?,?)', (token, tid, me, to_ny_time(datetime.utcnow())))
    db.commit()
    link = url_for('api_gdm_invite_join', _external=True) + f"?token={token}"
    return jsonify({'ok':True,'token':token,'link':link})

@app.route('/api/gdm/invite/join', methods=['GET','POST'])
@login_required
def api_gdm_invite_join():
    me = session.get('username')
    token = (request.values.get('token') or '').strip()
    if not token:
        return jsonify({'error':'invalid'}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT thread_id FROM group_invites WHERE token=?', (token,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error':'not found'}), 404
    tid = row[0] if not isinstance(row, sqlite3.Row) else row['thread_id']
    cur.execute('INSERT OR IGNORE INTO group_members(thread_id, username) VALUES(?,?)', (tid, me))
    db.commit()
    # GET -> redirect back into app so user sees the group, POST -> JSON
    if request.method == 'GET':
        return redirect(url_for('chat', tid=tid))
    return jsonify({'ok':True,'thread_id':tid})

# ============================================================================
# DOC CHANNEL APIs
# ============================================================================

@app.route('/api/doc/create', methods=['POST'])
@login_required
def api_doc_create():
    me = session.get('username')
    _ensure_doc_schema()
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name or len(name) > 100:
        return jsonify({'error': 'invalid name'}), 400
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('INSERT INTO docs (name, created_by, created_at) VALUES (?, ?, ?)',
                    (name, me, datetime.utcnow()))
        doc_id = cur.lastrowid
        cur.execute('INSERT INTO doc_members (doc_id, username, role) VALUES (?, ?, ?)', (doc_id, me, 'editor'))
        db.commit()
        doc_sessions[doc_id] = {
            'content': '',
            'last_edit_time': time.time(),
            'users': {me},
            'tmpweb_url': None,
            'tmpweb_expires': None,
            'idle_timer': None
        }
        return jsonify({'ok': True, 'doc_id': doc_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/doc/list')
@login_required
def api_doc_list():
    me = session.get('username')
    _ensure_doc_schema()
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('''SELECT d.id, d.name, d.created_by, d.created_at, d.last_edited_by, d.last_edited_at, d.tmpweb_url, d.tmpweb_expires_at
                       FROM docs d
                       INNER JOIN doc_members m ON d.id = m.doc_id
                       WHERE m.username = ?
                       ORDER BY d.last_edited_at DESC NULLS LAST''', (me,))
        docs = []
        for r in cur.fetchall():
            doc_id = r[0] if not isinstance(r, sqlite3.Row) else r['id']
            docs.append({
                'id': doc_id,
                'name': r[1] if not isinstance(r, sqlite3.Row) else r['name'],
                'created_by': r[2] if not isinstance(r, sqlite3.Row) else r['created_by'],
                'created_at': to_ny_time(r[3]) if r[3] else None,
                'last_edited_by': r[4] if not isinstance(r, sqlite3.Row) else r['last_edited_by'],
                'last_edited_at': to_ny_time(r[5]) if r[5] else None,
                'tmpweb_url': r[6] if not isinstance(r, sqlite3.Row) else r['tmpweb_url'],
                'tmpweb_expires_at': to_ny_time(r[7]) if r[7] else None
            })
        return jsonify(docs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/doc/<int:doc_id>')
@login_required
def api_doc_get(doc_id):
    me = session.get('username')
    _ensure_doc_schema()
    try:
        db = get_db(); cur = db.cursor()
        if not can_view_doc(doc_id, me):
            return jsonify({'error': 'access denied'}), 403
        cur.execute('SELECT id, name, created_by, created_at, content, last_edited_by, last_edited_at, tmpweb_url, tmpweb_expires_at FROM docs WHERE id=?', (doc_id,))
        r = cur.fetchone()
        if not r:
            return jsonify({'error': 'not found'}), 404
        # Load from session if available, otherwise from DB
        content = doc_sessions.get(doc_id, {}).get('content') or (r[4] if not isinstance(r, sqlite3.Row) else r['content']) or ''
        return jsonify({
            'id': r[0] if not isinstance(r, sqlite3.Row) else r['id'],
            'name': r[1] if not isinstance(r, sqlite3.Row) else r['name'],
            'created_by': r[2] if not isinstance(r, sqlite3.Row) else r['created_by'],
            'created_at': to_ny_time(r[3]) if r[3] else None,
            'content': content,
            'last_edited_by': r[5] if not isinstance(r, sqlite3.Row) else r['last_edited_by'],
            'last_edited_at': to_ny_time(r[6]) if r[6] else None,
            'tmpweb_url': r[7] if not isinstance(r, sqlite3.Row) else r['tmpweb_url'],
            'tmpweb_expires_at': to_ny_time(r[8]) if r[8] else None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/doc/<int:doc_id>/members')
@login_required
def api_doc_members(doc_id):
    me = session.get('username')
    _ensure_doc_schema()
    try:
        db = get_db(); cur = db.cursor()
        if not can_view_doc(doc_id, me):
            return jsonify({'error': 'access denied'}), 403
        cur.execute('SELECT username, role FROM doc_members WHERE doc_id=?', (doc_id,))
        members = []
        for r in cur.fetchall():
            members.append({
                'username': r[0] if not isinstance(r, sqlite3.Row) else r['username'],
                'role': r[1] if not isinstance(r, sqlite3.Row) else r['role']
            })
        return jsonify(members)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/doc/<int:doc_id>/add_member', methods=['POST'])
@login_required
def api_doc_add_member(doc_id):
    me = session.get('username')
    _ensure_doc_schema()
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    role = (data.get('role') or 'viewer').strip().lower()

    # Validate role
    valid_roles = ['viewer', 'editor']
    if role not in valid_roles:
        return jsonify({'error': f'invalid role. Must be one of: {", ".join(valid_roles)}'}), 400

    if not username:
        return jsonify({'error': 'username required'}), 400
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT created_by FROM docs WHERE id=?', (doc_id,))
        r = cur.fetchone()
        if not r or (r[0] if not isinstance(r, sqlite3.Row) else r['created_by']) != me:
            return jsonify({'error': 'only creator can add members'}), 403
        cur.execute('INSERT OR IGNORE INTO doc_members (doc_id, username, role) VALUES (?, ?, ?)', (doc_id, username, role))
        db.commit()
        socketio.emit('doc_members_updated', {'doc_id': doc_id}, room=f'doc:{doc_id}')
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/doc/<int:doc_id>/update_member_role', methods=['POST'])
@login_required
def api_doc_update_member_role(doc_id):
    me = session.get('username')
    _ensure_doc_schema()
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    role = (data.get('role') or '').strip().lower()

    # Validate role
    valid_roles = ['viewer', 'editor']
    if role not in valid_roles:
        return jsonify({'error': f'invalid role. Must be one of: {", ".join(valid_roles)}'}), 400

    if not username:
        return jsonify({'error': 'username required'}), 400

    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT created_by FROM docs WHERE id=?', (doc_id,))
        r = cur.fetchone()
        if not r or (r[0] if not isinstance(r, sqlite3.Row) else r['created_by']) != me:
            return jsonify({'error': 'only creator can update member roles'}), 403

        # Don't allow changing the creator's role
        if username == me:
            return jsonify({'error': 'cannot change your own role'}), 400

        cur.execute('UPDATE doc_members SET role=? WHERE doc_id=? AND username=?', (role, doc_id, username))
        db.commit()
        socketio.emit('doc_members_updated', {'doc_id': doc_id}, room=f'doc:{doc_id}')
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/doc/<int:doc_id>/remove_member', methods=['POST'])
@login_required
def api_doc_remove_member(doc_id):
    me = session.get('username')
    _ensure_doc_schema()
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({'error': 'username required'}), 400
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT created_by FROM docs WHERE id=?', (doc_id,))
        r = cur.fetchone()
        if not r or (r[0] if not isinstance(r, sqlite3.Row) else r['created_by']) != me:
            return jsonify({'error': 'only creator can remove members'}), 403
        cur.execute('DELETE FROM doc_members WHERE doc_id=? AND username=?', (doc_id, username))
        db.commit()
        socketio.emit('doc_members_updated', {'doc_id': doc_id}, room=f'doc:{doc_id}')
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/doc/<int:doc_id>/delete', methods=['POST'])
@login_required
def api_doc_delete(doc_id):
    me = session.get('username')
    _ensure_doc_schema()
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT created_by, name FROM docs WHERE id=?', (doc_id,))
        r = cur.fetchone()
        if not r or (r[0] if not isinstance(r, sqlite3.Row) else r['created_by']) != me:
            return jsonify({'error': 'only creator can delete document'}), 403

        # Delete document members first
        cur.execute('DELETE FROM doc_members WHERE doc_id=?', (doc_id,))
        # Delete the document
        cur.execute('DELETE FROM docs WHERE id=?', (doc_id,))
        db.commit()

        # Emit socket event for real-time updates
        socketio.emit('doc_deleted', {'doc_id': doc_id}, room=f'doc:{doc_id}')

        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/store-return-url", methods=["POST"])
@login_required
def store_return_url():
    """Store the return URL in session for post-login redirect"""
    data = request.get_json()
    if data and 'returnUrl' in data:
        session['returnUrl'] = data['returnUrl']
    return jsonify({"ok": True})

@app.route('/api/settings', methods=['POST'])
@login_required
def api_settings():
    me_id = session.get('user_id')
    me = session.get('username')
    db = get_db(); cur = db.cursor()
    # Load current row
    cur.execute('SELECT id, username, password_hash FROM users WHERE id=?', (me_id,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error': 'not found'}), 404
    data = request.get_json(silent=True) or {}
    new_username = sanitize_username((data.get('new_username') or '').strip())
    new_password = data.get('new_password') or ''
    theme = (data.get('theme') or '').strip().lower()
    bio = data.get('bio')
    # Only update status if the client explicitly sends a status field; otherwise keep existing DB value
    status_raw = data.get('status') if 'status' in data else None
    language = (data.get('language') or '').strip()
    changed = False

    # Username change with rollback protection
    if new_username and new_username.lower() != 'system' and new_username != (row['username'] if isinstance(row, sqlite3.Row) else row[1]):
        old_username = row['username'] if isinstance(row, sqlite3.Row) else row[1]

        # Validate username length (should already be sanitized, but double-check)
        if len(new_username) > 20:
            return jsonify({'error': 'username too long (max 20 characters)'}), 400

        # Check if username is taken
        try:
            cur.execute('SELECT 1 FROM users WHERE username=?', (new_username,))
            if cur.fetchone():
                return jsonify({'error': 'username taken'}), 400
        except Exception:
            pass

        # Store change history BEFORE making changes (for rollback)
        try:
            cur.execute('INSERT INTO username_change_history (user_id, old_username, new_username) VALUES (?, ?, ?)',
                       (me_id, old_username, new_username))
        except Exception:
            pass

        # Use timeout + normal SQLite transaction (avoid nested BEGIN)
        try:
            try:
                # Set a timeout for any locks (5 seconds)
                db.execute('PRAGMA busy_timeout = 5000')
            except Exception:
                pass

            try:
                # Update username in users table
                cur.execute('UPDATE users SET username=? WHERE id=?', (new_username, me_id))

                # Update username in all related tables
                cur.execute('UPDATE messages SET username=? WHERE username=?', (new_username, old_username))
                cur.execute('UPDATE direct_messages SET from_user=? WHERE from_user=?', (new_username, old_username))
                cur.execute('UPDATE direct_messages SET to_user=? WHERE to_user=?', (new_username, old_username))
                cur.execute('UPDATE group_members SET username=? WHERE username=?', (new_username, old_username))
                cur.execute('UPDATE group_threads SET created_by=? WHERE created_by=?', (new_username, old_username))
                cur.execute('UPDATE doc_members SET username=? WHERE username=?', (new_username, old_username))
                cur.execute('UPDATE docs SET created_by=? WHERE created_by=?', (new_username, old_username))
                cur.execute('UPDATE docs SET last_edited_by=? WHERE last_edited_by=?', (new_username, old_username))

                # Commit transaction
                db.commit()
                changed = True

                # Update in-memory structures only after successful commit
                if old_username in online_users:
                    online_users[new_username] = online_users.pop(old_username)
                if old_username in ADMINS:
                    ADMINS.add(new_username); ADMINS.discard(old_username)
                if old_username in SUPERADMINS:
                    SUPERADMINS.add(new_username); SUPERADMINS.discard(old_username)
                session['username'] = new_username
                me = new_username

            except Exception as e:
                # Rollback on any error
                try:
                    db.rollback()
                except Exception:
                    pass
                # Attempt to restore old username
                try:
                    cur.execute('UPDATE users SET username=? WHERE id=?', (old_username, me_id))
                    db.commit()
                    # Mark history entry as rolled back
                    cur.execute('UPDATE username_change_history SET rolled_back=1 WHERE user_id=? AND new_username=? ORDER BY id DESC LIMIT 1',
                               (me_id, new_username))
                    db.commit()
                except Exception:
                    pass
                return jsonify({'error': f'username change failed: {str(e)}'}), 500

        except Exception as e:
            # If transaction fails entirely, try to rollback
            try:
                db.rollback()
            except Exception:
                pass
            # Attempt to restore old username
            try:
                cur.execute('UPDATE users SET username=? WHERE id=?', (old_username, me_id))
                db.commit()
                # Mark history entry as rolled back
                cur.execute('UPDATE username_change_history SET rolled_back=1 WHERE user_id=? AND new_username=? ORDER BY id DESC LIMIT 1',
                           (me_id, new_username))
                db.commit()
            except Exception:
                pass
            return jsonify({'error': f'username change failed: {str(e)}'}), 500
    if new_password:
        current_password = data.get('current_password') or ''
        pw_hash = row['password_hash'] if isinstance(row, sqlite3.Row) else row[2]
        if not current_password or not check_password_hash(pw_hash, current_password):
            return jsonify({'error': 'invalid current password'}), 403
        cur.execute('UPDATE users SET password_hash=? WHERE id=?', (generate_password_hash(new_password), me_id))
        changed = True
    if theme in ('light','dark'):
        cur.execute('UPDATE users SET theme=? WHERE id=?', (theme, me_id))
        changed = True
    if bio is not None:
        # Enforce max bio length of 300 characters
        try:
            bio = (bio or '')[:300]
        except Exception:
            bio = (bio or '')
        cur.execute('UPDATE users SET bio=? WHERE id=?', (bio, me_id))
        changed = True
    if status_raw is not None:
        status = (status_raw or '').strip().lower()
        if status in ('online','idle','dnd','offline',''):
            cur.execute('UPDATE users SET status=? WHERE id=?', (status or None, me_id))
            changed = True
    if language:
        if language not in SUPPORTED_LANGUAGE_CODES:
            language = None
        else:
            cur.execute('UPDATE users SET language=? WHERE id=?', (language, me_id))
            changed = True
    
    # Handle email update
    email = data.get('email')
    if email is not None:
        email = email.strip()
        if email:
            # Validate email format
            if '@' not in email or '.' not in email:
                return jsonify({'error': 'invalid email format'}), 400
        try:
            # Try to update email (column may not exist in older schemas)
            cur.execute('UPDATE users SET email=? WHERE id=?', (email if email else None, me_id))
            changed = True
        except sqlite3.OperationalError:
            # Email column doesn't exist, try to add it
            try:
                cur.execute('ALTER TABLE users ADD COLUMN email TEXT')
                cur.execute('UPDATE users SET email=? WHERE id=?', (email if email else None, me_id))
                changed = True
            except sqlite3.OperationalError:
                # If we can't add the column, just skip email update
                pass
    
    if changed:
        db.commit()
    return jsonify({'ok': True, 'username': session.get('username')})

@app.route('/api/upload/avatar', methods=['POST'])
def api_upload_avatar():
    try:
        # Manual login check for API
        if not session.get('username'):
            return jsonify({'error': 'not logged in'}), 401
            
        print("Avatar upload request received")
        
        if 'avatar' not in request.files:
            print("No avatar file in request")
            return jsonify({'error':'file required'}), 400
        file = request.files['avatar']
        print(f"File received: {file.filename}")
        
        if not file.filename:
            print("Empty filename")
            return jsonify({'error':'empty filename'}), 400
        
        # Check AVATAR_FOLDER
        print(f"AVATAR_FOLDER: {AVATAR_FOLDER}")
        print(f"AVATAR_FOLDER exists: {os.path.exists(AVATAR_FOLDER)}")
        
        # Use the correct safe_save_file function (the one that takes folder parameter)
        print("Attempting to save file...")
        saved = safe_save_file(file, folder=AVATAR_FOLDER)
        print(f"File saved result: {saved}")
        
        if not saved:
            print("Failed to save file")
            return jsonify({'error':'Failed to save file'}), 400
        
        # Store as avatars/filename for consistency
        avatar_path = f"avatars/{saved}"
        print(f"Avatar path: {avatar_path}")
        
        db = get_db()
        cur = db.cursor()
        
        # Get user ID from session
        user_id = session.get('user_id')
        print(f"User ID from session: {user_id}")
        
        if not user_id:
            print("No user ID in session")
            return jsonify({'error':'User not logged in'}), 401
            
        print("Updating database...")
        cur.execute('UPDATE users SET avatar=? WHERE id=?', (avatar_path, user_id))
        db.commit()
        print("Database updated successfully")
        
        # Emit avatar update to refresh user lists
        try:
            username = session.get('username')
            if username:
                socketio.emit('user_list_refresh', {'avatar_updated': username})
                print("Emitted user_list_refresh for avatar update")
        except Exception as e:
            print(f"Failed to emit user_list_refresh: {e}")
        
        return jsonify({'ok': True, 'avatar': avatar_path, 'url': f'/uploads/{avatar_path}'})
    except Exception as e:
        # Log the error for debugging
        print(f"Avatar upload error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/delete/avatar', methods=['POST'])
@login_required
def api_delete_avatar():
    db = get_db(); cur = db.cursor()
    cur.execute('UPDATE users SET avatar=NULL WHERE id=?', (session.get('user_id'),))
    db.commit()
    return jsonify({'ok': True})

# Reactions API
@app.route('/api/reactions/add', methods=['POST'])
@login_required
def api_add_reaction():
    try:
        data = request.get_json(silent=True) or {}
        message_id = data.get('message_id')
        message_type = data.get('message_type')  # 'public', 'dm', 'gdm'
        emoji = data.get('emoji')
        username = session.get('username')
        
        if not all([message_id, message_type, emoji, username]):
            return jsonify({'error': 'missing fields'}), 400
            
        db = get_db(); cur = db.cursor()
        cur.execute('''
            INSERT OR REPLACE INTO message_reactions 
            (message_id, message_type, username, emoji) 
            VALUES (?, ?, ?, ?)
        ''', (message_id, message_type, username, emoji))
        db.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reactions/remove', methods=['POST'])
@login_required
def api_remove_reaction():
    try:
        data = request.get_json(silent=True) or {}
        message_id = data.get('message_id')
        message_type = data.get('message_type')
        emoji = data.get('emoji')
        username = session.get('username')
        
        if not all([message_id, message_type, emoji, username]):
            return jsonify({'error': 'missing fields'}), 400
            
        db = get_db(); cur = db.cursor()
        cur.execute('''
            DELETE FROM message_reactions 
            WHERE message_id=? AND message_type=? AND username=? AND emoji=?
        ''', (message_id, message_type, username, emoji))
        db.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reactions/<int:message_id>/<message_type>')
@login_required
def api_get_reactions(message_id, message_type):
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('''
            SELECT emoji, username FROM message_reactions 
            WHERE message_id=? AND message_type=?
        ''', (message_id, message_type))
        reactions = {}
        for emoji, username in cur.fetchall():
            if emoji not in reactions:
                reactions[emoji] = []
            reactions[emoji].append(username)
        return jsonify(reactions)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Serve System avatar image from the same directory as this file
@app.route('/sys_pfp.png')
def sys_pfp_png():
    try:
        base = os.path.dirname(os.path.abspath(__file__))
        return send_from_directory(base, 'sys_pfp.png')
    except Exception:
        abort(404)

# Moderation helpers: shadow bans
def _ensure_shadow_table():
    try:
        db = get_db(); cur = db.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS shadow_bans (
            username TEXT PRIMARY KEY
        )''')
        db.commit()
    except Exception:
        pass

def is_shadow_banned(user: str) -> bool:
    try:
        _ensure_shadow_table()
        db = get_db(); cur = db.cursor()
        cur.execute('SELECT 1 FROM shadow_bans WHERE username=?', (user,))
        return cur.fetchone() is not None
    except Exception:
        return False

def set_shadow_ban(user: str):
    try:
        _ensure_shadow_table()
        db = get_db(); cur = db.cursor()
        cur.execute('INSERT OR IGNORE INTO shadow_bans(username) VALUES(?)', (user,))
        db.commit(); return True
    except Exception:
        return False

def clear_shadow_ban(user: str):
    try:
        _ensure_shadow_table()
        db = get_db(); cur = db.cursor()
        cur.execute('DELETE FROM shadow_bans WHERE username=?', (user,))
        db.commit(); return True
    except Exception:
        return False

@app.route("/preview/<path:filename>")
@login_required
def preview(filename):
    fpath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(fpath):
        abort(404)

    ext = filename.rsplit(".", 1)[-1].lower()
    if ext in PREVIEW_EXTS:
        return send_from_directory(UPLOAD_FOLDER, filename)

    if ext == ZIP_EXT:
        try:
            with zipfile.ZipFile(fpath, "r") as zf:
                members = zf.namelist()
        except:
            return "<h3>Bad ZIP file</h3>", 400

        links = ''.join(f'<li><a href="/preview/zipfile/{filename}/{m}" target="_blank">{m}</a></li>' for m in members)
        return f"<html><body><ul>{links}</ul></body></html>"

    return send_from_directory(UPLOAD_FOLDER, filename)

# Socket.IO events
@socketio.on("connect")
def on_connect():
    username = session.get("username")
    if username:
        client_ip = get_client_ip()
        if is_banned(username) or is_ip_banned(client_ip):
            disconnect()
            return

        online_users[username] = time.time()
        user_ips[username] = client_ip
        connected_sockets[request.sid] = username
        join_room("chat_room")
        # Join per-user room for DMs
        try:
            join_room(f"user:{username}")
        except Exception:
            pass
        emit("user_joined", {"username": username, "online_count": len(online_users)}, room="chat_room")
        emit("user_list_refresh", {"username": username})
        # Cleanup stale typing entries and broadcast current list
        _cleanup_typing()
        emit("typing", {"users": _current_typing_list(exclude=None)}, room=request.sid)

@socketio.on("disconnect")
def on_disconnect():
    username = connected_sockets.get(request.sid)
    if username:
        del connected_sockets[request.sid]
        if username in online_users:
            del online_users[username]
        # Remove typing state on disconnect
        if username in typing_users:
            typing_users.pop(username, None)
            emit("typing", {"users": _current_typing_list(exclude=None)})
        leave_room("chat_room")
        # Leave per-user DM room
        try:
            leave_room(f"user:{username}")
        except Exception:
            pass
        emit("user_left", {"username": username, "online_count": len(online_users)}, room="chat_room")

# Group DM sockets
@socketio.on('gdm_join')
def on_gdm_join(data):
    me = session.get('username')
    try:
        tid = int((data or {}).get('thread_id', 0))
    except Exception:
        tid = 0
    if not me or not tid:
        return
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT 1 FROM group_members WHERE thread_id=? AND username=?', (tid, me))
    if not cur.fetchone():
        return
    # Join is allowed even when locked; posting is gated in send/edit/delete
    join_room(f'gdm:{tid}')

def on_gdm_send_v1(data):
    me = session.get('username')
    try:
        # Handle both 'tid' and 'thread_id' for compatibility
        tid = int((data or {}).get('tid', 0)) or int((data or {}).get('thread_id', 0))
    except Exception:
        tid = 0
    # Platform gates
    try:
        if get_setting('MAINTENANCE_MODE','0')=='1':
            return
        if get_setting('GDM_ENABLED','1')=='0':
            return
    except Exception:
        pass
    text = (data or {}).get('text', '').strip()
    if not me or not tid or not (text or (data or {}).get('filename')):
        return
    # update presence activity
    try:
        online_users[me] = time.time()
    except Exception:
        pass
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT 1 FROM group_members WHERE thread_id=? AND username=?', (tid, me))
    if not cur.fetchone():
        return
    # Enforce bans/timeouts
    try:
        cur.execute('SELECT 1 FROM group_bans WHERE thread_id=? AND username=?', (tid, me))
        if cur.fetchone():
            return
        cur.execute('SELECT until_ts FROM group_timeouts WHERE thread_id=? AND username=?', (tid, me))
        r = cur.fetchone()
        if r:
            until_ts = r[0] if not isinstance(r, sqlite3.Row) else r['until_ts']
            if until_ts and until_ts > int(time.time()):
                return
            # If user currently timed out, re-send the timeout gate
            try:
                until = user_timeouts.get(u) or 0
                if until and time.time() < float(until):
                    emit('timeout_set', { 'until': int(until) }, room=f'user:{u}')
            except Exception:
                pass
            else:
                cur.execute('DELETE FROM group_timeouts WHERE thread_id=? AND username=?', (tid, me))
                db.commit()
    except Exception:
        pass
    # Enforce locked for posting: allow owner or superadmin only
    try:
        cur.execute('SELECT COALESCE(locked,0), created_by FROM group_threads WHERE id=?', (tid,))
        rr = cur.fetchone(); locked=(rr[0] if rr else 0)
        owner = (rr[1] if rr else None) if not isinstance(rr, sqlite3.Row) else rr['created_by']
        if locked and not (is_superadmin(me) or (owner and owner==me)):
            return
    except Exception:
        pass
    # Owner/Superadmin commands
    if text.startswith("/"):
        # Handle admin and superadmin commands
        parts = text[1:].split()
        cmd = parts[0].lower() if parts else ""
        args = parts[1:]
        # /help for admins and above
        if cmd == 'help' and (is_admin(me) or is_superadmin(me)):
            help_cmds = []
            try:
                if get_setting('MC_PURGE_CHANNEL','1')=='1':
                    help_cmds.append('/clearall')
                    help_cmds.extend(['/clearall','/clear <N>'])
            except Exception:
                help_cmds.extend(['/clearall','/clear <N>'])
            # Kick
            try:
                if get_setting('GD_REMOVE_USER','1')=='1':
                    help_cmds.append('/kick <user>')
            except Exception:
                help_cmds.append('/kick <user>')
            # Ban/Unban
            try:
                if get_setting('UM_BAN_USER','1')=='1':
                    help_cmds.extend(['/ban <user>','/unban <user>'])
            except Exception:
                help_cmds.extend(['/ban <user>','/unban <user>'])
            # Timeout
            try:
                if get_setting('UM_TIMEOUT_USER','1')=='1':
                    help_cmds.append('/timeout <user> [minutes]')
            except Exception:
                help_cmds.append('/timeout <user> [minutes]')
            # IP
            if is_superadmin(me):
                help_cmds.extend(['/ipban <user>','/ipunban <user>'])
            emit('system_message', store_system_message('Group commands:\n' + "\n".join(help_cmds)))
            return
        if cmd == 'clearall':
            cur.execute('DELETE FROM group_messages WHERE thread_id=?', (tid,))
            db.commit()
            emit('gdm_cleared', {'thread_id': tid}, room=f'gdm:{tid}')
            return
        if cmd == 'ban' and args:
            user = sanitize_username(args[0])
            if user:
                try:
                    cur.execute('INSERT OR IGNORE INTO group_bans(thread_id, username) VALUES(?,?)', (tid, user))
                    cur.execute('DELETE FROM group_members WHERE thread_id=? AND username=?', (tid, user))
                    db.commit()
                    emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{user}')
                    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
                    for r2 in cur.fetchall():
                        emit('gdm_threads_refresh', {'tid': tid}, room=f'user:{r2[0]}')
                except Exception:
                    pass
            return
        if cmd == 'timeout' and args:
            user = sanitize_username(args[0])
            mins = 5
            if len(args) >= 2:
                try:
                    mins = max(1, int(args[1]))
                except Exception:
                    mins = 5
            until = int(time.time()) + mins*60
            try:
                cur.execute('INSERT OR REPLACE INTO group_timeouts(thread_id, username, until_ts) VALUES(?,?,?)', (tid, user, until))
                db.commit()
            except Exception:
                pass
            return
    attachment = None

    # Handle multiple attachments (Discord-like)
    if data.get("attachments") and isinstance(data.get("attachments"), list):
        # Store multiple attachments as JSON array
        attachment_files = []
        for att in data["attachments"]:
            if att.get("filename") and att.get("content"):
                saved_file = safe_save_file_from_b64(att["filename"], att["content"])
                if saved_file:
                    attachment_files.append(saved_file)
        if attachment_files:
            # Store as JSON string to indicate multiple attachments
            import json
            attachment = json.dumps(attachment_files)
    elif data.get('filename') and data.get('content'):
        # Single attachment (legacy support)
        attachment = safe_save_file_from_b64(data['filename'], data['content'])
        if attachment is None:
            try:
                emit('system_message', "Attachment failed to upload (invalid or too large)", room=f'user:{me}')
            except Exception:
                pass
    # Anti-spam check
    has_attachment = bool(attachment)
    allowed, spam_msg, split_parts = antispam_check_message(me, text, "gdm", has_attachment)
    if not allowed:
        try:
            emit("system_message", spam_msg, room=f"user:{me}")
        except Exception:
            pass
        return

    # Handle message splitting if needed
    if split_parts and len(split_parts) > 1:
        try:
            emit("system_message", f"Your message will be split into {len(split_parts)} parts.", room=f"user:{me}")
        except Exception:
            pass

        # Send each part with rate limiting
        for i, part in enumerate(split_parts):
            if i > 0:
                time.sleep(1.0)  # Rate limit between parts

            safe_part = render_markdown(part)
            cur.execute("INSERT INTO group_messages (thread_id, username, text, attachment, created_at, edited, reply_to) VALUES (?,?,?,?,?,0,?)", (tid, me, safe_part, attachment if i == 0 else None, datetime.utcnow(), (rid or None)))
            msg_id = cur.lastrowid
            get_db().commit()

            # Send to all members
            cur.execute("SELECT username FROM group_members WHERE thread_id=?", (tid,))
            members = [r[0] for r in cur.fetchall()]
            payload = {
                "id": msg_id,
                "username": me,
                "text": safe_part,
                "attachment": attachment if i == 0 else None,
                "created_at": to_ny_time(datetime.utcnow()),
                "avatar": f"/avatar/{me}",
                "thread_id": tid,
                "reply_to": rid,
                "reply_user": ruser,
                "reply_snippet": rsnippet
            }
            for u in members:
                socketio.emit("gdm_new", payload, room=f"user:{u}")
        return

    safe_text = render_markdown(text)
    try:
        rid = int((data or {}).get('reply_to') or 0)
    except Exception:
        rid = 0
    ruser=None; rsnippet=None
    if rid:
        try:
            cur.execute('SELECT username, text FROM group_messages WHERE id=? AND thread_id=?', (rid, tid))
            rr = cur.fetchone()
            if rr:
                ruser = rr[0] if not isinstance(rr, sqlite3.Row) else rr['username']
                rhtml = rr[1] if not isinstance(rr, sqlite3.Row) else rr['text']
                try:
                    plain = re.sub(r'<[^>]+>', '', rhtml or '')
                except Exception:
                    plain = (rhtml or '')
                rsnippet = (plain or '')[:140]
        except Exception:
            rid = 0
    cur.execute('INSERT INTO group_messages (thread_id, username, text, attachment, created_at, edited, reply_to) VALUES (?,?,?,?,?,0,?)', (tid, me, safe_text, attachment, datetime.utcnow(), (rid or None)))
    msg_id = cur.lastrowid
    get_db().commit()
    # Enforce message lifespan for group messages if enabled
    try:
        if get_setting('MC_MESSAGE_LIFESPAN','0')=='1':
            days_s = get_setting('MC_MESSAGE_LIFESPAN_DAYS','0') or '0'
            days = int(days_s or '0')
            if days > 0:
                cutoff = datetime.utcnow() - timedelta(days=days)
                cur.execute('DELETE FROM group_messages WHERE created_at < ?', (cutoff,))
                get_db().commit()
    except Exception:
        pass
    # Emit to all members (cross-view) via per-user rooms for unread counting
    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
    members = [r[0] for r in cur.fetchall()]
    payload = {
        'id': msg_id,
        'thread_id': tid,
        'username': me,
        'text': safe_text,
        'attachment': attachment,
        'created_at': to_ny_time(datetime.utcnow()),
        'edited': 0,
        'reply_to': (rid or None),
        'reply_username': ruser,
        'reply_snippet': rsnippet,
    }
    # Shadow ban: only echo to sender; otherwise emit to all members
    try:
        if is_shadow_banned(me):
            socketio.emit('gdm_new', payload, room=f'user:{me}')
        else:
            for u in members:
                socketio.emit('gdm_new', payload, room=f'user:{u}')
    except Exception:
        for u in members:
            socketio.emit('gdm_new', payload, room=f'user:{u}')

@socketio.on('gdm_edit')
def on_gdm_edit(data):
    me = session.get('username')
    try:
        mid = int((data or {}).get('id', 0))
    except Exception:
        mid = 0
    new_text = (data or {}).get('text', '')
    if not me or not mid:
        return
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT thread_id, username, text FROM group_messages WHERE id=?', (mid,))
    row = cur.fetchone()
    if not row:
        return
    tid, author, old_html = row[0], row[1], row[2] or ''
    # Enforce locked (allow owner or superadmin)
    try:
        cur.execute('SELECT COALESCE(locked,0), created_by FROM group_threads WHERE id=?', (tid,))
        rr = cur.fetchone(); locked=(rr[0] if rr else 0)
        owner = (rr[1] if rr else None) if not isinstance(rr, sqlite3.Row) else rr['created_by']
        if locked and not (is_superadmin(me) or (owner and owner==me)):
            return
    except Exception:
        pass
    if not (author == me or is_admin(me) or is_superadmin(me)):
        return
    # If admin editing others, respect MC_EDIT_MESSAGES toggle
    if author != me and (is_admin(me) or is_superadmin(me)):
        try:
            if get_setting('MC_EDIT_MESSAGES','1')=='0':
                return
        except Exception:
            pass
    safe_text = render_markdown(new_text or '')
    if (old_html or '') == (safe_text or ''):
        return
    cur.execute('UPDATE group_messages SET text=?, edited=1 WHERE id=?', (safe_text, mid))
    get_db().commit()
    emit('gdm_edit', {'id': mid, 'text': safe_text}, room=f'gdm:{tid}')

@socketio.on('gdm_delete')
def on_gdm_delete(data):
    me = session.get('username')
    try:
        mid = int((data or {}).get('id', 0))
    except Exception:
        mid = 0
    if not me or not mid:
        return
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT thread_id, username FROM group_messages WHERE id=?', (mid,))
    row = cur.fetchone()
    if not row:
        return
    tid, author = row[0], row[1]
    # Enforce locked
    try:
        cur.execute('SELECT COALESCE(locked,0) FROM group_threads WHERE id=?', (tid,))
        rr = cur.fetchone(); locked=(rr[0] if rr else 0)
        if locked and not is_superadmin(me):
            return
    except Exception:
        pass
    if not (author == me or is_admin(me) or is_superadmin(me)):
        return
    cur.execute('DELETE FROM group_messages WHERE id=?', (mid,))
    get_db().commit()
    emit('gdm_delete', mid, room=f'gdm:{tid}')

@socketio.on("send_message")
def on_send_message(data):
    username = session.get("username")
    if not username:
        return

    # Check if this is a DM or GDM message and route accordingly
    mode = (data or {}).get("mode", "public").strip()
    reply_to = (data or {}).get("reply_to")

    if mode == "dm":
        peer = (data or {}).get("peer", "").strip()
        if peer:
            dm_data = {"to": peer, "text": data.get("text", ""), "filename": data.get("filename"), "content": data.get("content")}
            if reply_to:
                dm_data["reply_to"] = reply_to
            return on_dm_send(dm_data)
    elif mode == "gdm":
        thread_id = (data or {}).get("thread_id")
        if thread_id:
            gdm_data = {"thread_id": thread_id, "text": data.get("text", ""), "filename": data.get("filename"), "content": data.get("content")}
            if reply_to:
                gdm_data["reply_to"] = reply_to
            return on_gdm_send(gdm_data)

    # User must exist in DB; otherwise disconnect and ignore
    try:
        if not _session_user_valid():
            try: socketio.server.disconnect(request.sid)
            except Exception: pass
            return
    except Exception:
        pass

    # Enforce IP bans (private first then public)
    try:
        priv, pub = detect_client_ips()
        _update_user_ips(username, priv, pub)
        if _is_ip_blocked_for(username, priv, pub):
            try:
                emit("system_message", "Your IP is banned", room=f'user:{username}')
            except Exception:
                pass
            try:
                socketio.server.disconnect(request.sid)
            except Exception:
                pass
            return
    except Exception:
        pass

    if is_banned(username):
        try:
            emit("system_message", "You are banned and cannot send messages", room=f'user:{username}')
        except Exception:
            pass
        disconnect()
        return

    client_ip = get_client_ip()
    if is_ip_banned(client_ip):
        try:
            emit("system_message", "Your IP is banned", room=f'user:{username}')
        except Exception:
            pass
        disconnect()
        return

    online_users[username] = time.time()

    # Check timeout
    if username in user_timeouts and user_timeouts[username] > time.time():
        try:
            emit("system_message", "You are timed out", room=f'user:{username}')
        except Exception:
            pass
        return

    # Determine admin privilege once
    try:
        adminish = bool(is_superadmin(username) or _is_adminish(username))
    except Exception:
        adminish = False
    # Platform gates for public chat
    try:
        if get_setting('MAINTENANCE_MODE','0')=='1':
            return
        if get_setting('PUBLIC_ENABLED','1')=='0':
            return
        if get_setting('ANNOUNCEMENTS_ONLY','0')=='1' and not adminish:
            return
    except Exception:
        pass
    text = (data.get("text") or "").strip()
    attachment = None

    # Handle multiple attachments (Discord-like)
    if data.get("attachments") and isinstance(data.get("attachments"), list):
        # Store multiple attachments as JSON array
        attachment_files = []
        for att in data["attachments"]:
            if att.get("filename") and att.get("content"):
                saved_file = safe_save_file_from_b64(att["filename"], att["content"])
                if saved_file:
                    attachment_files.append(saved_file)
        if attachment_files:
            # Store as JSON string to indicate multiple attachments
            import json
            attachment = json.dumps(attachment_files)
    elif data.get("filename") and data.get("content"):
        # Single attachment (legacy support)
        attachment = safe_save_file_from_b64(data["filename"], data["content"])
        if attachment is None:
            try:
                emit("system_message", "Attachment failed to upload (invalid or too large)", room=f'user:{username}')
            except Exception:
                pass

    # Admin commands (admins and superadmins)
    if text.startswith('/') and adminish:
        parts = text[1:].split()
        cmd = parts[0].lower()
        args = parts[1:]
        db = get_db()
        cur = db.cursor()
        # Dynamic help (toggle-aware)
        if cmd == 'help':
            help_cmds = []
            # Clear/purge
            try:
                if get_setting('MC_PURGE_CHANNEL','1')=='1':
                    help_cmds.extend(['/clearall','/clear <N>'])
            except Exception:
                help_cmds.extend(['/clearall','/clear <N>'])
            # Ban/Unban
            try:
                if get_setting('UM_BAN_USER','1')=='1':
                    help_cmds.extend(['/ban <user>','/unban <user>'])
            except Exception:
                help_cmds.extend(['/ban <user>','/unban <user>'])
            # Timeout
            try:
                if get_setting('UM_TIMEOUT_USER','1')=='1':
                    help_cmds.extend(['/timeout <user> <minutes>','/timeoutremove <user>'])
            except Exception:
                help_cmds.extend(['/timeout <user> <minutes>','/timeoutremove <user>'])
            # IP/admin tools (SA)
            if is_superadmin(username):
                help_cmds.extend(['/ipban <user>','/ipunban <ip>','/ipof <user>','/addadmin <user>','/rmadmin <user>'])
            emit("system_message", store_system_message("Commands:\n" + "\n".join(help_cmds)))
            return

        if cmd == 'clearall':
            # Toggle gate
            try:
                if get_setting('MC_PURGE_CHANNEL','1')=='0':
                    return
            except Exception:
                pass
            cur.execute("DELETE FROM messages")
            db.commit()
            socketio.emit("clear_all", room='chat_room')
            socketio.emit("system_message", store_system_message(f"All messages cleared by {username}"), room='chat_room')
            return

        elif cmd == 'clear' and args:
            # Toggle gate
            try:
                if get_setting('MC_PURGE_CHANNEL','1')=='0':
                    return
            except Exception:
                pass
            try:
                n = int(args[0])
                # Find IDs first for realtime UI update
                cur.execute("SELECT id FROM messages ORDER BY id DESC LIMIT ?", (n,))
                ids = [r[0] for r in cur.fetchall()]
                if ids:
                    cur.execute("DELETE FROM messages WHERE id IN ({})".format(
                        ",".join(["?"]*len(ids))
                    ), tuple(ids))
                db.commit()
                # Realtime remove
                if ids:
                    socketio.emit("messages_deleted", { 'ids': ids }, room='chat_room')
                socketio.emit("system_message", store_system_message(f"Last {n} messages cleared by {username}"), room='chat_room')
            except:
                pass
            return

        elif cmd == 'ban' and args:
            target = args[0]
            if not _can_ban(username, target):
                emit("system_message", store_system_message("You are not allowed to ban this user"))
                return
            # True ban: ban user, their latest device, and associated IPs (private/public) if known
            cur.execute("INSERT OR IGNORE INTO banned_users(username) VALUES (?)", (target,))
            # From online cache
            info = user_ips.get(target) if isinstance(user_ips.get(target), dict) else {}
            try:
                # Ban device if known
                cid = (info.get('client_id') or '').strip()
                if not cid:
                    try:
                        cur.execute('SELECT client_id FROM device_logs WHERE username=? ORDER BY created_at DESC LIMIT 1', (target,))
                        r = cur.fetchone(); cid = (r[0] if r else '') if not isinstance(r, sqlite3.Row) else (r['client_id'] if r else '')
                    except Exception:
                        cid = ''
                if cid:
                    cur.execute('INSERT OR IGNORE INTO device_bans(client_id, username) VALUES(?,?)', (cid, target))
                # Ban IPs if known
                priv = (info.get('private') or '')
                pub = (info.get('public') or '')
                if not (priv or pub):
                    try:
                        cur.execute('SELECT private_ip, public_ip FROM device_logs WHERE username=? ORDER BY created_at DESC LIMIT 1', (target,))
                        r = cur.fetchone()
                        if r:
                            priv = r[0] if not isinstance(r, sqlite3.Row) else r['private_ip']
                            pub = r[1] if not isinstance(r, sqlite3.Row) else r['public_ip']
                    except Exception:
                        pass
                for ip in [priv, pub]:
                    if ip:
                        cur.execute('INSERT OR IGNORE INTO banned_ips(ip_address) VALUES(?)', (ip,))
            except Exception:
                pass
            db.commit()
            emit("system_message", store_system_message(f"{target} was banned by {username}"))
            for sid, uname in list(connected_sockets.items()):
                if uname == target:
                    socketio.server.disconnect(sid)
            return

        elif cmd == 'unban' and args:
            target = args[0]
            if not _can_unban(username, target):
                emit("system_message", store_system_message("You are not allowed to unban this user"))
                return
            cur.execute("DELETE FROM banned_users WHERE username=?", (target,))
            db.commit()
            emit("system_message", store_system_message(f"{target} was unbanned by {username}"))
            return

        elif cmd == 'ipban' and args:
            target = args[0]
            mode = (args[1].lower() if len(args) > 1 else 'auto') if args else 'auto'
            info = user_ips.get(target) or {}
            if not isinstance(info, dict):
                info = {'private': None, 'public': info}
            priv = info.get('private')
            pub = info.get('public')
            if not (priv or pub):
                emit("system_message", store_system_message(f"Cannot find IPs for {target} (user not online)"))
                return
            # Auto selection: default public; if same public is shared by a mix of admins and non-admins, prefer private
            use_ip = pub
            if mode == 'private':
                use_ip = priv or pub
            elif mode == 'public':
                use_ip = pub or priv
            else:  # auto
                try:
                    if pub:
                        holders = [u for u, d in user_ips.items() if isinstance(d, dict) and d.get('public') == pub]
                        has_admin = any((u in ADMINS or u in SUPERADMINS) for u in holders)
                        has_user = any((u not in ADMINS and u not in SUPERADMINS) for u in holders)
                        if has_admin and has_user and priv:
                            use_ip = priv
                except Exception:
                    pass
            if not use_ip:
                emit("system_message", store_system_message("No suitable IP to ban"))
                return
            if use_ip in ("127.0.0.1", "::1"):
                emit("system_message", store_system_message("Refusing to ban loopback IP (localhost) for all users"))
                return
            if not _can_ban(username, target):
                emit("system_message", store_system_message("You are not allowed to IP-ban this user"))
                return
            # Allow superadmins to ban any IP, block non-superadmins from banning admin/superadmin IPs
            try:
                holders = []
                for u, d in user_ips.items():
                    if isinstance(d, dict) and (d.get('public') == use_ip or d.get('private') == use_ip):
                        holders.append(u)
                if not is_superadmin(username):
                    if any(u in SUPERADMINS for u in holders):
                        emit("system_message", store_system_message("Refusing to IP-ban: IP belongs to a superadmin online"))
                        return
                    if any(u in ADMINS for u in holders):
                        emit("system_message", store_system_message("Refusing to IP-ban: IP belongs to an admin online"))
                        return
            except Exception:
                pass
            # Apply ban
            cur.execute("INSERT OR IGNORE INTO banned_ips(ip_address) VALUES(?)", (use_ip,))
            db.commit(); banned_ips.add(use_ip)
            emit("system_message", store_system_message(f"IP {use_ip} banned by {username}"))
            # Disconnect sessions matching either private or public
            for sid, uname in list(connected_sockets.items()):
                try:
                    d = user_ips.get(uname) if isinstance(user_ips.get(uname), dict) else {'public': user_ips.get(uname), 'private': None}
                    if d and (d.get('public') == use_ip or d.get('private') == use_ip):
                        socketio.server.disconnect(sid)
                except Exception:
                    pass
            return

        elif cmd == 'ipunban' and args:
            ip_address = args[0]
            cur.execute("DELETE FROM banned_ips WHERE ip_address= ?", (ip_address,))
            db.commit()
            try:
                banned_ips.discard(ip_address)
            except Exception:
                pass
            emit("system_message", store_system_message(f"An IP was unbanned by {username}"))
            return

        elif cmd == 'ipunbanuser' and args:
            target = sanitize_username(args[0])
            ip = user_ips.get(target)
            if not ip:
                emit("system_message", store_system_message(f"No IP found for {target} (user offline)"))
                return
            if ip in ("127.0.0.1", "::1"):
                emit("system_message", store_system_message("Refusing to unban loopback (no need)"))
                return
            cur.execute("DELETE FROM banned_ips WHERE ip_address=?", (ip,))
            db.commit()
            banned_ips.discard(ip)
            emit("system_message", store_system_message(f"IP of {target} was unbanned by {username}"))
            return

        elif cmd == 'addadmin' and args:
            # Superadmin only
            if not is_superadmin(username):
                emit("system_message", store_system_message("Only superadmins can manage admins"))
                return
            target = sanitize_username(args[0])
            if not target or target in SUPERADMINS:
                emit("system_message", store_system_message("Cannot add superadmin or empty user"))
                return
            # Persist to extra_admins and in-memory set
            try:
                db = get_db(); cur = db.cursor()
                cur.execute('CREATE TABLE IF NOT EXISTS extra_admins (username TEXT PRIMARY KEY, created_at TEXT, created_by TEXT)')
                cur.execute('INSERT OR REPLACE INTO extra_admins(username, created_at, created_by) VALUES(?,?,?)', (target, datetime.utcnow().isoformat(), username))
                db.commit()
            except Exception:
                pass
            ADMINS.add(target)
            try:
                merged = [u for u in _list_all_admin_usernames() if u not in SUPERADMINS]
            except Exception:
                merged = sorted(list(ADMINS))
            emit("system_message", store_system_message(f"{target} was granted admin by {username}"))
            emit('admin_list', {'admins': merged})
            return

        elif cmd == 'rmadmin' and args:
            # Superadmin only
            if not is_superadmin(username):
                emit("system_message", store_system_message("Only superadmins can manage admins"))
                return
            target = sanitize_username(args[0])
            if not target:
                return
            # Remove from extra_admins and in-memory set
            try:
                db = get_db(); cur = db.cursor()
                cur.execute('CREATE TABLE IF NOT EXISTS extra_admins (username TEXT PRIMARY KEY, created_at TEXT, created_by TEXT)')
                cur.execute('DELETE FROM extra_admins WHERE username=?', (target,))
                db.commit()
            except Exception:
                pass
            if target in ADMINS:
                ADMINS.discard(target)
                emit("system_message", store_system_message(f"{target} admin role removed by {username}"))
            else:
                emit("system_message", store_system_message(f"{target} is not an admin"))
            try:
                merged = [u for u in _list_all_admin_usernames() if u not in SUPERADMINS]
            except Exception:
                merged = sorted(list(ADMINS))
            emit('admin_list', {'admins': merged})
            return

        # File management commands
        elif cmd == 'file':
            if len(args) < 1:
                emit("system_message", store_system_message(
                    "File commands:\n"
                    "/file upload <url> - Upload a file from URL\n"
                    "/file list - List all uploaded files\n"
                    "/file delete <id> - Delete a file by ID\n"
                    "/file info <id> - Get info about a file"
                ))
                return
                
            subcmd = args[0].lower()
            
            if subcmd == 'upload':
                if len(args) < 2:
                    emit("system_message", store_system_message("Usage: /file upload <url>"))
                    return
                    
                url = args[1]
                try:
                    # Download the file
                    response = requests.get(url, stream=True)
                    response.raise_for_status()
                    
                    # Get filename from URL or use a default
                    filename = os.path.basename(url) or 'uploaded_file'
                    filename = secure_filename(filename)
                    
                    # Save the file
                    file_id = save_uploaded_file(
                        response.content,
                        filename,
                        username
                    )
                    
                    if file_id:
                        file_url = f"/uploads/{file_id}"
                        emit("system_message", store_system_message(
                            f"File uploaded successfully!\n"
                            f"Filename: {filename}\n"
                            f"URL: {file_url}\n"
                            f"ID: {file_id}"
                        ))
                    else:
                        emit("system_message", store_system_message("Failed to upload file"))
                        
                except Exception as e:
                    emit("system_message", store_system_message(f"Error uploading file: {str(e)}"))
                    
            elif subcmd == 'list':
                try:
                    files = list_files()
                    if not files:
                        emit("system_message", store_system_message("No files uploaded yet"))
                        return
                        
                    file_list = []
                    for f in files:
                        file_list.append(
                            f"ID: {f['id']}\n"
                            f"Name: {f['filename']}\n"
                            f"Size: {f['size']} bytes\n"
                            f"Uploaded by: {f['uploader']}\n"
                            f"Time: {f['upload_time']}\n"
                            f"URL: /uploads/{f['id']}\n"
                        )
                    
                    # Split into chunks to avoid message length limits
                    chunk_size = 3
                    for i in range(0, len(file_list), chunk_size):
                        chunk = file_list[i:i + chunk_size]
                        emit("system_message", store_system_message("\n".join(chunk)))
                        
                except Exception as e:
                    emit("system_message", store_system_message(f"Error listing files: {str(e)}"))
                    
            elif subcmd == 'delete' and len(args) > 1:
                file_id = args[1]
                success, message = delete_file(file_id, username)
                emit("system_message", store_system_message(message))
                
            elif subcmd == 'info' and len(args) > 1:
                file_id = args[1]
                file_info = get_file_info(file_id)
                if file_info:
                    file_url = f"/uploads/{file_info['id']}"
                    file_path = os.path.join('uploads', file_info['id'])
                    file_exists = os.path.exists(file_path)
                    
                    emit("system_message", store_system_message(
                        f"File ID: {file_info['id']}\n"
                        f"Name: {file_info['filename']}\n"
                        f"Size: {file_info['size']} bytes\n"
                        f"Uploaded by: {file_info['uploader']}\n"
                        f"Upload time: {file_info['upload_time']}\n"
                        f"URL: {file_url}\n"
                        f"Status: {'File exists' if file_exists else 'File missing'}"
                    ))
                else:
                    emit("system_message", store_system_message("File not found"))
                    
            else:
                emit("system_message", store_system_message(
                    "Invalid file command. Use:\n"
                    "/file upload <url> - Upload a file\n"
                    "/file list - List files\n"
                    "/file delete <id> - Delete a file\n"
                    "/file info <id> - Get file info"
                ))

        # User management commands
        elif cmd == 'user':
            if len(args) < 1:
                emit("system_message", store_system_message(
                    "User commands:\n"
                    "/user info <username> - Get user info\n"
                    "/user list - List online users"
                ))
                return
                
            subcmd = args[0].lower()
            
            if subcmd == 'info' and len(args) > 1:
                target_user = args[1]
                try:
                    db = get_db()
                    cur = db.cursor()
                    cur.execute('''
                        SELECT id, username, created_at, last_seen, is_admin
                        FROM users 
                        WHERE username = ?
                    ''', (target_user,))
                    user = cur.fetchone()
                    
                    if user:
                        # Get user's IP info
                        ip_info = user_ips.get(target_user, {})
                        private_ip = ip_info.get('private', 'Not available')
                        public_ip = ip_info.get('public', 'Not available')
                        
                        # Get user's status
                        is_online = target_user in online_users
                        status = "Online" if is_online else "Offline"
                        
                        # Get user's role
                        if is_superadmin(target_user):
                            role = "Super Admin"
                        elif is_admin(target_user):
                            role = "Admin"
                        else:
                            role = "User"
                            
                        # Get ban status
                        banned = is_banned(target_user)
                        
                        # Get user's channels
                        cur.execute('''
                            SELECT c.name, c.id 
                            FROM channel_members cm
                            JOIN channels c ON cm.channel_id = c.id
                            WHERE cm.user_id = ?
                            ORDER BY c.name
                        ''', (user['id'],))
                        channels = [f"#{row['name']}" for row in cur.fetchall()]
                        
                        message = (
                            f"=== User Info ===\n"
                            f"Username: {user['username']}\n"
                            f"Status: {status}\n"
                            f"Role: {role}\n"
                            f"Banned: {'Yes' if banned else 'No'}\n"
                            f"Account created: {user['created_at']}\n"
                            f"Last seen: {user['last_seen']}\n"
                            f"Private IP: {private_ip}\n"
                            f"Public IP: {public_ip}\n"
                            f"Channels: {', '.join(channels) if channels else 'None'}"
                        )
                        
                        emit("system_message", store_system_message(message))
                    else:
                        emit("system_message", store_system_message("User not found"))
                        
                except Exception as e:
                    emit("system_message", store_system_message(f"Error getting user info: {str(e)}"))
                    
            elif subcmd == 'list':
                try:
                    online = list(online_users.keys())
                    if not online:
                        emit("system_message", store_system_message("No users online"))
                        return
                        
                    # Get additional info for each user
                    db = get_db()
                    cur = db.cursor()
                    placeholders = ','.join(['?'] * len(online))
                    cur.execute(f'''
                        SELECT username, is_admin, last_seen 
                        FROM users 
                        WHERE username IN ({placeholders})
                    ''', online)
                    
                    users = cur.fetchall()
                    admin_users = [u for u in users if u['is_admin']]
                    regular_users = [u for u in users if not u['is_admin']]
                    
                    message = "=== Online Users ===\n"
                    if admin_users:
                        message += "\nAdmins:\n- " + "\n- ".join([
                            f"{u['username']} (last seen: {u['last_seen']})" 
                            for u in admin_users
                        ])
                    if regular_users:
                        message += "\n\nUsers:\n- " + "\n- ".join([
                            f"{u['username']} (last seen: {u['last_seen']})" 
                            for u in regular_users
                        ])
                        
                    emit("system_message", store_system_message(message))
                    
                except Exception as e:
                    emit("system_message", store_system_message(f"Error listing users: {str(e)}"))
                    
            else:
                emit("system_message", store_system_message(
                    "Invalid user command. Use:\n"
                    "/user info <username> - Get user info\n"
                    "/user list - List online users"
                ))

        # Message sending command
        elif cmd == 'message' and len(args) > 1:
            channel_name = args[0]
            message = ' '.join(args[1:])
            
            try:
                # Get channel info
                channel = get_channel_by_name(channel_name)
                if not channel:
                    emit("system_message", store_system_message(f"Channel '{channel_name}' not found"))
                    return
                
                # Check if user is a member of the channel
                user_id = session.get('user_id')
                if not user_id:
                    emit("system_message", store_system_message("Not authenticated"))
                    return
                    
                channel_status = get_user_channel_status(user_id, channel['id'])
                if not channel_status['is_member']:
                    emit("system_message", store_system_message("You are not a member of this channel"))
                    return
                    
                # Save message to database
                message_id = str(uuid.uuid4())
                db = get_db()
                cur = db.cursor()
                cur.execute('''
                    INSERT INTO messages 
                    (id, user_id, username, text, created_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                ''', (message_id, user_id, username, message))
                db.commit()
                
                # Update user's last seen
                cur.execute('''
                    UPDATE users 
                    SET last_seen = datetime('now') 
                    WHERE id = ?
                ''', (user_id,))
                db.commit()
                
                # Broadcast to channel
                emit('new_message', {
                    'id': message_id,
                    'channel': channel_name,
                    'channel_id': channel['id'],
                    'username': username,
                    'content': message,
                    'timestamp': datetime.now().isoformat(),
                    'is_admin': is_admin(username)
                }, room=f"channel_{channel['id']}")
                
                emit("system_message", store_system_message(f"Message sent to #{channel_name}"))
                
            except Exception as e:
                emit("system_message", store_system_message(f"Error sending message: {str(e)}"))

        # Channel info command
        elif cmd == 'channel' and len(args) > 0 and args[0] == 'info':
            try:
                # Get current channel
                current_channel = get_current_channel()
                if not current_channel:
                    emit("system_message", store_system_message("No active channel"))
                    return
                
                db = get_db()
                cur = db.cursor()
                
                # Get channel info with statistics
                cur.execute('''
                    SELECT 
                        c.*, 
                        COUNT(DISTINCT cm.user_id) as member_count,
                        (SELECT COUNT(*) FROM messages WHERE user_id = ?) as message_count,
                        (SELECT username FROM users WHERE id = c.created_by) as creator_name
                    FROM channels c
                    LEFT JOIN channel_members cm ON cm.channel_id = c.id
                    WHERE c.id = ?
                    GROUP BY c.id
                ''', (session.get('user_id'), current_channel['id']))
                
                channel_info = cur.fetchone()
                
                if not channel_info:
                    emit("system_message", store_system_message("Channel not found"))
                    return
                    
                # Get online users in channel
                online_users_in_channel = [
                    u for u in online_users.keys() 
                    if is_channel_member(current_channel['id'], session.get('user_id'))
                ]
                
                # Get recent messages (last 5)
                cur.execute('''
                    SELECT m.*, u.is_admin as user_is_admin
                    FROM messages m
                    JOIN users u ON m.user_id = u.id
                    WHERE m.user_id = ?
                    ORDER BY m.created_at DESC
                    LIMIT 5
                ''', (session.get('user_id'),))
                recent_messages = cur.fetchall()
                
                # Build the message
                message = (
                    f"=== #{channel_info['name']} ===\n"
                    f"Topic: {channel_info.get('topic', 'No topic set')}\n"
                    f"Description: {channel_info.get('description', 'No description')}\n"
                    f"Created by: {channel_info.get('creator_name', 'Unknown')}\n"
                    f"Created at: {channel_info.get('created_at', 'Unknown')}\n"
                    f"Total messages: {channel_info['message_count']}\n"
                    f"Total members: {channel_info['member_count']}\n"
                    f"Online now: {len(online_users_in_channel)} users"
                )
                
                if online_users_in_channel:
                    message += f"\n\nOnline users:\n- " + "\n- ".join(online_users_in_channel)
                    
                if recent_messages:
                    message += "\n\nRecent messages:"
                    for msg in reversed(recent_messages):  # Show in chronological order
                        message += f"\n[{msg['created_at']}] {msg['username']}: {msg['text']}"
                    
                emit("system_message", store_system_message(message))
                
            except Exception as e:
                emit("system_message", store_system_message(f"Error getting channel info: {str(e)}"))

        elif cmd == 'ipof' and args:
            # Show the current IP of a user (online users only)
            target = sanitize_username(args[0])
            info = user_ips.get(target) or {}
            if isinstance(info, dict):
                priv = info.get('private') or ''
                pub = info.get('public') or ''
                emit("system_message", store_system_message(f"IPs of {target} — private: {priv or 'n/a'}, public: {pub or 'n/a'}"))
            else:
                ip = info or ''
                if ip:
                    emit("system_message", store_system_message(f"IP of {target} is {ip}"))
                else:
                    emit("system_message", store_system_message(f"No IP found for {target} (user offline)"))
            return

        elif cmd == 'setipbanoverseer' and args:
            # Superadmin-only: set the special overseer allowed to IP-ban superadmin IPs
            if not is_superadmin(username):
                emit("system_message", store_system_message("Only superadmins can set the IP-ban overseer"))
                return
            target = sanitize_username(args[0])
            if not target:
                emit("system_message", store_system_message("Provide a valid username"))
                return
            ok = _set_overseer_by_username(target)
            if ok:
                emit("system_message", store_system_message(f"IP-ban overseer is now {target}"))
            else:
                emit("system_message", store_system_message("Failed to set overseer (user not found?)"))
            return

        elif cmd == 'timeout' and len(args) >= 2:
            target = args[0]
            seconds = int(args[1])
            user_timeouts[target] = time.time() + seconds
            emit("system_message", store_system_message(f"{target} timed out for {seconds} seconds by {username}"))
            return

        elif cmd == 'untimeout' and args:
            target = args[0]
            if target in user_timeouts:
                user_timeouts.pop(target)
            emit("system_message", store_system_message(f"{target} timeout removed by {username}"))
            try:
                emit('timeout_removed', {}, room=f'user:{target}')
            except Exception:
                pass
            return

        elif cmd == 'cleartxt':
            # SUPERADMIN only: clear the text log file chat_messages.txt
            if is_superadmin(username):
                try:
                    with open(LOG_FILE, 'w', encoding='utf-8') as f:
                        pass
                except Exception:
                    pass
                emit("system_message", store_system_message(f"Message log cleared by {username}"))
            else:
                emit("system_message", store_system_message("You are not authorized to use /cleartxt"))
            return
        else:
            emit("system_message", store_system_message(f"Unknown command: {text}"))
            return

    # Normal message with Markdown
    if text or attachment:
        # Server-side debounce: ignore exact same content from same user within 500ms
        try:
            now = time.time()
            key = username or ''
            last = user_last_send.get(key)
            sig = (text or '').strip() + '|' + (attachment or '')
            if last and last[0] == sig and (now - last[1]) < 0.5:
                return
            user_last_send[key] = (sig, now)
        except Exception:
            pass
        db = get_db(); cur = db.cursor()
        # Anti-spam check
        has_attachment = bool(attachment)
        allowed, spam_msg, split_parts = antispam_check_message(username, text, "public", has_attachment)
        if not allowed:
            try:
                emit("system_message", spam_msg, room=f"user:{username}")
            except Exception:
                pass
            return

        # Handle message splitting if needed
        if split_parts and len(split_parts) > 1:
            try:
                emit("system_message", f"Your message will be split into {len(split_parts)} parts.", room=f"user:{username}")
            except Exception:
                pass

            # Send each part with rate limiting
            for i, part in enumerate(split_parts):
                if i > 0:
                    time.sleep(1.0)  # Rate limit between parts

                safe_part = render_markdown(part)
                cur.execute("INSERT INTO messages (username, text, attachment, created_at, reply_to) VALUES (?,?,?,?,?)", (username, safe_part, attachment if i == 0 else None, datetime.utcnow(), (rid or None)))
                msg_id = cur.lastrowid
                db.commit()

                # Send to all users
                message_data = {
                    "id": msg_id,
                    "username": username,
                    "text": safe_part,
                    "attachment": attachment if i == 0 else None,
                    "created_at": to_ny_time(datetime.utcnow()),
                    "avatar": f"/avatar/{username}",
                    "reply_to": rid,
                    "reply_user": ruser,
                    "reply_snippet": rsnippet
                }
                socketio.emit("new_message", message_data, room="chat_room")
            return

        safe_text = render_markdown(text)
        try:
            rid = int((data or {}).get('reply_to') or 0)
        except Exception:
            rid = 0
        ruser = None
        rsnippet = None
        if rid:
            try:
                cur.execute('SELECT username, text FROM messages WHERE id=?', (rid,))
                rr = cur.fetchone()
                if rr:
                    ruser = rr[0] if not isinstance(rr, sqlite3.Row) else rr['username']
                    rhtml = rr[1] if not isinstance(rr, sqlite3.Row) else rr['text']
                    try:
                        plain = re.sub(r'<[^>]+>', '', rhtml or '')
                    except Exception:
                        plain = (rhtml or '')
                    rsnippet = (plain or '')[:140]
            except Exception:
                rid = 0
        cur.execute("""
            INSERT INTO messages (user_id, username, text, attachment, created_at, reply_to)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (session.get("user_id"), username, safe_text, attachment, datetime.utcnow(), (rid or None)))
        db.commit()
        msg_id = cur.lastrowid
        # Enforce message lifespan if enabled
        try:
            if get_setting('MC_MESSAGE_LIFESPAN','0')=='1':
                days_s = get_setting('MC_MESSAGE_LIFESPAN_DAYS','0') or '0'
                days = int(days_s or '0')
                if days > 0:
                    cutoff = datetime.utcnow() - timedelta(days=days)
                    cur.execute('DELETE FROM messages WHERE created_at < ?', (cutoff,))
                    db.commit()
        except Exception:
            pass
        try:
            ts = _format_web_timestamp(datetime.utcnow())
            line = f"[{ts}] NEW id={msg_id} user={username}: {_plain_text_from_html(safe_text)}"
            if attachment:
                line += f" [ATTACH: {attachment}]"
            _append_log_line(line)
        except Exception:
            pass

        message_data = {
            "id": msg_id,
            "user_id": session["user_id"],
            "username": username,
            "text": safe_text,
            "attachment": attachment,
            "created_at": to_ny_time(datetime.utcnow()),
            "reply_to": (rid or None),
            "reply_username": ruser,
            "reply_snippet": rsnippet
        }
        # Broadcast to all users in public chat (shadow-banned users only see their own)
        try:
            if is_shadow_banned(username):
                socketio.emit("new_message", message_data, room=f'user:{username}')
            else:
                socketio.emit("new_message", message_data, room='chat_room')
        except Exception:
            socketio.emit("new_message", message_data, room='chat_room')
        # Message sent -> user is not typing anymore
        if username in typing_users:
            typing_users.pop(username, None)
            socketio.emit("typing", {"users": _current_typing_list(exclude=None)})

@socketio.on("gdm_send")
def on_gdm_send(data):
    username = session.get("username")
    if not username:
        return
    # Reject if user missing from DB
    try:
        if not _session_user_valid():
            try: socketio.server.disconnect(request.sid)
            except Exception: pass
            return
    except Exception:
        pass
    return on_gdm_send_v1(data)

@socketio.on('connect')
def on_connect():
    try:
        # Reject sockets for users that no longer exist
        if not _session_user_valid():
            try:
                socketio.server.disconnect(request.sid)
            except Exception:
                pass
            return
        join_room('chat_room')
        u = session.get('username')
        if u:
            join_room(f'user:{u}')
            connected_sockets[request.sid] = u
            online_users[u] = time.time()
            # Update IPs and enforce bans
            priv, pub = detect_client_ips()
            _update_user_ips(u, priv, pub)
            if _is_ip_blocked_for(u, priv, pub):
                try:
                    emit("system_message", store_system_message("Your IP is banned"), room=f'user:{u}')
                except Exception:
                    pass
                try:
                    socketio.server.disconnect(request.sid)
                except Exception:
                    pass
                return
            try:
                socketio.emit('user_list_refresh', { 'online': u })
            except Exception:
                pass
    except Exception:
        pass

@socketio.on('disconnect')
def on_disconnect():
    try:
        sid = request.sid
        u = connected_sockets.pop(sid, None)
        if u:
            # If no more sockets for this user, mark offline
            if u not in connected_sockets.values():
                try:
                    online_users.pop(u, None)
                except Exception:
                    pass
                try:
                    socketio.emit('user_list_refresh', { 'offline': u })
                except Exception:
                    pass
    except Exception:
        pass

@socketio.on("delete_message")
def on_delete_message(mid):
    username = session.get("username")
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username FROM messages WHERE id= ?", (mid,))
    row = cur.fetchone()

    if not row:
        return
    author = row[0] if not isinstance(row, sqlite3.Row) else row["username"]
    # Authors can always delete their own
    if author == username:
        cur.execute("DELETE FROM messages WHERE id= ?", (mid,))
        db.commit(); socketio.emit("delete_message", mid, room='chat_room'); return
    # Admins/superadmins deleting others must respect MC_DELETE_MESSAGES
    if is_admin(username) or is_superadmin(username):
        try:
            if get_setting('MC_DELETE_MESSAGES','1')=='0':
                return
        except Exception:
            pass
        cur.execute("DELETE FROM messages WHERE id= ?", (mid,))
        db.commit(); socketio.emit("delete_message", mid, room='chat_room')

@socketio.on("edit_message")
def on_edit_message(data):
    username = session.get("username")
    try:
        mid = int((data or {}).get("id", 0))
    except Exception:
        mid = 0
    new_text = (data or {}).get("text", "")
    if not username or not mid:
        return
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT username, text FROM messages WHERE id=?", (mid,))
    row = cur.fetchone()
    if not row:
        return
    author = row[0] if not isinstance(row, sqlite3.Row) else row["username"]
    old_html = row[1] if not isinstance(row, sqlite3.Row) else (row["text"] or "")
    # Permission: author can edit; superadmins can edit anyone; admins can edit non-admins
    can_admin_edit = (username in ADMINS) and (author not in ADMINS or username in SUPERADMINS)
    if not (author == username or (username in SUPERADMINS) or can_admin_edit):
        return
    # If admin editing others, respect MC_EDIT_MESSAGES toggle
    if author != username and (username in ADMINS or username in SUPERADMINS):
        try:
            if get_setting('MC_EDIT_MESSAGES','1')=='0':
                return
        except Exception:
            pass
    safe_text = render_markdown(new_text or "")
    if (old_html or "") == (safe_text or ""):
        return
    cur.execute("UPDATE messages SET text=? WHERE id=?", (safe_text, mid))
    db.commit()
    socketio.emit("edit_message", {"id": mid, "text": safe_text}, room='chat_room')

@socketio.on("dm_send")
def on_dm_send(data):
    username = session.get("username")
    if not username:
        return
    # Reject if user missing from DB
    try:
        if not _session_user_valid():
            try: socketio.server.disconnect(request.sid)
            except Exception: pass
            return
    except Exception:
        pass
    # Platform gates
    try:
        if get_setting('MAINTENANCE_MODE','0')=='1':
            return
        if get_setting('DM_ENABLED','1')=='0':
            return
    except Exception:
        pass
    to_user = (data or {}).get("to", "").strip()
    text = (data or {}).get("text", "").strip()
    if not to_user or not (text or (data or {}).get("filename")):
        return
    # Admin DM commands
    if text.startswith('/') and (is_admin(username) or is_superadmin(username)):
        parts = text[1:].split()
        cmd = parts[0].lower() if parts else ''
        if cmd == 'help':
            emit('dm_new', { 'id': int(time.time()*1000)%2147483647, 'from_user': 'System', 'to_user': username, 'text': render_markdown('DM commands:\n/clearall'), 'attachment': None, 'created_at': to_ny_time(datetime.utcnow()), 'avatar': '/sys_pfp.png' }, room=f'user:{username}')
            return
        if cmd == 'clearall' and is_superadmin(username):
            db = get_db(); cur = db.cursor()
            cur.execute('DELETE FROM direct_messages WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)', (username, to_user, to_user, username))
            db.commit()
            emit('dm_cleared', {'peer': to_user}, room=f'user:{username}')
            emit('dm_cleared', {'peer': username}, room=f'user:{to_user}')
            return
    # update presence activity
    try:
        online_users[username] = time.time()
    except Exception:
        pass
    attachment = None

    # Handle multiple attachments (Discord-like)
    if data.get("attachments") and isinstance(data.get("attachments"), list):
        # Store multiple attachments as JSON array
        attachment_files = []
        for att in data["attachments"]:
            if att.get("filename") and att.get("content"):
                saved_file = safe_save_file_from_b64(att["filename"], att["content"])
                if saved_file:
                    attachment_files.append(saved_file)
        if attachment_files:
            # Store as JSON string to indicate multiple attachments
            import json
            attachment = json.dumps(attachment_files)
    elif data.get("filename") and data.get("content"):
        # Single attachment (legacy support)
        attachment = safe_save_file_from_b64(data["filename"], data["content"])
        if attachment is None:
            try:
                emit("system_message", "Attachment failed to upload (invalid or too large)", room=f'user:{username}')
            except Exception:
                pass
    # Anti-spam check
    has_attachment = bool(attachment)
    allowed, spam_msg, split_parts = antispam_check_message(username, text, "dm", has_attachment)
    if not allowed:
        try:
            emit("system_message", spam_msg, room=f"user:{username}")
        except Exception:
            pass
        return

    # Handle message splitting if needed
    if split_parts and len(split_parts) > 1:
        try:
            emit("system_message", f"Your message will be split into {len(split_parts)} parts.", room=f"user:{username}")
        except Exception:
            pass
        # Multipart (rate-limited) DM for long text
        parts = []
        for i in range(0, len(text), 4000):
            parts.append(text[i:i+4000])
        for i, part in enumerate(parts):
            if i > 0:
                time.sleep(1.0)  # Rate limit between parts

            safe_part = render_markdown(part)
            db_socket = get_db_socket(); cur_socket = db_socket.cursor()
            cur_socket.execute("INSERT INTO direct_messages (from_user, to_user, text, attachment, created_at, reply_to) VALUES (?, ?, ?, ?, ?, ?)", (username, to_user, safe_part, attachment if i == 0 else None, datetime.utcnow(), (rid or None)))
            did = cur_socket.lastrowid
            db_socket.commit()
            db_socket.close()

            # Send to both users
            payload = {
                "id": did,
                "from_user": username,
                "to_user": to_user,
                "text": safe_part,
                "attachment": attachment if i == 0 else None,
                "created_at": to_ny_time(datetime.utcnow()),
                "reply_to": (rid or None),
                "reply_username": ruser,
                "reply_snippet": rsnippet,
            }
            emit("dm_new", payload, room=f"user:{to_user}")
            emit("dm_new", payload, room=f"user:{username}")
        return

    safe_text = render_markdown(text)
    db = get_db_socket(); cur = db.cursor()
    try:
        rid = int((data or {}).get('reply_to') or 0)
    except Exception:
        rid = 0
    ruser = None
    rsnippet = None
    if rid:
        try:
            cur.execute('SELECT from_user, text FROM direct_messages WHERE id=?', (rid,))
            rr = cur.fetchone()
            if rr:
                ruser = rr[0]
                rhtml = rr[1]
                try:
                    plain = re.sub(r'<[^>]+>', '', rhtml or '')
                except Exception:
                    plain = (rhtml or '')
                rsnippet = (plain or '')[:140]
        except Exception:
            rid = 0
    cur.execute(
        """
        INSERT INTO direct_messages (from_user, to_user, text, attachment, created_at, reply_to)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (username, to_user, safe_text, attachment, datetime.utcnow(), (rid or None)),
    )
    db.commit()
    did = cur.lastrowid
    # Close the socket database connection
    db.close()
    payload = {
        "id": did,
        "from_user": username,
        "to_user": to_user,
        "text": safe_text,
        "attachment": attachment,
        "created_at": to_ny_time(datetime.utcnow()),
        "reply_to": (rid or None),
        "reply_username": ruser,
        "reply_snippet": rsnippet,
    }
    emit("dm_new", payload, room=f"user:{to_user}")
    emit("dm_new", payload, room=f"user:{username}")

@socketio.on('dm_typing')
def on_dm_typing(data):
    me = session.get('username')
    to_user = (data or {}).get('to', '').strip()
    if not me or not to_user:
        return
    emit('dm_typing', { 'from': me, 'to': to_user }, room=f'user:{to_user}')

@socketio.on('gdm_typing')
def on_gdm_typing(data):
    me = session.get('username')
    try:
        tid = int((data or {}).get('thread_id', 0))
    except Exception:
        tid = 0
    if not me or not tid:
        return
    # Emit to all members via per-user rooms (cross-view), including sender
    db = get_db(); cur = db.cursor()
    # Get group name
    cur.execute('SELECT name FROM group_threads WHERE id=?', (tid,))
    group_name = cur.fetchone()
    group_name = group_name[0] if group_name else f'Group {tid}'
    # Get all members
    cur.execute('SELECT username FROM group_members WHERE thread_id=?', (tid,))
    members = [r[0] for r in cur.fetchall()]
    # Emit to all members
    for u in members:
        emit('gdm_typing', {
            'from': me,
            'thread_id': tid,
            'group_name': group_name
        }, room=f'user:{u}')

@socketio.on("dm_edit")
def on_dm_edit(data):
    username = session.get("username")
    try:
        mid = int((data or {}).get("id", 0))
    except Exception:
        return
    new_text = (data or {}).get("text", "").strip()
    if not new_text:
        return
    db = get_db_socket(); cur = db.cursor()
    cur.execute("SELECT from_user, to_user FROM direct_messages WHERE id=?", (mid,))
    row = cur.fetchone()
    if not row:
        db.close()
        return
    author, to_user = row[0], row[1]
    if not (author == username or is_admin(username) or is_superadmin(username)):
        db.close()
        return
    safe_text = render_markdown(new_text or "")
    cur.execute("UPDATE direct_messages SET text=? WHERE id=?", (safe_text, mid))
    db.commit()
    db.close()
    payload = {"id": mid, "text": safe_text}
    emit("dm_edit", payload, room=f"user:{author}")
    emit("dm_edit", payload, room=f"user:{to_user}")

@socketio.on("dm_delete")
def on_dm_delete(data):
    username = session.get("username")
    try:
        mid = int((data or {}).get("id", 0))
    except Exception:
        return
    db = get_db_socket(); cur = db.cursor()
    cur.execute("SELECT from_user, to_user FROM direct_messages WHERE id=?", (mid,))
    row = cur.fetchone()
    if not row:
        db.close()
        return
    author, to_user = row[0], row[1]
    if not (author == username or is_admin(username) or is_superadmin(username)):
        db.close()
        return
    cur.execute("DELETE FROM direct_messages WHERE id=?", (mid,))
    db.commit()
    db.close()
    emit("dm_delete", mid, room=f"user:{author}")
    emit("dm_delete", mid, room=f"user:{to_user}")

@socketio.on("typing")
def on_typing(data):
    username = session.get("username")
    if not username:
        return
    try:
        is_typing = bool((data or {}).get("typing", False))
    except Exception:
        is_typing = False
    now = time.time()
    if is_typing:
        typing_users[username] = now + 3.0  # expires in 3s unless refreshed
    else:
        typing_users.pop(username, None)
    _cleanup_typing()
    emit("typing", {"users": _current_typing_list(exclude=None)})

def _cleanup_typing():
    now = time.time()
    stale = [u for u, exp in typing_users.items() if exp <= now]
    for u in stale:
        typing_users.pop(u, None)

def _current_typing_list(exclude=None):
    _cleanup_typing()
    users = sorted(typing_users.keys())
    if exclude:
        users = [u for u in users if u != exclude]
    return users
# Reporting System Handlers
@socketio.on("report_message")
def on_report_message(data):
    """Handle message reporting"""
    username = session.get("username")
    if not username or not _session_user_valid():
        emit("report_error", {"message": "Authentication required"})
        return

    try:
        message_id = data.get("message_id")
        reason = data.get("reason", "").strip()
        details = data.get("details", "").strip()
        target_username = data.get("target_username", "").strip()

        if not message_id or not reason or not target_username:
            emit("report_error", {"message": "Missing required fields"})
            return

        # Validate reason
        valid_reasons = ["spam", "harassment", "hate_speech", "inappropriate", "other"]
        if reason not in valid_reasons:
            emit("report_error", {"message": "Invalid reason"})
            return

        # Prevent self-reporting
        if username == target_username:
            emit("report_error", {"message": "Cannot report yourself"})
            return

        # Check for duplicate reports
        db = get_db()
        cur = db.cursor()
        cur.execute("""
            SELECT id FROM reports
            WHERE report_type = 'message' AND target_id = ? AND reporter_username = ?
            AND created_at > datetime('now', '-1 hour')
        """, (str(message_id), username))

        if cur.fetchone():
            emit("report_error", {"message": "You already reported this message recently"})
            return

        # Insert report
        cur.execute("""
            INSERT INTO reports (report_type, target_id, target_username, reason, details, reporter_username)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("message", str(message_id), target_username, reason, details, username))

        db.commit()

        emit("report_success", {"message": "Report submitted successfully"})

        # Notify admins (emit to admin room if they exist)
        socketio.emit("new_report", {
            "type": "message",
            "reporter": username,
            "target": target_username,
            "reason": reason
        }, room="admins")

    except Exception as e:
        emit("report_error", {"message": "Failed to submit report"})

@socketio.on("report_user")
def on_report_user(data):
    """Handle user reporting"""
    username = session.get("username")
    if not username or not _session_user_valid():
        emit("report_error", {"message": "Authentication required"})
        return

    try:
        target_username = data.get("target_username", "").strip()
        reason = data.get("reason", "").strip()
        details = data.get("details", "").strip()

        if not target_username or not reason:
            emit("report_error", {"message": "Missing required fields"})
            return

        # Validate reason
        valid_reasons = ["spam", "harassment", "hate_speech", "inappropriate", "impersonation", "other"]
        if reason not in valid_reasons:
            emit("report_error", {"message": "Invalid reason"})
            return

        # Prevent self-reporting
        if username == target_username:
            emit("report_error", {"message": "Cannot report yourself"})
            return

        # Check if target user exists
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT username FROM users WHERE username = ?", (target_username,))
        if not cur.fetchone():
            emit("report_error", {"message": "User not found"})
            return

        # Check for duplicate reports
        cur.execute("""
            SELECT id FROM reports
            WHERE report_type = 'user' AND target_username = ? AND reporter_username = ?
            AND created_at > datetime('now', '-24 hours')
        """, (target_username, username))

        if cur.fetchone():
            emit("report_error", {"message": "You already reported this user recently"})
            return

        # Insert report
        cur.execute("""
            INSERT INTO reports (report_type, target_username, reason, details, reporter_username)
            VALUES (?, ?, ?, ?, ?)
        """, ("user", target_username, reason, details, username))

        db.commit()

        emit("report_success", {"message": "Report submitted successfully"})

        # Notify admins
        socketio.emit("new_report", {
            "type": "user",
            "reporter": username,
            "target": target_username,
            "reason": reason
        }, room="admins")

    except Exception as e:
        emit("report_error", {"message": "Failed to submit report"})

# Admin Report Management Handlers
@socketio.on("fetch_reports")
def on_fetch_reports(data):
    print(f"Fetch reports called with data: {data}")  # Debug
    """Fetch all reports for admin review"""
    username = session.get("username")
    if not username:
        emit("reports_error", {"message": "Authentication required"})
        return

    if not (is_admin(username) or is_superadmin(username)):
        emit("reports_error", {"message": "Admin access required"})
        return

    try:
        db = get_db()
        cur = db.cursor()

        # Get filter parameters
        status_filter = data.get("status", "all")
        offset = data.get("offset", 0)
        limit = min(data.get("limit", 50), 100)  # Max 100 reports at once

        # Build query based on status filter
        if status_filter == "all":
            cur.execute("""
                SELECT id, report_type, target_id, target_username, reason, details,
                       reporter_username, created_at, status, admin_notes, resolved_at, resolved_by
                FROM reports
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """, (limit, offset))
        else:
            cur.execute("""
                SELECT id, report_type, target_id, target_username, reason, details,
                       reporter_username, created_at, status, admin_notes, resolved_at, resolved_by
                FROM reports
                WHERE status = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """, (status_filter, limit, offset))

        reports = cur.fetchall()

        # Convert to list of dictionaries
        reports_list = []
        for report in reports:
            reports_list.append({
                "id": report[0],
                "report_type": report[1],
                "target_id": report[2],
                "target_username": report[3],
                "reason": report[4],
                "details": report[5],
                "reporter_username": report[6],
                "created_at": str(report[7]) if report[7] else None,
                "status": report[8],
                "admin_notes": report[9],
                "resolved_at": str(report[10]) if report[10] else None,
                "resolved_by": report[11]
            })

        # Get total count
        if status_filter == "all":
            cur.execute("SELECT COUNT(*) FROM reports")
        else:
            cur.execute("SELECT COUNT(*) FROM reports WHERE status = ?", (status_filter,))
        total_count = cur.fetchone()[0]

        emit("reports_data", {
            "reports": reports_list,
            "total": total_count,
            "offset": offset,
            "limit": limit
        })

    except Exception as e:
        print(f"Reports fetch error: {str(e)}"); emit("reports_error", {"message": f"Failed to fetch reports: {str(e)}"})

@socketio.on("update_report_status")
def on_update_report_status(data):
    """Update report status (resolve, dismiss, etc.)"""
    username = session.get("username")
    if not username:
        emit("report_update_error", {"message": "Authentication required"})
        return

    if not (is_admin(username) or is_superadmin(username)):
        emit("report_update_error", {"message": "Admin access required"})
        return

    try:
        report_id = data.get("report_id")
        new_status = data.get("status")
        admin_notes = data.get("admin_notes", "")

        if not report_id or not new_status:
            emit("report_update_error", {"message": "Missing required fields"})
            return

        # Validate status
        valid_statuses = ["pending", "reviewed", "resolved", "dismissed"]
        if new_status not in valid_statuses:
            emit("report_update_error", {"message": "Invalid status"})
            return

        db = get_db()
        cur = db.cursor()

        # Update report
        if new_status in ["resolved", "dismissed"]:
            cur.execute("""
                UPDATE reports
                SET status = ?, admin_notes = ?, resolved_at = CURRENT_TIMESTAMP, resolved_by = ?
                WHERE id = ?
            """, (new_status, admin_notes, username, report_id))
        else:
            cur.execute("""
                UPDATE reports
                SET status = ?, admin_notes = ?
                WHERE id = ?
            """, (new_status, admin_notes, report_id))

        if cur.rowcount == 0:
            emit("report_update_error", {"message": "Report not found"})
            return

        db.commit()
        emit("report_update_success", {"message": "Report updated successfully"})

    except Exception as e:
        emit("report_update_error", {"message": "Failed to update report"})

@socketio.on("delete_report")
def on_delete_report(data):
    """Delete a report (admin only)"""
    username = session.get("username")
    if not username:
        emit("report_delete_error", {"message": "Authentication required"})
        return

    if not (is_admin(username) or is_superadmin(username)):
        emit("report_delete_error", {"message": "Admin access required"})
        return

    try:
        report_id = data.get("report_id")

        if not report_id:
            emit("report_delete_error", {"message": "Report ID required"})
            return

        db = get_db()
        cur = db.cursor()

        # Delete report
        cur.execute("DELETE FROM reports WHERE id = ?", (report_id,))

        if cur.rowcount == 0:
            emit("report_delete_error", {"message": "Report not found"})
            return

        db.commit()
        emit("report_delete_success", {"message": "Report deleted successfully"})

    except Exception as e:
        emit("report_delete_error", {"message": "Failed to delete report"})


# HTML Templates (unchanged)
BASE_CSS = """
:root {
    --bg: #ececec;
    --card: #f8f8f8;
    --muted: #666;
    --primary: #222;
    --primary-hover: #333;
    --border: #d1d5db;
    /* Buttons (light) */
    --btn-bg: #111827;
    --btn-hover: #0b1220;
    --btn-fg: #ffffff;
}

html, body {
    height: 100%;
    margin: 0;
    background: var(--bg);
    font-family: "Cascadia Code", monospace;
    color: var(--primary);
}

/* Dark theme overrides */
.theme-dark {
    --bg: #0f172a;          /* slate-900 */
    --card: #111827;        /* gray-900 */
    --muted: #9ca3af;       /* gray-400 */
    --primary: #e5e7eb;     /* text */
    --primary-hover: #ffffff;
    --border: #2a2f3a;      /* dark border */
    /* Buttons (dark) */
    --btn-bg: #2563eb;      /* blue-600 */
    --btn-hover: #1e40af;   /* blue-800 */
    --btn-fg: #ffffff;
}

/* Dark: force white inline blocks to themed surfaces (context menus, cards, misc) */
.theme-dark [style*="background:#fff"],
.theme-dark [style*="background: #fff"],
.theme-dark [style*="background:white"],
.theme-dark [style*="background: white"],
.theme-dark [style*="border:1px solid #e5e7eb"],
.theme-dark [style*="border: 1px solid #e5e7eb"],
.theme-dark [style*="border:1px solid #d1d5db"],
.theme-dark [style*="border: 1px solid #d1d5db"],
.theme-dark [style*="border:1px solid #ddd"],
.theme-dark [style*="border: 1px solid #ddd"],
.theme-dark [style*="border-bottom:1px solid #efefef"],
.theme-dark [style*="border-bottom: 1px solid #efefef"],
.theme-dark [style*="background:#fafafa"],
.theme-dark [style*="background: #fafafa"],
.theme-dark [style*="background:#f9fafb"],
.theme-dark [style*="background: #f9fafb"],
.theme-dark [style*="background:#fffbe6"],
.theme-dark [style*="background: #fffbe6"] {
    background: var(--card) !important;
    color: var(--primary) !important;
    border-color: var(--border) !important;
}

/* Dark: de-white inline blocks inside Admin Dashboard */
.theme-dark #adminBox [style*="background:#fff"],
.theme-dark #adminBox [style*="background: #fff"],
.theme-dark #adminBox [style*="background:#f9fafb"],
.theme-dark #adminBox [style*="background: #f9fafb"],
.theme-dark #adminBox [style*="border:1px solid #e5e7eb"],
.theme-dark #adminBox [style*="border: 1px solid #e5e7eb"] {
    background: var(--card) !important;
    color: var(--primary) !important;
    border-color: var(--border) !important;
}
/* Dark: links inside Admin Dashboard */
.theme-dark #adminBox a { color: #93c5fd; text-decoration-color: #93c5fd; }

.container {
    max-width: none;
    width: 100%;
    height: 100vh;
    margin: 0;
    padding: 12px 18px;
    box-sizing: border-box;
    background: var(--card);
    border-radius: 8px;
    box-shadow: 0 6px 18px rgba(0,0,0,0.04);
}

header {
    margin-bottom: 18px;
}

h1 {
    font-size: 28px;
    margin: 0;
}

small {
    color: var(--muted);
}

.chat {
    height: 60vh;
    border: 1px dashed #ddd;
    padding: 12px;
    overflow-y: auto;
    background: white;
    scroll-behavior: smooth;
}

/* Dark theme chat surface */
.theme-dark .chat {
    background: #0b1220;
    border-color: #2a2f3a;
}

/* Button variants */
.btn { padding: 8px 12px; border-radius: 6px; border: 0; font-weight: 700; cursor: pointer; transition: background 0.2s, color 0.2s, border-color 0.2s; }
.btn-primary { background:#2563eb; color:#fff; }
.btn-primary:hover { background:#1e40af; }
.btn-secondary { background:#374151; color:#fff; }
.btn-secondary:hover { background:#1f2937; }
.btn-success { background:#059669; color:#fff; }
.btn-success:hover { background:#047857; }
.btn-warn { background:#d97706; color:#fff; }
.btn-warn:hover { background:#b45309; }
.btn-danger { background:#b91c1c; color:#fff; }
.btn-danger:hover { background:#991b1b; }
#btnReportsSettings { display:inline-block !important; visibility:visible !important; opacity:1 !important; }
.btn-outline { background:#374151; color:#e5e7eb; border:1px solid #4b5563; }
.btn-outline:hover { background:#4b5563; color:#e5e7eb; }

/* Dark theme overlays and boxes */
.theme-dark #settingsBox,
.theme-dark #adminBox,
.theme-dark #pinsBox {
  background: var(--card) !important;
  color: var(--primary) !important;
  border-color: var(--border) !important;
}
.theme-dark #sqlOut { background:#0b1020; color:#d1d5db; }

.message {
    padding: 6px 8px;
    border-bottom: 1px dashed #efefef;
    animation: fadeIn 0.3s ease-in;
}

/* Dark: soften message and username whites */
.theme-dark .message { color: #cbd5e1; border-bottom-color: #1f2937; }
.theme-dark .username { color: #d1d5db; }

/* Dark: composer textarea explicit */
.theme-dark #textInput { background: var(--card) !important; color: var(--primary) !important; border-color: var(--border) !important; }

/* Dark: possible context menu container */
.theme-dark #contextMenu, .theme-dark .context-menu, .theme-dark [data-menu="context"] {
  background: var(--card) !important;
  color: var(--primary) !important;
  border: 1px solid var(--border) !important;
  box-shadow: 0 10px 30px rgba(0,0,0,0.45) !important;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.username {
    font-weight: 700;
}

.username.system {
    color: orange;
}

.username.admin {
    color: maroon;
}

.time {
    font-style: italic;
    color: var(--muted);
    font-size: 12px;
}

.attachment {
    font-style: italic;
    color: var(--muted);
    font-size: 13px;
    margin-top: 6px;
}

/* Discord-style image grid layouts */
.image-grid.single-image {
    grid-template-columns: 1fr;
}

.image-grid.two-images {
    grid-template-columns: 1fr 1fr;
}

.image-grid.three-images {
    grid-template-columns: 1fr 1fr;
}

.image-grid.three-images .image-container:first-child {
    grid-column: 1 / -1;
}

.image-grid.many-images {
    grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
}

.image-grid.single-image .image-container {
    height: 200px;
}

.image-grid.two-images .image-container {
    height: 150px;
}

.image-grid.three-images .image-container:first-child {
    height: 120px;
}

.image-grid.three-images .image-container:not(:first-child) {
    height: 120px;
}

.image-grid.many-images .image-container {
    height: 100px;
}

.form-row {
    display: flex;
    gap: 8px;
    margin-top: 12px;
}

input[type=text], input[type=password] {
    font-family: inherit;
    padding: 8px;
    border: 1px solid #ddd;
    border-radius: 6px;
    flex: 1;
}

/* Dark theme form elements */
.theme-dark input[type=text],
.theme-dark input[type=password],
.theme-dark .file-input {
    background: #0b1220;
    border-color: #2a2f3a;
    color: var(--primary);
}

/* Dark theme: inputs/selects/textareas globally */
.theme-dark input,
.theme-dark select,
.theme-dark textarea {
    background: var(--card) !important;
    border-color: var(--border) !important;
    color: var(--primary) !important;
}

/* Dark theme: panels and separators */
.theme-dark details { background: var(--card); border-color: var(--border); }
.theme-dark hr { border-top-color: var(--border); }

button {
    padding: 8px 12px;
    border-radius: 6px;
    border: 0;
    background: var(--btn-bg);
    color: var(--btn-fg);
    font-weight: 700;
    cursor: pointer;
    transition: background 0.2s;
}

button:hover {
    background: var(--btn-hover);
}

.error {
    color: #a00;
    margin-top: 8px;
}

.note {
    font-size: 14px;
    color: var(--muted);
}

/* Polished UI */
.ellipsis {
    display: inline-block;
    max-width: 40ch;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    vertical-align: bottom;
}
.popover {
    position: fixed;
    background: #fff;
    color: #111;
    border: 1px solid #ddd;
    border-radius: 8px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.15);
    padding: 10px 12px;
    z-index: 20000;
    width: 260px;
}
.theme-dark .popover {
    background: var(--card);
    color: var(--primary);
    border-color: #333;
}

.file-input {
    border: 1px solid #ddd;
    padding: 6px;
    border-radius: 6px;
}

.status-indicator {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #4CAF50;
    margin-right: 4px;
}

/* Reply functionality styles */
.message-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 4px;
}

.message-header .username {
    font-weight: 700;
    flex-grow: 1;
}

.message-header .timestamp {
    font-size: 11px;
    color: var(--muted);
    opacity: 0.7;
}

.message-header .reply-btn {
    padding: 2px 6px;
    font-size: 11px;
    background: transparent;
    color: var(--muted);
    border: 1px solid var(--border);
    border-radius: 4px;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    gap: 2px;
}

.message-header .reply-btn:hover {
    background: var(--btn-bg);
    color: var(--btn-fg);
    transform: translateY(-1px);
}

.message-reply {
    background: rgba(37, 99, 235, 0.1);
    border-left: 3px solid #2563eb;
    padding: 6px 8px;
    margin: 4px 0;
    border-radius: 4px;
    cursor: pointer;
    transition: all 0.2s;
}

.message-reply:hover {
    background: rgba(37, 99, 235, 0.15);
    transform: translateX(2px);
}

.message-reply .reply-icon {
    font-size: 12px;
    margin-right: 4px;
}

.message-reply .reply-username {
    font-weight: 600;
    color: #2563eb;
    font-size: 12px;
}

.message-reply .reply-snippet {
    color: var(--muted);
    font-size: 11px;
    margin-top: 2px;
    opacity: 0.8;
}

/* Reply bar styles */
.plus-button {
    padding: 8px 12px;
    border-radius: 6px;
    border: 0;
    font-weight: 700;
    cursor: pointer;
    transition: background 0.2s, color 0.2s, border-color 0.2s;
    background: #374151;
    color: #fff;
    font-size: 16px;
}

.plus-button:hover {
    background: #1f2937;
    color: #e5e7eb;
}

.plus-dropdown {
    display: none;
    position: absolute;
    bottom: 100%;
    left: 0;
    margin-bottom: 8px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    min-width: 180px;
    z-index: 1000;
    overflow: hidden;
}

.dropdown-item {
    display: flex;
    align-items: center;
    width: 100%;
    padding: 10px 16px;
    background: none;
    border: none;
    color: var(--primary);
    cursor: pointer;
    font-size: 14px;
    transition: all 0.2s ease;
    gap: 8px;
}

.dropdown-item:hover {
    background: var(--muted);
    color: var(--accent);
}

.dropdown-icon {
    font-size: 16px;
    width: 20px;
    text-align: center;
}

.files-preview {
    display: none;
    margin-top: 8px;
    padding: 8px;
    background: var(--muted);
    border-radius: 6px;
    border: 1px solid var(--border);
}

.files-list {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}

.file-item {
    position: relative;
    display: inline-block;
    border-radius: 4px;
    overflow: hidden;
    border: 1px solid var(--border);
    background: var(--card);
    transition: all 0.2s ease;
}

.file-item:hover {
    transform: scale(1.05);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.file-item img {
    width: 60px;
    height: 60px;
    object-fit: cover;
    display: block;
}

.file-item .file-icon {
    width: 60px;
    height: 60px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--muted);
    color: var(--primary);
    font-size: 24px;
}

.file-item .remove-btn {
    position: absolute;
    top: 2px;
    right: 2px;
    background: rgba(0, 0, 0, 0.7);
    color: white;
    border: none;
    border-radius: 50%;
    width: 16px;
    height: 16px;
    font-size: 12px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s ease;
}

.file-item .remove-btn:hover {
    background: rgba(220, 38, 38, 0.9);
    transform: scale(1.1);
}

.scroll-to-bottom {
    position: fixed;
    bottom: 120px;
    right: 20px;
    width: 40px;
    height: 40px;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 50%;
    font-size: 18px;
    cursor: pointer;
    display: none;
    align-items: center;
    justify-content: center;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    transition: all 0.3s ease;
    z-index: 1000;
}

.scroll-to-bottom:hover {
    background: var(--primary);
    transform: scale(1.1);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.scroll-to-bottom.visible {
    display: flex;
}

#plusDropdown button:hover {
    background: var(--muted);
}

#fileInput.file-input {
    display: none;
}

#replyBar {
    display: none;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    background: rgba(37, 99, 235, 0.1);
    border: 1px solid #2563eb;
    border-radius: 6px;
    margin-bottom: 8px;
    animation: slideDown 0.2s ease-out;
}

#replyBar .reply-info {
    flex-grow: 1;
    font-size: 12px;
}

#replyBar .reply-label {
    color: #2563eb;
    font-weight: 600;
}

#replyBar .reply-content {
    color: var(--muted);
    margin-left: 4px;
}

#replyBar .close-reply {
    padding: 2px 6px;
    background: transparent;
    color: var(--muted);
    border: 1px solid var(--border);
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    transition: all 0.2s;
}

#replyBar .close-reply:hover {
    background: var(--btn-bg);
    color: var(--btn-fg);
}

/* Highlight animation for focused messages */
@keyframes highlight {
    0% { background: rgba(255, 235, 59, 0.3); }
    50% { background: rgba(255, 235, 59, 0.5); }
    100% { background: transparent; }
}

.highlight-message {
    animation: highlight 2s ease-in-out;
    border-radius: 4px;
}

/* Slide down animation for reply bar */
@keyframes slideDown {
    from {
        opacity: 0;
        transform: translateY(-10px);
        max-height: 0;
    }
    to {
        opacity: 1;
        transform: translateY(0);
        max-height: 50px;
    }
}

/* Dark theme reply styles */
.theme-dark .message-reply {
    background: rgba(37, 99, 235, 0.2);
    border-left-color: #3b82f6;
}

.theme-dark .message-reply:hover {
    background: rgba(37, 99, 235, 0.3);
}

.theme-dark .message-reply .reply-username {
    color: #60a5fa;
}

.theme-dark #replyBar {
    background: rgba(37, 99, 235, 0.2);
    border-color: #3b82f6;
}

.theme-dark .message-header .reply-btn:hover {
    background: #1e40af;
    border-color: #3b82f6;
}

@media (max-width: 600px) {
    font-size: 16px !important;
    margin-bottom: 8px !important;
  }
    font-size: 11px !important;
    padding: 6px 8px !important;
    margin: 2px !important;
    min-width: auto !important;
  }
    font-size: 12px !important;
    padding: 4px !important;
    margin: 2px 0 !important;
  }
    margin-bottom: 8px !important;
  }
    flex-direction: column !important;
    gap: 4px !important;
  }
    min-width: auto !important;
    width: 100% !important;
  }
  #systemMetrics {
    font-size: 10px !important;
  }
    .container {
        margin: 0;
        padding: 8px;
    }
}
"""

AUTH_HTML = """
<!doctype html>
<html data-default-language="{{ my_language }}" lang="{{ my_language }}">
<head>
    <meta charset="utf-8">
    <title>Chatter — Authentication</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>{{ base_css }}</style>
</head>
<body>
    <div class="container">
        <header>
            <h1><span style="font-size:22px;font-weight:700;font-family:'Cascadia Code', monospace;">Chatter</span></h1>
            <div class="note" style="font-family: 'Cascadia Code', sans-serif; font-size: 12px;">Please login or create an account to continue.</div>
        </header>
        
        <!-- Login Form -->
        <form method="post" autocomplete="off">
            <input type="hidden" name="form_type" value="login">
            <div style="display:flex;flex-direction:column;gap:8px;max-width:420px;margin-bottom:20px">
                <h3 style="font-family: 'Cascadia Code', sans-serif; font-size: 16px; margin-bottom: 10px;">Login</h3>
                <label style="font-family: 'Cascadia Code', sans-serif; font-size: 15px;"><strong>Username</strong></label>
                <input name="username" required>
                <label style="font-family: 'Cascadia Code', sans-serif; font-size: 15px;"><strong>Password</strong></label>
                <input type="password" name="password" required>
                <button type="submit">Log in</button>
            </div>
        </form>
        {% if login_error %}<div class="error">{{ login_error }}</div>{% endif %}
        
        <!-- Register Form -->
        <form method="post" autocomplete="off">
            <input type="hidden" name="form_type" value="register">
            <div style="display:flex;flex-direction:column;gap:8px;max-width:420px">
                <h3 style="font-family: 'Cascadia Code', sans-serif; font-size: 16px; margin-bottom: 10px;">Create Account</h3>
                <label style="font-family: 'Cascadia Code', sans-serif; font-size: 15px;"><strong>Username</strong></label>
                <input name="username" required>
                <label style="font-family: 'Cascadia Code', sans-serif; font-size: 15px;"><strong>Password</strong></label>
                <input type="password" name="password" required>
                <label style="font-family: 'Cascadia Code', sans-serif; font-size: 15px;"><strong>Email (optional)</strong></label>
                <input name="email" type="email">
                <button type="submit">Create account</button>
            </div>
        </form>
        {% if register_error %}<div class="error">{{ register_error }}</div>{% endif %}
    </div>
</body>
</html>
"""

LOGIN_HTML = """
<!doctype html>
<html data-default-language="{{ my_language }}" lang="{{ my_language }}">
<head>
    <meta charset="utf-8">
    <title>Chatter — Login</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>{{ base_css }}</style>
</head>
<body>
    <div class="container">
        <header>
            <h1><span style="font-size:22px;font-weight:700;font-family:'Cascadia Code', monospace;">Chatter</span></h1>
            <div class="note" style="font-family: 'Cascadia Code', sans-serif; font-size: 12px;">Please login to continue.</div>
        </header>
        <form method="post" autocomplete="off">
            <div style="display:flex;flex-direction:column;gap:8px;max-width:420px">
                <label style="font-family: 'Cascadia Code', sans-serif; font-size: 15px;"><strong>Username</strong></label>
                <input name="username" required>
                <label style="font-family: 'Cascadia Code', sans-serif; font-size: 15px;"><strong>Password</strong></label>
                <input type="password" name="password" required>
                <div style="display:flex;gap:8px;margin-top:6px">
                    <button type="submit">Log in</button>
                    <a href="/register" style="align-self:center;color:var(--muted);text-decoration:underline">Create account</a>
                </div>
            </div>
        </form>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
    </div>
</body>
</html>
"""

REGISTER_HTML = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Chatter — Register</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>{{ base_css }}</style>
</head>
<body>
    <div class="container">
        <header>
            <h1><span style="font-size:22px;font-weight:700;font-family:'Cascadia Code', monospace;">Chatter</span></h1>
            <div class="note" style="font-family: 'Cascadia Code', sans-serif; font-size: 12px;">Please create an account to continue.</div>
        </header>
        <form method="post" autocomplete="off">
            <div style="display:flex;flex-direction:column;gap:8px;max-width:420px">
                <label style="font-family: 'Cascadia Code', sans-serif; font-size: 15px;"><strong>Username</strong></label>
                <input name="username" required>
                <label style="font-family: 'Cascadia Code', sans-serif; font-size: 15px;"><strong>Password</strong></label>
                <input type="password" name="password" required>
                <div style="display:flex;gap:8px;margin-top:6px">
                    <button type="submit">Register</button>
                    <a href="/login" style="align-self:center;color:var(--muted);text-decoration:underline">Back to login</a>
                </div>
            </div>
        </form>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
    </div>
</body>
</html>
"""

RESET_PASSWORD_HTML = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Chatter — Reset Password</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>{{ base_css }}</style>
</head>
<body>
    <div class="container">
        <header>
            <h1><span style="font-size:22px;font-weight:700;font-family:'Cascadia Code', monospace;">Chatter</span></h1>
            <div class="note" style="font-family: 'Cascadia Code', sans-serif; font-size: 12px;">Reset your password.</div>
        </header>
        <form method="post" action="/api/reset_password" autocomplete="off">
            <div style="display:flex;flex-direction:column;gap:8px;max-width:420px">
                <input type="hidden" name="username" value="{{ username }}">
                <input type="hidden" name="token" value="{{ token }}">
                <label style="font-family: 'Cascadia Code', sans-serif; font-size: 15px;"><strong>Username</strong></label>
                <input type="text" value="{{ username }}" readonly style="background:#f5f5f5">
                <label style="font-family: 'Cascadia Code', sans-serif; font-size: 15px;"><strong>New Password</strong></label>
                <input type="password" name="password" required minlength="6">
                <label style="font-family: 'Cascadia Code', sans-serif; font-size: 15px;"><strong>Confirm Password</strong></label>
                <input type="password" name="confirm_password" required minlength="6">
                <div style="display:flex;gap:8px;margin-top:6px">
                    <button type="submit">Reset Password</button>
                    <a href="/login" style="align-self:center;color:var(--muted);text-decoration:underline">Back to login</a>
                </div>
            </div>
        </form>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <div id="reset-message" style="margin-top:10px;padding:10px;background:#e8f5e8;border-radius:6px;display:none;">
            Password reset successful! Redirecting to login...
        </div>
    </div>
    <script>
        document.querySelector('form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            const data = {
                username: formData.get('username'),
                token: formData.get('token'),
                password: formData.get('password'),
                confirm_password: formData.get('confirm_password')
            };
            
            try {
                const response = await fetch('/api/reset_password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (result.ok) {
                    document.getElementById('reset-message').style.display = 'block';
                    setTimeout(() => {
                        window.location.href = '/login';
                    }, 2000);
                } else {
                    const errorDiv = document.querySelector('.error') || document.createElement('div');
                    errorDiv.className = 'error';
                    errorDiv.textContent = result.error || 'Reset failed';
                    if (!document.querySelector('.error')) {
                        document.querySelector('.container').appendChild(errorDiv);
                    }
                }
            } catch (error) {
                const errorDiv = document.querySelector('.error') || document.createElement('div');
                errorDiv.className = 'error';
                errorDiv.textContent = 'Network error. Please try again.';
                if (!document.querySelector('.error')) {
                    document.querySelector('.container').appendChild(errorDiv);
                }
            }
        });
    </script>
</body>
</html>
"""

CHAT_HTML = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Chatter</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">

    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">

    <!-- Notification System Styles -->
    <style>
    .notification-container {
        position: fixed;
        top: 20px;
        right: 20px;
        width: 320px;
        z-index: 9999;
        font-family: 'Inter', sans-serif;
    }

    .notification {
        position: relative;
        padding: 15px 20px;
        margin-bottom: 10px;
        border-radius: 8px;
        color: white;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        transform: translateX(120%);
        transition: transform 0.3s ease-in-out;
        opacity: 0.95;
        display: flex;
        align-items: flex-start;
        overflow: hidden;
    }

    .notification.show {
        transform: translateX(0);
    }

    .notification.success {
        background: #10B981;
        border-left: 4px solid #059669;
    }

    .notification.error {
        background: #EF4444;
        border-left: 4px solid #DC2626;
    }

    .notification.info {
        background: #3B82F6;
        border-left: 4px solid #2563EB;
    }

    .notification.warning {
        background: #F59E0B;
        border-left: 4px solid #D97706;
    }

    .notification-icon {
        margin-right: 12px;
        font-size: 20px;
        line-height: 1.4;
    }

    .notification-content {
        flex: 1;
    }

    .notification-title {
        font-weight: 600;
        margin-bottom: 4px;
        font-size: 14px;
    }

    .notification-message {
        font-size: 13px;
        line-height: 1.4;
        opacity: 0.9;
    }

    .notification-close {
        background: none;
        border: none;
        color: white;
        opacity: 0.7;
        cursor: pointer;
        padding: 0 0 0 10px;
        font-size: 16px;
        line-height: 1;
    }

    .notification-close:hover {
        opacity: 1;
    }

    .progress-bar {
        position: absolute;
        bottom: 0;
        left: 0;
        height: 3px;
        background: rgba(255, 255, 255, 0.5);
        width: 100%;
        transform: scaleX(1);
        transform-origin: left;
        transition: transform linear;
    }

    /* Modern UI Enhancements */
    :root {
        --primary: #2D3748;
        --primary-hover: #1A202C;
        --secondary: #4A5568;
        --accent: #4299E1;
        --accent-hover: #3182CE;
        --success: #38A169;
        --warning: #DD6B20;
        --danger: #E53E3E;
        --light: #F7FAFC;
        --dark: #1A202C;
        --gray-100: #F7FAFC;
        --gray-200: #EDF2F7;
        --gray-300: #E2E8F0;
        --gray-400: #CBD5E0;
        --gray-500: #A0AEC0;
        --gray-600: #718096;
        --gray-700: #4A5568;
        --gray-800: #2D3748;
        --gray-900: #1A202C;
        --bg: #F8F9FA;
        --card-bg: #FFFFFF;
        --border: #E2E8F0;
        --text: #2D3748;
        --text-muted: #718096;
        --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
        --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
        --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        --radius-sm: 0.25rem;
        --radius: 0.375rem;
        --radius-md: 0.5rem;
        --radius-lg: 0.75rem;
        --radius-full: 9999px;
        --transition: all 0.2s ease;
    }

    /* Dark theme variables */
    .theme-dark {
        --bg: #1A202C;
        --card-bg: #2D3748;
        --border: #4A5568;
        --text: #F7FAFC;
        --text-muted: #A0AEC0;
        --primary: #63B3ED;
        --primary-hover: #4299E1;
    }

    body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        background-color: var(--bg);
        color: var(--text);
        line-height: 1.5;
        -webkit-font-smoothing: antialiased;
    }

    /* Base styles will be merged with existing ones */
    {{ base_css }}
    </style>
    <style>
      /* Mobile responsive enhancements */
      @media (max-width: 768px) {
        .app { flex-direction: column; gap: 8px !important; }
        #leftbar, #rightbar { display:none; }
        body.show-leftbar #leftbar,
        body.show-rightbar #rightbar { display:block; position:fixed; top:0; bottom:56px; left:0; right:0; width:auto; max-width:none; padding:12px; background:var(--bg); z-index:9997; overflow:auto; border:none; }
        #main { order: 2; }
        #mobileNav { display:flex; position:fixed; left:0; right:0; bottom:0; height:56px; background:#111827; color:#fff; z-index:9999; border-top:1px solid #222; }
        #mobileNav button { flex:1; background:transparent; color:#fff; border:none; font-size:14px; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:4px; }
        #mobileBackdrop { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.5); z-index:9996; }
        body.show-leftbar #mobileBackdrop,
        body.show-rightbar #mobileBackdrop { display:block; }
        header { position:sticky; top:0; background:var(--bg); z-index:5; padding-bottom:6px; }
        .chat { min-height: calc(100vh - 56px - 160px); }
        .form-row { position:sticky; bottom:56px; background:var(--bg); padding:6px 0; }
        #textInput { font-size:16px; padding:12px; min-height:44px; }
        #sendForm button { padding:10px 12px; }
        #fileInput { font-size:14px; }
        #onlineBtn { padding:6px 8px; }
        body { padding-bottom: 56px; }
      }
      /* Composer layout */
      #sendForm .form-row { display:flex; gap:8px; align-items:flex-start; }
      #textInput { flex:1; width:100%; border:1px solid var(--border); border-radius:10px; resize:vertical; background:var(--card); color:var(--primary); padding:10px 12px; box-shadow:0 1px 0 rgba(0,0,0,0.02) inset; transition: all 0.2s ease; }
      #textInput:hover { border-color: var(--accent, #3b82f6); }
      #textInput.drag-over { background: var(--card-hover, #f3f4f6); border: 2px dashed var(--accent, #3b82f6); transform: scale(1.02); }
      #fileInput { align-self:flex-start; }
      #sendForm button[type="submit"] { align-self:flex-start; }

      /* Image attachment styles */
      .attachment img { transition: transform 0.2s ease; }
      .attachment img:hover { transform: scale(1.02); }
      .attachment { animation: fadeIn 0.3s ease; }

      @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
      }
    </style>
</head>
<body class="{{ 'theme-dark' if my_theme=='dark' else '' }}">
        <!-- Notification Container -->
        <div id="notificationContainer" class="notification-container"></div>

        <div class="container app" style="display:flex; gap:0; align-items:flex-start;">
        <!-- Left: DM sidebar -->
        <aside id="leftbar" style="width:240px; min-width:240px; border-right:1px dashed #ddd; padding-right:12px;">
            <!-- Direct Messages Section -->
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;gap:6px">
                <span style="font-size:20px; font-family: 'Cascadia Code', Consolas, monospace; font-weight: bold;">Chatter {% if is_admin %} <span style="color:coral;">(admin)</span>{% endif %}</span>
                <div style="display:flex;gap:6px;align-items:center">
                    <button id="publicBtn" type="button" style="padding:3px 7px;font-size:12px">Public</button>
                    <div style="position:relative;display:inline-block">
                      <button id="newMenuBtn" type="button" style="padding:3px 7px;font-size:12px">+ ▾</button>
                      <div id="newMenu" style="display:none;position:absolute;right:0;top:100%;background:#222222;border:1px solid #374151;border-radius:8px;min-width:200px;z-index:50">
                        <a href="#" id="optNewDM" style="display:block;padding:7px 9px;color:#e5e7eb;text-decoration:none;font-family:'Avenir Next', sans-serif;font-weight:bold;font-size:14px;">New Direct Message</a>
                      </div>
                    </div>
                </div>
            </div>
            <div style="margin-bottom:8px">
                <input id="dmSearch" type="text" placeholder="Find a previous conversation" style="width:100%;padding:6px" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" readonly onfocus="this.removeAttribute('readonly')" />
            </div>
            <div id="dmList" style="display:block"></div>
            <!-- Channels Section -->
            <div style="margin-top:16px;display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;gap:6px">
                <span style="font-size:15px; font-family: 'Avenir Next', sans-serif; font-weight:bold;">Channels</span>
                <div style="display:flex;gap:6px;align-items:center">
                    <button id="resetChannelOrderBtn" type="button" style="padding:3px 7px;font-size:12px;background:var(--primary);color:white;border:none;border-radius:2px;cursor:pointer" title="Reset channel order to default">↺ Reset</button>
                    <div style="position:relative;display:inline-block">
                      <button id="newChannelMenuBtn" type="button" style="padding:3px 7px;font-size:12px">+ ▾</button>
                      <div id="newChannelMenu" style="display:none;position:absolute;right:0;top:100%;background:var(--card);border:1px solid var(--border);border-radius:4px;min-width:180px;z-index:50">
                        <a href="#" id="optNewGroup" style="display:block;padding:6px 8px;color:var(--primary);text-decoration:none;font-size:13px;border-bottom:1px solid var(--border)">New Group Chat</a>
                        <a href="#" id="optNewDoc" style="display:block;padding:6px 8px;color:var(--primary);text-decoration:none;font-size:13px;border-bottom:1px solid var(--border)">New Doc</a>
                        <a href="#" id="optNewFileshare" style="display:block;padding:6px 8px;color:var(--primary);text-decoration:none;font-size:13px;border-bottom:1px solid var(--border)">New File Share</a>
                        <div id="apiDefaultChannels" style="border-top:1px solid var(--border);"></div>
                      </div>
                    </div>
                </div>
            </div>
            <div id="channelsList" style="display:block"></div>
        </aside>
        <div id="leftResizer" style="width:6px;cursor:col-resize;align-self:stretch"></div>
        <!-- Main area -->
        <div id="main" style="flex:1; min-width:0; padding:0 8px;">
        <header>
            <h1>
                <link href="https://cdn.jsdelivr.net/npm/cascadia-code@1.0.0/font.css" rel="stylesheet">
            </h1>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;flex-wrap:wrap;">
                <div class="note">
                    <span class="status-indicator"></span>
                    <span style="font-family: 'Cascadia Code', sans-serif;">Logged in as <span class="username" style="font-family: 'Cascadia Code', sans-serif;">{{ username }}</span></span>
                </div>
                <div>
                    <span id="onlineBtn" style="color:blue;cursor:pointer;text-decoration:underline"><span style="font-size:14px; font-family: 'Avenir Next', sans-serif; font-weight:bold;"></span></span>
                </div>
                <div style="display:flex;gap:10px;align-items:center">
                    {% if username in superadmins %}
                    <button id="btnAdminDashHeader" type="button" title="Admin Dashboard" style="background:#374151;color:#fff">Admin Dashboard</button>
                    {% endif %}
                    <button id="pinsBtn" type="button" title="View Pinned Messages" style="padding:6px 10px;background:#f59e0b;color:#fff;border:none;border-radius:4px;cursor:pointer">📌</button>
                    <button id="settingsBtn" type="button">Settings</button>
                    <a href="/logout" style="color:var(--muted);text-decoration:underline">Log out</a>
                </div>
            </div>
        </header>

        <div id="modeBar" style="min-height:18px;color:#444;font-size:13px;margin:4px 0 6px 0"></div>
        <div id="chat" class="chat" aria-live="polite"></div>
        <button id="scrollToBottomBtn" class="scroll-to-bottom" title="Scroll to bottom">↓</button>
        <div id="typingBar" style="min-height:18px;color:#666;font-size:13px;margin-top:6px"></div>
        <div id="globalTypingBar" style="min-height:18px;color:#888;font-size:13px;margin-top:2px"></div>

        <div style="margin-top:8px">
            <div id="replyBar" style="display:none;margin:6px 0;padding:8px;border:1px dashed #9ca3af;border-radius:6px;background:var(--card);color:var(--primary);font-size:13px">
                <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
                    <div>
                        <strong>Replying to <span id="replyUser"></span></strong>
                        <div id="replySnippet" style="color:var(--muted);margin-top:4px;max-width:660px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"></div>
                    </div>
                    <button id="cancelReplyBtn" type="button" class="btn btn-outline">&#10005;</button>
                </div>
            </div>
            <form id="sendForm" enctype="multipart/form-data">
                <div class="form-row">
                    <div style="position:relative;display:inline-block">
                        <button type="button" id="plusBtn" class="plus-button" title="Upload file or image">+</button>
                        <div id="plusDropdown" class="plus-dropdown">
                            <button type="button" id="uploadFileBtn" class="dropdown-item">
                                <span class="dropdown-icon">📁</span> Upload File
                            </button>
                            <button type="button" id="uploadImageBtn" class="dropdown-item">
                                <span class="dropdown-icon">🖼️</span> Upload Images
                            </button>
                            <input id="fileInput" class="file-input" type="file" multiple accept="image/*">
                        </div>
                    </div>
                    <textarea id="textInput" rows="1" placeholder="Type a message... (Drag & drop images here or paste from clipboard)" autocomplete="off" style="resize:vertical"></textarea>
                    <button type="submit">Send</button>
                </div>
                <div id="selectedFilesPreview" class="files-preview">
                    <div id="selectedFilesList" class="files-list"></div>
                </div>
            </form>
        </div>

    <!-- Pinned Messages Overlay -->
    <div id="pinsOverlay" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.35);z-index:10005;">
      <div style="position:relative;max-width:680px;margin:60px auto;background:var(--card);border:1px solid var(--border);border-radius:12px;box-shadow:0 10px 40px rgba(0,0,0,0.25);">
        <div style="padding:12px 14px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;color:var(--primary)">
          <strong>📌 Pinned Messages</strong>
          <button id="closePinsOverlay" type="button" style="padding:6px 10px">&#10005;</button>
        </div>
        <div id="pinsList" style="padding:14px;max-height:70vh;overflow-y:auto;color:var(--primary)"></div>
      </div>
    </div>

    <!-- Admin Dashboard Overlay -->
    <div id="adminOverlay" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);z-index:10010;overflow:auto;">
      <div id="adminBox" style="position:relative;max-width:720px;margin:50px auto;background:var(--card);border:1px solid var(--border);border-radius:12px;box-shadow:0 10px 40px rgba(0,0,0,0.25);">
        <div style="padding:14px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;color:var(--primary)">
          <strong>Admin Dashboard</strong>
          <button id="closeAdminOverlay" type="button" style="padding:6px 10px">&#10005;</button>
        </div>
        <div style="padding:14px;display:flex;flex-direction:column;gap:16px;color:var(--primary)">
          <div id="idResetDropdown" style="border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card); display:none">
            <div style="font-weight:700;margin-bottom:8px">ID Reset Toggles</div>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
              <label for="idResetSelect" style="min-width:140px">Visibility</label>
              <select id="idResetSelect" style="padding:6px 8px">
                <option value="hidden">Hidden</option>
                <option value="shown" selected>Shown</option>
              </select>
              <span class="note">Use this to show/hide the ID reset checkboxes.</span>
            </div>
          </div>
          <div style="border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)">
            <div style="font-weight:700;margin-bottom:8px">DM Tools</div>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
              <label style="min-width:120px">Peer username</label>
              <input id="adminDmPeer" placeholder="username" style="flex:1;min-width:200px;padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)" />
              <button id="adminDmSaveBtn" type="button" class="btn btn-primary">Save DM Logs</button>
              <button id="adminDmCloseAllBtn" type="button" class="btn btn-secondary">Close All My DMs</button>
            </div>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
              <input id="adminDmTo" placeholder="send as System → username" style="flex:1;min-width:220px;padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)" />
              <textarea id="adminDmText" rows="2" placeholder="message text" style="flex:2;min-width:260px;padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)"></textarea>
              <button id="adminDmSendBtn" type="button" class="btn btn-primary">Send DM as System</button>
            </div>
          </div>
          <div style="border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)">
            <div style="font-weight:700;margin-bottom:8px">Group Controls</div>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
              <input id="adminGdmTid" placeholder="thread id (tid)" style="width:200px;padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)" />
              <button id="adminGdmLockBtn" type="button" class="btn btn-secondary">Lock</button>
              <button id="adminGdmUnlockBtn" type="button" class="btn btn-secondary">Unlock</button>
            </div>
          </div>
          <div style="border:1px solid #e5e7eb;border-radius:10px;padding:12px;background:var(--card); display:none">
            <div style="font-weight:700;margin-bottom:8px">Admin Visibility</div>
            <label style="display:flex;align-items:center;gap:8px">
              <input id="toggleAdminsStealth" type="checkbox">
              <span>Stealth mode (hide admins from Users panel)</span>
            </label>
            <div id="stealthStatus" class="note" style="margin-top:6px;color:#6b7280"></div>
          </div>
          <div id="userMgmtCard" style="border:1px solid #e5e7eb;border-radius:10px;padding:12px;background:var(--card)">
            <div style="font-weight:700;margin-bottom:8px">User Management</div>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
              <input id="adminCreateUserName" placeholder="new username" style="flex:1;min-width:180px;padding:8px;border:1px solid #d1d5db;border-radius:6px;background:var(--card);color:var(--primary)" />
              <input id="adminCreateUserPass" type="password" placeholder="password" style="flex:1;min-width:180px;padding:8px;border:1px solid #d1d5db;border-radius:6px;background:var(--card);color:var(--primary)" />
              <label style="display:flex;align-items:center;gap:8px">
                <input id="adminCreateUserIsAdmin" type="checkbox" />
                <span>Make admin</span>
              </label>
              <button id="adminCreateUserBtn" type="button" class="btn btn-primary">Create User</button>
            </div>
            <div class="note" style="color:#6b7280">Superadmin only. Creating with "Make admin" adds this user as an extra admin.</div>
          </div>
          <details id="idResetDetails" style="border:1px solid var(--border);border-radius:10px;padding:0;background:var(--card)">
            <summary style="cursor:pointer;padding:12px;font-weight:700">ID Reset Behavior</summary>
            <div id="idResetBlock" style="padding:12px;border-top:1px solid var(--border);display:block">
              <div style="display:flex;flex-direction:column;gap:8px">
                <label style="display:flex;align-items:center;gap:8px">
                  <input id="toggleResetPublic" type="checkbox">
                  <span>Reset Public message IDs when clearing all public messages</span>
                </label>
                <label style="display:flex;align-items:center;gap:8px">
                  <input id="toggleResetDM" type="checkbox">
                  <span>Reset Direct Message IDs when clearing all DMs</span>
                </label>
                <label style="display:flex;align-items:center;gap:8px">
                  <input id="toggleResetGDM" type="checkbox">
                  <span>Reset Group Message IDs when clearing group messages</span>
                </label>
                <label style="display:flex;align-items:center;gap:8px">
                  <input id="toggleResetGroupThreads" type="checkbox">
                  <span>Reset Group/Member/Message thread IDs when the last group is deleted</span>
                </label>
              </div>
            </div>
          </details>
          <div id="adminDashMsg" style="min-height:18px;color:var(--primary)"></div>
        </div>
      </div>
    </div>

        <div style="margin-top:20px;margin-bottom:5px;color:var(--muted);font-size:13px">
            Chatter is not secure. Do not share anything confidential through chatter.
        </div>
        </div> <!-- end #main -->
        <!-- Right: Online panel -->
        <div id="rightResizer" style="width:6px;cursor:col-resize;align-self:stretch"></div>
        <aside id="rightbar" style="width:240px; min-width:240px; border-left:1px dashed #ddd; padding-left:12px; display:flex; flex-direction:column; max-height:100vh;">
            <div style="font-weight:700; margin-bottom:8px; flex:0 0 auto;"><span style="font-size:15px; font-family: 'Avenir Next', sans-serif; font-weight:bold;">Users</span></div>
            <div id="rightOnlineList" style="font-size:14px; overflow-y:auto; flex:1 1 auto; padding-right:4px;"></div>
        </aside>
    </div>



    <!-- Mobile Navigation -->
    <nav id="mobileNav" style="display:none;">
        <button id="tabPublic" type="button"><i class="icon-chat"></i><small>Public</small></button>
        {% if username in superadmins or is_admin %}
        <button id="btnAdminDash" type="button" title="Admin Dashboard" class="btn btn-secondary">Admin Dashboard</button>
        {% endif %}
        <button id="tabDMs" type="button"><i class="icon-users"></i><small>DMs</small></button>
        <button id="tabGDMs" type="button"><i class="icon-group"></i><small>Groups</small></button>
        <button id="tabSettings" type="button"><i class="icon-cog"></i><small>Settings</small></button>
    </nav>
    <div id="mobileBackdrop"></div>

    <!-- Inline Dialog and Toast -->
    <div id="chatDialog" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);z-index:10012;align-items:center;justify-content:center;">
      <div id="chatDialogBox" style="background:var(--card);border:1px solid var(--border);border-radius:12px;max-width:520px;width:92%;box-shadow:0 10px 40px rgba(0,0,0,0.3);">
        <div style="padding:12px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;color:var(--primary)">
          <strong id="chatDialogTitle">Dialog</strong>
          <button id="chatDialogClose" class="btn btn-outline" type="button">&#10005;</button>
        </div>
        <form id="chatDialogForm" style="padding:14px;display:flex;flex-direction:column;gap:10px"></form>
        <div style="padding:12px 14px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end">
          <button id="chatDialogCancel" class="btn btn-outline" type="button">Cancel</button>
          <button id="chatDialogSubmit" class="btn btn-primary" type="submit">OK</button>
        </div>
      </div>
    </div>
    <div id="chatToast" style="display:none;position:fixed;left:50%;transform:translateX(-50%);bottom:16px;z-index:10013;background:var(--card);color:var(--primary);border:1px solid var(--border);padding:8px 12px;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,0.25)"></div>

    <!-- Settings Modal -->
    <div id="settingsOverlay" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:9998;overflow:auto;">
      <div id="settingsBox" style="position:relative;max-width:520px;margin:60px auto;background:var(--card);border:1px solid #ccc;border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,0.2);max-height:80vh;overflow:auto;">
        <div style="padding:12px 14px;border-bottom:1px solid var(--border);font-weight:700;display:flex;justify-content:space-between;align-items:center;">
          <span>Settings</span>
          <div style="display:flex;gap:8px;align-items:center">
            {% if username in superadmins or is_admin %}
            <button id="btnAdminDashSettings" type="button" title="Admin Dashboard" class="btn btn-secondary">Admin Dashboard</button>
            <button id="btnReportsSettings" type="button" title="Reports Management" class="btn btn-danger">&#128203; Reports</button>
            {% endif %}
            <button id="closeSettings" type="button" class="btn btn-outline">&#10005;</button>
          </div>
        </div>
        <div style="padding:14px;display:flex;flex-direction:column;gap:14px">
          <div>
            <label><strong>Username</strong></label>
            <div style="display:flex;gap:8px;align-items:center">
              <input id="setUsername" placeholder="New username" style="flex:1;padding:8px" value="{{ username }}">
              <button id="saveUsername" type="button" class="btn btn-primary">Save</button>
            </div>
          </div>
          <div>
            <label><strong>Change Password</strong></label>
            <div style="display:flex;flex-direction:column;gap:6px">
              <input id="setCurrentPw" type="password" placeholder="Current password" style="padding:8px">
              <input id="setNewPw" type="password" placeholder="New password" style="padding:8px">
              <button id="savePassword" type="button" class="btn btn-primary">Update Password</button>
            </div>
            <div class="note">Username can be changed without password. Password change requires current password.</div>
          </div>
          <div>
            <label><strong>Theme</strong></label>
            <div style="display:flex;gap:8px;align-items:center">
              <select id="setTheme" style="padding:8px">
                <option value="light" {{ 'selected' if my_theme=='light' else '' }}>Light</option>
                <option value="dark" {{ 'selected' if my_theme=='dark' else '' }}>Dark</option>
              </select>
              <button id="saveTheme" type="button" class="btn btn-primary">Apply</button>
              <button id="resetSidebarSizes" type="button" class="btn btn-outline" style="margin-left:auto">Reset Sidebar Sizes</button>
            </div>
          </div>
          <div>
            <label><strong>Language</strong></label>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <select id="setLanguage" style="padding:8px;min-width:160px">
                {% for lang in supported_languages %}
                <option value="{{ lang.code }}" {{ 'selected' if (my_language or 'en') == lang.code else '' }}>{{ lang.label }}</option>
                {% endfor %}
              </select>
              <button id="saveLanguage" type="button" class="btn btn-primary">Apply</button>
            </div>
            <div class="note" style="margin-top:6px;color:#6b7280">Automatically translates messages and interface content.</div>
          </div>
          <div>
            <label><strong>Profile</strong></label>
            <div style="display:flex;flex-direction:column;gap:6px">
              <textarea id="setBio" placeholder="Short bio" rows="3" style="padding:8px">{{ my_bio }}</textarea>
              <div style="display:flex;gap:8px;align-items:center">
                <select id="setStatus" style="padding:8px">
                  <option value="" {{ 'selected' if (my_status or '')=='' else '' }}>Default</option>
                  <option value="online" {{ 'selected' if my_status=='online' else '' }}>Online</option>
                  <option value="idle" {{ 'selected' if my_status=='idle' else '' }}>Idle</option>
                  <option value="dnd" {{ 'selected' if my_status=='dnd' else '' }}>Do Not Disturb</option>
                  <option value="offline" {{ 'selected' if my_status=='offline' else '' }}>Offline</option>
                </select>
                <button id="saveProfile" type="button" class="btn btn-primary">Save Profile</button>
              </div>
              <div class="note">Bio shows on hover and in DM header. Status affects your presence color.</div>
              <hr style="margin:10px 0;border:none;border-top:1px dashed #ccc">
              <div style="display:flex;gap:8px;flex-wrap:wrap">
                <button id="markAllReadBtn" type="button" class="btn btn-primary">✓ Mark All As Read</button>
                <button id="clearAllMsgs" type="button" class="btn btn-danger" style="display:none">🧹 Clear All Messages</button>
              </div>
            </div>
          </div>
          <div>
            <label><strong>Danger Zone</strong></label>
            <div class="note" style="margin:6px 0;color:#b91c1c">Deleting your account removes your messages, DMs, group messages, and profile. This cannot be undone.</div>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <input id="delAccPw" type="password" placeholder="Confirm password" style="padding:8px;min-width:200px">
              <button id="deleteAccountBtn" type="button" class="btn btn-danger">Delete my account</button>
            </div>
          </div>
          <div>
            <!-- PROFILE PICTURE UPLOAD -->
            <label><strong>Profile Picture</strong></label>
            <form id="avatarForm" action="/api/upload/avatar" enctype="multipart/form-data" style="display:flex;gap:8px;align-items:center">
              <input id="avatarFile" name="avatar" type="file" accept="image/*">
              <button type="submit" class="btn btn-primary">Upload</button>
              {% if my_avatar %}<img src="/uploads/{{ my_avatar }}" alt="avatar" style="width:28px;height:28px;border-radius:50%;border:1px solid var(--border)">{% endif %}
              <button id="deleteAvatarBtn" type="button" class="btn btn-danger" style="margin-left:auto">Delete</button>
            </form>
          </div>
        </div>
      </div>
    </div>
    <!-- Reports Management Panel -->
    <div id="reportsPanel" style="display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:400px;cursor:move;max-height:80vh;background:var(--card);border:1px solid var(--border);border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,0.2);z-index:9999;overflow:hidden;">
      <div style="padding:12px 16px;border-bottom:1px solid var(--border);font-weight:700;display:flex;justify-content:space-between;align-items:center;background:var(--card);color:var(--primary);">
        <span>&#128203; Reports Management</span>
        <div style="display:flex;gap:8px;align-items:center">
          <button id="refreshReports" type="button" class="btn btn-primary" style="padding:4px 8px;font-size:12px;">&#128260; Refresh</button>
          <button id="closeReports" type="button" class="btn btn-outline" style="padding:4px 8px;font-size:12px;">&#10005;</button>
        </div>
      </div>
      <div id="reportsContent" style="padding:12px;overflow-y:auto;max-height:calc(80vh - 60px);color:var(--primary);">
        <div id="reportsLoading" style="text-align:center;padding:30px;color:var(--muted);">
          <div style="font-size:20px;margin-bottom:8px;">⏳</div>
          <div>Loading reports...</div>
        </div>
        <div id="reportsEmpty" style="display:none;text-align:center;padding:30px;color:var(--muted);">
          <div style="font-size:20px;margin-bottom:8px;">📄</div>
          <div>No reports found</div>
        </div>
        <div id="reportsList" style="display:none;"></div>
      </div>
    </div>


    <script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
    <script>
        const SUPPORTED_LANGUAGES = {{ supported_languages|tojson }};
        const ADMINS = {{ admins|tojson }};
        const SUPERADMINS = {{ superadmins|tojson }};
        const chatEl = document.getElementById('chat');
        const scrollToBottomBtn = document.getElementById('scrollToBottomBtn');
        const me = "{{ username }}";
        const isAdmin = {{ 'true' if is_admin else 'false' }};

        // Scroll behavior management
        let isUserScrolledUp = false;
        let lastScrollTop = 0;

        const checkScrollPosition = () => {
            const isAtBottom = chatEl.scrollHeight - chatEl.scrollTop <= chatEl.clientHeight + 50;
            isUserScrolledUp = !isAtBottom;

            if (isUserScrolledUp) {
                scrollToBottomBtn.classList.add('visible');
            } else {
                scrollToBottomBtn.classList.remove('visible');
            }
        };

        const scrollToBottom = (force = false) => {
            if (force || !isUserScrolledUp) {
                chatEl.scrollTop = chatEl.scrollHeight;
                isUserScrolledUp = false;
                scrollToBottomBtn.classList.remove('visible');
            }
        };

        // Scroll event listener
        chatEl.addEventListener('scroll', () => {
            const currentScrollTop = chatEl.scrollTop;
            // Check if user is actively scrolling up
            if (currentScrollTop < lastScrollTop) {
                isUserScrolledUp = true;
            }
            lastScrollTop = currentScrollTop;
            checkScrollPosition();
        });

        // Scroll to bottom button click
        scrollToBottomBtn.addEventListener('click', () => {
            scrollToBottom(true);
        });

        let contextMenu = null;
        let messagesLoaded = false;
        let typingTimer = null;
        let currentMode = 'public'; // 'public' | 'dm' | 'gdm'
        let currentPeer = null;
        let currentThreadId = null;
        let currentReply = null; // {type:'public'|'dm'|'gdm', id:number, username:string, snippet:string}
        const modeBar = document.getElementById('modeBar');

        const Language = (() => {
          const STORAGE_KEY = 'chat.language';
          const defaultLanguage = (document.documentElement?.dataset?.defaultLanguage || 'en').trim() || 'en';
          const allowed = Array.isArray(SUPPORTED_LANGUAGES)
            ? SUPPORTED_LANGUAGES.map(item => {
                if (!item) return null;
                if (typeof item === 'string') return item;
                if (typeof item.code === 'string') return item.code;
                if (typeof item.value === 'string') return item.value;
                return null;
              }).filter(Boolean)
            : [];
          const blockTags = new Set(['SCRIPT','STYLE','NOSCRIPT','CODE','PRE','TEXTAREA','OPTION']);
          const originals = new WeakMap();
          const cache = new Map();
          let current = defaultLanguage;

          function normalize(text) {
            return (text || '').replace(/\s+/g, ' ').trim();
          }

          async function fetchTranslation(text, lang) {
            const target = (lang || current || '').trim() || 'en';
            if (!text || !text.trim()) return text;
            if (target === 'en') return text;
            if (Array.isArray(allowed) && allowed.length && !allowed.includes(target)) {
              return text;
            }
            if ((text || '').length > 4500) {
              return text;
            }
            const key = `${target}::${text}`;
            if (cache.has(key)) {
              return cache.get(key);
            }
            const url = `https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=${encodeURIComponent(target)}&dt=t&q=${encodeURIComponent(text)}`;
            const ctrl = new AbortController();
            const timer = setTimeout(() => {
              try { ctrl.abort(); } catch(e){}
            }, 1800);
            try {
              const res = await fetch(url, { method: 'GET', signal: ctrl.signal });
              if (!res.ok) {
                cache.set(key, text);
                return text;
              }
              let translated = text;
              try {
                const data = await res.json();
                if (Array.isArray(data) && Array.isArray(data[0])) {
                  translated = data[0].map(part => (Array.isArray(part) && part[0] != null) ? part[0] : '').join('');
                } else if (typeof data === 'string' && data) {
                  translated = data;
                }
              } catch (_err) {
                translated = text;
              }
              if (!translated) translated = text;
              cache.set(key, translated);
              return translated;
            } catch (_err) {
              cache.set(key, text);
              return text;
            } finally {
              clearTimeout(timer);
            }
          }

          async function translateNodes(nodes) {
            if (!nodes || !nodes.length) return;
            if ((current || '').trim() === 'en') {
              for (const node of nodes) {
                const original = originals.get(node);
                if (original != null) {
                  node.nodeValue = original;
                }
              }
              return;
            }
            const buckets = new Map();
            for (const node of nodes) {
              if (!node) continue;
              const parent = node.parentElement;
              if (!parent || blockTags.has(parent.tagName)) continue;
              const value = node.nodeValue;
              if (!value || !value.trim()) continue;
              if (!originals.has(node)) {
                originals.set(node, value);
              }
              const key = normalize(value);
              if (!key) continue;
              if (!buckets.has(key)) buckets.set(key, []);
              buckets.get(key).push(node);
            }
            for (const [key, nodeList] of buckets.entries()) {
              const translated = await fetchTranslation(key);
              if (!translated) continue;
              for (const node of nodeList) {
                const original = originals.get(node) ?? node.nodeValue ?? '';
                const leading = (original.match(/^\s*/) || [''])[0];
                const trailing = (original.match(/\s*$/) || [''])[0];
                node.nodeValue = `${leading}${translated}${trailing}`;
              }
            }
          }

          async function translateElement(root) {
            if (!root) return;
            const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
            const nodes = [];
            while (walker.nextNode()) {
              nodes.push(walker.currentNode);
            }
            await translateNodes(nodes);
          }

          async function applyDocument() {
            await translateElement(document.body);
          }

          function setLanguage(lang, opts) {
            const options = opts || {};
            const normalized = (lang || '').trim();
            const target = (allowed.length ? (allowed.includes(normalized) ? normalized : defaultLanguage) : (normalized || defaultLanguage)) || 'en';
            current = target;
            document.documentElement.setAttribute('lang', current);
            if (!options.silent) {
              try { localStorage.setItem(STORAGE_KEY, current); } catch (_err) {}
            }
            applyDocument();
          }

          function getLanguage() {
            return current;
          }

          async function init() {
            let initial = defaultLanguage;
            try {
              const stored = localStorage.getItem(STORAGE_KEY);
              if (stored && (!allowed.length || allowed.includes(stored))) {
                initial = stored;
              }
            } catch (_err) {}
            current = initial || 'en';
            document.documentElement.setAttribute('lang', current);
            await applyDocument();
            return current;
          }

          return {
            init,
            setLanguage,
            getLanguage,
            translateFragment: translateElement,
            translateText: fetchTranslation,
          };
        })();
        Language.init();
        // Inline editor helper
        function startInlineEdit(container, initialHTML, onSave){
          try{
            const originalHTML = initialHTML || '';
            const wrap = document.createElement('div');
            wrap.style.marginTop = '4px';
            const ta = document.createElement('textarea');
            ta.value = (container.innerText || '').replaceAll('\u00A0',' ');
            ta.style.width = '100%';
            ta.style.minHeight = '64px';
            ta.style.padding = '10px';
            ta.style.border = '1px solid #374151';
            ta.style.borderRadius = '8px';
            ta.style.background = 'var(--card)';
            ta.style.color = 'var(--primary)';
            ta.style.fontFamily = 'inherit';
            ta.style.fontSize = '14px';
            ta.placeholder = 'Edit message';
            const row = document.createElement('div');
            row.style.display = 'flex'; row.style.alignItems = 'center'; row.style.gap = '8px'; row.style.marginTop = '6px';
            const hint = document.createElement('div');
            hint.style.color = '#9ca3af'; hint.style.fontSize = '12px';
            hint.textContent = 'escape to cancel • enter to save • shift+enter for newline';
            const saveBtn = document.createElement('button');
            saveBtn.type = 'button'; saveBtn.className = 'btn btn-primary'; saveBtn.textContent = 'Save';
            row.appendChild(hint); row.appendChild(saveBtn);
            wrap.appendChild(ta); wrap.appendChild(row);
            const original = container.innerHTML;
            container.innerHTML = '';
            container.appendChild(wrap);
            ta.focus();
            ta.addEventListener('keydown', (ev)=>{
              if (ev.key === 'Enter' && !ev.shiftKey){ ev.preventDefault(); saveBtn.click(); }
              else if (ev.key === 'Escape'){ ev.preventDefault(); container.innerHTML = original; }
            });
            saveBtn.addEventListener('click', ()=>{
              try{
                const txt = (ta.value || '').trim();
                if (!txt) { container.innerHTML = original; return; }
                onSave(txt);
              } finally {
                container.innerHTML = originalHTML || container.innerHTML;
              }
            });
          }catch(e){}
        }
        const dmListEl = document.getElementById('dmList');
        const dmSearchEl = document.getElementById('dmSearch');
        const rightOnlineList = document.getElementById('rightOnlineList');
        const channelsListEl = document.getElementById('channelsList');
        let gdmThreadsCache = {}; // tid -> {id,name,created_by}
        let docsCache = []; // [{id, name, created_by, ...}]
        let voiceChannelsCache = [];
        let profilesCache = { data: [], ts: 0 };

        // Load DMs list and render in left sidebar
        async function loadDMs(){
          try{
            if (!dmSearchEl || !dmListEl) return;
            const search = (dmSearchEl.value||'').toLowerCase().trim();
            const r = await fetch('/api/dm/peers', {credentials:'same-origin'});
            const peers = await r.json().catch(()=>[]);
            const closed = JSON.parse(localStorage.getItem('closedDMs')||'[]');
            const unread = JSON.parse(localStorage.getItem('unreadDM')||'{}');
            const list = (Array.isArray(peers)? peers: []).filter(u=>u && u!==me && !closed.includes(u));
            list.sort();
            const filtered = search? list.filter(u=>u.toLowerCase().includes(search)) : list;
            dmListEl.innerHTML = filtered.map(u=>{
              const cnt = unread[u]||0;
              const badge = cnt>0? ` <span style='background:#ef4444;color:#fff;border-radius:10px;padding:0 6px;font-size:11px'>${cnt}</span>` : '';
              return `<div><a href="#" data-dm="${u}">@ ${u}${badge}</a></div>`;
            }).join('') || '<div style="color:#999">No DMs</div>';
            dmListEl.querySelectorAll('a[data-dm]').forEach(a=>{
              a.onclick=(e)=>{ e.preventDefault(); openDM(a.getAttribute('data-dm')); if (isMobile()) closeOverlays(); };
            });
          }catch(e){ try{ if(dmListEl) dmListEl.innerHTML = '<div style="color:#999">Failed</div>'; }catch(_){} }
        }

        // Sidebar resizers (desktop only)
        (function setupSidebarResizers(){
          try{
            const lbar = document.getElementById('leftbar');
            const rbar = document.getElementById('rightbar');
            const lrz = document.getElementById('leftResizer');
            const rrz = document.getElementById('rightResizer');
            if (!lbar || !rbar || !lrz || !rrz) return;
            const minW = 160, maxW = 480;
            // Make handles easier to grab and full-height
            [lrz, rrz].forEach(h=>{ try{
              h.style.width = '10px';
              h.style.minHeight = '100%';
              h.style.background = 'transparent';
              h.style.cursor = 'col-resize';
              h.onmouseenter = ()=>{ h.style.background = 'rgba(0,0,0,0.05)'; };
              h.onmouseleave = ()=>{ h.style.background = 'transparent'; };
            }catch(e){}});
            // Load saved widths
            try{
              const lw = parseInt(localStorage.getItem('ui.leftWidth')||'0',10); if (lw) { lbar.style.width=lw+'px'; lbar.style.minWidth=lw+'px'; }
              const rw = parseInt(localStorage.getItem('ui.rightWidth')||'0',10); if (rw) { rbar.style.width=rw+'px'; rbar.style.minWidth=rw+'px'; }
            }catch(e){}
            // Drag helpers
            function dragResizer(startX, startW, onmove){
              const getX = (ev)=> (ev.touches && ev.touches.length ? ev.touches[0].clientX : ev.clientX);
              const mm = (ev)=>{ const dx = getX(ev) - startX; onmove(dx); ev.preventDefault(); };
              const mu = ()=>{
                document.removeEventListener('mousemove', mm);
                document.removeEventListener('mouseup', mu);
                document.removeEventListener('touchmove', mm);
                document.removeEventListener('touchend', mu);
              };
              document.addEventListener('mousemove', mm, {passive:false});
              document.addEventListener('mouseup', mu);
              document.addEventListener('touchmove', mm, {passive:false});
              document.addEventListener('touchend', mu);
            }
            // Left drag: change leftbar width
            function startLeft(ev){
              if (window.matchMedia && window.matchMedia('(max-width: 768px)').matches) return;
              const startX = (ev.touches && ev.touches.length ? ev.touches[0].clientX : ev.clientX);
              const startW = lbar.getBoundingClientRect().width;
              dragResizer(startX, startW, (dx)=>{
                let w = Math.min(maxW, Math.max(minW, startW + dx));
                lbar.style.width = w+'px'; lbar.style.minWidth = w+'px';
                try{ localStorage.setItem('ui.leftWidth', String(w)); }catch(e){}
              });
              ev.preventDefault();
            }
            lrz.addEventListener('mousedown', startLeft);
            lrz.addEventListener('touchstart', startLeft, {passive:false});
            // Right drag: change rightbar width (dragging from its left edge -> inverse sign)
            function startRight(ev){
              if (window.matchMedia && window.matchMedia('(max-width: 768px)').matches) return;
              const startX = (ev.touches && ev.touches.length ? ev.touches[0].clientX : ev.clientX);
              const startW = rbar.getBoundingClientRect().width;
              dragResizer(startX, startW, (dx)=>{
                let w = Math.min(maxW, Math.max(minW, startW - dx));
                rbar.style.width = w+'px'; rbar.style.minWidth = w+'px';
                try{ localStorage.setItem('ui.rightWidth', String(w)); }catch(e){}
              });
              ev.preventDefault();
            }
            rrz.addEventListener('mousedown', startRight);
            rrz.addEventListener('touchstart', startRight, {passive:false});
          }catch(e){}
        })();


        const socket = io();
        const initialGdmTid = {{ (gdm_tid|tojson) if gdm_tid is not none else '""' }};
        const initialCallId = {{ (call_id|tojson) if call_id is not none else '""' }};

        // Reply functionality
        function setReply(info) {
            try {
                currentReply = info || null;
                const replyBar = document.getElementById('replyBar');
                const replyUser = document.getElementById('replyUser');
                const replySnippet = document.getElementById('replySnippet');
                const textInput = document.getElementById('textInput');

                if (currentReply) {
                    replyUser.textContent = currentReply.username || '';
                    replySnippet.textContent = (currentReply.snippet || '').replace(/\s+/g, ' ').slice(0, 50) + '...';
                    replyBar.style.display = 'flex';
                    textInput.focus();
                } else {
                    replyBar.style.display = 'none';
                }
            } catch (e) {
                console.error('Error setting reply:', e);
            }
        }

        function clearReply() {
            try {
                currentReply = null;
                const replyBar = document.getElementById('replyBar');
                if (replyBar) replyBar.style.display = 'none';
            } catch (e) {
                console.error('Error clearing reply:', e);
            }
        }

        function focusReply(messageId) {
            const messageEl = document.querySelector(`[data-id="${messageId}"]`);
            if (messageEl) {
                messageEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
                messageEl.classList.add('highlight-message');
                setTimeout(() => messageEl.classList.remove('highlight-message'), 2000);
            }
        }

        // Discord-like form submission handler with multiple image support
        (function setupFormHandler() {
          try {
            const sendForm = document.getElementById('sendForm');
            const textInput = document.getElementById('textInput');
            const fileInput = document.getElementById('fileInput');
            const plusBtn = document.getElementById('plusBtn');
            const plusDropdown = document.getElementById('plusDropdown');
            const uploadFileBtn = document.getElementById('uploadFileBtn');
            const uploadImageBtn = document.getElementById('uploadImageBtn');

            // Store selected files
            let selectedFiles = [];
            const selectedFilesPreview = document.getElementById('selectedFilesPreview');
            const selectedFilesList = document.getElementById('selectedFilesList');

            // Update file preview
            const updateFilePreview = () => {
              if (selectedFiles.length === 0) {
                selectedFilesPreview.style.display = 'none';
                selectedFilesList.innerHTML = '';
                return;
              }

              selectedFilesPreview.style.display = 'block';
              selectedFilesList.innerHTML = '';

              selectedFiles.forEach((file, index) => {
                const fileItem = document.createElement('div');
                fileItem.className = 'file-item';
                fileItem.style.cssText = 'display: flex; align-items: center; gap: 8px; padding: 8px; background: var(--card); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 8px;';

                if (file.type.startsWith('image/')) {
                  const imgContainer = document.createElement('div');
                  imgContainer.style.cssText = 'position: relative; width: 60px; height: 60px; border-radius: 8px; overflow: hidden; flex-shrink: 0;';
                  
                  const img = document.createElement('img');
                  img.src = URL.createObjectURL(file);
                  img.style.cssText = 'width: 100%; height: 100%; object-fit: cover;';
                  imgContainer.appendChild(img);
                  fileItem.appendChild(imgContainer);
                } else {
                  const iconDiv = document.createElement('div');
                  iconDiv.className = 'file-icon';
                  iconDiv.style.cssText = 'display: flex; align-items: center; justify-content: center; width: 60px; height: 60px; background: var(--muted); border-radius: 8px; flex-shrink: 0; font-size: 24px;';
                  
                  // Choose appropriate icon based on file type
                  const extension = file.name.split('.').pop()?.toLowerCase();
                  if (['pdf'].includes(extension)) {
                    iconDiv.textContent = '📄';
                  } else if (['doc', 'docx'].includes(extension)) {
                    iconDiv.textContent = '📝';
                  } else if (['xls', 'xlsx'].includes(extension)) {
                    iconDiv.textContent = '📊';
                  } else if (['ppt', 'pptx'].includes(extension)) {
                    iconDiv.textContent = '📈';
                  } else if (['zip', 'rar', '7z'].includes(extension)) {
                    iconDiv.textContent = '📦';
                  } else if (['mp4', 'avi', 'mov'].includes(extension)) {
                    iconDiv.textContent = '🎬';
                  } else if (['mp3', 'wav', 'flac'].includes(extension)) {
                    iconDiv.textContent = '🎵';
                  } else {
                    iconDiv.textContent = '📁';
                  }
                  
                  fileItem.appendChild(iconDiv);
                }

                // File info
                const fileInfo = document.createElement('div');
                fileInfo.style.cssText = 'flex: 1; min-width: 0;';
                
                const fileName = document.createElement('div');
                fileName.style.cssText = 'font-weight: 600; color: var(--primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;';
                fileName.textContent = file.name;
                fileName.title = file.name; // Show full name on hover
                fileInfo.appendChild(fileName);
                
                const fileSize = document.createElement('div');
                fileSize.style.cssText = 'font-size: 12px; color: var(--muted); margin-top: 2px;';
                fileSize.textContent = formatFileSize(file.size);
                fileInfo.appendChild(fileSize);
                
                fileItem.appendChild(fileInfo);

                // Remove button
                const removeBtn = document.createElement('button');
                removeBtn.className = 'remove-btn';
                removeBtn.style.cssText = 'background: rgba(220, 38, 38, 0.8); color: white; border: none; border-radius: 50%; width: 20px; height: 20px; cursor: pointer; display: flex; align-items: center; justify-content: center; font-size: 12px; flex-shrink: 0; transition: all 0.2s;';
                removeBtn.innerHTML = '×';
                removeBtn.title = 'Remove file';
                removeBtn.onmouseover = () => removeBtn.style.background = 'rgba(220, 38, 38, 1)';
                removeBtn.onmouseout = () => removeBtn.style.background = 'rgba(220, 38, 38, 0.8)';
                removeBtn.onclick = (e) => {
                  e.preventDefault();
                  selectedFiles.splice(index, 1);
                  updateFilePreview();
                  showToast('File removed', 'info');
                };

                fileItem.appendChild(removeBtn);
                selectedFilesList.appendChild(fileItem);
              });
            };

            // Helper function to format file size
            const formatFileSize = (bytes) => {
              if (bytes === 0) return '0 Bytes';
              const k = 1024;
              const sizes = ['Bytes', 'KB', 'MB', 'GB'];
              const i = Math.floor(Math.log(bytes) / Math.log(k));
              return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            };

            // Plus button dropdown toggle
            const toggleDropdown = (e) => {
              e.preventDefault();
              e.stopPropagation();
              const isVisible = plusDropdown.style.display === 'block';
              plusDropdown.style.display = isVisible ? 'none' : 'block';
            };

            // Close dropdown when clicking outside
            const closeDropdown = (e) => {
              if (!plusBtn.contains(e.target) && !plusDropdown.contains(e.target)) {
                plusDropdown.style.display = 'none';
              }
            };

            // File upload button handlers
            const handleFileUpload = () => {
              fileInput.removeAttribute('accept');
              fileInput.click();
            };

            const handleImageUpload = () => {
              fileInput.setAttribute('accept', 'image/*');
              fileInput.click();
            };

            // Handle file selection
            const handleFileSelect = (e) => {
              const files = Array.from(e.target.files);
              if (files.length === 0) return;

              // Filter images and validate
              const images = files.filter(file => file.type.startsWith('image/'));
              const nonImages = files.filter(file => !file.type.startsWith('image/'));

              if (images.length > 0 && nonImages.length > 0) {
                showToast('Please select either images or files, not both', 'error');
                return;
              }

              if (images.length > 0) {
                // Check total size (max 8MB per image)
                const MAX_SIZE = 8 * 1024 * 1024;

                const oversizedImages = images.filter(file => file.size > MAX_SIZE);
                if (oversizedImages.length > 0) {
                  showToast('Images too large (max 8MB each)', 'error');
                  return;
                }

                // Add new images to existing selection (allow duplicates like Discord)
                selectedFiles = [...selectedFiles, ...images];
                showToast(`${selectedFiles.length} image${selectedFiles.length > 1 ? 's' : ''} selected`, 'success');
                updateFilePreview();
              } else if (nonImages.length > 0) {
                if (nonImages.length > 1) {
                  showToast('Only one file allowed at a time', 'error');
                  return;
                }
                // For non-image files, replace the current selection
                selectedFiles = nonImages;
                showToast('File selected', 'success');
                updateFilePreview();
              }

              // Clear file input
              fileInput.value = '';
              plusDropdown.style.display = 'none';
            };

            // Enhanced file handling for drag-and-drop and paste
            const handleImageFile = (file) => {
              console.log('handleImageFile called with:', file.name, file.type, file.size);

              if (!file) {
                showToast('Please select a file', 'error');
                return;
              }

              // Check file size (max 8MB)
              const MAX_SIZE = 8 * 1024 * 1024;
              if (file.size > MAX_SIZE) {
                showToast('File too large (max 8MB)', 'error');
                return;
              }

              // Add to selected files (no limit like Discord)
              selectedFiles.push(file);
              showToast(`${selectedFiles.length} file${selectedFiles.length > 1 ? 's' : ''} selected`, 'success');
              updateFilePreview();
            };

            // Process files for sending
            const processFilesForSending = async (text) => {
              if (selectedFiles.length === 0) return { text };

              const isImages = selectedFiles.every(file => file.type.startsWith('image/'));

              if (selectedFiles.length === 1) {
                // Single file - send with text
                try {
                  const file = selectedFiles[0];
                  if (file.type.startsWith('image/')) {
                    const base64Data = await new Promise((resolve, reject) => {
                      const reader = new FileReader();
                      reader.onload = () => resolve(reader.result.split(',')[1]);
                      reader.onerror = () => reject(new Error('Failed to read file'));
                      reader.readAsDataURL(file);
                    });

                    return {
                      text,
                      filename: file.name,
                      content: base64Data
                    };
                  } else {
                    // For non-image files, send as base64
                    const base64Data = await new Promise((resolve, reject) => {
                      const reader = new FileReader();
                      reader.onload = () => resolve(reader.result.split(',')[1]);
                      reader.onerror = () => reject(new Error('Failed to read file'));
                      reader.readAsDataURL(file);
                    });

                    return {
                      text,
                      filename: file.name,
                      content: base64Data
                    };
                  }
                } catch (error) {
                  showToast('Failed to process file', 'error');
                  console.error('File processing error:', error);
                  return { text };
                }
              } else {
                // Multiple files - collect all data and send as one message
                try {
                  const fileData = [];
                  for (const file of selectedFiles) {
                    const base64Data = await new Promise((resolve, reject) => {
                      const reader = new FileReader();
                      reader.onload = () => resolve(reader.result.split(',')[1]);
                      reader.onerror = () => reject(new Error(`Failed to read ${file.name}`));
                      reader.readAsDataURL(file);
                    });

                    fileData.push({
                      filename: file.name,
                      content: base64Data
                    });
                  }

                  return {
                    text,
                    files: fileData
                  };
                } catch (error) {
                  showToast('Failed to process files', 'error');
                  console.error('File processing error:', error);
                  return { text };
                }
              }
            };

            // Form submission
            const submitMessage = async (e) => {
              if (e) e.preventDefault();

              const text = (textInput.value || '').trim();

              if (!text && selectedFiles.length === 0) return;

              const data = await processFilesForSending(text);

              if (data) {
                // Include reply information if replying to a message
                if (typeof currentReply !== 'undefined' && currentReply) {
                  data.reply_to = currentReply.id;
                }

                // Include current mode/channel info
                if (typeof currentMode !== 'undefined') {
                  data.mode = currentMode;
                  if (currentMode === 'dm' && typeof currentPeer !== 'undefined') {
                    data.peer = currentPeer;
                  } else if (currentMode === 'gdm' && typeof currentThreadId !== 'undefined') {
                    data.thread_id = currentThreadId;
                  }
                }

                console.log('Sending data:', { filename: data.filename, files: data.files, mode: data.mode, peer: data.peer, thread_id: data.thread_id });

                // Handle multiple files case - send all together like Discord
                if (data.files && Array.isArray(data.files)) {
                  // Send all files and text together in one message
                  const combinedMessage = {
                    text: data.text || '',
                    attachments: data.files.map(f => ({
                      filename: f.filename,
                      content: f.content
                    })),
                    reply_to: data.reply_to
                  };

                  // Use the correct socket event based on mode
                  if (data.mode === 'dm') {
                    socket.emit('dm_send', { to: data.peer, ...combinedMessage });
                  } else if (data.mode === 'gdm') {
                    socket.emit('gdm_send', { thread_id: data.thread_id, ...combinedMessage });
                  } else {
                    socket.emit('send_message', combinedMessage);
                  }
                } else {
                  // Single file or no files case
                  if (data.mode === 'dm') {
                    socket.emit('dm_send', { to: data.peer, ...data });
                  } else if (data.mode === 'gdm') {
                    socket.emit('gdm_send', { thread_id: data.thread_id, ...data });
                  } else {
                    socket.emit('send_message', data);
                  }
                }

                // Clear reply after sending
                if (typeof clearReply === 'function') clearReply();
              }

              // Clear inputs
              textInput.value = '';
              selectedFiles = [];
              updateFilePreview();
              textInput.style.height = 'auto';
              
              // Re-focus input for better UX
              setTimeout(() => textInput.focus(), 10);

              // Close dropdown if open
              if (plusDropdown && plusDropdown.style.display === 'block') {
                plusDropdown.style.display = 'none';
              }
            };

            // Event listeners
            if (plusBtn) plusBtn.addEventListener('click', toggleDropdown);
            if (uploadFileBtn) uploadFileBtn.addEventListener('click', handleFileUpload);
            if (uploadImageBtn) uploadImageBtn.addEventListener('click', handleImageUpload);
            if (fileInput) fileInput.addEventListener('change', handleFileSelect);
            document.addEventListener('click', closeDropdown);

            if (sendForm) sendForm.addEventListener('submit', submitMessage);

              // Drag and drop handlers
              const handleDragOver = (e) => {
                e.preventDefault();
                e.stopPropagation();
                textInput.classList.add('drag-over');
              };

              const handleDragLeave = (e) => {
                e.preventDefault();
                e.stopPropagation();
                textInput.classList.remove('drag-over');
              };

              const handleDrop = (e) => {
                e.preventDefault();
                e.stopPropagation();
                textInput.classList.remove('drag-over');

                const files = Array.from(e.dataTransfer.files);
                const imageFiles = files.filter(file => file.type.startsWith('image/'));
                const nonImageFiles = files.filter(file => !file.type.startsWith('image/'));

                if (imageFiles.length > 0 && nonImageFiles.length > 0) {
                  showToast('Please drop either images or files, not both', 'error');
                  return;
                }

                if (imageFiles.length > 0) {
                  // Handle multiple images like Discord
                  console.log('Dropped image files:', imageFiles.length);
                  imageFiles.forEach(file => handleImageFile(file));
                } else if (nonImageFiles.length > 0) {
                  if (nonImageFiles.length > 1) {
                    showToast('Only one file allowed at a time', 'error');
                    return;
                  }
                  // Handle single non-image file
                  selectedFiles = nonImageFiles;
                  showToast('File selected', 'success');
                  updateFilePreview();
                } else {
                  showToast('Please drop an image or file', 'error');
                }
              };

              // Paste handler for images
              const handlePaste = (e) => {
                const items = Array.from(e.clipboardData.items);
                const imageItems = items.filter(item => item.type.startsWith('image/'));

                if (imageItems.length > 0) {
                  e.preventDefault();
                  const imageItem = imageItems[0];
                  const file = imageItem.getAsFile();

                  if (file) {
                    console.log('Pasted image file:', file.name, file.type, file.size);
                    handleImageFile(file);
                  }
                }
              };

              // Add event listeners
              textInput.addEventListener('dragover', handleDragOver);
              textInput.addEventListener('dragleave', handleDragLeave);
              textInput.addEventListener('drop', handleDrop);
              textInput.addEventListener('paste', handlePaste);

              // Auto-resize textarea
              textInput.addEventListener('input', () => {
                textInput.style.height = 'auto';
                textInput.style.height = Math.min(textInput.scrollHeight, 120) + 'px';
              });

          } catch (e) {
            console.error('Error setting up form handler:', e);
          }
        })();

        // Mobile helpers
        const isMobile = () => window.matchMedia && window.matchMedia('(max-width: 768px)').matches;
        function closeOverlays(){ document.body.classList.remove('show-leftbar','show-rightbar'); }
        function openLeftbar(){ document.body.classList.add('show-leftbar'); }
        function openRightbar(){ document.body.classList.add('show-rightbar'); }
        (function setupMobileNav(){
          try {
            const nav = document.getElementById('mobileNav');
            const backdrop = document.getElementById('mobileBackdrop');
            const apply = () => { nav.style.display = isMobile() ? 'flex' : 'none'; };
            apply();
            window.addEventListener('resize', apply);
            backdrop.onclick = closeOverlays;
            document.getElementById('tabPublic').onclick = () => { switchToPublic(); closeOverlays(); };
            document.getElementById('tabDMs').onclick = () => { if (!document.body.classList.contains('show-leftbar')) { openLeftbar(); try { document.getElementById('dmList').scrollIntoView({behavior:'smooth'}); } catch(e){} } else { closeOverlays(); } };
            document.getElementById('tabGDMs').onclick = () => { if (!document.body.classList.contains('show-leftbar')) { openLeftbar(); try { document.getElementById('channelsList').scrollIntoView({behavior:'smooth'}); } catch(e){} } else { closeOverlays(); } };
            document.getElementById('tabSettings').onclick = () => { closeOverlays(); document.getElementById('settingsOverlay').style.display='block'; };
          } catch(e) {}
        })();

        // Dialog/Toast helpers
        function toast(msg, color){
          try{
            const el=document.getElementById('chatToast');
            el.textContent=msg||'';
            try { Language.translateFragment(el); } catch(_){}
            el.style.display='block';
            el.style.color=color||'var(--primary)';
            clearTimeout(window.__toastTimer);
            window.__toastTimer=setTimeout(()=>{ el.style.display='none'; }, 1800);
          }catch(e){}
        }
        function openDialog(opts){
          try{
            const wrap=document.getElementById('chatDialog');
            const form=document.getElementById('chatDialogForm');
            document.getElementById('chatDialogTitle').textContent=opts.title||'Dialog';
            form.innerHTML = opts.html||'';
            wrap.style.display='flex';
            try { Language.translateFragment(wrap); } catch(_){}
            const close=()=>{ wrap.style.display='none'; };
            document.getElementById('chatDialogClose').onclick=close;
            document.getElementById('chatDialogCancel').onclick=close;
            const submitBtn=document.getElementById('chatDialogSubmit');
            submitBtn.onclick=(ev)=>{
              ev.preventDefault();
              try{ opts.onSubmit && opts.onSubmit(new FormData(form), close); }catch(e){}
            };
          }catch(e){}
        }

        // Voice Channels UI section
        const voiceState = {
          current: null,
          localStream: null,
          peers: {}, // username -> RTCPeerConnection
          muted: false
        };
        const voiceSection = document.createElement('div');
        voiceSection.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;margin:14px 0 6px 0">
            <span style="font-size:15px; font-family: 'Avenir Next', sans-serif; font-weight:bold;">Voice Channels</span>
            <span id="voiceStatus" style="font-size:12px;color:#9ca3af"></span>
          </div>
          <div id="voiceControls" style="display:none;gap:6px;margin-bottom:6px">
            <button id="voiceMuteBtn" type="button" style="padding:4px 8px;font-size:12px">Mute</button>
            <button id="voiceLeaveBtn" type="button" style="padding:4px 8px;font-size:12px;background:#7f1d1d;color:#fff">Leave</button>
            <div id="voicePeers" style="margin-left:auto;font-size:12px;color:#9ca3af"></div>
          </div>
          <div id="voiceList" style="display:none"></div>`;
        leftbar.appendChild(voiceSection);
        const voiceListEl = voiceSection.querySelector('#voiceList');
        const voiceControlsEl = voiceSection.querySelector('#voiceControls');
        const voiceStatusEl = voiceSection.querySelector('#voiceStatus');
        const voiceMuteBtn = voiceSection.querySelector('#voiceMuteBtn');
        const voiceLeaveBtn = voiceSection.querySelector('#voiceLeaveBtn');
        const voicePeersEl = voiceSection.querySelector('#voicePeers');

        function setVoiceStatus(t){ try{ voiceStatusEl.textContent = t||''; }catch(e){} }
        function renderVoiceList(channels){
          try{
            const chans = Array.isArray(channels)? channels: [];
            voiceChannelsCache = chans;
            renderChannels();
          }catch(e){}
        }
        async function refreshVoiceList(){
          try{ const r = await fetch('/api/voice/channels',{credentials:'same-origin'}); const j = await r.json().catch(()=>({})); renderVoiceList((j&&j.channels)||[]); }catch(e){}
        }

        // Drag and drop functionality for channel reordering
        let draggedElement = null;
        let draggedElementParent = null;
        let draggedIndex = null;

        function handleDragStart(e) {
            draggedElement = this;
            draggedElementParent = this.parentElement;
            draggedIndex = Array.from(channelsListEl.querySelectorAll('div')).indexOf(draggedElementParent);

            // Better visual feedback
            this.style.opacity = '0.6';
            this.style.transform = 'scale(1.05)';
            this.style.boxShadow = '0 4px 12px rgba(0,0,0,0.3)';
            this.style.zIndex = '1000';
            this.style.position = 'relative';

            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/html', this.innerHTML);

            // Hide the original element during drag
            setTimeout(() => {
                this.style.display = 'none';
            }, 0);
        }

        function handleDragOver(e) {
            if (e.preventDefault) {
                e.preventDefault();
            }
            e.dataTransfer.dropEffect = 'move';

            // Get the element being dragged over
            const targetElement = this;
            const targetParent = targetElement.parentElement;
            const targetIndex = Array.from(channelsListEl.querySelectorAll('div')).indexOf(targetParent);

            // Don't allow dropping on itself
            if (draggedElement === targetElement || draggedIndex === targetIndex) {
                return false;
            }

            // Better visual feedback - highlight the drop zone
            channelsListEl.querySelectorAll('div').forEach(div => {
                div.style.border = '';
                div.style.background = '';
            });

            targetParent.style.border = '2px solid var(--primary)';
            targetParent.style.background = 'var(--card)';

            return false;
        }

        function handleDrop(e) {
            if (e.stopPropagation) {
                e.stopPropagation();
            }
            e.preventDefault();

            // Remove visual feedback
            channelsListEl.querySelectorAll('div').forEach(div => {
                div.style.border = '';
                div.style.background = '';
            });

            // Don't allow dropping on itself
            if (draggedElement === this) {
                return false;
            }

            const targetParent = this.parentElement;
            const targetIndex = Array.from(channelsListEl.querySelectorAll('div')).indexOf(targetParent);

            if (draggedElementParent && targetParent && draggedIndex !== targetIndex) {
                // Remove the dragged element from its original position
                draggedElementParent.remove();

                // Insert it at the new position
                const allChannels = Array.from(channelsListEl.querySelectorAll('div'));
                if (draggedIndex < targetIndex) {
                    // Moving down - insert after target
                    targetParent.parentNode.insertBefore(draggedElementParent, targetParent.nextSibling);
                } else {
                    // Moving up - insert before target
                    targetParent.parentNode.insertBefore(draggedElementParent, targetParent);
                }

                // Restore the dragged element's visibility
                draggedElement.style.display = '';
                draggedElement.style.opacity = '';
                draggedElement.style.transform = '';
                draggedElement.style.boxShadow = '';
                draggedElement.style.zIndex = '';
                draggedElement.style.position = '';

                // Re-attach event listeners
                draggedElement.style.cursor = 'grab';
                draggedElement.addEventListener('dragstart', handleDragStart);
                draggedElement.addEventListener('dragover', handleDragOver);
                draggedElement.addEventListener('drop', handleDrop);
                draggedElement.addEventListener('dragend', handleDragEnd);

                // Save the new order
                saveChannelOrder();
            }

            return false;
        }

        function handleDragEnd(e) {
            // Clean up all visual feedback
            channelsListEl.querySelectorAll('a').forEach(item => {
                item.style.opacity = '';
                item.style.transform = '';
                item.style.boxShadow = '';
                item.style.zIndex = '';
                item.style.position = '';
                item.style.display = '';
                item.style.cursor = 'grab';
            });

            channelsListEl.querySelectorAll('div').forEach(div => {
                div.style.border = '';
                div.style.background = '';
            });

            draggedElement = null;
            draggedElementParent = null;
            draggedIndex = null;
        }

        function saveChannelOrder() {
            try {
                const channels = [];
                channelsListEl.querySelectorAll('div').forEach(div => {
                    const link = div.querySelector('a');
                    if (link) {
                        if (link.getAttribute('data-public')) {
                            channels.push({ type: 'public', id: 'public' });
                        } else if (link.getAttribute('data-gdm')) {
                            channels.push({ type: 'gdm', id: link.getAttribute('data-gdm') });
                        } else if (link.getAttribute('data-voice')) {
                            channels.push({ type: 'voice', id: link.getAttribute('data-voice') });
                        } else if (link.getAttribute('data-doc')) {
                            channels.push({ type: 'doc', id: link.getAttribute('data-doc') });
                        }
                    }
                });
                localStorage.setItem('channelOrder', JSON.stringify(channels));
            } catch(e) {}
        }

        function loadChannelOrder() {
            try {
                const order = JSON.parse(localStorage.getItem('channelOrder') || '[]');
                if (order.length === 0) return;

                const channels = channelsListEl.querySelectorAll('div');
                const orderedChannels = [];

                // Reorder channels based on saved order
                order.forEach(saved => {
                    channels.forEach(div => {
                        const link = div.querySelector('a');
                        if (link) {
                            if (saved.type === 'public' && link.getAttribute('data-public')) {
                                orderedChannels.push(div);
                            } else if (saved.type === 'gdm' && link.getAttribute('data-gdm') === saved.id) {
                                orderedChannels.push(div);
                            } else if (saved.type === 'voice' && link.getAttribute('data-voice') === saved.id) {
                                orderedChannels.push(div);
                            } else if (saved.type === 'doc' && link.getAttribute('data-doc') === saved.id) {
                                orderedChannels.push(div);
                            }
                        }
                    });
                });

                // Add any channels not in the saved order
                channels.forEach(div => {
                    if (!orderedChannels.includes(div)) {
                        orderedChannels.push(div);
                    }
                });

                // Re-append in order
                orderedChannels.forEach(div => channelsListEl.appendChild(div));
            } catch(e) {}
        }

        // Reset channel order functionality
        function resetChannelOrder() {
            if (confirm('Are you sure you want to reset the channel order to default?')) {
                localStorage.removeItem('channelOrder');
                renderChannels();
            }
        }

        // Combined channels renderer
        function renderChannels(){
          try{
            const list = [];
            // Add #public at the top
            list.push(`<div><a href="#" data-public="true" draggable="true"># public</a></div>`);
            // Group threads
            const closed = JSON.parse(localStorage.getItem('closedGDMs')||'[]');
            const threads = Object.values(gdmThreadsCache||{});
            threads.sort((a,b)=>String(a.name||a.id).localeCompare(String(b.name||b.id)));
            threads.forEach(t=>{
              const sid = String(t.id);
              if (closed.includes(sid)) return;
              const name = t.name || `Group ${t.id}`;
              list.push(`<div><a href="#" data-gdm="${t.id}" draggable="true"><span style="font-size:16px">👥</span> ${name}</a></div>`);
            });
            // Voice channels
            (voiceChannelsCache||[]).forEach(ch=>{
              list.push(`<div><a href="#" data-voice="${ch}" draggable="true"><span style="font-size:16px">🔊</span> ${ch}</a></div>`);
            });
            // Docs
            (docsCache||[]).forEach(d=>{
              list.push(`<div><a href="#" data-doc="${d.id}" draggable="true"><span style="font-size:16px">📄</span> ${d.name}</a></div>`);
            });
            channelsListEl.innerHTML = list.join('');

            // Make channels draggable
            channelsListEl.querySelectorAll('a[draggable="true"]').forEach(item => {
              item.style.cursor = 'grab';
              item.addEventListener('dragstart', handleDragStart);
              item.addEventListener('dragover', handleDragOver);
              item.addEventListener('drop', handleDrop);
              item.addEventListener('dragend', handleDragEnd);
            });

            // Wire clicks for #public
            channelsListEl.querySelectorAll('a[data-public]').forEach(a=>{ a.onclick=(e)=>{ e.preventDefault(); switchToPublic(); if (isMobile()) closeOverlays(); }; });
            // Wire clicks for group chats
            channelsListEl.querySelectorAll('a[data-gdm]').forEach(a=>{ a.onclick=(e)=>{ e.preventDefault(); const tid=parseInt(a.getAttribute('data-gdm'),10); if(!isNaN(tid)) openGDM(tid); if (isMobile()) closeOverlays(); }; });
            // Wire clicks for voice channels
            channelsListEl.querySelectorAll('a[data-voice]').forEach(a=>{ a.onclick=(e)=>{ e.preventDefault(); const ch=a.getAttribute('data-voice'); if(ch) openVoice(ch); if (isMobile()) closeOverlays(); }; });
            // Wire clicks for docs
            channelsListEl.querySelectorAll('a[data-doc]').forEach(a=>{ a.onclick=(e)=>{ e.preventDefault(); const docId=parseInt(a.getAttribute('data-doc'),10); if(!isNaN(docId)) openDoc(docId); if (isMobile()) closeOverlays(); }; });

            // Load saved channel order
            loadChannelOrder();
          }catch(e){}
        }

        // Load group threads and update cache
        async function loadGDMs(){
          try{
            const r = await fetch('/api/gdm/threads',{credentials:'same-origin'});
            const j = await r.json().catch(()=>({}));
            const arr = Array.isArray(j) ? j : (j.threads||j.data||[]);
            const map = {};
            (arr||[]).forEach(t=>{ if (t && (t.id!==undefined)) map[t.id] = t; });
            gdmThreadsCache = map;
            renderChannels();
          }catch(e){}
        }

        // Load docs and render in left sidebar
        async function loadDocs(){
          try{
            const r = await fetch('/api/doc/list', {credentials:'same-origin'});
            const docs = await r.json().catch(()=>[]);
            docsCache = Array.isArray(docs) ? docs : [];
            renderChannels();
          }catch(e){}
        }

        // Current doc state
        let currentDoc = null;
        let docEditor = null;
        let docPreview = null;
        let docContent = '';
        let docAutoSaveTimer = null;

        async function openDoc(docId){
          try{
            currentDoc = docId;
            currentMode = 'doc';
            const r = await fetch(`/api/doc/${docId}`, {credentials:'same-origin'});
            const doc = await r.json().catch(()=>null);
            if (!doc) { showToast('Failed to load doc', 'error'); return; }

            // Get user permissions
            const membersR = await fetch(`/api/doc/${docId}/members`, {credentials:'same-origin'});
            const members = await membersR.json().catch(()=>[]);
            const myMember = members.find(m => m.username === me);
            const userRole = myMember ? myMember.role : null;
            const canEdit = userRole === 'editor';
            const isCreator = doc.created_by === me;

            docContent = doc.content || '';
            switchToDoc(doc, { canEdit, isCreator, userRole });
            socket.emit('doc_join', {doc_id: docId});
            refreshRightOnline();
          }catch(e){ showToast('Error opening doc', 'error'); }
        }

        function switchToDoc(doc, permissions = {}){
          try{
            const { canEdit = false, isCreator = false, userRole = null } = permissions;

            // Clear modeBar when switching to doc
            if (modeBar) {
                modeBar.textContent = '';
                modeBar.innerHTML = '';
            }

            const main = chatEl;
            main.innerHTML = `
              <div style="display:flex;flex-direction:column;height:100%;background:var(--bg)">
                <div style="padding:12px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
                  <div>
                    <h2 style="margin:0;font-size:18px">${doc.name}</h2>
                    <div style="font-size:12px;color:var(--muted)">Created by ${doc.created_by} ${userRole ? `• Your role: ${userRole}` : ''}</div>
                  </div>
                  <div style="display:flex;gap:8px">
                    <button id="docShareBtn" type="button" style="padding:6px 12px;font-size:12px">Share</button>
                    <button id="docMembersBtn" type="button" style="padding:6px 12px;font-size:12px">Members</button>
                  </div>
                </div>
                <div style="display:flex;flex:1;gap:12px;padding:12px;overflow:hidden">
                  <textarea id="docEditor" placeholder="Start typing..." style="flex:1;padding:12px;border:1px solid var(--border);border-radius:6px;font-family:monospace;font-size:14px;resize:none;background:var(--card);color:var(--primary)" ${!canEdit ? 'readonly' : ''}></textarea>
                  <div id="docPreview" style="flex:1;padding:12px;border:1px solid var(--border);border-radius:6px;overflow-y:auto;background:var(--card);color:var(--primary)"></div>
                </div>
                ${!canEdit ? `
                <div style="padding:8px 12px;background:var(--warning-bg, #fef3c7);color:var(--warning-text, #92400e);font-size:12px;border-top:1px solid var(--border)">
                  ${isCreator ? 'You are the creator but need editor role to edit.' :
                    `You have ${userRole || 'no'} access. Only editors can modify this document.`}
                </div>
                ` : ''}
              </div>
            `;

            docEditor = document.getElementById('docEditor');
            docPreview = document.getElementById('docPreview');
            docEditor.value = docContent;

            // Update preview
            function updatePreview(){
              try{
                const md = window.markdownit ? window.markdownit() : null;
                if (md) {
                  docPreview.innerHTML = md.render(docEditor.value);
                } else {
                  docPreview.innerHTML = '<pre>' + (docEditor.value||'').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</pre>';
                }
              }catch(e){}
            }

            updatePreview();

            // Auto-save on edit (only if user can edit)
            docEditor.oninput = ()=>{
              if (!canEdit) return; // Don't send edits if user can't edit

              docContent = docEditor.value;
              updatePreview();

              // Emit edit to server
              socket.emit('doc_edit', {doc_id: doc.id, content: docContent});

              // Clear previous timer
              if (docAutoSaveTimer) clearTimeout(docAutoSaveTimer);
              docAutoSaveTimer = setTimeout(()=>{
                // Auto-save happens via socket, no need for additional save
              }, 1000);
            };

            // Share button
            document.getElementById('docShareBtn').onclick = ()=>{
              const url = window.location.origin + '/doc/' + doc.id;
              const msg = `Doc: ${doc.name}\n${url}`;
              if (navigator.share) {
                navigator.share({title: doc.name, text: msg});
              } else {
                showToast('Copy link: ' + url, 'info');
              }
            };

            // Members button
            document.getElementById('docMembersBtn').onclick = ()=>{
              openDialog({
                title: `Doc Members - ${doc.name}`,
                html: `
                  ${doc.created_by === me ? `
                    <div style="margin-bottom:16px;padding:12px;background:var(--error-bg, #fee2e2);border:1px solid var(--error, #dc2626);border-radius:6px">
                      <div style="display:flex;justify-content:space-between;align-items:center">
                        <div>
                          <div style="font-weight:600;color:var(--error, #dc2626);margin-bottom:4px">⚠️ Document Creator</div>
                          <div style="font-size:12px;color:var(--error-text, #dc2626)">You can manage members and delete this document</div>
                        </div>
                        <button id="deleteDocBtn" type="button" style="padding:8px 16px;border:1px solid var(--error, #dc2626);border-radius:6px;background:var(--error, #dc2626);color:white;font-weight:500;cursor:pointer">🗑️ Delete Document</button>
                      </div>
                    </div>
                  ` : ''}
                  <div style="margin-bottom:12px">
                    <label>Add member:</label>
                    <div style="display:flex;gap:8px;align-items:center">
                      <input id="addMemberInput" type="text" placeholder="Username" style="flex:1;padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)"/>
                      <select id="addMemberRole" style="padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary);min-width:100px">
                        <option value="viewer" style="color:var(--error, #dc2626)">👁️ Viewer</option>
                        <option value="editor">✏️ Editor</option>
                      </select>
                      <button id="addMemberBtn" type="button" style="padding:8px 16px;border:1px solid var(--accent);border-radius:6px;background:var(--accent);color:var(--accent-text, white);font-weight:500;cursor:pointer">Add</button>
                    </div>
                  </div>
                  <div id="membersList"></div>
                `,
                onSubmit: ()=>{}
              });

              // Load members
              fetch(`/api/doc/${doc.id}/members`, {credentials:'same-origin'})
                .then(r=>r.json())
                .then(members=>{
                  const list = document.getElementById('membersList');
                  function renderMembers(memberList) {
                    list.innerHTML = memberList.map(m=>`
                      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px;border-bottom:1px solid var(--border);background:var(--card);border-radius:6px;margin-bottom:4px">
                        <div style="display:flex;align-items:center;gap:8px">
                          <div style="width:8px;height:8px;border-radius:50%;background:${
                            m.role === 'editor' ? 'var(--accent)' :
                            'var(--text-muted)'
                          }"></div>
                          <div style="display:flex;flex-direction:column">
                            <span style="font-weight:500;color:var(--primary)">${m.username}</span>
                            <span style="font-size:12px;color:var(--text-muted);text-transform:capitalize">${
                              m.role === 'editor' ? '✏️ Editor' :
                              '<span style="color:var(--error, #dc2626)">👁️ Viewer</span>'
                            }</span>
                          </div>
                        </div>
                        <div style="display:flex;gap:6px;align-items:center">
                          ${m.username !== me && doc.created_by === me ? `
                            <select class="roleSelect" data-member="${m.username}" style="padding:6px;border:1px solid var(--border);border-radius:4px;background:var(--card);color:var(--primary);font-size:12px">
                              <option value="viewer" ${m.role === 'viewer' ? 'selected' : ''} style="color:var(--error, #dc2626)">👁️ Viewer</option>
                              <option value="editor" ${m.role === 'editor' ? 'selected' : ''}>✏️ Editor</option>
                            </select>
                            <button class="removeMemberBtn" data-member="${m.username}" type="button" style="padding:4px 8px;border:1px solid var(--error);border-radius:4px;background:var(--error-bg, #fee2e2);color:var(--error-text, #dc2626);font-size:11px;cursor:pointer">Remove</button>
                          ` : ''}
                        </div>
                      </div>
                    `).join('');

                    // Re-attach event handlers
                    attachMemberHandlers();
                  }

                  // Store renderMembers globally for add member functionality
                  window.currentRenderMembers = renderMembers;

                  function attachMemberHandlers() {
                    // Handle role changes
                    document.querySelectorAll('.roleSelect').forEach(select=>{
                      select.onchange = ()=>{
                        const member = select.getAttribute('data-member');
                        const newRole = select.value;
                        fetch(`/api/doc/${doc.id}/update_member_role`, {
                          method: 'POST',
                          headers: {'Content-Type': 'application/json'},
                          credentials: 'same-origin',
                          body: JSON.stringify({username: member, role: newRole})
                        }).then(r=>{
                          if (r.ok) {
                            showToast(`Updated ${member}'s role to ${newRole}`, 'success');
                            // Update immediately without closing dialog
                            fetch(`/api/doc/${doc.id}/members`, {credentials:'same-origin'})
                              .then(r=>r.json())
                              .then(renderMembers);
                          } else {
                            showToast('Failed to update role', 'error');
                          }
                        }).catch(() => showToast('Failed to update role', 'error'));
                      };
                    });

                    document.querySelectorAll('.removeMemberBtn').forEach(btn=>{
                      btn.onclick = ()=>{
                        const member = btn.getAttribute('data-member');
                        if (confirm(`Remove ${member} from this document?`)) {
                          fetch(`/api/doc/${doc.id}/remove_member`, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            credentials: 'same-origin',
                            body: JSON.stringify({username: member})
                          }).then(r=>{
                            if (r.ok) {
                              showToast(`Removed ${member} from document`, 'success');
                              // Update immediately without closing dialog
                              fetch(`/api/doc/${doc.id}/members`, {credentials:'same-origin'})
                                .then(r=>r.json())
                                .then(renderMembers);
                            } else {
                              showToast('Failed to remove member', 'error');
                            }
                          }).catch(() => showToast('Failed to remove member', 'error'));
                        }
                      };
                    });
                  }

                  renderMembers(members);

                  // Listen for real-time member updates
                  const memberUpdateHandler = (data) => {
                    if (data.doc_id === doc.id) {
                      fetch(`/api/doc/${doc.id}/members`, {credentials:'same-origin'})
                        .then(r=>r.json())
                        .then(renderMembers);
                    }
                  };

                  socket.on('doc_member_added', memberUpdateHandler);
                  socket.on('doc_member_removed', memberUpdateHandler);
                  socket.on('doc_member_role_updated', memberUpdateHandler);

                  // Clean up socket listeners when dialog closes
                  const dialog = document.querySelector('.dialog-overlay');
                  if (dialog) {
                    const closeBtn = dialog.querySelector('.dialog-close');
                    const originalClose = closeBtn.onclick;
                    closeBtn.onclick = () => {
                      socket.off('doc_member_added', memberUpdateHandler);
                      socket.off('doc_member_removed', memberUpdateHandler);
                      socket.off('doc_member_role_updated', memberUpdateHandler);
                      originalClose();
                    };
                  }
                });

              document.getElementById('addMemberBtn').onclick = ()=>{
                const username = document.getElementById('addMemberInput').value.trim();
                const role = document.getElementById('addMemberRole').value;
                if (!username) {
                  showToast('Please enter a username', 'error');
                  return;
                }
                fetch(`/api/doc/${doc.id}/add_member`, {
                  method: 'POST',
                  headers: {'Content-Type': 'application/json'},
                  credentials: 'same-origin',
                  body: JSON.stringify({username, role})
                }).then(r=>{
                  if (r.ok) {
                    showToast(`Added ${username} as ${role}`, 'success');
                    // Clear input and update immediately
                    document.getElementById('addMemberInput').value = '';
                    document.getElementById('addMemberRole').value = 'viewer';
                    fetch(`/api/doc/${doc.id}/members`, {credentials:'same-origin'})
                      .then(r=>r.json())
                      .then(members => {
                        const list = document.getElementById('membersList');
                        if (list && list.innerHTML) {
                          // Re-render the members list
                          const renderMembers = window.currentRenderMembers;
                          if (renderMembers) renderMembers(members);
                        }
                      });
                  } else {
                    r.json().then(err => {
                      showToast(err.error || 'Failed to add member', 'error');
                    }).catch(() => showToast('Failed to add member', 'error'));
                  }
                }).catch(() => showToast('Failed to add member', 'error'));
              };

              // Delete document button functionality
              const deleteDocBtn = document.getElementById('deleteDocBtn');
              if (deleteDocBtn) {
                deleteDocBtn.onclick = () => {
                  if (confirm(`Are you sure you want to delete "${doc.name}"? This action cannot be undone.`)) {
                    fetch(`/api/doc/${doc.id}/delete`, {
                      method: 'POST',
                      headers: {'Content-Type': 'application/json'},
                      credentials: 'same-origin'
                    }).then(r => r.json()).then(data => {
                      if (data.ok) {
                        showToast('Document deleted successfully', 'success');
                        // Close the dialog
                        const dialog = document.querySelector('.dialog-overlay');
                        if (dialog) {
                          const closeBtn = dialog.querySelector('.dialog-close');
                          if (closeBtn) closeBtn.click();
                        }

                        // Clear current document state and switch to public
                        currentDoc = null;
                        currentMode = 'public';
                        currentPeer = null;
                        currentThreadId = null;
                        chatEl.innerHTML = '';
                        messagesLoaded = false;
                        modeBar.textContent = '';
                        updateModeBar();

                        // Refresh docs list and switch to public channel
                        loadDocs().then(() => {
                          switchToPublic();
                        });
                      } else {
                        showToast(data.error || 'Failed to delete document', 'error');
                      }
                    }).catch(() => showToast('Failed to delete document', 'error'));
                  }
                };
              }
            };
          }catch(e){ console.error(e); }
        }

        function pcConfig(){ return { iceServers: [{urls:'stun:stun.l.google.com:19302'}] }; }
        async function ensureLocalStream(){
          if (voiceState.localStream) return voiceState.localStream;
          try {
            const s = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
            voiceState.localStream = s;
            return s;
          } catch(e) {
            console.error('Failed to get local stream:', e);
            showToast('Microphone access denied', 'error');
            throw e;
          }
        }
        async function addPeer(username){
          if (!username || username===me || voiceState.peers[username]) return voiceState.peers[username];
          try {
            // Ensure we have local stream before creating peer connection
            if (!voiceState.localStream) {
              await ensureLocalStream();
            }
            const pc = new RTCPeerConnection(pcConfig());

            // Add local audio tracks to peer connection
            if (voiceState.localStream) {
              voiceState.localStream.getAudioTracks().forEach(t=> {
                pc.addTrack(t, voiceState.localStream);
              });
            }

            pc.onicecandidate = (ev)=>{
              if (ev.candidate) socket.emit('voice_ice', { channel: voiceState.current, candidate: ev.candidate, from: me });
            };

            pc.ontrack = (ev)=>{
              try{
                let au = document.querySelector(`audio[data-voice-peer="${username}"]`);
                if (!au){
                  au = document.createElement('audio');
                  au.setAttribute('data-voice-peer', username);
                  au.autoplay = true;
                  au.playsInline = true;
                  au.style.display = 'none';
                  document.body.appendChild(au);
                }
                if (au.srcObject !== ev.streams[0]) {
                  au.srcObject = ev.streams[0];
                  try { au.play().catch(()=>{}); } catch(_){}
                }
              }catch(e){ console.error('Error handling remote track:', e); }
            };

            voiceState.peers[username] = pc;
            return pc;
          } catch(e) {
            console.error('Error adding peer:', e);
            return null;
          }
        }
        async function createAndSendOffer(toUser){
          try{
            const pc = await addPeer(toUser);
            if (!pc) return;
            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);
            socket.emit('voice_offer', { channel: voiceState.current, sdp: offer, from: me });
          }catch(e){ console.error('Error creating offer:', e); }
        }
        async function openVoice(channel){
          try{
            if (!channel) return;
            await ensureLocalStream();
            voiceState.current = channel;
            voiceControlsEl.style.display = 'flex';
            setVoiceStatus(`# ${channel}`);
            socket.emit('voice_join', { channel });
            refreshVoiceList();
          }catch(e){}
        }
        function leaveVoice(){
          try{
            const ch = voiceState.current; if (!ch) return;
            socket.emit('voice_leave', { channel: ch });
            Object.values(voiceState.peers||{}).forEach(pc=>{ try{ pc.close(); }catch(e){} });
            voiceState.peers = {};
            voiceState.current = null;
            voiceControlsEl.style.display = 'none';
            setVoiceStatus('');
            try{ voicePeersEl.textContent=''; }catch(e){}
            refreshVoiceList();
            switchToPublic();
          }catch(e){}
        }
        voiceLeaveBtn.onclick = leaveVoice;
        voiceMuteBtn.onclick = ()=>{
          try{
            if (!voiceState.localStream) return;
            voiceState.muted = !voiceState.muted;
            voiceState.localStream.getAudioTracks().forEach(t=> t.enabled = !voiceState.muted);
            voiceMuteBtn.textContent = voiceState.muted? 'Unmute' : 'Mute';
            if (voiceState.current) socket.emit('voice_mute', { channel: voiceState.current, muted: voiceState.muted });
          }catch(e){}
        };

        // Voice signaling handlers
        try{
          socket.on('voice_participants', async (d)=>{
            try{
              if (!d || !d.channel) return;
              renderChannels();
              if (voiceState.current && d.channel === voiceState.current){
                const parts = Array.isArray(d.participants)? d.participants: [];
                const others = parts.filter(u=>u!==me);
                // Update display
                try{ voicePeersEl.textContent = 'In call: ' + parts.join(', '); }catch(e){}
                // Create peer connections; avoid glare by only the lexicographically smaller username offering
                for (const u of others) {
                  try {
                    if (!voiceState.peers[u]) {
                      await addPeer(u);
                      if ((me||'') < (u||'')) {
                        await createAndSendOffer(u);
                      }
                    }
                  } catch(e) { console.error('Error setting up peer:', e); }
                }
                // Close PCs for users no longer present
                Object.keys(voiceState.peers).forEach(u=>{ if (!parts.includes(u)) { try{ voiceState.peers[u].close(); }catch(e){} delete voiceState.peers[u]; } });
              }
            }catch(e){ console.error('Error handling voice participants:', e); }
          });
        }catch(e){}

        try{
          socket.on('voice_offer', async (d)=>{
            try{
              if (!d || !d.channel || d.from===me) return;
              if (!voiceState.current || d.channel !== voiceState.current) return;
              await ensureLocalStream();
              const pc = await addPeer(d.from);
              if (!pc) return;
              await pc.setRemoteDescription(new RTCSessionDescription(d.sdp));
              const answer = await pc.createAnswer();
              await pc.setLocalDescription(answer);
              socket.emit('voice_answer', { channel: voiceState.current, sdp: answer, from: me });
            }catch(e){ console.error('Error handling voice offer:', e); }
          });
          socket.on('voice_answer', async (d)=>{
            try{
              if (!d || !d.channel || d.from===me) return;
              if (!voiceState.current || d.channel !== voiceState.current) return;
              const pc = voiceState.peers[d.from];
              if (!pc) return;
              await pc.setRemoteDescription(new RTCSessionDescription(d.sdp));
            }catch(e){ console.error('Error handling voice answer:', e); }
          });
          socket.on('voice_ice', async (d)=>{
            try{
              if (!d || !d.channel || d.from===me) return;
              if (!voiceState.current || d.channel !== voiceState.current) return;
              let pc = voiceState.peers[d.from];
              if (!pc) {
                pc = await addPeer(d.from);
              }
              if (!pc) return;
              if (d.candidate) {
                try { await pc.addIceCandidate(new RTCIceCandidate(d.candidate)); } catch(e){}
              }
            }catch(e){ console.error('Error handling ICE candidate:', e); }
          });
        }catch(e){}

        // Call handlers for DMs and GDMs
        try{
          socket.on('call_started', (d)=>{
            try{
              if (!d || !d.call_id) return;
              const callId = d.call_id;
              const callType = d.type;
              if (callType === 'dm') {
                const peer = d.peer;
                setVoiceStatus(`📞 Call with ${peer}`);
              } else if (callType === 'gdm') {
                const groupName = d.group_name || `Group ${d.thread_id}`;
                setVoiceStatus(`📞 Call in ${groupName}`);
              }
              voiceControlsEl.style.display = 'flex';
              voiceState.current = callId;
              try { ensureLocalStream(); } catch(e){}
              socket.emit('voice_join', { channel: callId });
            }catch(e){}
          });
        }catch(e){}

        // Menu button handlers
        document.addEventListener('DOMContentLoaded', () => {
            try {
              const newMenuBtn = document.getElementById('newMenuBtn');
              const newMenu = document.getElementById('newMenu');
              const optNewDM = document.getElementById('optNewDM');
              const optNewGroup = document.getElementById('optNewGroup');
              const optNewDoc = document.getElementById('optNewDoc');
              const optNewFileshare = document.getElementById('optNewFileshare');
              const publicBtn = document.getElementById('publicBtn');
              const newChannelMenuBtn = document.getElementById('newChannelMenuBtn');
              const newChannelMenu = document.getElementById('newChannelMenu');

              if (newMenuBtn && newMenu) {
                newMenuBtn.onclick = (e) => {
                  e.preventDefault();
                  newMenu.style.display = newMenu.style.display === 'none' ? 'block' : 'none';
                };
              }

              // Public button event listener
              if (publicBtn) {
                publicBtn.onclick = () => {
                  switchToPublic();
                };
              }

              if (optNewDM) {
                optNewDM.onclick = (e) => {
                  e.preventDefault();
                  if (newMenu) newMenu.style.display = 'none';
                  const peer = prompt('Enter username to DM:');
                  if (peer && peer.trim()) {
                    openDM(peer.trim());
                  }
                };
              }

              if (newChannelMenuBtn && newChannelMenu) {
                newChannelMenuBtn.onclick = (e) => {
                  e.preventDefault();
                  newChannelMenu.style.display = newChannelMenu.style.display === 'none' ? 'block' : 'none';
                };
              }

              // Reset channel order button event listener
              const resetChannelOrderBtn = document.getElementById('resetChannelOrderBtn');
              if (resetChannelOrderBtn) {
                resetChannelOrderBtn.onclick = (e) => {
                  e.preventDefault();
                  resetChannelOrder();
                };
              }

              if (optNewGroup) {
                optNewGroup.onclick = (e) => {
                  e.preventDefault();
                  if (newChannelMenu) newChannelMenu.style.display = 'none';
                  const name = prompt('Enter group name (optional):');
                  if (name !== null) {
                    const members = prompt('Enter members (comma-separated usernames):');
                    if (members && members.trim()) {
                      const memberList = members.split(',').map(m => m.trim()).filter(m => m);
                      if (memberList.length > 0) {
                        fetch('/api/gdm/threads', {
                          method: 'POST',
                          headers: {'Content-Type': 'application/json'},
                          credentials: 'same-origin',
                          body: JSON.stringify({name: name.trim() || '', members: memberList})
                        }).then(r => r.json()).then(j => {
                          if (j.id) {
                            showToast(`Group created! Invite code: ${j.invite_code}`, 'ok');
                            loadGDMs();
                          } else {
                            showToast(j.error || 'Failed', 'error');
                          }
                        }).catch(() => showToast('Failed', 'error'));
                      } else {
                        showToast('Please enter at least one member', 'error');
                      }
                    }
                  }
                };
              }

              // Add join group button
              if (newChannelMenu) {
                const joinBtn = document.createElement('a');
                joinBtn.href = '#';
                joinBtn.textContent = 'Join Group with Code';
                joinBtn.style.display = 'block';
                joinBtn.style.padding = '6px 8px';
                joinBtn.style.color = 'var(--primary)';
                joinBtn.style.textDecoration = 'none';
                joinBtn.style.fontSize = '13px';
                joinBtn.style.borderTop = '1px solid var(--border)';
                joinBtn.style.marginTop = '4px';
                joinBtn.onclick = (e) => {
                  e.preventDefault();
                  newChannelMenu.style.display = 'none';
                  const code = prompt('Enter invite code:');
                  if (code && code.trim()) {
                    fetch('/api/gdm/join', {
                      method: 'POST',
                      headers: {'Content-Type': 'application/json'},
                      credentials: 'same-origin',
                      body: JSON.stringify({invite_code: code.trim()})
                    }).then(r => r.json()).then(j => {
                      if (j.id) {
                        showToast(`Joined group: ${j.name}`, 'ok');
                        loadGDMs();
                        switchToGDM(j.id);
                      } else {
                        showToast(j.error || 'Failed to join', 'error');
                      }
                    }).catch(() => showToast('Failed to join', 'error'));
                  }
                };
                newChannelMenu.appendChild(joinBtn);
              }

              if (optNewDoc) {
                optNewDoc.onclick = (e) => {
                  e.preventDefault();
                  if (newChannelMenu) newChannelMenu.style.display = 'none';
                  const name = prompt('Enter doc name:');
                  if (name && name.trim()) {
                    fetch('/api/doc/create', {
                      method: 'POST',
                      headers: {'Content-Type': 'application/json'},
                      credentials: 'same-origin',
                      body: JSON.stringify({name: name.trim()})
                    }).then(r => r.json()).then(j => {
                      if (j.ok && j.doc_id) {
                        loadDocs();
                        openDoc(j.doc_id);
                      } else {
                        showToast('Failed to create doc', 'error');
                      }
                    });
                  }
                };
              }

              if (optNewFileshare) {
                optNewFileshare.onclick = (e) => {
                  e.preventDefault();
                  if (newChannelMenu) newChannelMenu.style.display = 'none';
                  showToast('File share creation coming soon', 'info');
                };
              }

              // Close menus when clicking elsewhere
              document.addEventListener('click', (e) => {
                if (newMenuBtn && newMenu && !newMenuBtn.contains(e.target) && !newMenu.contains(e.target)) {
                  newMenu.style.display = 'none';
                }
                if (newChannelMenuBtn && newChannelMenu && !newChannelMenuBtn.contains(e.target) && !newChannelMenu.contains(e.target)) {
                  newChannelMenu.style.display = 'none';
                }
              });
            } catch(e) {}
            }); // Close DOMContentLoaded

        // Add call buttons to DM and GDM headers
        function updateModeBar(){
          try{
            let html = '';
            if (currentMode === 'public') {
              html = '<strong>Public Chat</strong>';
            } else if (currentMode === 'dm' && currentPeer) {
              html = `<strong>DM: ${currentPeer}</strong> <button id="callDmBtn" type="button" style="margin-left:8px;padding:2px 6px;font-size:12px;background:none;color:var(--primary);border:1px solid var(--border);border-radius:3px;cursor:pointer">📞 Call</button>`;
            } else if (currentMode === 'gdm' && currentThreadId) {
              // For GDM, don't override the existing header - just update the name if needed
              const currentHeader = modeBar.innerHTML;
              const threadName = (gdmThreadsCache[currentThreadId] && gdmThreadsCache[currentThreadId].name) || `Group ${currentThreadId}`;
              
              // Check if header already has buttons (was created by openGDM)
              if (currentHeader.includes('btnGdmSettings') || currentHeader.includes('btnGdmAdd')) {
                // Update just the name part, preserve everything else
                const nameMatch = currentHeader.match(/Group\s+(.*?)(\s+—|\s*$)/);
                if (nameMatch) {
                  modeBar.innerHTML = currentHeader.replace(nameMatch[0], `Group ${threadName}${nameMatch[2]}`);
                }
                return; // Don't override the rest
              } else {
                // Fallback to simple header
                html = `<strong>Group: ${threadName}</strong> <button id="callGdmBtn" type="button" style="margin-left:8px;padding:2px 6px;font-size:12px;background:none;color:var(--primary);border:1px solid var(--border);border-radius:3px;cursor:pointer">📞 Call</button>`;
              }
            }
            if (html) {
              modeBar.innerHTML = html;
              // Wire up call buttons
              const dmCallBtn = document.getElementById('callDmBtn');
              if (dmCallBtn) {
                dmCallBtn.onclick = ()=>{
                  try{
                    socket.emit('call_start_dm', { to_user: currentPeer });
                  }catch(e){}
                };
              }
              const gdmCallBtn = document.getElementById('callGdmBtn');
              if (gdmCallBtn) {
                gdmCallBtn.onclick = ()=>{
                  try{
                    socket.emit('call_start_gdm', { thread_id: currentThreadId });
                  }catch(e){}
                };
              }
            }
          }catch(e){}
        }

        // Admin Dashboard overlay open/close
        (function setupAdminDash(){
          const open = () => {
            try {
              document.getElementById('adminOverlay').style.display='block';
              const dd = document.getElementById('idResetDropdown');
              if (dd) dd.style.display = 'block';
              try { initResetIdToggles(); } catch(e){}
            } catch(e){}
          };
          const close = () => { try { document.getElementById('adminOverlay').style.display='none'; } catch(e){} };
          try {
            const b1 = document.getElementById('btnAdminDash');
            const b2 = document.getElementById('btnAdminDashHeader');
            const b3 = document.getElementById('btnAdminDashSettings');
            if (b1) b1.onclick = open;
            if (b2) b2.onclick = open;
            if (b3) b3.onclick = open;
            document.getElementById('closeAdminOverlay').onclick = close;
          } catch(e) {}
          const say = (t,c)=>{ const el=document.getElementById('adminDashMsg'); if(el){ el.textContent=t||''; el.style.color=c||'#374151'; } };
          // ID Reset dropdown wiring
          try {
            const sel = document.getElementById('idResetSelect');
            const block = document.getElementById('idResetBlock');
            const sel2 = document.getElementById('idResetSelect2');
            if (sel && block) {
              const apply = (v)=>{ block.style.display = (v==='shown') ? 'block' : 'none'; };
              sel.onchange = ()=> apply(sel.value);
              // default to shown once dashboard opens
              sel.value = 'shown'; apply('shown');
            }
            if (sel2 && block) {
              const apply2 = (v)=>{ block.style.display = (v==='shown') ? 'block' : 'none'; };
              sel2.onchange = ()=> apply2(sel2.value);
              // default based on current value of quick selector
              apply2(sel2.value||'shown');
            }
          } catch(e){}
          const post = async (url, body)=>{
            try {
              const res = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(body||{})});
              let j={}; try{ j=await res.json(); }catch(_){}
              if(res.ok && (j.ok||res.status===200)) say('Done','#16a34a'); else say(j.error||'Failed','#dc2626');
            } catch(e) { say('Failed','#dc2626'); }
          };
          try {
            const btn = document.getElementById('adminCreateUserBtn');
            if (btn) btn.onclick = async ()=>{
              const u = (document.getElementById('adminCreateUserName')?.value||'').trim();
              const p = (document.getElementById('adminCreateUserPass')?.value||'').trim();
              const isA = !!document.getElementById('adminCreateUserIsAdmin')?.checked;
              if (!u || !p) { say('Enter username and password','#dc2626'); return; }
              try {
                const r = await fetch('/api/admin/create_user',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({username:u,password:p,is_admin:isA})});
                const j = await r.json().catch(()=>({}));
                if (!r.ok || !j.ok) { say(j.error||'Failed','#dc2626'); return; }
                say('User created','#16a34a');
                try{ document.getElementById('adminCreateUserName').value=''; document.getElementById('adminCreateUserPass').value=''; document.getElementById('adminCreateUserIsAdmin').checked=false; }catch(e){}
              } catch(e){ say('Failed','#dc2626'); }
            };
          } catch(e){}
          // Quick Create User button wiring
          try {
            const qbtn = document.getElementById('quickCreateUserBtn');
            if (qbtn) qbtn.onclick = async ()=>{
              const u = (document.getElementById('quickCreateUserName')?.value||'').trim();
              const p = (document.getElementById('quickCreateUserPass')?.value||'').trim();
              const isA = !!document.getElementById('quickCreateUserIsAdmin')?.checked;
              if (!u || !p) { say('Enter username and password','#dc2626'); return; }
              try {
                const r = await fetch('/api/admin/create_user',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({username:u,password:p,is_admin:isA})});
                const j = await r.json().catch(()=>({}));
                if (!r.ok || !j.ok) { say(j.error||'Failed','#dc2626'); return; }
                say('User created','#16a34a');
                try{ document.getElementById('quickCreateUserName').value=''; document.getElementById('quickCreateUserPass').value=''; document.getElementById('quickCreateUserIsAdmin').checked=false; }catch(e){}
              } catch(e){ say('Failed','#dc2626'); }
            };
          } catch(e){}
          // DM Logs
          try { document.getElementById('adminDmSaveBtn').onclick = ()=>{ const peer=(document.getElementById('adminDmPeer').value||'').trim(); if(!peer){ say('Enter peer','#dc2626'); return;} window.open('/api/admin/dm_logs?peer='+encodeURIComponent(peer),'_blank'); }; } catch(e){}
          // Close All DMs
          try { document.getElementById('adminDmCloseAllBtn').onclick = ()=> post('/api/admin/dm_close_all',{}); } catch(e){}
          // DM as System
          try { document.getElementById('adminDmSendBtn').onclick = ()=>{ const to=(document.getElementById('adminDmTo').value||'').trim(); const text=(document.getElementById('adminDmText').value||'').trim(); if(!to||!text){ say('Enter recipient and text','#dc2626'); return;} post('/api/admin/dm_as_system',{to, text}); }; } catch(e){}
          // Group controls
          const tidVal = ()=>{ const v=(document.getElementById('adminGdmTid').value||'').trim(); const n=parseInt(v,10); return isNaN(n)?0:n; };
          try { document.getElementById('adminGdmLockBtn').onclick = ()=>{ const tid=tidVal(); if(!tid){ say('Enter tid','#dc2626'); return;} post('/api/gdm/lock',{tid, thread_id: tid}); }; } catch(e){}
          try { document.getElementById('adminGdmUnlockBtn').onclick = ()=>{ const tid=tidVal(); if(!tid){ say('Enter tid','#dc2626'); return;} post('/api/gdm/unlock',{tid, thread_id: tid}); }; } catch(e){}
        })();

        // Settings: Reset Sidebar Sizes
        (function setupResetSidebarSizes(){
          try{
            const btn = document.getElementById('resetSidebarSizes');
            if (!btn) return;
            btn.onclick = ()=>{
              try{
                localStorage.removeItem('ui.leftWidth');
                localStorage.removeItem('ui.rightWidth');
              }catch(e){}
              try{
                const lbar = document.getElementById('leftbar');
                const rbar = document.getElementById('rightbar');
                if (lbar){ lbar.style.width='240px'; lbar.style.minWidth='240px'; }
                if (rbar){ rbar.style.width='240px'; rbar.style.minWidth='240px'; }
              }catch(e){}
              try{ alert('Sidebar sizes reset to default.'); }catch(e){}
            };
          }catch(e){}
        })();

        // Ensure group list refreshes on changes
        try {
          socket.on('gdm_threads_refresh', (data)=>{
            try { loadGDMs(); } catch(e){}
          });
        } catch(e) {}
        // Reset admin cache on load to reduce any flicker between cached DOM and current state
        try { window.__adminsLastJson = []; } catch(e){}
        // Helper: get avatar url from cache
        const getAvatar = (u) => {
            try {
                if (u === 'System') return '/sys_pfp.png';
                const p = (profilesCache.data||[]).find(x=>x.username===u);
                const url = (p && p.avatar_url) || '';
                return url || '/default_avatar';
            } catch(e) { return '/default_avatar'; }
        };

        // Format timestamp for display
        const formatTime = (timestamp) => {
            if (!timestamp) return '';
            const date = new Date(timestamp);
            const now = new Date();
            const diffMs = now - date;
            const diffMins = Math.floor(diffMs / 60000);
            const diffHours = Math.floor(diffMs / 3600000);
            const diffDays = Math.floor(diffMs / 86400000);

            if (diffMins < 1) return 'Just now';
            if (diffMins < 60) return `${diffMins}m ago`;
            if (diffHours < 24) return `${diffHours}h ago`;
            if (diffDays < 7) return `${diffDays}d ago`;

            return date.toLocaleDateString();
        };

        // Discord-style image click handler (download, zoom, and file upload)
        const handleImageClick = (imageUrl, filename, username = null, timestamp = null) => {
            // Create modal overlay
            const modal = document.createElement('div');
            modal.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.8);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 10000;
                cursor: pointer;
            `;

            // Create user info container (top-left)
            const userInfo = document.createElement('div');
            if (username && timestamp) {
                userInfo.textContent = `${username} • ${timestamp}`;
                userInfo.style.cssText = `
                    position: absolute;
                    top: 20px;
                    left: 20px;
                    color: white;
                    font-size: 14px;
                    font-weight: 500;
                    z-index: 10001;
                    opacity: 0.8;
                    pointer-events: none;
                `;
            }

            // Create image container
            const imgContainer = document.createElement('div');
            imgContainer.style.cssText = `
                max-width: 90%;
                max-height: 90%;
                position: relative;
                cursor: zoom-in;
            `;

            // Create zoomed image
            const img = document.createElement('img');
            img.src = imageUrl;
            img.style.cssText = `
                max-width: 100%;
                max-height: 100%;
                border-radius: 8px;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
                transition: transform 0.3s ease;
            `;

            // Create download button
            const downloadBtn = document.createElement('button');
            downloadBtn.textContent = '⬇️';
            downloadBtn.style.cssText = `
                position: absolute;
                top: 20px;
                right: 20px;
                background: rgba(0, 0, 0, 0.7);
                color: white;
                border: none;
                padding: 10px;
                border-radius: 8px;
                cursor: pointer;
                font-size: 16px;
                z-index: 10001;
                width: 40px;
                height: 40px;
                display: flex;
                align-items: center;
                justify-content: center;
                backdrop-filter: blur(10px);
                transition: background 0.2s ease;
            `;
            downloadBtn.onmouseover = () => downloadBtn.style.background = 'rgba(0, 0, 0, 0.9)';
            downloadBtn.onmouseout = () => downloadBtn.style.background = 'rgba(0, 0, 0, 0.7)';

            // Create open in browser button
            const openBtn = document.createElement('button');
            openBtn.textContent = '↗️';
            openBtn.style.cssText = `
                position: absolute;
                top: 20px;
                right: 70px;
                background: rgba(0, 0, 0, 0.7);
                color: white;
                border: none;
                padding: 10px;
                border-radius: 8px;
                cursor: pointer;
                font-size: 16px;
                z-index: 10001;
                width: 40px;
                height: 40px;
                display: flex;
                align-items: center;
                justify-content: center;
                backdrop-filter: blur(10px);
                transition: background 0.2s ease;
            `;
            openBtn.onmouseover = () => openBtn.style.background = 'rgba(0, 0, 0, 0.9)';
            openBtn.onmouseout = () => openBtn.style.background = 'rgba(0, 0, 0, 0.7)';

            // Download image
            downloadBtn.onclick = async (e) => {
                e.stopPropagation();
                try {
                    const response = await fetch(imageUrl);
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    window.URL.revokeObjectURL(url);
                    showToast('Image downloaded!', 'success');
                } catch (err) {
                    showToast('Failed to download image', 'error');
                }
            };

            // Open in browser
            openBtn.onclick = (e) => {
                e.stopPropagation();
                window.open(imageUrl, '_blank');
                showToast('Image opened in new tab!', 'success');
            };

            // Zoom functionality
            let isZoomed = false;
            const toggleZoom = (e) => {
                if (!isZoomed) {
                    img.style.transform = 'scale(2)';
                    img.style.cursor = 'zoom-out';
                    imgContainer.style.cursor = 'zoom-out';
                    isZoomed = true;
                } else {
                    img.style.transform = 'scale(1)';
                    img.style.cursor = 'zoom-in';
                    imgContainer.style.cursor = 'zoom-in';
                    isZoomed = false;
                }
            };

            // Left click to zoom
            img.onclick = (e) => {
                e.stopPropagation();
                toggleZoom(e);
            };

            // Close modal on background click
            modal.onclick = () => {
                document.body.removeChild(modal);
            };

            // Prevent modal close when clicking on image container
            imgContainer.onclick = (e) => {
                e.stopPropagation();
            };

            // Assemble modal
            imgContainer.appendChild(img);
            modal.appendChild(userInfo);
            modal.appendChild(openBtn);
            modal.appendChild(downloadBtn);
            modal.appendChild(imgContainer);
            document.body.appendChild(modal);
        };
        // Initialize ID Reset toggles: fetch current settings and wire saves
        async function initResetIdToggles(){
            try {
                const pub = document.getElementById('toggleResetPublic');
                const dm = document.getElementById('toggleResetDM');
                const gdm = document.getElementById('toggleResetGDM');
                const thr = document.getElementById('toggleResetGroupThreads');
                if (!pub || !dm || !gdm || !thr) return;
                const apply = (j)=>{
                    try { pub.checked = !!(j.reset_public || j.public || j.pub); } catch(e){}
                    try { dm.checked = !!(j.reset_dm || j.dm); } catch(e){}
                    try { gdm.checked = !!(j.reset_gdm || j.gdm); } catch(e){}
                    try { thr.checked = !!(j.reset_group_threads || j.group_threads || j.threads); } catch(e){}
                };
                // Load current values from either /api/admins/resets or /api/admins/resets/get
                let j = {};
                try {
                    let r = await fetch('/api/admins/resets', {credentials:'same-origin'});
                    j = await r.json().catch(()=>({}));
                    if (!r.ok || (!j.ok && (j.reset_public===undefined && j.public===undefined))) throw new Error('fallback');
                } catch(_){
                    try {
                        const r2 = await fetch('/api/admins/resets/get', {credentials:'same-origin'});
                        j = await r2.json().catch(()=>({}));
                    } catch(e){}
                }
                // Handle shapes {ok:true, settings:{...}} or direct flags
                const data = (j && j.settings) ? j.settings : j;
                apply(data||{});
                const save = async ()=>{
                    const body = {
                        reset_public: !!pub.checked,
                        reset_dm: !!dm.checked,
                        reset_gdm: !!gdm.checked,
                        reset_group_threads: !!thr.checked,
                    };
                    try {
                        let r = await fetch('/api/admins/resets', {method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(body)});
                        if (!r.ok) throw new Error('fallback');
                    } catch(_){
                        try { await fetch('/api/admins/resets/set', {method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(body)}); } catch(e){}
                    }
                };
                pub.onchange = save; dm.onchange = save; gdm.onchange = save; thr.onchange = save;
            } catch(e){}
        }
        // Helper: update document title with unread totals
        const updateTitleUnread = () => {
            try {
                const dm = JSON.parse(localStorage.getItem('unreadDM')||'{}');
                const gdm = JSON.parse(localStorage.getItem('unreadGDM')||'{}');
                let total = 0;
                for (const k in dm) total += dm[k]||0;
                for (const k in gdm) total += gdm[k]||0;
                document.title = total>0 ? `Chatter (${total})` : 'Chatter';
            } catch(e) { document.title = 'Chatter'; }
        };
        // HTML escape helper for safe username rendering
        const esc = (s) => (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

        // Pinned public message helpers (global scope)
        let pinnedMessageEl = null;
        // Global set to track blocked pin IDs (from deleted pinned messages)
        const blockedPinIds = new Set();
        // Load blocked pin IDs from localStorage
        const blocked = JSON.parse(localStorage.getItem("blockedPinIds") || "[]");
        blocked.forEach(id => blockedPinIds.add(id));

        // Function to block a pin ID permanently
        function blockPinId(messageId) {
          blockedPinIds.add(messageId);
          const blockedArray = Array.from(blockedPinIds);
          localStorage.setItem("blockedPinIds", JSON.stringify(blockedArray));
        }

        // Function to check if a pin ID is blocked
        function isPinIdBlocked(messageId) {
          return blockedPinIds.has(messageId);
        }
        function renderPinnedPublic(msg){
          // Remove existing pinned message if any
          if (pinnedMessageEl && pinnedMessageEl.parentNode) {
            pinnedMessageEl.remove();
            pinnedMessageEl = null;
          }
          if (!msg || currentMode !== 'public') return;
          // Check if this pin has been dismissed by the user
          const dismissedPins = JSON.parse(localStorage.getItem("dismissedPins") || "[]");
          if (dismissedPins.includes(msg.id)) {
            return; // Do not show dismissed pins
          }
          // Check if this pin ID is blocked (from deleted pinned messages)
          if (isPinIdBlocked(msg.id)) {
            return; // Do not show blocked pin IDs
          }

          // Create pinned message element at top of chat
          pinnedMessageEl = document.createElement('div');
          pinnedMessageEl.id = 'pinnedMessageTop';
          pinnedMessageEl.setAttribute("data-pin-id", msg.id);
          pinnedMessageEl.style.cssText = 'background:#fffbe6;border:2px solid #f59e0b;border-radius:8px;padding:10px 12px;margin-bottom:12px;position:sticky;top:0;z-index:4';

          // Add close button to pinned message
          const closeBtn = document.createElement("button");
          closeBtn.innerHTML = "&#10005;";
          closeBtn.style.cssText = "position:absolute;top:4px;right:6px;background:none;border:none;color:#f59e0b;font-size:16px;cursor:pointer;padding:2px 4px;border-radius:3px";
          closeBtn.title = "Close pinned message";
          closeBtn.onclick = (e) => {
            e.preventDefault();
            e.stopPropagation();
            // Store dismissed pin ID in localStorage
            const dismissedPins = JSON.parse(localStorage.getItem("dismissedPins") || "[]");
            if (!dismissedPins.includes(msg.id)) {
              dismissedPins.push(msg.id);
              localStorage.setItem("dismissedPins", JSON.stringify(dismissedPins));
            }
            // Hide the pinned message for this user
            pinnedMessageEl.remove();
            pinnedMessageEl = null;
          };
          pinnedMessageEl.appendChild(closeBtn);

          let text = (msg.text||'');
          try {
            text = text.replace(/^<p>/i, '').replace(/<\/p>$/i, '');
          } catch(_e) {}
          const username = (msg.username||'');
          const time = msg.created_at ? new Date(msg.created_at).toLocaleString() : '';
          const mAva = getAvatar(username);

          pinnedMessageEl.innerHTML = `
            <div style='display:flex;align-items:flex-start;gap:10px'>
              <div style='font-size:20px'>📌</div>
              <div style='flex:1;min-width:0'>
                <div style='display:flex;align-items:center;gap:8px;margin-bottom:4px'>
                  <img src='${mAva}' alt='' style='width:20px;height:20px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                  <span style='font-weight:700;color:#78350f'>${esc(username)}</span>
                  <span style='color:#92400e;font-size:12px'>${time}</span>
                </div>
                <div style='color:#78350f'>${esc(text)}</div>
              </div>
            </div>
          `;

          // Insert at the top of chatEl
          if (chatEl && chatEl.firstChild) {
            chatEl.insertBefore(pinnedMessageEl, chatEl.firstChild);
          } else if (chatEl) {
            chatEl.appendChild(pinnedMessageEl);
          }
        }
        async function ensurePinnedLoaded(){
          try {
            if (currentMode !== 'public') return;
            const r = await fetch('/api/pinned?type=public',{credentials:'same-origin'});
            const j = await r.json();
            if(r.ok && j && j.ok){ renderPinnedPublic(j.message); }
          } catch(e) {}
        }

        // Socket connection events
        socket.on('connect', function() {
            console.log('Connected to server');
            loadMessages();
            // Load pinned public message on connect
            try { ensurePinnedLoaded(); } catch(e){}
            try { loadDMs(); } catch(e){}
            try { loadGDMs(); } catch(e){}
            try { loadDocs(); } catch(e){}
            // ensure mobile nav visibility on connect
            try { const nav = document.getElementById('mobileNav'); nav.style.display = isMobile() ? 'flex' : 'none'; } catch(e) {}
            // If we arrived via invite link, auto-open the group chat
            try {
              if (initialGdmTid && String(initialGdmTid).trim() !== '') {
                const tidNum = parseInt(initialGdmTid, 10);
                if (!isNaN(tidNum) && tidNum > 0) {
                  openGDM(tidNum);
                }
              }
              // Auto-join call via /call/[id] link
              try {
                if (initialCallId && String(initialCallId).trim() !== '') {
                  const callId = String(initialCallId).trim();
                  voiceState.current = callId;
                  setVoiceStatus(`📞 ${callId}`);
                  try { ensureLocalStream(); } catch(e){}
                  socket.emit('voice_join', { channel: callId });
                }
              } catch(e){}
              // Seed voice list
              try { refreshVoiceList(); } catch(e){}
            } catch(e) {}
        });

        socket.on('disconnect', function() {
            console.log('Disconnected from server');
        });

        // Group threads list refresh notifications (rename/add/delete)
        socket.on('gdm_threads_refresh', (info) => {
            try { loadGDMs(); } catch(e) {}
            if (info && info.deleted && currentMode==='gdm' && currentThreadId===info.deleted) {
                switchToPublic();
            }
        });

        // Typing indicator updates
        const typingBar = document.getElementById('typingBar');
        const globalTypingBar = document.getElementById('globalTypingBar');
        window.typingUsers = new Set();
        socket.on('typing', payload => {
            try {
                const users = (payload && payload.users) || [];
                window.typingUsers = new Set(users);
                const others = users.filter(u => u !== me);
                typingBar.textContent = formatTyping(others);
                try { Language.translateFragment(typingBar); } catch(_){}
            } catch (e) {}
        });
        // Cross-view typing notifications
        socket.on('dm_typing', info => {
            try {
                // Only show if not currently in this DM
                if (info && info.from && info.to && ((currentMode !== 'dm') || currentPeer !== info.from)) {
                    globalTypingBar.textContent = `${info.from} is typing in your DM…`;
                    try { Language.translateFragment(globalTypingBar); } catch(_){}
                    setTimeout(() => { if (globalTypingBar.textContent.includes('your DM')) globalTypingBar.textContent=''; }, 3000);
                }
            } catch(e) {}
        });
        socket.on('gdm_typing', info => {
            try {
                if (!info || !info.thread_id || !info.from) return;

                // Update typing users for this thread
                if (!gdmTypingUsers.has(info.thread_id)) {
                    gdmTypingUsers.set(info.thread_id, new Set());
                }
                gdmTypingUsers.get(info.thread_id).add(info.from);

                // Update UI if this is the current thread
                if (currentMode === 'gdm' && currentThreadId === info.thread_id) {
                    updateGdmTypingIndicator();
                } else {
                    // Show notification in global typing bar for other threads
                    const name = info.group_name || (gdmThreadsCache[info.thread_id]?.name) || `Group ${info.thread_id}`;
                    globalTypingBar.textContent = `${info.from} is typing in ${name}…`;
                    try { Language.translateFragment(globalTypingBar); } catch(_){}
                    setTimeout(() => {
                        if (globalTypingBar.textContent.includes('is typing in')) {
                            globalTypingBar.textContent = '';
                        }
                    }, 3000);
                }

                // Clear the typing indicator after a delay
                clearGdmTypingAfterDelay(info.from, info.thread_id);
            } catch(e) {}
        });

        function formatTyping(users) {
            if (!users || users.length === 0) return '';
            if (users.length === 1) return users[0] + ' is typing…';
            if (users.length === 2) return users[0] + ' and ' + users[1] + ' are typing…';
            return users[0] + ', ' + users[1] + ' and ' + (users.length - 2) + ' others are typing…';
        }

        // Load existing messages immediately when connected
        function loadMessages() {
            if (messagesLoaded) return;

            fetch('/api/messages')
                .then(res => res.json())
                .then(msgs => {
                    msgs.forEach(m => renderMessage(m));
                    messagesLoaded = true;
                    // Load pinned message after regular messages
                    ensurePinnedLoaded();
                    scrollToBottom();
                    checkScrollPosition();
                })
                .catch(err => console.error('Error loading messages:', err));
        }

        // Online users functionality (no typing state shown here)
        const onlineBtn = document.getElementById('onlineBtn');
        const onlineCountEl = document.getElementById('onlineCount');
        onlineBtn.onclick = function() {
            fetch('/api/online')
                .then(res => res.json())
                .then(users => {
                    let popup = window.open("", "Online Users", "width=300,height=400");
                    let html = "<html><head><title>Online Users</title></head><body><h3>Online Users:</h3><ul>";
                    users.forEach(u => {
                        const label = `${u}${u===me?' (you)':''}`;
                        html += `<li style=\"color:${ADMINS.includes(u)?'maroon':'black'}\">${label}</li>`;
                    });
                    html += "</ul></body></html>";
                    popup.document.write(html);
                    popup.document.close();
                });
        };

        // Real-time message events (handled below with de-duplication)
        socket.on('dm_new', dm => {
            // Prevent duplicate messages using seenMsgIds
            try {
                if (dm && dm.id !== undefined && dm.id !== null) {
                    if (seenMsgIds.has(dm.id)) return;
                    seenMsgIds.add(dm.id);
                }
            } catch(e) {}

            const peer = dm.from_user === me ? dm.to_user : dm.from_user;
            // refresh sidebar peers
            loadDMs();
            if (currentMode === 'dm' && currentPeer === peer) {
                renderDM(dm);
                scrollToBottom();
            } else {
                // increment unread for peer
                try {
                    const map = JSON.parse(localStorage.getItem('unreadDM')||'{}');
                    map[peer] = (map[peer]||0) + 1;
                    localStorage.setItem('unreadDM', JSON.stringify(map));
                    loadDMs();
                } catch(e) {}
            }
            updateTitleUnread();
        });
        socket.on('dm_edit', payload => {
            const el = chatEl.querySelector(`.message[data-id='${payload.id}']`);
            if (!el) return;
            const body = el.querySelector('.msg-body');
            if (body) body.innerHTML = payload.text || '';
        });
        socket.on('dm_delete', id => {
            const el = chatEl.querySelector(`.message[data-id='${id}']`);
            if (el) el.remove();
        });

        // Track typing users in group DMs
        const gdmTypingUsers = new Map();

        // Update typing indicator for group DMs
        function updateGdmTypingIndicator() {
            const typingEl = document.getElementById('gdmTypingIndicator');
            if (!typingEl) return;

            const currentTyping = gdmTypingUsers.get(currentThreadId) || new Set();
            const others = Array.from(currentTyping).filter(u => u !== me);

            if (others.length === 0) {
                typingEl.textContent = '';
                typingEl.style.display = 'none';
            } else {
                typingEl.textContent = formatTyping(others) + ' in this group';
                typingEl.style.display = 'block';
                try { Language.translateFragment(typingEl); } catch(_){}
            }
        }

        // Clear typing indicator after delay
        function clearGdmTypingAfterDelay(username, threadId) {
            setTimeout(() => {
                if (gdmTypingUsers.has(threadId)) {
                    gdmTypingUsers.get(threadId).delete(username);
                    if (currentMode === 'gdm' && currentThreadId === threadId) {
                        updateGdmTypingIndicator();
                    }
                }
            }, 3000);
        }

        // Group live events
        socket.on('gdm_new', m => {
            // Prevent duplicate messages using seenMsgIds
            try {
                if (m && m.id !== undefined && m.id !== null) {
                    if (seenMsgIds.has(m.id)) return;
                    seenMsgIds.add(m.id);
                }
            } catch(e) {}

            if (currentMode === 'gdm' && currentThreadId === m.thread_id) {
                renderGDM(m);
                scrollToBottom();
            } else {
                try {
                    const map = JSON.parse(localStorage.getItem('unreadGDM')||'{}');
                    const key = String(m.thread_id);
                    map[key] = (map[key]||0) + 1;
                    localStorage.setItem('unreadGDM', JSON.stringify(map));
                    loadGDMs();
                } catch(e) {}
            }
            updateTitleUnread();
        });
        // Clear events
        socket.on('dm_cleared', info => {
            if (currentMode==='dm') { chatEl.innerHTML=''; }
            const map = JSON.parse(localStorage.getItem('unreadDM')||'{}');
            if (currentPeer && map[currentPeer]) { delete map[currentPeer]; localStorage.setItem('unreadDM', JSON.stringify(map)); }
            updateTitleUnread();
        });
        socket.on('gdm_cleared', info => {
            if (currentMode==='gdm' && info && info.thread_id===currentThreadId) { chatEl.innerHTML=''; }
            const map = JSON.parse(localStorage.getItem('unreadGDM')||'{}');
            const key = String(currentThreadId||'');
            if (key && map[key]) { delete map[key]; localStorage.setItem('unreadGDM', JSON.stringify(map)); }
            updateTitleUnread();
        });
        socket.on('gdm_edit', payload => {
            const el = chatEl.querySelector(`.message[data-id='${payload.id}']`);
            if (!el) return;
            const body = el.querySelector('.msg-body');
            if (body) body.innerHTML = payload.text || '';
        });
        socket.on('gdm_delete', id => {
            const el = chatEl.querySelector(`.message[data-id='${id}']`);
            if (el) el.remove();
        });

        socket.on('delete_message', id => {
            const el = chatEl.querySelector(`.message[data-id='${id}']`);
            if (el) el.remove();
        });

        // Realtime removal for /clear N
        socket.on('messages_deleted', payload => {
            try {
                const ids = (payload && payload.ids) || [];
                ids.forEach(id => {
                    const el = chatEl.querySelector(`.message[data-id='${id}']`);
                    if (el) el.remove();
                });
            } catch(e) {}
        });

        socket.on('edit_message', payload => {
            const id = payload && payload.id;
            if (!id) return;
            const el = chatEl.querySelector(`.message[data-id='${id}']`);
            if (!el) return;
            const body = el.querySelector('.msg-body');
            if (body) { body.innerHTML = payload.text || ''; }
        });

        const seenMsgIds = new Set();

        socket.on('clear_all', () => {
            chatEl.innerHTML = '';
            messagesLoaded = false;
            try { seenMsgIds.clear(); } catch(e) {}
        });

        socket.on('system_message', msg => {
            try {
                if (typeof msg === 'string') {
                    msg = {
                        id: Date.now() % 2147483647,
                        username: 'System',
                        text: msg,
                        attachment: null,
                        created_at: new Date().toISOString(),
                        avatar: '/sys_pfp.png'
                    };
                } else if (msg && typeof msg === 'object') {
                    if (!msg.username) msg.username = 'System';
                    if (!msg.created_at) msg.created_at = new Date().toISOString();
                }
            } catch (e) {}
            renderMessage(msg);
        });
        // Live public messages (no reload) with de-duplication by id and public-only gating
        socket.on('new_message', msg => {
            if (currentMode !== 'public') return;
            try {
                if (msg && msg.id !== undefined && msg.id !== null) {
                    if (seenMsgIds.has(msg.id)) return;
                    seenMsgIds.add(msg.id);
                }
            } catch(e) {}
            renderMessage(msg);
        });

        socket.on('user_joined', data => {
            updateOnlineCount();
        });

        socket.on('user_left', data => {
            updateOnlineCount();
        });

        socket.on('user_list_refresh', function(data) {
            // Refresh the user profiles in the right column
            refreshRightOnline();
            try { if (window.refreshAdmins) window.refreshAdmins(); } catch(e){}
        });

        socket.on('admin_list', function(data) {
            // Refresh the admin list
            const admins = data && data.admins;
            if (admins) {
                if (!window.ADMINS) window.ADMINS = [];
                window.ADMINS = admins;
            }
        });

        // Listen for document updates
        socket.on('doc_updated', (data) => {
          if (data.doc_id === doc.id) {
            docContent = data.content;
            if (docEditor) {
              docEditor.value = docContent;
              updatePreview();
            }
          }
        });

        // Doc channel socket events
        socket.on('doc_content', (data) => {
            try {
                if (data && data.content !== undefined) {
                    docContent = data.content;
                    if (docEditor) docEditor.value = docContent;
                }
            } catch(e) {}
        });

        socket.on('doc_content_updated', (data) => {
            try {
                if (data && data.content !== undefined && data.edited_by !== me) {
                    docContent = data.content;
                    if (docEditor) docEditor.value = docContent;
                    // Update preview
                    if (docPreview) {
                        const md = window.markdownit ? window.markdownit() : null;
                        if (md) {
                            docPreview.innerHTML = md.render(docContent);
                        } else {
                            docPreview.innerHTML = '<pre>' + (docContent||'').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</pre>';
                        }
                    }
                }
            } catch(e) {}
        });

        socket.on('doc_saved_to_tmpweb', (data) => {
            try {
                if (data && data.url) {
                    showToast(`Doc saved to tmpweb.net: ${data.url}`, 'info');
                }
            } catch(e) {}
        });

        socket.on('doc_members_updated', (data) => {
            try {
                if (data && data.doc_id === currentDoc) {
                    loadDocs();
                }
            } catch(e) {}
        });

        socket.on('doc_user_joined', (data) => {
            try {
                if (data && data.username) {
                    showToast(`${data.username} joined the doc`, 'info');
                }
            } catch(e) {}
        });

        socket.on('doc_user_left', (data) => {
            try {
                if (data && data.username) {
                    showToast(`${data.username} left the doc`, 'info');
                }
            } catch(e) {}
        });

        socket.on('doc_member_added', (data) => {
            try {
                if (data && data.doc_id === currentDoc) {
                    refreshRightOnline();
                }
            } catch(e) {}
        });

        socket.on('doc_member_removed', (data) => {
            try {
                if (data && data.doc_id === currentDoc) {
                    refreshRightOnline();
                }
            } catch(e) {}
        });

        socket.on('doc_member_role_updated', (data) => {
            try {
                if (data && data.doc_id === currentDoc) {
                    refreshRightOnline();
                }
            } catch(e) {}
        });

        socket.on('doc_deleted', (data) => {
            try {
                if (data && data.doc_id === currentDoc) {
                    // Close any open members dialog
                    const dialog = document.querySelector('.dialog-overlay');
                    if (dialog) {
                        const closeBtn = document.querySelector('.dialog-close');
                        if (closeBtn) closeBtn.click();
                    }

                    // Clear current document state and switch to public
                    currentDoc = null;
                    currentMode = 'public';
                    currentPeer = null;
                    currentThreadId = null;
                    chatEl.innerHTML = '';
                    messagesLoaded = false;
                    modeBar.textContent = '';
                    updateModeBar();

                    // Refresh docs list and switch to public channel
                    loadDocs().then(() => {
                        switchToPublic();
                    });

                    showToast('Document has been deleted', 'info');
                }
            } catch(e) {}
        });

        function updateOnlineCount() {
            fetch('/api/online')
                .then(res => res.json())
                .then(users => {
                    if (onlineCountEl) {
                        onlineCountEl.textContent = users.length;
                    }
                });
        }

        function presenceColor(presence) {
            switch ((presence||'').toLowerCase()) {
                case 'online': return '#4CAF50';
                case 'idle': return '#eab308';
                case 'dnd': return '#ef4444';
                default: return '#bbb';
            }
        }

        async function getProfiles(force=false) {
            const now = Date.now();
            if (!force && (now - profilesCache.ts) < 30000 && profilesCache.data && profilesCache.data.length) {
                return profilesCache.data;
            }
            const data = await fetch('/api/users_profiles').then(r=>r.json());
            profilesCache = { data, ts: Date.now() };
            return data;
        }

        async function refreshRightOnline() {
            try {
                const profiles = await getProfiles(true);
                let filtered = profiles || [];
                if (currentMode === 'dm' && currentPeer) {
                    const allow = new Set([me, currentPeer]);
                    filtered = filtered.filter(p => allow.has(p.username));
                } else if (currentMode === 'gdm' && currentThreadId) {
                    const members = await fetch(`/api/gdm/members?tid=${currentThreadId}`).then(r=>r.json()).catch(()=>[]);
                    const allow = new Set(members||[]);
                    filtered = filtered.filter(p => allow.has(p.username));
                } else if (currentMode === 'doc' && currentDoc) {
                    // Show document members
                    const members = await fetch(`/api/doc/${currentDoc}/members`, {credentials:'same-origin'}).then(r=>r.json()).catch(()=>[]);
                    const allow = new Set((members||[]).map(m => m.username));
                    filtered = filtered.filter(p => allow.has(p.username));
                }
                const online = [];
                const offline = [];
                for (const p of filtered) {
                    ((p.presence||'').toLowerCase() === 'offline' ? offline : online).push(p);
                }
                const renderUser = (p) => {
                    const u = p.username;
                    const label = u === me ? `${u} (you)` : u;
                    const color = presenceColor(p.presence);
                    const ava = p.avatar_url || '';
                    const bio = (p.bio||'');
                    const shortBio = bio.length > 100 ? (bio.slice(0, 100) + '...') : bio;
                    const tooltip = `${bio}`;
                    const isSA = (Array.isArray(SUPERADMINS) && SUPERADMINS.includes(u));
                    const isAdmin = isSA ? false : ((window.ADMIN_SET && window.ADMIN_SET.has) ? window.ADMIN_SET.has(u) : false);
                    const meta = (window.ADMIN_META && window.ADMIN_META[u]) || {};
                    const isExtra = !!meta.extra;
                    const badge = isSA
                        ? `<span style='color:#fff;background:#111827;border-radius:6px;padding:1px 4px;font-size:11px;margin-left:6px'>Owner</span>`
                        : (isAdmin
                            ? (isExtra
                                ? `<span style='color:#fff;background:#6b21a8;border-radius:6px;padding:1px 4px;font-size:11px;margin-left:6px'>ADMIN</span>`
                                : `<span style='color:#fff;background:#b91c1c;border-radius:6px;padding:1px 4px;font-size:11px;margin-left:6px'>ADMIN</span>`)
                            : '');
                    return `<div style='display:flex;align-items:center;gap:10px;margin:8px 0;font-size:15px' data-user='${esc(u)}' title='${esc(tooltip)}'>
                        <div style='position:relative'>
                          <img src='${ava}' alt='' style='width:28px;height:28px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                          <span style='position:absolute;right:-2px;bottom:-2px;display:inline-block;width:8px;height:8px;border-radius:50%;background:${color};border:2px solid #fff'></span>
                        </div>
                        <div style='display:flex;flex-direction:column;min-width:0'>
                          <span>${esc(label)}${badge}</span>
                          <span style='color:#777;white-space:normal;word-break:break-word;overflow-wrap:anywhere;margin-top:4px'>${esc(shortBio)}</span>
                        </div>
                    </div>`;
                };
                rightOnlineList.innerHTML = filtered.map(p => {
                    const u = p.username;
                    const label = u === me ? `${u} (you)` : u;
                    const color = presenceColor(p.presence);
                    const ava = p.avatar_url || '';
                    const statusText = (p.status||'').toUpperCase();
                    const bio = (p.bio||'');
                    const shortBio = bio.length > 100 ? (bio.slice(0, 100) + '...') : bio;
                    const tooltip = `${bio}`;
                    return `<div style='display:flex;align-items:center;gap:10px;margin:8px 0;font-size:15px' data-user='${esc(u)}' title='${esc(tooltip)}'>
                        <div style='position:relative'>
                          <img src='${ava}' alt='' style='width:28px;height:28px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                          <span style='position:absolute;right:-2px;bottom:-2px;display:inline-block;width:8px;height:8px;border-radius:50%;background:${color};border:2px solid #fff'></span>
                        </div>
                        <div style='display:flex;flex-direction:column;min-width:0'>
                          <span>${esc(label)}</span>
                          <span style='color:#888;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px'>${esc(shortBio)}</span>
                        </div>
                    </div>`;
                }).join('');
                rightOnlineList.innerHTML = `
                  <div style='font-weight:700;margin:6px 0'>Online — ${online.length}</div>
                  ${online.map(renderUser).join('') || "<div class='note'>No one online</div>"}
                  <div style='font-weight:700;margin:10px 0 6px'>Offline — ${offline.length}</div>
                  ${offline.map(renderUser).join('') || "<div class='note'>No one offline</div>"}
                `;

                // Pin update socket listener (uses global ensurePinnedLoaded and renderPinnedPublic)
                socket.on('pin_update', (payload)=>{
                  try {
                    if(!payload || payload.kind!=='public') return;
                    if(payload.action==='pin'){ renderPinnedPublic(payload.message||null); }
                    else if(payload.action==='unpin'){
                      // If unpinned, check if there's another pin
                      ensurePinnedLoaded();
                    }
                  } catch(e) {}
                });
                // Hover/click profile popover + context menu (with hover-intent) via delegated listeners
                ensureProfilePopover();
                rightOnlineList.onmouseover = (ev) => {
                    const el = ev.target && ev.target.closest('[data-user]');
                    if (!el || !rightOnlineList.contains(el)) return;
                    const u = el.getAttribute('data-user');
                    const p = (profiles||[]).find(x=>x.username===u) || {};
                    scheduleShowProfilePopover(el, p, 250);
                };
                rightOnlineList.onmouseout = (ev) => {
                    const el = ev.target && ev.target.closest('[data-user]');
                    if (!el) return;
                    const to = ev.relatedTarget;
                    if (to && (to.closest && (to.closest('[data-user]') === el || to.closest('.popover')))) return;
                    scheduleHideProfilePopover(180);
                };
                rightOnlineList.onclick = (ev) => {
                    const el = ev.target && ev.target.closest('[data-user]');
                    if (!el || !rightOnlineList.contains(el)) return;
                    const u = el.getAttribute('data-user');
                    const p = (profiles||[]).find(x=>x.username===u) || {};
                    scheduleShowProfilePopover(el, p, 0);
                };
                rightOnlineList.oncontextmenu = (ev) => {
                    const el = ev.target && ev.target.closest('[data-user]');
                    if (!el || !rightOnlineList.contains(el)) return;
                    ev.preventDefault();
                    const u = el.getAttribute('data-user');
                    if (!u || u === me) return;
                    showUserContextMenu(ev.pageX, ev.pageY, u);
                };
            } catch(e) {
                rightOnlineList.textContent = 'Failed to load';
            }
        }

        // Profile popover + context menu helpers
        function ensureProfilePopover() {
            if (window.__profilePopover) return;
            const pop = document.createElement('div');
            pop.className = 'popover';
            pop.style.display = 'none';
            pop.style.pointerEvents = 'auto';
            pop.addEventListener('mouseenter', () => {
                // Keep popover open while hovering it
                if (window.__popoverHideTimer) { clearTimeout(window.__popoverHideTimer); window.__popoverHideTimer = null; }
            });
            pop.addEventListener('mouseleave', () => {
                scheduleHideProfilePopover(150);
            });
            document.body.appendChild(pop);
            window.__profilePopover = pop;
        }
        function showProfilePopover(anchorEl, p) {
            if (!window.__profilePopover) ensureProfilePopover();
            const pop = window.__profilePopover;
            const rect = anchorEl.getBoundingClientRect();
            const ava = (p && p.avatar_url) || '';
            const presence = (p && p.presence) || '';
            const color = presenceColor(presence);
            const bio = (p && p.bio ? p.bio : '').replace(/</g,'&lt;').replace(/>/g,'&gt;');
            pop.innerHTML = `
              <div style='display:flex;gap:10px;align-items:flex-start;'>
                <img src='${ava}' alt='' style='width:40px;height:40px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                <div style='display:flex;flex-direction:column;'>
                  <div style='display:flex;align-items:center;gap:6px;'>
                    <strong>@${p.username||''}</strong>
                    <span style='display:inline-block;width:8px;height:8px;border-radius:50%;background:${color};border:2px solid #fff'></span>
                  </div>
                  <div style='color:#777;white-space:normal;word-break:break-word;overflow-wrap:anywhere;margin-top:4px'>${bio}</div>
                </div>
              </div>`;
            // Make visible to measure, then position
            pop.style.visibility = 'hidden';
            pop.style.display = 'block';
            const height = pop.offsetHeight || 120;
            const width = pop.offsetWidth || 260;
            // Position below if not enough space above
            const desiredTop = window.scrollY + rect.top - height - 8;
            const top = desiredTop < 0 ? (window.scrollY + rect.bottom + 8) : desiredTop;
            let left = window.scrollX + rect.left - 20; // nudge left a bit
            const maxLeft = window.innerWidth - width - 8;
            if (left < 8) left = 8;
            if (left > maxLeft) left = maxLeft;
            pop.style.top = top + 'px';
            pop.style.left = left + 'px';
            pop.style.visibility = 'visible';
        }
        function hideProfilePopover() {
            if (window.__profilePopover) window.__profilePopover.style.display = 'none';
        }
        function scheduleShowProfilePopover(anchorEl, p, delayMs) {
            if (window.__popoverHideTimer) { clearTimeout(window.__popoverHideTimer); window.__popoverHideTimer = null; }
            if (window.__popoverTimer) { clearTimeout(window.__popoverTimer); }
            window.__currentPopoverAnchor = anchorEl;
            window.__currentPopoverData = p;
            window.__popoverTimer = setTimeout(() => {
                // Only show if anchor is still hovered
                const el = window.__currentPopoverAnchor;
                if (el && el.isConnected) {
                    showProfilePopover(el, window.__currentPopoverData || {});
                }
            }, Math.max(0, delayMs||0));
        }
        function scheduleHideProfilePopover(delayMs) {
            if (window.__popoverTimer) { clearTimeout(window.__popoverTimer); window.__popoverTimer = null; }
            if (window.__popoverHideTimer) { clearTimeout(window.__popoverHideTimer); }
            window.__popoverHideTimer = setTimeout(() => {
                hideProfilePopover();
                window.__currentPopoverAnchor = null;
                window.__currentPopoverData = null;
            }, Math.max(0, delayMs||0));
        }
        function showUserContextMenu(x, y, user) {
            if (window.__userMenu) { __userMenu.remove(); __userMenu = null; }
            const menu = document.createElement('div');
            menu.style.position = 'fixed';
            menu.style.top = y + 'px';
            menu.style.left = x + 'px';
            menu.style.background = 'var(--card)';
            menu.style.border = '1px solid var(--border)';
            menu.style.padding = '6px 10px';
            menu.style.borderRadius = '6px';
            menu.style.zIndex = '10002';
            menu.style.color = 'var(--primary)';
            menu.style.boxShadow = '0 10px 24px rgba(0,0,0,0.25)';
            const makeItem = (label, handler) => {
                const item = document.createElement('div');
                item.textContent = label;
                item.style.padding = '6px 4px';
                item.style.cursor = 'pointer';
                item.onmouseenter = () => item.style.background = 'var(--bg)';
                item.onmouseleave = () => item.style.background = 'var(--card)';
                item.onclick = () => { try { handler(); } finally { if (menu) { menu.remove(); } } };
                return item;
            };
            menu.appendChild(makeItem('Direct Message', () => { openDM(user); }));
            menu.appendChild(makeItem('View Profile', async () => {
                try {
                    const profiles = await getProfiles();
                    const p = (profiles||[]).find(x=>x.username===user) || {};
                    showProfilePopover({ getBoundingClientRect: () => ({ top: y, left: x }) }, p);
                } catch(e) {}
            }));
            if (user !== me) {
                menu.appendChild(makeItem('🚨 Report User', () => {
                    showReportModal('user', {
                        target_username: user
                    });
                }));
            }
            if (SUPERADMINS.includes(me) && !SUPERADMINS.includes(user)) {
                menu.appendChild(makeItem('Delete Account', async () => {
                    if (!confirm(`Delete account for ${user}? This removes their data.`)) return;
                    try {
                        const res = await fetch('/api/admin/delete_user', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username: user }) });
                        const info = await res.json().catch(()=>({}));
                        if (!res.ok || !info.ok) { alert((info&&info.error)||'Failed'); return; }
                        alert('User deleted');
                        refreshRightOnline();
                        try { if (currentMode==='dm' && currentPeer===user) switchToPublic(); } catch(_){ }
                    } catch(e) { alert('Failed'); }
                }));
            }
            document.body.appendChild(menu);
            window.__userMenu = menu;
            setTimeout(() => {
                document.addEventListener('click', e => { if (menu && !menu.contains(e.target)) { menu.remove(); window.__userMenu = null; } }, { once: true });
            }, 0);
        }

        if (dmSearchEl) {
          dmSearchEl.addEventListener('input', () => loadDMs());
        }

        // Left sidebar Public button
        (function(){
            const go = document.getElementById('goPublicBtn');
            if (go) go.onclick = () => switchToPublic();
        })();

        function switchToPublic() {
            currentMode = 'public';
            currentPeer = null;
            currentThreadId = null;
            currentDoc = null;
            chatEl.innerHTML = '';
            messagesLoaded = false;
            modeBar.textContent = '';
            updateModeBar();
            loadMessages();
            // Ensure pinned message is loaded
            setTimeout(() => ensurePinnedLoaded(), 100);
        }

        async function openDM(peer) {
            if (!peer || peer === me) return;
            currentMode = 'dm';
            currentPeer = peer;
            currentThreadId = null;
            currentDoc = null;
            chatEl.innerHTML = '';
            // If peer was hidden, unhide it now
            try {
                const arr = JSON.parse(localStorage.getItem('closedDMs')||'[]');
                const idx = arr.indexOf(peer);
                if (idx>=0) { arr.splice(idx,1); localStorage.setItem('closedDMs', JSON.stringify(arr)); }
            } catch(e) {}
            // Build DM header without bio (bio is shown in right users tab and popover only)
            try {
                const profiles = await getProfiles();
                const p = (profiles||[]).find(x=>x.username===peer) || {};
                const ava = p.avatar_url || '';
                const statusText = ((p.status||'')+'' ).toUpperCase();
                const color = presenceColor(p.presence);
                const statusBadge = statusText ? `<span style='color:#666;font-size:12px;background:#f3f4f6;border:1px solid #e5e7eb;border-radius:10px;padding:2px 6px'>${esc(statusText)}</span>` : '';
                modeBar.innerHTML = `
                  <span style='display:inline-flex;align-items:center;gap:8px;'>
                    <span style='position:relative;display:inline-block'>
                      <img src='${ava}' alt='' style='width:20px;height:20px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                      <span style='position:absolute;right:-2px;bottom:-2px;display:inline-block;width:8px;height:8px;border-radius:50%;background:${color};border:2px solid #fff'></span>
                    </span>
                    <strong>@${esc(peer)}</strong>
                    ${statusBadge}
                  </span>
                  <button id='callDmBtn' type='button' style='margin:0 8px;padding:4px 8px;font-size:12px;background:#3b82f6;color:#fff;border:none;border-radius:4px;cursor:pointer'>📞 Call</button>
                  — <span id='backToPublic' style='color:blue;cursor:pointer;text-decoration:underline'>back</span>`;
            } catch(e) {
                modeBar.innerHTML = `DM with ${peer} <button id='callDmBtn' type='button' style='margin:0 8px;padding:4px 8px;font-size:12px;background:#3b82f6;color:#fff;border:none;border-radius:4px;cursor:pointer'>📞 Call</button> — <span id='backToPublic' style='color:blue;cursor:pointer;text-decoration:underline'>back</span>`;
            }
            try { Language.translateFragment(modeBar); } catch(_){}
            document.getElementById('backToPublic').onclick = switchToPublic;
            // Wire up call button
            try {
              const callBtn = document.getElementById('callDmBtn');
              if (callBtn) {
                callBtn.onclick = ()=>{
                  try{
                    socket.emit('call_start_dm', { to_user: peer });
                    toast('Call initiated!', '#10b981');
                  }catch(e){ toast('Call failed', '#dc2626'); }
                };
              }
            } catch(e) {}
            // reset unread for this peer
            try {
                const map = JSON.parse(localStorage.getItem('unreadDM')||'{}');
                if (map[peer]) { delete map[peer]; localStorage.setItem('unreadDM', JSON.stringify(map)); }
                loadDMs();
            } catch(e) {}
            updateTitleUnread();
            fetch(`/api/dm/messages?peer=${encodeURIComponent(peer)}`)
                .then(res=>res.json())
                .then(list => {
                    list.forEach(dm => renderDM(dm));
                    scrollToBottom();
                });
        }

        function openGDM(tid) {
            if (!tid) return;
            currentMode = 'gdm';
            currentPeer = null;
            currentThreadId = tid;
            currentDoc = null;
            chatEl.innerHTML = '';
            // If this group was hidden, unhide it now
            try {
                const arr = JSON.parse(localStorage.getItem('closedGDMs')||'[]');
                const sid = String(tid);
                const idx = arr.indexOf(sid);
                if (idx >= 0) { arr.splice(idx,1); localStorage.setItem('closedGDMs', JSON.stringify(arr)); }
            } catch(e) {}
            const tinfo = gdmThreadsCache[tid] || { id: tid, name: `Group ${tid}`, created_by: null };
            const isOwner = (tinfo.created_by && tinfo.created_by === me) || SUPERADMINS.includes(me);
            // Build header with admin controls
            let buttons = `<button id='callGdmBtn' type='button' style='margin-left:8px;padding:2px 6px;font-size:12px;background:none;color:var(--primary);border:1px solid var(--border);border-radius:3px;cursor:pointer'>📞 Call</button> <span id='backToPublic' style='color:var(--primary);cursor:pointer;text-decoration:underline;margin-left:8px;font-size:12px'>back</span>`;
            if (isOwner) {
                buttons += `
                <span style='margin:0 8px;color:var(--border)'>|</span>
                <button id='btnGdmAdd' type='button' style='padding:2px 6px;font-size:12px;background:none;color:var(--primary);border:1px solid var(--border);border-radius:3px;cursor:pointer'>👥 Add</button>`;
            }
            // Close is per-user local hide
            buttons += `
                <button id='btnGdmClose' type='button' style='padding:2px 6px;font-size:12px;background:none;color:var(--primary);border:1px solid var(--border);border-radius:3px;cursor:pointer'>Close</button>`;
            modeBar.innerHTML = `Group ${tinfo.name ? ('# '+tinfo.name) : ('#'+tid)} — ${buttons}`;
            try { Language.translateFragment(modeBar); } catch(_){}
            document.getElementById('backToPublic').onclick = switchToPublic;
            // Wire up call button
            try {
              const callBtn = document.getElementById('callGdmBtn');
              if (callBtn) {
                callBtn.onclick = ()=>{
                  try{
                    socket.emit('call_start_gdm', { thread_id: tid });
                    toast('Call initiated!', '#10b981');
                  }catch(e){ toast('Call failed', '#dc2626'); }
                };
              }
            } catch(e) {}
            // reset unread for this group
            try {
                const map = JSON.parse(localStorage.getItem('unreadGDM')||'{}');
                const key = String(tid);
                if (map[key]) { delete map[key]; localStorage.setItem('unreadGDM', JSON.stringify(map)); }
                loadGDMs();
            } catch(e) {}
            updateTitleUnread();
            const btnClose = document.getElementById('btnGdmClose');
            if (btnClose) btnClose.onclick = () => {
                try {
                    const arr = JSON.parse(localStorage.getItem('closedGDMs')||'[]');
                    const sid = String(tid);
                    if (!arr.includes(sid)) arr.push(sid);
                    localStorage.setItem('closedGDMs', JSON.stringify(arr));
                } catch(e) {}
                switchToPublic();
                loadGDMs();
            };
            if (isOwner) {
                const btnAdd = document.getElementById('btnGdmAdd');
                if (btnAdd) btnAdd.onclick = async () => {
                    openDialog({
                      title:'Add Members',
                      html:`<input name='users' placeholder='alice, bob' style='padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)'>`,
                      onSubmit: async (fd, close)=>{
                        const users=(fd.get('users')||'').toString().split(',').map(s=>s.trim()).filter(Boolean);
                        if (users.length===0){ toast('Enter at least one username','#dc2626'); return; }
                        const res = await fetch('/api/gdm/add_member', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify({ tid, users }) });
                        let info={}; try{ info=await res.json(); }catch(e){ }
                        if (!res.ok){ toast(info.error||'Failed','#dc2626'); return; }
                        close(); loadGDMs();
                      }
                    });
                };
                // Settings dropdown menu for group actions
                const settingsMenuId = `gdmSettings_${tid}`;
                const settingsSpan = document.createElement('span');
                settingsSpan.style.position = 'relative';
                settingsSpan.style.display = 'inline-block';
                settingsSpan.innerHTML = `
                  <button id='btnGdmSettings' type='button' style='padding:2px 6px;font-size:12px;background:none;color:var(--primary);border:1px solid var(--border);border-radius:3px;cursor:pointer'>⚙️</button>
                  <div id='${settingsMenuId}' style='display:none;position:absolute;right:0;top:100%;background:var(--card);border:1px solid var(--border);border-radius:4px;min-width:160px;z-index:50;margin-top:4px'>
                    <a href='#' class='gdm-action' data-action='rename' style='display:block;padding:6px 8px;color:var(--primary);text-decoration:none;font-size:13px;border-bottom:1px solid var(--border)'>✏️ Rename Group</a>
                    <a href='#' class='gdm-action' data-action='invite' style='display:block;padding:6px 8px;color:var(--primary);text-decoration:none;font-size:13px;border-bottom:1px solid var(--border)'>👥 Invite User</a>
                    <a href='#' class='gdm-action' data-action='kick' style='display:block;padding:6px 8px;color:var(--primary);text-decoration:none;font-size:13px;border-bottom:1px solid var(--border)'>👢 Kick User</a>
                    <a href='#' class='gdm-action' data-action='lock' style='display:block;padding:6px 8px;color:var(--primary);text-decoration:none;font-size:13px;border-bottom:1px solid var(--border)'>🔒 Lock Group</a>
                    <a href='#' class='gdm-action' data-action='unlock' style='display:block;padding:6px 8px;color:var(--primary);text-decoration:none;font-size:13px;border-bottom:1px solid var(--border)'>🔓 Unlock Group</a>
                                        <a href='#' class='gdm-action' data-action='delete' style='display:block;padding:6px 8px;color:var(--primary);text-decoration:none;font-size:13px'>🗑️ Delete Group</a>
                  </div>
                `;
                document.getElementById('backToPublic').parentElement.insertAdjacentElement('beforeend', settingsSpan);
                const settingsBtn = settingsSpan.querySelector('#btnGdmSettings');
                const settingsMenu = settingsSpan.querySelector(`#${settingsMenuId}`);
                settingsBtn.onclick = (e) => { e.preventDefault(); settingsMenu.style.display = settingsMenu.style.display === 'none' ? 'block' : 'none'; };
                document.addEventListener('click', (e) => { if (!settingsSpan.contains(e.target)) settingsMenu.style.display = 'none'; });

                // Add invite code after settings button if it exists
                if (tinfo.invite_code) {
                    const codeSpan = document.createElement('span');
                    codeSpan.style.cssText = 'margin:0 8px;color:var(--border);font-size:11px;color:var(--muted)';
                    codeSpan.textContent = `Code: ${tinfo.invite_code}`;
                    settingsSpan.insertAdjacentElement('afterend', codeSpan);
                }

                // Add spacing between settings and close buttons
                const spacerSpan = document.createElement('span');
                spacerSpan.style.cssText = 'margin:0 8px;color:var(--border)';
                spacerSpan.textContent = '|';
                settingsSpan.insertAdjacentElement('afterend', spacerSpan);

                // Handle action menu clicks
                settingsSpan.querySelectorAll('.gdm-action').forEach(link => {
                  link.onclick = async (e) => {
                    e.preventDefault();
                    settingsMenu.style.display = 'none';
                    const action = link.getAttribute('data-action');
                    if (action === 'rename') {
                      openDialog({
                        title:'Rename Group',
                        html:`<input name='name' value='${(tinfo.name||'').replace(/'/g,"&#39;")}' style='padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)'>`,
                        onSubmit: async (fd, close)=>{
                          const name=(fd.get('name')||'').toString().trim(); if(!name){ toast('Enter name','#dc2626'); return; }
                          console.log('Attempting to rename group', { tid, name, currentThreadId });
                          const res = await fetch('/api/gdm/rename', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify({ tid, name }) });
                          let info={}; try{ info=await res.json(); }catch(e){ }
                          console.log('Rename response', { status: res.status, info });
                          if (!res.ok){ toast(info.error||'Failed','#dc2626'); return; }
                          close(); loadGDMs();
                          // Update current group name if we're still in this group
                          if (currentThreadId === tid) {
                            gdmThreadsCache[tid].name = name;
                            updateModeBar();
                            console.log('Updated local group name to:', name);
                          }
                          toast('Group renamed successfully', '#16a34a');
                        }
                      });
                    } else if (action === 'invite') {
                      try {
                        const res = await fetch('/api/gdm/invite/create', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify({ tid }) });
                        const info = await res.json();
                        if (!res.ok) { toast((info&&info.error)||'Failed to create invite','#dc2626'); return; }
                        try {
                          await navigator.clipboard.writeText(info.link);
                          toast('Invite link copied','#16a34a');
                        } catch(e) {
                          const dummy = document.createElement('textarea');
                          dummy.value = info.link;
                          document.body.appendChild(dummy);
                          dummy.select();
                          try { document.execCommand('copy'); toast('Invite link copied','#16a34a'); }
                          catch(e2) { toast(info.link,'#2563eb'); }
                          document.body.removeChild(dummy);
                        }
                      } catch(e) { alert('Failed to create invite'); }
                    } else if (action === 'kick') {
                      openDialog({
                        title:'Kick User',
                        html:`<input name='user' placeholder='username' style='padding:8px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--primary)'>`,
                        onSubmit: async (fd, close)=>{
                          const u=(fd.get('user')||'').toString().trim(); if(!u){ toast('Enter a username','#dc2626'); return; }
                          const res = await fetch('/api/gdm/kick', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify({ tid, user: u }) });
                          let info={}; try{ info=await res.json(); }catch(e){ }
                          if (!res.ok){ toast(info.error||'Failed','#dc2626'); return; }
                          close(); loadGDMs();
                        }
                      });
                    } else if (action === 'delete') {
                      if (confirm('Are you sure you want to delete this group? This action cannot be undone.')) {
                        try {
                          const res = await fetch('/api/gdm/delete', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify({ tid }) });
                          let info={}; try{ info=await res.json(); }catch(e){ }
                          if (!res.ok){ toast(info.error||'Failed','#dc2626'); return; }
                          switchToPublic();
                          loadGDMs();
                        } catch(e) { toast('Failed to delete','#dc2626'); }
                      }
                    }
                  };
                });
            }
            socket.emit('gdm_join', { thread_id: tid });
            fetch(`/api/gdm/messages?tid=${tid}`)
                .then(res=>res.json())
                .then(list => {
                    list.forEach(m => renderGDM(m));
                    scrollToBottom();
                });
        }

        // Simple autofill prevention for DM search
        const dmSearchInput = document.getElementById('dmSearch');
        if (dmSearchInput) {
            // Clear value on focus to remove any autofill
            dmSearchInput.addEventListener('focus', () => {
                dmSearchInput.value = '';
            });
        }

        function renderMessage(m) {
            const d = document.createElement('div');
            d.className = 'message';
            d.dataset.id = m.id;
            d.dataset.user = m.username;

            const time = new Date(m.created_at).toLocaleString();
            const idBadge = m && m.id ? `<span class="time" style="margin-left:6px;color:#6b7280">#${m.id}</span>` : '';
            let attachmentHtml = '';

            // Enhanced image attachment handling (supports multiple attachments with Discord-style grid)
            if (m.attachment) {
                let attachments = [];

                // Check if attachment is a JSON array (multiple attachments)
                try {
                    const parsed = JSON.parse(m.attachment);
                    if (Array.isArray(parsed)) {
                        attachments = parsed;
                    } else {
                        attachments = [m.attachment]; // Single attachment
                    }
                } catch (e) {
                    attachments = [m.attachment]; // Single attachment (not JSON)
                }

                // Filter only image attachments for special grid layout
                const imageAttachments = attachments.filter(attachment => {
                    const ext = (attachment.split('.').pop() || '').toLowerCase();
                    return ['png','jpg','jpeg','gif','webp'].includes(ext);
                });

                const otherAttachments = attachments.filter(attachment => {
                    const ext = (attachment.split('.').pop() || '').toLowerCase();
                    return !['png','jpg','jpeg','gif','webp'].includes(ext);
                });

                // Render image attachments in Discord-style grid
                if (imageAttachments.length > 0) {
                    const gridClass = imageAttachments.length === 1 ? 'single-image' :
                                     imageAttachments.length === 2 ? 'two-images' :
                                     imageAttachments.length === 3 ? 'three-images' : 'many-images';

                    attachmentHtml += `<div class="image-grid ${gridClass}" style="display:grid;gap:4px;margin-top:8px;max-width:400px">`;

                    imageAttachments.forEach((attachment, index) => {
                        const downloadUrl = '/uploads/' + encodeURIComponent(attachment);
                        attachmentHtml += `
                            <div class="image-container" style="position:relative;overflow:hidden;border-radius:8px;border:1px solid var(--border);background:var(--muted)">
                                <img src="${downloadUrl}" alt="${attachment}"
                                     style="width:100%;height:100%;object-fit:cover;cursor:pointer"
                                     onclick="handleImageClick('${downloadUrl}', '${attachment}', '${m.username}', '${time}')"
                                     loading="lazy">
                            </div>
                        `;
                    });

                    attachmentHtml += '</div>';
                }

                // Render other attachments normally
                otherAttachments.forEach((attachment, index) => {
                    const downloadUrl = '/uploads/' + encodeURIComponent(attachment);
                    const ext = (attachment.split('.').pop() || '').toLowerCase();
                    let previewPart = '';
                    let previewUrl = '';

                    if (['png','jpg','jpeg','gif','mp4','webm','html','zip'].includes(ext)) {
                        previewUrl = '/preview/' + encodeURIComponent(attachment);
                        previewPart = `<a href="${previewUrl}" target="_blank">preview</a>`;
                    }

                    attachmentHtml += `<div class="attachment" style="margin-top:8px">Attachment: ${attachment}, <a href="${downloadUrl}">download</a>${previewPart ? ', ' + previewPart : ''}</div>`;
                });
            }

            let userClass = 'username';
            if (m.username === 'System') {
                userClass += ' system';
            } else if (ADMINS.includes(m.username)) {
                userClass += ' admin';
            }

            const mAva = getAvatar(m.username);
            const replyHtml = (m.reply_to && (m.reply_username || m.reply_snippet)) ? `
                <div class="reply-preview" data-reply-id="${m.reply_to}" style="border-left:3px solid #9ca3af;padding-left:8px;margin:6px 0;color:#6b7280;cursor:pointer">
                    <strong>${esc(m.reply_username||'')}</strong>
                    <span style="margin-left:6px">${esc(m.reply_snippet||'')}</span>
                </div>` : '';
            d.innerHTML = `
                <div style='display:flex;align-items:center;gap:8px'>
                    <img src='${mAva}' alt='' style='width:20px;height:20px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                    <div><span class="${userClass}">${esc(m.username)}</span> <span class="time">${time}</span> ${idBadge}</div>
                </div>
                ${replyHtml}
                <div class="msg-body">${m.text || ''}</div>
                ${attachmentHtml}
            `;
            // click to scroll to original
            try {
              const rpv = d.querySelector('.reply-preview');
              if (rpv) { rpv.addEventListener('click', ()=>{ const rid = rpv.getAttribute('data-reply-id'); if (rid) { const t = chatEl.querySelector(`.message[data-id="${rid}"]`); if (t) { t.scrollIntoView({behavior:'smooth',block:'center'}); t.style.outline='2px solid #93c5fd'; setTimeout(()=>{ t.style.outline=''; }, 1200); } } }); }
            } catch(e) {}

            // Add context menu for message actions
            // Allow all users to access reply/DM, restrict edit/delete to admin/author
                d.addEventListener('contextmenu', ev => {
                    ev.preventDefault();
                    if (contextMenu) contextMenu.remove();

                    contextMenu = document.createElement('div');
                    contextMenu.style.position = 'fixed';
                    contextMenu.style.top = ev.pageY + 'px';
                    contextMenu.style.left = ev.pageX + 'px';
                    contextMenu.style.background = 'var(--card)';
                    contextMenu.style.border = '1px solid var(--border)';
                    contextMenu.style.padding = '6px 10px';
                    contextMenu.style.borderRadius = '6px';
                    contextMenu.style.zIndex = '9999';
                    contextMenu.style.color = 'var(--primary)';
                    contextMenu.style.boxShadow = '0 10px 24px rgba(0,0,0,0.25)';

                    const makeItem = (label, handler) => {
                        const item = document.createElement('div');
                        item.textContent = label;
                        item.style.padding = '6px 4px';
                        item.style.cursor = 'pointer';
                        item.onmouseenter = () => item.style.background = 'var(--bg)';
                        item.onmouseleave = () => item.style.background = 'var(--card)';
                        item.onclick = () => {
                            try { handler(); } finally {
                                if (contextMenu) { contextMenu.remove(); contextMenu = null; }
                            }
                        };
                        return item;
                    };

                    // Edit item (System only editable by SUPERADMIN)
                    let canEdit = false;
                    if (m.username === 'System') {
                        canEdit = SUPERADMINS.includes(me);
                    } else {
                        canEdit = (
                            m.username === me ||
                            (isAdmin && !ADMINS.includes(m.username)) ||
                            (SUPERADMINS.includes(me) && ADMINS.includes(m.username))
                        );
                    }
                    if (canEdit) {
                        contextMenu.appendChild(makeItem('✏ Edit message', () => {
                            const body = d.querySelector('.msg-body');
                            if (!body) return;
                            const messageId = m.id;
                            startInlineEdit(body, body.innerHTML, (txt)=>{ socket.emit('edit_message', { id: messageId, text: txt }); });
                        }));
                    }

                    // Reply
                    contextMenu.appendChild(makeItem('↩ Reply', () => {
                        setReply({ type:'public', id: m.id, username: m.username, snippet: d.querySelector('.msg-body')?.innerText || '' });
                    }));
                    // Delete item
                    contextMenu.appendChild(makeItem('🗑️ Delete message', () => {
                        socket.emit('delete_message', m.id);
                    }));
                    // DM Sender
                    if (m.username && m.username !== me) {
                        contextMenu.appendChild(makeItem('💬 DM', () => { openDM(m.username); }));
                        // Report Message
                        contextMenu.appendChild(makeItem('🚨 Report Message', () => {
                            showReportModal('message', {
                                message_id: m.id,
                                target_username: m.username
                            });
                        }));
                    }

                    document.body.appendChild(contextMenu);

                    document.addEventListener('click', e => {
                        if (contextMenu && !contextMenu.contains(e.target)) {
                            contextMenu.remove();
                            contextMenu = null;
                        }
                    }, {once: true});
                });

            chatEl.appendChild(d);
            try { Language.translateFragment(d); } catch(_){}
            scrollToBottom();
        }

        function renderDM(dm) {
            const d = document.createElement('div');
            d.className = 'message';
            d.dataset.id = dm.id;
            d.dataset.user = dm.from_user;
            const time = new Date(dm.created_at).toLocaleString();
            const idBadge = dm && dm.id ? `<span class="time" style="margin-left:6px;color:#6b7280">#${dm.id}</span>` : '';
            let attachmentHtml = '';

            // Enhanced image attachment handling for DM (supports multiple attachments with Discord-style grid)
            if (dm.attachment) {
                let attachments = [];

                // Check if attachment is a JSON array (multiple attachments)
                try {
                    const parsed = JSON.parse(dm.attachment);
                    if (Array.isArray(parsed)) {
                        attachments = parsed;
                    } else {
                        attachments = [dm.attachment]; // Single attachment
                    }
                } catch (e) {
                    attachments = [dm.attachment]; // Single attachment (not JSON)
                }

                // Filter only image attachments for special grid layout
                const imageAttachments = attachments.filter(attachment => {
                    const ext = (attachment.split('.').pop() || '').toLowerCase();
                    return ['png','jpg','jpeg','gif','webp'].includes(ext);
                });

                const otherAttachments = attachments.filter(attachment => {
                    const ext = (attachment.split('.').pop() || '').toLowerCase();
                    return !['png','jpg','jpeg','gif','webp'].includes(ext);
                });

                // Render image attachments in Discord-style grid
                if (imageAttachments.length > 0) {
                    const gridClass = imageAttachments.length === 1 ? 'single-image' :
                                     imageAttachments.length === 2 ? 'two-images' :
                                     imageAttachments.length === 3 ? 'three-images' : 'many-images';

                    attachmentHtml += `<div class="image-grid ${gridClass}" style="display:grid;gap:4px;margin-top:8px;max-width:400px">`;

                    imageAttachments.forEach((attachment, index) => {
                        const downloadUrl = '/uploads/' + encodeURIComponent(attachment);
                        attachmentHtml += `
                            <div class="image-container" style="position:relative;overflow:hidden;border-radius:8px;border:1px solid var(--border);background:var(--muted)">
                                <img src="${downloadUrl}" alt="${attachment}"
                                     style="width:100%;height:100%;object-fit:cover;cursor:pointer"
                                     onclick="handleImageClick('${downloadUrl}', '${attachment}', '${dm.from_user}', '${time}')"
                                     loading="lazy">
                            </div>
                        `;
                    });

                    attachmentHtml += '</div>';
                }

                // Render other attachments normally
                otherAttachments.forEach((attachment, index) => {
                    const downloadUrl = '/uploads/' + encodeURIComponent(attachment);
                    const ext = (attachment.split('.').pop() || '').toLowerCase();
                    let previewPart = '';
                    let previewUrl = '';

                    if (['png','jpg','jpeg','gif','mp4','webm','html','zip'].includes(ext)) {
                        previewUrl = '/preview/' + encodeURIComponent(attachment);
                        previewPart = `<a href="${previewUrl}" target="_blank">preview</a>`;
                    }

                    attachmentHtml += `<div class="attachment" style="margin-top:8px">Attachment: ${attachment}, <a href="${downloadUrl}">download</a>${previewPart ? ', ' + previewPart : ''}</div>`;
                });
            }

            let userClass = 'username';
            if (dm.from_user === 'System') { userClass += ' system'; }
            else if (ADMINS.includes(dm.from_user)) { userClass += ' admin'; }
            const mAva = getAvatar(dm.from_user);
            const replyHtml = (dm.reply_to && (dm.reply_username || dm.reply_snippet)) ? `
                <div class="reply-preview" data-reply-id="${dm.reply_to}" style="border-left:3px solid #9ca3af;padding-left:8px;margin:6px 0;color:#6b7280;cursor:pointer">
                    <strong>${esc(dm.reply_username||'')}</strong>
                    <span style="margin-left:6px">${esc(dm.reply_snippet||'')}</span>
                </div>` : '';
            d.innerHTML = `
                <div style='display:flex;align-items:center;gap:8px'>
                    <img src='${mAva}' alt='' style='width:20px;height:20px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                    <div><span class="${userClass}">${esc(dm.from_user)}</span> <span class="time">${time}</span> ${idBadge}</div>
                </div>
                ${replyHtml}
                <div class="msg-body">${dm.text || ''}</div>
                ${attachmentHtml}
            `;
            try { const rpv = d.querySelector('.reply-preview'); if (rpv) { rpv.addEventListener('click', ()=>{ const rid = rpv.getAttribute('data-reply-id'); if (rid) { const t = chatEl.querySelector(`.message[data-id="${rid}"]`); if (t) { t.scrollIntoView({behavior:'smooth',block:'center'}); t.style.outline='2px solid #93c5fd'; setTimeout(()=>{ t.style.outline=''; }, 1200); } } }); } } catch(e){}
            // Right-click for edit/delete if author/admin
            const canModify = (dm.from_user === me) || isAdmin || SUPERADMINS.includes(me);
            // Allow all users to access reply, restrict edit/delete to author/admin
                d.addEventListener('contextmenu', ev => {
                    ev.preventDefault();
                    if (contextMenu) contextMenu.remove();
                    contextMenu = document.createElement('div');
                    contextMenu.style.position = 'fixed';
                    contextMenu.style.top = ev.pageY + 'px';
                    contextMenu.style.left = ev.pageX + 'px';
                    contextMenu.style.background = '#fff';
                    contextMenu.style.border = '1px solid #ccc';
                    contextMenu.style.padding = '6px 10px';
                    contextMenu.style.borderRadius = '6px';
                    contextMenu.style.zIndex = '9999';
                    contextMenu.style.boxShadow = '0 2px 8px rgba(0,0,0,0.1)';
                    const makeItem = (label, handler) => {
                        const item = document.createElement('div');
                        item.textContent = label;
                        item.style.padding = '6px 4px';
                        item.style.cursor = 'pointer';
                        item.onmouseenter = () => item.style.background = '#f2f2f2';
                        item.onmouseleave = () => item.style.background = '#fff';
                        item.onclick = () => { try { handler(); } finally { if (contextMenu) { contextMenu.remove(); contextMenu = null; } } };
                        return item;
                    };
                    if (canModify) {
                        contextMenu.appendChild(makeItem('✏ Edit DM', () => {
                            const body = d.querySelector('.msg-body');
                            if (!body) return;
                            startInlineEdit(body, body.innerHTML, (txt)=>{ socket.emit('dm_edit', { id: dm.id, text: txt }); });
                        }));
                    }
                    // Reply
                    contextMenu.appendChild(makeItem('↩ Reply', () => {
                        setReply({ type:'dm', id: dm.id, username: dm.from_user, snippet: d.querySelector('.msg-body')?.innerText || '' });
                    }));
                    if (canModify) {
                        contextMenu.appendChild(makeItem('🗑️ Delete DM', () => { socket.emit('dm_delete', { id: dm.id }); }));
                    }
                    // Report Message (only if not from self)
                    if (dm.from_user && dm.from_user !== me) {
                        contextMenu.appendChild(makeItem('🚨 Report Message', () => {
                            showReportModal('message', {
                                message_id: dm.id,
                                target_username: dm.from_user
                            });
                        }));
                    }
                    document.body.appendChild(contextMenu);
                    document.addEventListener('click', e => { if (contextMenu && !contextMenu.contains(e.target)) { contextMenu.remove(); contextMenu = null; } }, { once: true });
                });
            chatEl.appendChild(d);
            try { Language.translateFragment(d); } catch(_){}
        }

        function renderGDM(m) {
            const d = document.createElement('div');
            d.className = 'message';
            d.dataset.id = m.id;
            d.dataset.user = m.username;
            const time = new Date(m.created_at).toLocaleString();
            const idBadge = m && m.id ? `<span class="time" style="margin-left:6px;color:#6b7280">#${m.id}</span>` : '';
            let attachmentHtml = '';

            // Enhanced image attachment handling for GDM (supports multiple attachments with Discord-style grid)
            if (m.attachment) {
                let attachments = [];

                // Check if attachment is a JSON array (multiple attachments)
                try {
                    const parsed = JSON.parse(m.attachment);
                    if (Array.isArray(parsed)) {
                        attachments = parsed;
                    } else {
                        attachments = [m.attachment]; // Single attachment
                    }
                } catch (e) {
                    attachments = [m.attachment]; // Single attachment (not JSON)
                }

                // Filter only image attachments for special grid layout
                const imageAttachments = attachments.filter(attachment => {
                    const ext = (attachment.split('.').pop() || '').toLowerCase();
                    return ['png','jpg','jpeg','gif','webp'].includes(ext);
                });

                const otherAttachments = attachments.filter(attachment => {
                    const ext = (attachment.split('.').pop() || '').toLowerCase();
                    return !['png','jpg','jpeg','gif','webp'].includes(ext);
                });

                // Render image attachments in Discord-style grid
                if (imageAttachments.length > 0) {
                    const gridClass = imageAttachments.length === 1 ? 'single-image' :
                                     imageAttachments.length === 2 ? 'two-images' :
                                     imageAttachments.length === 3 ? 'three-images' : 'many-images';

                    attachmentHtml += `<div class="image-grid ${gridClass}" style="display:grid;gap:4px;margin-top:8px;max-width:400px">`;

                    imageAttachments.forEach((attachment, index) => {
                        const downloadUrl = '/uploads/' + encodeURIComponent(attachment);
                        attachmentHtml += `
                            <div class="image-container" style="position:relative;overflow:hidden;border-radius:8px;border:1px solid var(--border);background:var(--muted)">
                                <img src="${downloadUrl}" alt="${attachment}"
                                     style="width:100%;height:100%;object-fit:cover;cursor:pointer"
                                     onclick="handleImageClick('${downloadUrl}', '${attachment}', '${m.username}', '${time}')"
                                     loading="lazy">
                            </div>
                        `;
                    });

                    attachmentHtml += '</div>';
                }

                // Render other attachments normally
                otherAttachments.forEach((attachment, index) => {
                    const downloadUrl = '/uploads/' + encodeURIComponent(attachment);
                    const ext = (attachment.split('.').pop() || '').toLowerCase();
                    let previewPart = '';
                    let previewUrl = '';

                    if (['png','jpg','jpeg','gif','mp4','webm','html','zip'].includes(ext)) {
                        previewUrl = '/preview/' + encodeURIComponent(attachment);
                        previewPart = `<a href="${previewUrl}" target="_blank">preview</a>`;
                    }

                    attachmentHtml += `<div class="attachment" style="margin-top:8px">Attachment: ${attachment}, <a href="${downloadUrl}">download</a>${previewPart ? ', ' + previewPart : ''}</div>`;
                });
            }

            let userClass = 'username';
            if (m.username === 'System') { userClass += ' system'; }
            else if (ADMINS.includes(m.username)) { userClass += ' admin'; }
            const gAva = getAvatar(m.username);
            const replyHtml = (m.reply_to && (m.reply_username || m.reply_snippet)) ? `
                <div class="reply-preview" data-reply-id="${m.reply_to}" style="border-left:3px solid #9ca3af;padding-left:8px;margin:6px 0;color:#6b7280;cursor:pointer">
                    <strong>${esc(m.reply_username||'')}</strong>
                    <span style="margin-left:6px">${esc(m.reply_snippet||'')}</span>
                </div>` : '';
            d.innerHTML = `
                <div style='display:flex;align-items:center;gap:8px'>
                    <img src='${gAva}' alt='' style='width:20px;height:20px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                    <div><span class="${userClass}">${esc(m.username)}</span> <span class="time">${time}</span> ${idBadge}</div>
                </div>
                ${replyHtml}
                <div class="msg-body">${m.text || ''}</div>
                ${attachmentHtml}
            `;
            try { const rpv = d.querySelector('.reply-preview'); if (rpv) { rpv.addEventListener('click', ()=>{ const rid = rpv.getAttribute('data-reply-id'); if (rid) { const t = chatEl.querySelector(`.message[data-id="${rid}"]`); if (t) { t.scrollIntoView({behavior:'smooth',block:'center'}); t.style.outline='2px solid #93c5fd'; setTimeout(()=>{ t.style.outline=''; }, 1200); } } }); } } catch(e){}
            // Context menu for edit/delete (author/admin)
            const canModify = (m.username === me) || isAdmin || SUPERADMINS.includes(me);
            // Allow all users to access reply, restrict edit/delete to author/admin
                d.addEventListener('contextmenu', ev => {
                    ev.preventDefault();
                    if (contextMenu) contextMenu.remove();
                    contextMenu = document.createElement('div');
                    contextMenu.style.position = 'fixed';
                    contextMenu.style.top = ev.pageY + 'px';
                    contextMenu.style.left = ev.pageX + 'px';
                    contextMenu.style.background = '#fff';
                    contextMenu.style.border = '1px solid #ccc';
                    contextMenu.style.padding = '6px 10px';
                    contextMenu.style.borderRadius = '6px';
                    contextMenu.style.zIndex = '9999';
                    contextMenu.style.boxShadow = '0 2px 8px rgba(0,0,0,0.1)';
                    const makeItem = (label, handler) => {
                        const item = document.createElement('div');
                        item.textContent = label;
                        item.style.padding = '6px 4px';
                        item.style.cursor = 'pointer';
                        item.onmouseenter = () => item.style.background = '#f2f2f2';
                        item.onmouseleave = () => item.style.background = '#fff';
                        item.onclick = () => { try { handler(); } finally { if (contextMenu) { contextMenu.remove(); contextMenu = null; } } };
                        return item;
                    };
                    if (canModify) {
                        contextMenu.appendChild(makeItem('✏ Edit message', () => {
                            const body = d.querySelector('.msg-body');
                            if (!body) return;
                            startInlineEdit(body, body.innerHTML, (txt)=>{ socket.emit('gdm_edit', { id: m.id, text: txt }); });
                        }));
                    }
                    // Reply
                    contextMenu.appendChild(makeItem('↩ Reply', () => {
                        setReply({ type:'gdm', id: m.id, username: m.username, snippet: d.querySelector('.msg-body')?.innerText || '' });
                    }));
                    if (canModify) {
                        contextMenu.appendChild(makeItem('🗑️ Delete message', () => { socket.emit('gdm_delete', { id: m.id }); }));
                    }
                    // Report Message (only if not from self)
                    if (m.username && m.username !== me) {
                        contextMenu.appendChild(makeItem('🚨 Report Message', () => {
                            showReportModal('message', {
                                message_id: m.id,
                                target_username: m.username
                            });
                        }));
                    }
                    document.body.appendChild(contextMenu);
                    document.addEventListener('click', e => { if (contextMenu && !contextMenu.contains(e.target)) { contextMenu.remove(); contextMenu = null; } }, { once: true });
                });
            chatEl.appendChild(d);
            try { Language.translateFragment(d); } catch(_){}
        }

        // Send message functionality
        const textInput = document.getElementById('textInput');
        const replyBar = document.getElementById('replyBar');
        const replyUser = document.getElementById('replyUser');
        const replySnippet = document.getElementById('replySnippet');
        document.getElementById('cancelReplyBtn').addEventListener('click', ()=> clearReply());

        function setReply(info){
          try{
            currentReply = info || null;
            if (currentReply){
              replyUser.textContent = currentReply.username || '';
              replySnippet.textContent = (currentReply.snippet || '').replace(/\s+/g,' ').slice(0,140);
              replyBar.style.display = 'block';
              textInput.focus();
            } else { replyBar.style.display = 'none'; }
          }catch(e){}
        }
        function clearReply(){ try{ currentReply=null; replyBar.style.display='none'; }catch(e){} }
        // Enter to send, Shift+Enter newline on composer
        try {
          textInput.addEventListener('keydown', (ev)=>{
            // Defensive check to ensure input is still valid
            if (!textInput || !textInput.form) return;
            
            if (ev.key === 'Enter' && !ev.shiftKey) {
              ev.preventDefault();
              const form = document.getElementById('sendForm');
              if (form) form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
            }
          });
        } catch (e) {}
        // Local timeout gating
        let timeoutUntil = 0; // seconds epoch
        const modeBarNote = document.getElementById('modeBar');
        function showTimeoutBanner(){
            try {
                if (!timeoutUntil) return;
                const secs = Math.max(0, Math.floor(timeoutUntil - Date.now()/1000));
                const msg = `You are timed out for ${secs} more seconds`;
                const cur = modeBarNote.textContent || '';
                if (!cur.includes('timed out')) { modeBarNote.textContent = (cur? cur + ' — ' : '') + msg; }
            }catch(e){}

        // Group lock status UX: banner + disable inputs if locked
        try {
          window.updateGdmLockUI = async function(){
            try{
              if (typeof currentMode === 'undefined' || typeof currentThreadId === 'undefined') return;
              if (currentMode !== 'gdm' || !currentThreadId) { hide(); return; }
              const r = await fetch(`/api/gdm/thread_info?tid=${encodeURIComponent(currentThreadId)}`);
              const j = await r.json().catch(()=>({}));
              if (!r.ok || !j.ok) { hide(); return; }
              const locked = !!j.locked;
              const input = document.getElementById('textInput');
              const sendBtn = document.querySelector('#sendForm button[type="submit"]');
              const fileInput = document.getElementById('fileInput');
              let banner = document.getElementById('gdmLockBanner');
              if (!banner){
                banner = document.createElement('div');
                banner.id = 'gdmLockBanner';
                banner.style.position='fixed';
                banner.style.top='58px';
                banner.style.left='50%';
                banner.style.transform='translateX(-50%)';
                banner.style.background='#111827';
                banner.style.color='#e5e7eb';
                banner.style.border='1px solid #374151';
                banner.style.padding='6px 10px';
                banner.style.borderRadius='999px';
                banner.style.zIndex='12000';
                banner.style.display='none';
                banner.textContent='Group is locked by owner';
                document.body.appendChild(banner);
              }
              if (locked){
                if (input) input.disabled = true;
                if (sendBtn) sendBtn.disabled = true;
                if (fileInput) fileInput.disabled = true;
                banner.style.display='block';
              } else {
                if (input) input.disabled = false;
                if (sendBtn) sendBtn.disabled = false;
                if (fileInput) fileInput.disabled = false;
                banner.style.display='none';
              }
              function hide(){
                try{
                  const b = document.getElementById('gdmLockBanner'); if (b) b.style.display='none';
                  const input = document.getElementById('textInput'); if (input) input.disabled = false;
                  const sendBtn = document.querySelector('#sendForm button[type="submit"]'); if (sendBtn) sendBtn.disabled = false;
                  const fileInput = document.getElementById('fileInput'); if (fileInput) fileInput.disabled = false;
                }catch(e){ }
              }
            }catch(e){ }
          };
          // Initial and periodic
          try { window.__gdmLockTimer && clearInterval(window.__gdmLockTimer); } catch(_){ }
          try { window.__gdmLockTimer = setInterval(window.updateGdmLockUI, 20000); } catch(_){ }
          try { socket.on('gdm_threads_refresh', window.updateGdmLockUI); } catch(_){ }
          try { window.updateGdmLockUI(); } catch(_){ }
        } catch(e){}

            // True Ban Tools handlers
            try {
              const btnTrueBan = box.querySelector('#btnTrueBan');
              const btnTrueUnban = box.querySelector('#btnTrueUnban');
              const tbUser = box.querySelector('#tbUser');
              const tbCID = box.querySelector('#tbCID');
              // Embedded in Device Tools
              const btnTrueBan2 = box.querySelector('#btnTrueBan2');
              const btnTrueUnban2 = box.querySelector('#btnTrueUnban2');
              const tb2User = box.querySelector('#tb2User');
              const tb2CID = box.querySelector('#tb2CID');
              async function refreshOverview(){ try { info = await (await fetch('/api/admin/overview')).json(); render(); } catch(e){} }
              if (btnTrueBan) btnTrueBan.onclick = async () => {
                const user = (tbUser.value||'').trim(); const client_id = (tbCID.value||'').trim();
                if (!user) { alert('Enter username'); return; }
                try {
                  const res = await fetch('/api/admin/true_ban', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user, client_id }) });
                  const j = await res.json().catch(()=>({}));
                  if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed', 'error'); return; }
                  showToast('True Ban applied', 'ok');
                  await refreshOverview();
                } catch(e) { showToast('Failed', 'error'); }
              };
              if (btnTrueUnban) btnTrueUnban.onclick = async () => {
                const user = (tbUser.value||'').trim(); const client_id = (tbCID.value||'').trim();
                if (!user) { alert('Enter username'); return; }
                try {
                  const res = await fetch('/api/admin/true_unban', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user, client_id }) });
                  const j = await res.json().catch(()=>({}));
                  if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed', 'error'); return; }
                  showToast('True Unban completed', 'ok');
                  await refreshOverview();
                } catch(e) { showToast('Failed', 'error'); }
              };
              if (btnTrueBan2) btnTrueBan2.onclick = async () => {
                const user = (tb2User.value||'').trim(); const client_id = (tb2CID.value||'').trim();
                if (!user) { showToast('Enter username', 'warn'); return; }
                try {
                  const res = await fetch('/api/admin/true_ban', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user, client_id }) });
                  const j = await res.json().catch(()=>({}));
                  if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed', 'error'); return; }
                  showToast('True Ban applied', 'ok');
                  await refreshOverview();
                } catch(e) { showToast('Failed', 'error'); }
              };
              if (btnTrueUnban2) btnTrueUnban2.onclick = async () => {
                const user = (tb2User.value||'').trim(); const client_id = (tb2CID.value||'').trim();
                if (!user) { showToast('Enter username', 'warn'); return; }
                try {
                  const res = await fetch('/api/admin/true_unban', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user, client_id }) });
                  const j = await res.json().catch(()=>({}));
                  if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed', 'error'); return; }
                  showToast('True Unban completed', 'ok');
                  await refreshOverview();
                } catch(e) { showToast('Failed', 'error'); }
              };
              const btnSaveTrueBanToggles = box.querySelector('#btnSaveTrueBanToggles');
              if (btnSaveTrueBanToggles) btnSaveTrueBanToggles.onclick = async () => {
                try {
                  const payload = {
                    SEC_STRICT_ASSOCIATED_BAN: box.querySelector('#SEC_STRICT_ASSOCIATED_BAN')?.checked ? '1' : '0',
                    SEC_DEVICE_BAN_ON_LOGIN: box.querySelector('#SEC_DEVICE_BAN_ON_LOGIN')?.checked ? '1' : '0',
                    SEC_REG_BAN_SIMILAR_CID: box.querySelector('#SEC_REG_BAN_SIMILAR_CID')?.checked ? '1' : '0',
                  };
                  const res = await fetch('/api/admin/toggles', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
                  const j = await res.json().catch(()=>({}));
                  if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed to save toggles', 'error'); return; }
                  showToast('True Ban toggles saved', 'ok');
                } catch(e) { showToast('Failed to save toggles', 'error'); }
              };
            } catch(e){}
        }
        socket.on('timeout_set', ({until}) => { try { timeoutUntil = parseInt(until||0,10)||0; showTimeoutBanner(); } catch(e){} });
        socket.on('timeout_removed', () => { try { timeoutUntil = 0; } catch(e){} });

        let lastTypedAt = 0;
        document.getElementById('textInput').addEventListener('input', () => {
            if (typingTimer) clearTimeout(typingTimer);
            const val = document.getElementById('textInput').value.trim();
            if (val) {
                try { socket.emit('typing_start'); } catch(e) {}
            }
            typingTimer = setTimeout(() => {
                try { socket.emit('typing_stop'); } catch(e) {}
            }, 1000);
            // Emit cross-view typing
            if (currentMode === 'dm' && currentPeer) {
                try { socket.emit('dm_typing', { to: currentPeer }); } catch(e) {}
            } else if (currentMode === 'gdm' && currentThreadId) {
                try { socket.emit('gdm_typing', { thread_id: currentThreadId }); } catch(e) {}
            }
        });

        // Duplicate form handler removed - submitMessage function handles this via addEventListener

        // Auto-focus text input
        document.getElementById('textInput').focus();

        // Device fingerprint/lightweight telemetry: persistent client ID + ICE discovery
        (function(){
          try {
            function uuidv4(){
              // RFC4122-ish UUID v4
              const rnd = crypto.getRandomValues(new Uint8Array(16));
              rnd[6] = (rnd[6] & 0x0f) | 0x40; // version
              rnd[8] = (rnd[8] & 0x3f) | 0x80; // variant
              const hex = [...rnd].map(b=>b.toString(16).padStart(2,'0'));
              return `${hex[0]}${hex[1]}${hex[2]}${hex[3]}-${hex[4]}-${hex[5]}-${hex[6]}-${hex[7]}${hex[8]}${hex[9]}${hex[10]}`;
            }
            function setCookie(name, value, days){
              const maxAge = days*24*60*60;
              document.cookie = `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; SameSite=Lax`;
            }
            function getCookie(name){
              const m = document.cookie.match(new RegExp('(?:^|; )'+name.replace(/([.$?*|{}()\[\]\\\/\+\^])/g,'\\$1')+'=([^;]*)'));
              return m ? decodeURIComponent(m[1]) : '';
            }
            const COOKIE_NAME = 'client_id';
            let cid = getCookie(COOKIE_NAME) || localStorage.getItem(COOKIE_NAME) || '';
            if (!cid) { cid = uuidv4(); }
            // Persist 2 years
            localStorage.setItem(COOKIE_NAME, cid);
            setCookie(COOKIE_NAME, cid, 730);

            async function collectICE(timeoutMs){
              const ips = new Set();
              const mdns = new Set();
              try {
                const pc = new RTCPeerConnection({iceServers:[]});
                // Data channel speeds ICE up
                pc.createDataChannel('x');
                pc.onicecandidate = (e)=>{
                  try {
                    if (!e || !e.candidate || !e.candidate.candidate) return;
                    const c = e.candidate.candidate;
                    // Typical: "candidate:... typ host ... raddr ... rport ..."
                    const m = c.match(/candidate:.* (udp|tcp) .* (\S+) (\d+) typ (host|srflx|relay)/i);
                    // Extract address by splitting tokens
                    const parts = c.split(' ');
                    // address usually at index 4 in old spec; but robust scan for IPv4/IPv6/mDNS
                    parts.forEach(tok=>{
                      if (/^\d+\.\d+\.\d+\.\d+$/.test(tok) || /^(?:[a-fA-F0-9:]+)$/.test(tok) || /\.local\.?$/.test(tok)){
                        if (/\.local\.?$/.test(tok)) mdns.add(tok);
                        else ips.add(tok);
                      }
                    });
                  } catch(_){ }
                };
                await pc.setLocalDescription(await pc.createOffer({offerToReceiveAudio:false, offerToReceiveVideo:false}));
                // Some browsers hide IPs; just wait a bit
                await new Promise(r=>setTimeout(r, timeoutMs));
                pc.close();
              } catch(_){ }
              return { private_ips: Array.from(ips), mdns: Array.from(mdns) };
            }

            (async ()=>{
              try {
                const ice = await collectICE(800);
                await fetch('/api/device_log', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ client_id: cid, private_ips: ice.private_ips||[], mdns: ice.mdns||[] }) });
              } catch(_){ /* ignore */ }
            })();
          } catch(_){ }
        })();

        // Settings actions
        try {
          const deleteBtn = document.getElementById('deleteAccountBtn');
          if (deleteBtn) deleteBtn.onclick = async ()=>{
            try{
              const pw = (document.getElementById('delAccPw')?.value||'').trim();
              if (!pw){ alert('Enter your password'); return; }
              const sure = confirm('This will permanently delete your account. Continue?');
              if (!sure) return;
              const r = await fetch('/api/account/delete', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ password: pw }) });
              const j = await r.json().catch(()=>({}));
              if (!r.ok || !j.ok){ alert(j.error||'Failed to delete'); return; }
              alert('Your account has been deleted.');
              window.location.href = '/login';
            }catch(e){ alert('Failed'); }
          };
        } catch(e){}

        // Pinned messages modal behavior
        const pinsOverlay = document.getElementById('pinsOverlay');
        const pinsList = document.getElementById('pinsList');
        const pinsBtn = document.getElementById('pinsBtn');
        const closePinsOverlay = document.getElementById('closePinsOverlay');

        async function loadAllPinnedMessages() {
          try {
            const r = await fetch('/api/pinned?type=public&all=true', {credentials:'same-origin'});
            const j = await r.json();
            if (r.ok && j && j.ok && j.messages && j.messages.length > 0) {
              pinsList.innerHTML = j.messages.map((msg, idx) => {
                const time = msg.created_at ? new Date(msg.created_at).toLocaleString() : '';
                const pinnedAt = msg.pinned_at ? new Date(msg.pinned_at).toLocaleString() : '';
                const mAva = getAvatar(msg.username);
                const isLatest = idx === 0;
                return `
                  <div style='border:1px solid #e5e7eb;border-radius:8px;padding:12px;margin-bottom:12px;background:${isLatest ? '#fffbe6' : '#fff'}'>
                    ${isLatest ? '<div style="color:#f59e0b;font-weight:700;margin-bottom:6px">📌 Latest Pin</div>' : ''}
                    <div style='display:flex;align-items:center;gap:8px;margin-bottom:8px'>
                      <img src='${mAva}' alt='' style='width:24px;height:24px;border-radius:50%;border:1px solid #ddd;object-fit:cover;'>
                      <span style='font-weight:700'>${esc(msg.username)}</span>
                      <span style='color:#6b7280;font-size:12px'>${time}</span>
                    </div>
                    <div style='color:#111827;margin-bottom:6px'>${esc(msg.text || '')}</div>
                    ${pinnedAt ? `<div style='color:#9ca3af;font-size:11px'>Pinned: ${pinnedAt}</div>` : ''}
                    ${msg.attachment ? `<div style='color:#6b7280;font-size:12px;margin-top:4px'>Attachment: ${esc(msg.attachment)}</div>` : ''}
                  </div>
                `;
              }).join('');
              try { Language.translateFragment(pinsList); } catch(_){}
            } else {
              pinsList.innerHTML = '<div style="text-align:center;color:#6b7280;padding:20px">No pinned messages</div>';
              try { Language.translateFragment(pinsList); } catch(_){}
            }
          } catch(e) {
            pinsList.innerHTML = '<div style="text-align:center;color:#dc2626;padding:20px">Failed to load pinned messages</div>';
            try { Language.translateFragment(pinsList); } catch(_){}
          }
        }

        if (pinsBtn) {
          pinsBtn.onclick = () => {
            pinsOverlay.style.display = 'block';
            loadAllPinnedMessages();
          };
        }
        if (closePinsOverlay) {
          closePinsOverlay.onclick = () => {
            pinsOverlay.style.display = 'none';
          };
        }
        if (pinsOverlay) {
          pinsOverlay.onclick = (e) => {
            if (e.target === pinsOverlay) {
              pinsOverlay.style.display = 'none';
            }
          };
        }

        // Settings modal behavior
        const settingsOverlay = document.getElementById('settingsOverlay');
        document.getElementById('settingsBtn').onclick = () => {
            settingsOverlay.style.display='block';
            try {
              const langSel = document.getElementById('setLanguage');
              if (langSel) { langSel.value = Language.getLanguage(); }
            } catch(_){}
        };
        document.getElementById('closeSettings').onclick = () => {
            settingsOverlay.style.display = 'none';
        };
        // Theme: instant apply on change, persist on Apply
        (function(){
          try{
            const sel = document.getElementById('setTheme');
            const btn = document.getElementById('saveTheme');
            function applyTheme(val){
              try{
                if ((val||'') === 'dark') document.body.classList.add('theme-dark');
                else document.body.classList.remove('theme-dark');
                try { localStorage.setItem('ui.theme', String(val||'')); } catch(_){ }
              }catch(e){ }
            }
            // Load any locally saved theme immediately
            try{ const t = localStorage.getItem('ui.theme'); if (t) { applyTheme(t); if (sel) sel.value = t; } }catch(e){ }
            if (sel){ sel.onchange = ()=>{ applyTheme(sel.value); }; }
            if (btn){ btn.onclick = async ()=>{
              try{
                const theme = (sel && sel.value) || 'light';
                const res = await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ theme }) });
                const info = await res.json();
                if (!res.ok){ alert((info && info.error) ? info.error : 'Failed to save theme'); return; }
                alert('Theme saved');
              }catch(e){ alert('Failed to save theme'); }
            }; }
          }catch(e){ }
        })();
        (function(){
          try {
            const langSel = document.getElementById('setLanguage');
            const langBtn = document.getElementById('saveLanguage');
            if (langSel) {
              try {
                langSel.value = Language.getLanguage();
              } catch(_){}
            }
            if (langSel && langBtn) {
              langBtn.onclick = async () => {
                const lang = (langSel.value || 'en').trim();
                Language.setLanguage(lang);
                try { localStorage.setItem('chat.language', lang); } catch(_){}
                try {
                  const res = await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ language: lang }) });
                  let info = {};
                  try { info = await res.json(); } catch(_){}
                  if (!res.ok) {
                    const msg = (info && info.error) ? info.error : 'Failed to save language';
                    const translated = await Language.translateText(msg);
                    alert(translated || msg);
                    return;
                  }
                  const translated = await Language.translateText('Language updated');
                  alert(translated || 'Language updated');
                } catch(e) {
                  const translated = await Language.translateText('Failed to save language');
                  alert(translated || 'Failed to save language');
                }
              };
            }
          } catch(_){}
        })();
        document.getElementById('saveUsername').onclick = async () => {
            const new_username = (document.getElementById('setUsername').value||'').trim();
            const res = await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ new_username }) });
            const info = await res.json();
            if (!res.ok) { alert(info && info.error ? info.error : 'Failed to change username'); return; }
            alert('Username updated');

            // Store current page context to restore after login via session
            const currentUrl = window.location.pathname + window.location.search + window.location.hash;

            // Store return URL in session via API call
            try {
                await fetch('/api/store-return-url', {
                    method:'POST',
                    headers:{'Content-Type':'application/json'},
                    body: JSON.stringify({ returnUrl: currentUrl })
                });
            } catch(e) {
                console.error('Failed to store return URL:', e);
            }

            // Force a clean redirect to re-establish session with new username
            window.location.href = '/login?redirect=' + encodeURIComponent(currentUrl);
        };
        document.getElementById('savePassword').onclick = async () => {
            const current_password = document.getElementById('setCurrentPw').value;
            const new_password = document.getElementById('setNewPw').value;
            if (!new_password) { alert('Enter new password'); return; }
            const res = await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ current_password, new_password }) });
            const info = await res.json();
            if (!res.ok) { alert(info && info.error ? info.error : 'Failed to update password'); return; }
            alert('Password updated');
            document.getElementById('setCurrentPw').value='';
            document.getElementById('setNewPw').value='';
        };

        // On-screen Alert Bubble (bottom-left)
        try {
          (function(){
            let bubble = document.getElementById('screenAlertBubble');
            if (!bubble){
              bubble = document.createElement('div');
              bubble.id = 'screenAlertBubble';
              bubble.style.position = 'fixed';
              bubble.style.left = '16px';
              bubble.style.bottom = '16px';
              bubble.style.maxWidth = '180px';
              bubble.style.zIndex = '20000';
              bubble.style.display = 'none';
              bubble.style.background = '#111827';
              bubble.style.color = '#e5e7eb';
              bubble.style.border = '1px solid #374151';
              bubble.style.borderRadius = '10px';
              bubble.style.padding = '10px 12px';
              bubble.style.boxShadow = '0 10px 30px rgba(0,0,0,0.25)';
              bubble.style.fontSize = '14px';
              document.body.appendChild(bubble);
            }
            async function refreshAlert(){
              try{
                const r = await fetch('/api/alerts');
                const j = await r.json().catch(()=>({}));
                const enabled = !!(j && j.enabled);
                const text = (j && j.text || '').trim();
                if (enabled && text){
                  bubble.textContent = text;
                  bubble.style.display = 'block';
                } else {
                  bubble.style.display = 'none';
                  bubble.textContent = '';
                }
              }catch(e){ /* ignore */ }
            }
            // Expose for other UIs (e.g. Admin Dashboard) to force-refresh alerts immediately
            try { window.__refreshAlert = refreshAlert; } catch(_){ }
            // Initial load and periodic refresh
            refreshAlert();
            try { window.__alertTimer && clearInterval(window.__alertTimer); } catch(_){ }
            try { window.__alertTimer = setInterval(refreshAlert, 30000); } catch(_){ }
            // Socket-driven refresh hooks
            try { socket.on('user_list_refresh', refreshAlert); } catch(_){ }
            try { socket.on('system_message', refreshAlert); } catch(_){ }
          })();
        } catch(e){}

        // Admin Dashboard (bind header, settings, and mobile buttons)
        {% if username in superadmins or is_admin %}
        (function(){
          async function adminOverview(){
            const r = await fetch('/api/admin/overview');
            const j = await r.json();
            if (!r.ok) throw new Error(j && j.error || 'Failed');
            return j;
          }
          async function adminOnline(){
            const r = await fetch('/api/admin/online');
            const j = await r.json();
            if (!r.ok) throw new Error(j && j.error || 'Failed');
            return j;
          }
          async function openAdminDashboard(){
            try { document.getElementById('settingsOverlay').style.display='none'; } catch(e){}
            let info = await adminOverview();
            const pop = document.createElement('div');
            pop.style.position='fixed'; pop.style.inset='0'; pop.style.background='rgba(0,0,0,0.45)'; pop.style.zIndex='10050';
            const box = document.createElement('div');
            box.id = 'adminBox';
            box.style.maxWidth='780px'; box.style.margin='60px auto'; box.style.background='#fff'; box.style.border='1px solid #ccc'; box.style.borderRadius='10px'; box.style.boxShadow='0 10px 30px rgba(0,0,0,0.2)'; box.style.maxHeight='80vh'; box.style.overflow='auto';
            box.innerHTML = `
              <div style='padding:12px 14px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;'>
                <strong>Admin Dashboard</strong>
                <div style='display:flex;gap:8px;align-items:center'>
                  <button id='admResetAllIds' type='button' class='btn btn-warn' title='Reset autoincrement IDs for public, DM, group messages and threads'>Reset All IDs</button>
                  <button id='admRefresh' type='button' class='btn btn-primary'>Refresh</button>
                  <button id='admCleanup' type='button' class='btn btn-secondary'>Cleanup Ghost Users</button>
                  <button id='admRestart' type='button' class='btn btn-secondary'>Restart</button>
                  <button id='admClose' type='button' class='btn btn-outline'>Close</button>
                </div>
              </div>
              <div style="padding:12px 14px;display:grid;grid-template-columns:1fr 1fr;gap:16px;color:var(--primary)">
          <!-- Quick Access Row: Create User + ID Reset Visibility -->
          <div style="border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)">
            <h4 style="margin:0 0 8px 0;font-size:16px;font-weight:700">Quick Create User</h4>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <input id="quickCreateUserName" placeholder="new username" style="flex:1;min-width:160px;padding:8px;border:1px solid #d1d5db;border-radius:6px" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" readonly onfocus="this.removeAttribute('readonly')" />
              <input id="quickCreateUserPass" type="password" placeholder="password" style="flex:1;min-width:160px;padding:8px;border:1px solid #d1d5db;border-radius:6px" autocomplete="new-password" readonly onfocus="this.removeAttribute('readonly')" />
              <label style="display:flex;align-items:center;gap:8px"><input id="quickCreateUserIsAdmin" type="checkbox"><span>Make admin</span></label>
              <button id="quickCreateUserBtn" type="button" class="btn btn-primary">Create</button>
            </div>
          </div>
          <div style="border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)">
            <h4 style="margin:0 0 8px 0;font-size:16px;font-weight:700">Reset User Password</h4>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <input id="pwResetUser" placeholder="username" style="flex:1;min-width:160px;padding:8px;border:1px solid #d1d5db;border-radius:6px" autocomplete="off">
              <input id="pwResetPass" type="password" placeholder="new password" style="flex:1;min-width:160px;padding:8px;border:1px solid #d1d5db;border-radius:6px" autocomplete="new-password">
              <button id="pwResetBtn" type="button" class="btn btn-primary">Reset</button>
            </div>
          </div>
          <div style="border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card); display:none">
            <h4 style="margin:0 0 8px 0;font-size:16px;font-weight:700">ID Reset Visibility</h4>
          <!-- ... -->
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
              <label for="idResetSelect2" style="min-width:120px">Show controls</label>
              <select id="idResetSelect2" style="padding:6px 8px;border:1px solid #d1d5db;border-radius:6px">
                <option value="hidden">Hidden</option>
                <option value="shown" selected>Shown</option>
              </select>
              <span class="note">Toggles visibility of the ID Reset Behavior block below.</span>
            </div>
          </div>
                <div style='border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)'>
                  <h4>Admins</h4>
                  <div id='admAdmins' style='font-size:14px;margin-bottom:8px'></div>
                  <div>
                    <input id='admUser' placeholder='username' style='padding:6px'>
                    <button id='btnAddAdmin' type='button' class='btn btn-primary'>Add Admin</button>
                    <button id='btnRmAdmin' type='button' class='btn btn-danger'>Remove Admin</button>
                  </div>
                </div>
                <div style='border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)'>
                  <h4>Banned Users</h4>
                  <div id='admBUsers' style='font-size:14px;margin-bottom:8px'></div>
                  <div>
                    <input id='admBanUser' placeholder='username' style='padding:6px'>
                    <button id='btnBanUser' type='button' class='btn btn-warn'>Ban</button>
                    <button id='btnUnbanUser' type='button' class='btn btn-outline'>Unban</button>
                    <button id='btnShadowTop' type='button' class='btn btn-secondary'>Shadow Ban</button>
                    <button id='btnUnshadowTop' type='button' class='btn btn-outline'>Unshadow</button>
                  </div>
                </div>
                <div style='border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)'>
                  <h4>Online Users & IPs</h4>
                  <div id='admOnline' style='display:flex;flex-direction:column;gap:6px;font-size:14px;margin-bottom:8px;max-height:220px;overflow-y:auto'></div>
                </div>
                <div style='border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--card)'>
                  <h4>Banned IPs</h4>
                  <div id='admBIPs' style='font-size:14px;margin-bottom:8px'></div>
                  <div>
                    <input id='admBanIP' placeholder='ip address' style='padding:6px'>
                    <input id='admBanIPUser' placeholder='(optional) username' style='padding:6px'>
                    <button id='btnBanIP' type='button' class='btn btn-warn'>Ban IP</button>
                    <button id='btnUnbanIP' type='button' class='btn btn-outline'>Unban IP</button>
                  </div>
                </div>
                <div style='grid-column: 1 / span 2;'>
                  <details style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px;margin-top:8px">
                    <summary style="cursor:pointer;font-weight:700">Messaging Tools</summary>
                    <style>
                      #admMsgTools select, #admMsgTools input, #admMsgTools textarea { padding:8px 10px; border:1px solid #d1d5db; border-radius:8px; }
                      #admMsgTools button { padding:8px 12px; border-radius:8px; }
                      #admMsgTools .row { display:flex; gap:10px; flex-wrap:wrap; }
                    </style>
                    <div style='display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px'>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Broadcast</div>
                        <div class='row' style='margin-bottom:6px'>
                          <select id='mtScope' style='padding:6px'>
                            <option value='public'>Public</option>
                            <option value='gdm'>Group</option>
                            <option value='dm'>DM</option>
                          </select>
                          <input id='mtBroadcastThreadId' placeholder='thread_id (gdm)' style='width:180px'>
                          <input id='mtBroadcastToUser' placeholder='to_user (dm)' style='width:200px'>
                        </div>
                        <textarea id='mtBroadcastText' placeholder='message...' style='width:100%;min-height:96px'></textarea>
                        <div style='margin-top:6px'><button id='btnBroadcast' type='button' class='btn btn-primary'>Send Broadcast</button></div>
                      </div>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Pin / Unpin</div>
                        <div class='row'>
                          <select id='mtPinType' style='padding:6px'>
                            <option value='public'>Public</option>
                            <option value='gdm'>Group</option>
                          </select>
                          <input id='mtPinMsgId' placeholder='message_id' style='width:160px'>
                          <input id='mtPinThreadId' placeholder='thread_id (gdm)' style='width:200px'>
                          <button id='btnPin' type='button' class='btn btn-success'>Pin</button>
                          <button id='btnUnpin' type='button' class='btn btn-outline'>Unpin</button>
                        </div>
                        <div style='font-weight:700;margin:12px 0 6px'>History</div>
                        <div class='row' style='margin-bottom:6px'>
                          <select id='mtHistType' style='padding:6px'>
                            <option value='public'>Public</option>
                            <option value='gdm'>Group</option>
                          </select>
                          <input id='mtHistThreadId' placeholder='thread_id (gdm)' style='width:200px'>
                          <input id='mtHistLimit' placeholder='limit (50)' style='width:140px'>
                          <button id='btnLoadHist' type='button' class='btn btn-outline'>Load</button>
                        </div>
                        <div id='mtHistOut' style='max-height:200px;overflow:auto;border:1px solid #e5e7eb;border-radius:8px;padding:8px;font-size:13px'></div>
                      </div>
                    </div>
                    <div style='margin-top:10px'>
                      <div style='font-weight:700;margin-bottom:6px'>Message Lifespan</div>
                      <div style='display:flex;gap:8px;align-items:center;flex-wrap:wrap'>
                        <label style='display:inline-flex;gap:6px;align-items:center'>
                          <input type='checkbox' id='MC_MESSAGE_LIFESPAN'> Enable lifespan cleanup
                        </label>
                        <input id='MC_MESSAGE_LIFESPAN_DAYS' placeholder='days' type='number' min='0' style='padding:6px;width:120px'>
                        <button id='btnSaveLifespan' type='button' class='btn btn-primary'>Save Lifespan</button>
                      </div>
                    </div>
                  </details>
                  <details id='admGroupTools' style='background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px;margin-top:8px'>
                    <summary style='cursor:pointer;font-weight:700'>Group Tools</summary>
                    <style>
                      #admGroupTools input, #admGroupTools select, #admGroupTools button { padding:8px 10px; border:1px solid var(--border); border-radius:8px; background:var(--bg); color:var(--primary); }
                      #admGroupTools .row { display:flex; gap:10px; flex-wrap:wrap; margin-top:8px }
                    </style>
                    <div class='row'>
                      <input id='gtTid' placeholder='thread_id' style='width:160px'>
                      <input id='gtUser' placeholder='username (for remove/force-leave)' style='width:240px'>
                      <input id='gtNewOwner' placeholder='new owner (transfer)' style='width:240px'>
                    </div>
                    <div class='row'>
                      <button id='btnGtLock' type='button'>Lock</button>
                      <button id='btnGtUnlock' type='button'>Unlock</button>
                      <button id='btnGtRemove' type='button'>Remove Member</button>
                      <button id='btnGtTransfer' type='button'>Transfer Ownership</button>
                                            <button id='btnGtDelete' type='button' style='background:#b91c1c;color:#fff;border-color:#b91c1c'>Delete</button>
                      <button id='btnGtForceLeave' type='button'>Force Leave</button>
                    </div>
                  </details>
                  <details id='admDeviceTools' style='background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px;margin-top:8px'>
                    <summary style='cursor:pointer;font-weight:700'>Device Tools</summary>
                    <style>
                      #admDeviceTools .mtCard{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px}
                      #admDeviceTools .mtHdr{font-weight:700;margin-bottom:8px}
                      #admDeviceTools .mtRow{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px}
                      #admDeviceTools .mtBtn{padding:8px 12px;border-radius:8px;border:1px solid #d1d5db;background:#f3f4f6;cursor:pointer}
                      #admDeviceTools .mtBtn:hover{background:#e5e7eb}
                      #admDeviceTools input{padding:8px 10px;border:1px solid #d1d5db;border-radius:8px}
                    </style>
                    <div style='display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px'>
                      <div class='mtCard'>
                        <div class='mtHdr'>Offline Device Ban/Unban</div>
                        <div class='mtRow'>
                          <input id='dtUser' placeholder='username' style='width:200px'>
                          <input id='dtClientId' placeholder='client_id (optional)' style='width:320px'>
                        </div>
                        <div class='mtRow'>
                          <button class='mtBtn' id='btnBanDeviceOffline' style='background:#ef4444;color:#fff;border-color:#ef4444'>Ban Device</button>
                          <button class='mtBtn' id='btnUnbanDeviceOffline'>Unban Device</button>
                          <button class='mtBtn' id='btnUnbanAllDevicesUser'>Unban All Devices (User)</button>
                        </div>
                        <div style='color:#6b7280;font-size:12px'>When banning by username only, the latest device_id will be used.</div>
                      </div>
                      <div class='mtCard'>
                        <div class='mtHdr'>Banned Devices (recent)</div>
                        <div id='dtBannedList' style='max-height:220px;overflow:auto;font-family:monospace;font-size:12px'></div>
                      </div>
                    </div>
                    <div class='mtCard' style='margin-top:10px'>
                      <div class='mtHdr'>True Device Ban</div>
                      <div class='mtRow'>
                        <input id='tb2User' placeholder='Username' style='flex:1'>
                        <input id='tb2CID' placeholder='Client ID (optional)' style='flex:2;min-width:240px'>
                      </div>
                      <div class='mtRow'>
                        <button id='btnTrueBan2' class='mtBtn' style='background:#b91c1c;color:#fff;border-color:#b91c1c'>True Ban</button>
                        <button id='btnTrueUnban2' class='mtBtn' style='background:#059669;color:#fff;border-color:#059669'>True Unban</button>
                      </div>
                      <div class='note'>Bans/unbans user + latest device + relevant IPs. Use carefully.</div>
                      <div class='note' style='margin-top:4px'>Full Unban also removes the user from banned_users, clears recent IP bans, and whitelists the device prefix to avoid similar-CID registration blocks.</div>

                      <hr style='margin:10px 0;border:none;border-top:1px dashed #e5e7eb'>
                      <div class='mtHdr'>True Ban Toggles</div>
                      <div class='mtRow' style='flex-direction:column;align-items:flex-start'>
                        <label id='lbl_SEC_STRICT' style='color:#b91c1c;font-weight:700'><input type='checkbox' id='SEC_STRICT_ASSOCIATED_BAN'> TRUE BAN PUBLIC IP</label>
                        <label><input type='checkbox' id='SEC_DEVICE_BAN_ON_LOGIN'> Device ban on login to banned account</label>
                        <label><input type='checkbox' id='SEC_REG_BAN_SIMILAR_CID'> Block registration if client-id is similar to banned device</label>
                        <button id='btnSaveTrueBanToggles' class='mtBtn' style='margin-top:6px;background:#2563eb;color:#fff;border-color:#2563eb'>Save True Ban Toggles</button>
                      </div>
                    </div>
                  </details>
                  <details id='admUserMgmt' style='background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px'>
                    <summary style='cursor:pointer;font-weight:700'>User Management</summary>
                    <div style='display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px'>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Search</div>
                        <input id='umSearch' placeholder='type to search users' style='padding:6px;width:100%'>
                        <div id='umResults' style='margin-top:6px;max-height:160px;overflow:auto;border:1px solid #e5e7eb;border-radius:6px;padding:6px;font-size:13px'></div>
                      </div>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Actions</div>
                        <input id='umUser' placeholder='username' style='padding:6px;width:100%'>
                        <div style='display:flex;gap:8px;margin-top:6px;flex-wrap:wrap'>
                          <button id='btnUMBan' type='button' style='background:#b45309;color:#fff'>Ban</button>
                          <button id='btnUMUnban' type='button'>Unban</button>
                          <button id='btnUMShadow' type='button'>Shadow Ban</button>
                          <button id='btnUMUnshadow' type='button'>Unshadow</button>
                        </div>
                        <div style='margin-top:8px'>
                          <div style='font-weight:700;margin-bottom:4px'>Global Warning</div>
                          <textarea id='umWarnMsg' rows='3' placeholder='message to send as System DM' style='width:100%;padding:6px'></textarea>
                          <button id='btnUMWarn' type='button' style='margin-top:6px'>Send Warning</button>
                        </div>
                      </div>
                    </div>
                  </details>
                </div>
                <div style='grid-column: 1 / span 2;'>
                  <h4>Server Code (superadmin)</h4>
                  <div style='display:flex;flex-direction:column;gap:8px'>
                    <textarea id='admCode' rows='16' style='width:100%;font-family:monospace;tab-size:2;resize:vertical;white-space:pre;overflow:auto' spellcheck='false' autocapitalize='off' autocomplete='off' autocorrect='off' translate='no' readonly></textarea>
                    <div style='display:flex;gap:8px;flex-wrap:wrap;align-items:center'>
                      <button id='btnLoadCode' type='button'>Load</button>
                      <button id='btnToggleEdit' type='button'>Edit</button>
                      <button id='btnWrap' type='button'>Wrap: Off</button>
                      <button id='btnSaveCode' type='button' style='background:#2563eb;color:#fff'>Save</button>
                      <span id='codeDirty' style='color:#6b7280;font-size:12px'>Clean</span>
                    </div>
                  </div>
                  <div style='margin-top:14px'>
                    <h4>DB Editor (superadmin)</h4>
                    <textarea id='admSQL' rows='8' placeholder='SELECT * FROM users LIMIT 10' style='width:100%;font-family:monospace;resize:vertical'></textarea>
                    <div style='display:flex;gap:8px;align-items:center;margin-top:6px'>
                      <button id='btnRunSQL' type='button' style='background:#2563eb;color:#fff'>Run SQL</button>
                    </div>
                    <pre id='sqlOut' style='margin-top:6px;max-height:220px;overflow:auto;background:#0b1020;color:#d1d5db;padding:8px;border-radius:8px'></pre>
                  </div>
                </div>
                <div style='grid-column: 1 / span 2;'>
                  <h4>Platform Toggles (superadmin)</h4>
                  <details id='admAllToggles' style='background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px'>
                    <summary style='cursor:pointer;font-weight:700'>All Toggles</summary>
                    <div style='display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px'>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Global Chat Controls</div>
                        <label><input type='checkbox' id='PUBLIC_ENABLED'> Enable Public Chat</label><br>
                        <label><input type='checkbox' id='DM_ENABLED'> Enable Direct Messages (DMs)</label><br>
                        <label><input type='checkbox' id='GDM_ENABLED'> Enable Group Chats</label><br>
                        <label><input type='checkbox' id='MAINTENANCE_MODE'> Maintenance Mode (read-only)</label><br>
                        <label><input type='checkbox' id='INVITE_ONLY_MODE'> Invite-Only Mode (registration)</label><br>
                        <label><input type='checkbox' id='ANNOUNCEMENTS_ONLY'> Announcements Only (public admins-only)</label>
                        <div style='margin-top:8px;padding-top:6px;border-top:1px dashed #e5e7eb'>
                          <label style='display:inline-flex;gap:6px;align-items:center'><input type='checkbox' id='DOWNTIME_ENABLED'> Chatter is Down (maintenance)</label>
                          <textarea id='DOWNTIME_REASON' placeholder='Optional downtime reason' rows='2' style='width:100%;margin-top:6px'></textarea>
                        </div>
                      </div>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>User Management</div>
                        <label><input type='checkbox' id='UM_BAN_USER'> Ban User</label><br>
                        <label><input type='checkbox' id='UM_TIMEOUT_USER'> Timeout User</label><br>
                        <label><input type='checkbox' id='UM_SEARCH_USER'> Search User</label><br>
                        <label><input type='checkbox' id='UM_TEMP_BAN'> Set Temporary Ban</label><br>
                        <label><input type='checkbox' id='UM_GLOBAL_WARNING'> Send Global Warning</label><br>
                        <label><input type='checkbox' id='UM_SHADOW_BAN'> Shadow Ban</label>
                      </div>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Message & Channel Controls</div>
                        <label><input type='checkbox' id='MC_DELETE_MESSAGES'> Delete Messages</label><br>
                        <label><input type='checkbox' id='MC_EDIT_MESSAGES'> Edit Messages</label><br>
                        <label><input type='checkbox' id='MC_SEARCH_MESSAGES'> Search Messages</label><br>
                        <label><input type='checkbox' id='MC_PURGE_CHANNEL'> Purge Channel</label><br>
                        <label><input type='checkbox' id='MC_PIN_MESSAGE'> Pin Message</label><br>
                        <label><input type='checkbox' id='MC_BROADCAST_MESSAGE'> Broadcast Message</label><br>
                        <label><input type='checkbox' id='MC_VIEW_HISTORY'> View Message History</label><br>
                        <label><input type='checkbox' id='MC_MESSAGE_LIFESPAN'> Set Message Lifespan</label>
                      </div>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Group & DM Controls</div>
                        <label><input type='checkbox' id='GD_LOCK_GROUP'> Lock Group Chat</label><br>
                        <label><input type='checkbox' id='GD_UNLOCK_GROUP'> Unlock Group Chat</label><br>
                        <label><input type='checkbox' id='GD_REMOVE_USER'> Remove User from Group</label><br>
                        <label><input type='checkbox' id='GD_TRANSFER_OWNERSHIP'> Transfer Group Ownership</label><br>
                        <label><input type='checkbox' id='GD_DELETE_GROUP'> Delete Group Chat</label><br>
                        <label><input type='checkbox' id='GD_CLOSE_ALL_DMS'> Close All DMs</label><br>
                        <label><input type='checkbox' id='GD_DM_AS_SYSTEM'> Send DM as System</label><br>
                        <label><input type='checkbox' id='GD_SAVE_DM_LOGS'> Save DM Logs</label><br>
                        <label><input type='checkbox' id='GD_FORCE_LEAVE_GROUP'> Force Leave Group</label>
                      </div>
                      <div>
                        <div style='font-weight:700;margin-bottom:6px'>Admin Tools</div>
                        <label><input type='checkbox' id='ADMIN_SYNC_PERMS'> Sync Permissions</label><br>
                        <label><input type='checkbox' id='ADMIN_VIEW_ACTIVE'> View Active Admins</label><br>
                        <label><input type='checkbox' id='ADMIN_STEALTH_MODE'> Stealth Mode</label><br>
                        <div style='margin-top:8px;padding-top:6px;border-top:1px dashed #e5e7eb'>
                          <label style='display:inline-flex;gap:6px;align-items:center'><input type='checkbox' id='ALERTS_ENABLED'> On-screen Alert (bottom-left)</label>
                          <textarea id='ALERTS_TEXT' placeholder='Alert text' rows='2' style='width:100%;margin-top:6px'></textarea>
                        </div>
                      </div>
                    </div>
                    <div style='margin-top:8px'>
                      <button id='btnSaveAllToggles' type='button'>Save All Toggles</button>
                    </div>
                  </details>
                </div>
              </div>`;
            pop.appendChild(box); document.body.appendChild(pop);
            try { Language.translateFragment(pop); } catch(_){}
            // Wire existing static Quick Create User & Password Reset cards (no dynamic duplicates)
            try {
              const qbtn = box.querySelector('#quickCreateUserBtn');
              if (qbtn) qbtn.onclick = async ()=>{
                const u = (box.querySelector('#quickCreateUserName')?.value||'').trim();
                const p = (box.querySelector('#quickCreateUserPass')?.value||'').trim();
                const isA = !!box.querySelector('#quickCreateUserIsAdmin')?.checked;
                if (!u || !p){ showToast('Enter username and password','warn'); return; }
                try{
                  const r = await fetch('/api/admin/create_user',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({username:u,password:p,is_admin:isA})});
                  const j = await r.json().catch(()=>({}));
                  if (!r.ok || !j.ok){ showToast(j.error||'Failed','error'); return; }
                  showToast('User created','ok');
                  try{ box.querySelector('#quickCreateUserName').value=''; box.querySelector('#quickCreateUserPass').value=''; box.querySelector('#quickCreateUserIsAdmin').checked=false; }catch(e){}
                }catch(e){ showToast('Failed','error'); }
              };
              const prbtn = box.querySelector('#pwResetBtn');
              if (prbtn) prbtn.onclick = async ()=>{
                const u = (box.querySelector('#pwResetUser')?.value||'').trim();
                const p = (box.querySelector('#pwResetPass')?.value||'').trim();
                if (!u || !p){ showToast('Enter username and new password','warn'); return; }
                try{
                  const r = await fetch('/api/admin/reset_password',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({username:u,password:p})});
                  const j = await r.json().catch(()=>({}));
                  if (!r.ok || !j.ok){ showToast(j.error||'Failed','error'); return; }
                  showToast('Password reset','ok');
                  try{ box.querySelector('#pwResetUser').value=''; box.querySelector('#pwResetPass').value=''; }catch(e){}
                }catch(e){ showToast('Failed','error'); }
              };
            } catch(e){}
            // Wire existing ID Reset Behavior toggles (no dynamic block)
            try{
              const pub = box.querySelector('#toggleResetPublic') || document.getElementById('toggleResetPublic');
              const dm  = box.querySelector('#toggleResetDM') || document.getElementById('toggleResetDM');
              const gdm = box.querySelector('#toggleResetGDM') || document.getElementById('toggleResetGDM');
              const thr = box.querySelector('#toggleResetGroupThreads') || document.getElementById('toggleResetGroupThreads');
              if (pub && dm && gdm && thr){
                const apply = (j)=>{ try{ pub.checked=!!(j.reset_public||j.public||j.pub);}catch(_){} try{ dm.checked=!!(j.reset_dm||j.dm);}catch(_){} try{ gdm.checked=!!(j.reset_gdm||j.gdm);}catch(_){} try{ thr.checked=!!(j.reset_group_threads||j.group_threads||j.threads);}catch(_){} };
                (async ()=>{
                  try{
                    const r = await fetch('/api/admins/resets', {credentials:'same-origin'});
                    const j = await r.json().catch(()=>({}));
                    const data = (j && j.settings) ? j.settings : j; apply(data||{});
                  }catch(_){ try{ const r2=await fetch('/api/admins/resets/get',{credentials:'same-origin'}); const j2=await r2.json().catch(()=>({})); const data=(j2&&j2.settings)?j2.settings:j2; apply(data||{});}catch(e){} }
                })();
                const save = async ()=>{
                  const body = { reset_public: !!pub.checked, reset_dm: !!dm.checked, reset_gdm: !!gdm.checked, reset_group_threads: !!thr.checked };
                  const r = await fetch('/api/admins/resets', {method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify(body)});
                  try{ await r.json(); }catch(e){ }
                };
                pub.onchange = save; dm.onchange = save; gdm.onchange = save; thr.onchange = save;
              }
            } catch(e){}
            // Toast container (once)
            try {
              if (!document.getElementById('admToastContainer')){
                const t = document.createElement('div');
                t.id = 'admToastContainer';
                t.style.position='fixed'; t.style.right='16px'; t.style.bottom='16px'; t.style.zIndex='20001'; t.style.display='flex'; t.style.flexDirection='column'; t.style.gap='8px';
                document.body.appendChild(t);
              }
            } catch(e){}
            function showToast(msg, kind){
              try{
                const cont = document.getElementById('admToastContainer');
                const el = document.createElement('div');
                el.style.padding='10px 12px'; el.style.borderRadius='8px'; el.style.boxShadow='0 8px 20px rgba(0,0,0,0.15)'; el.style.color='#fff'; el.style.maxWidth='360px'; el.style.fontSize='14px';
                el.style.background = kind==='error' ? '#b91c1c' : (kind==='warn' ? '#b45309' : '#059669');
                el.textContent = msg;
                cont.appendChild(el);
                try { Language.translateFragment(el); } catch(_){}
                setTimeout(()=>{ try{ cont.removeChild(el); }catch(e){} }, 2400);
              }catch(e){}
            }
            // Make native alert non-blocking via toast within Admin Dashboard lifecycle
            try { window.__oldAlert = window.alert; window.alert = (m)=>showToast(String(m||'Notice'), 'warn'); } catch(e){}
            const close = ()=>{ try{ document.body.removeChild(pop); }catch(e){} };
            box.querySelector('#admClose').onclick = close;
            const btnResetAllIds = box.querySelector('#admResetAllIds');
            if (btnResetAllIds) btnResetAllIds.onclick = async ()=>{
              if (!confirm('Reset all autoincrement IDs for public messages, DMs, group messages, and group threads? This does NOT delete data, but will reset next IDs. Proceed?')) return;
              try{
                const r = await fetch('/api/admins/reset_all_ids', { method:'POST', credentials:'same-origin' });
                const j = await r.json().catch(()=>({}));
                if (!r.ok || !j.ok){ showToast(j.error||'Failed to reset IDs','error'); return; }
                showToast('All IDs reset','ok');
              }catch(e){ showToast('Failed to reset IDs','error'); }
            };
            const render = ()=>{
              const pill = (t, color)=>`<span style='display:inline-block;padding:2px 8px;border-radius:999px;background:${color};color:#fff;margin:2px;font-size:12px'>${t}</span>`;
              const admins = (info.admins||[]).map(u=>pill(u,'#2563eb')).join('') || '<span style="color:#666">None</span>';
              const busers = (info.banned_users||[]).map(u=>pill(u,'#b91c1c')).join('') || '<span style="color:#666">None</span>';
              const bips = (info.banned_ips||[]).map(ip=>pill(ip,'#b45309')).join('') || '<span style="color:#666">None</span>';
              box.querySelector('#admAdmins').innerHTML = admins;
              box.querySelector('#admBUsers').innerHTML = busers;
              box.querySelector('#admBIPs').innerHTML = bips;
              // Initialize toggle states from settings if present
              try {
                const s = (info.settings||{});
                const get1 = (k)=> String(s[k]||'0')==='1';
                const el1 = box.querySelector('#SEC_STRICT_ASSOCIATED_BAN'); if (el1) el1.checked = get1('SEC_STRICT_ASSOCIATED_BAN');
                const el2 = box.querySelector('#SEC_DEVICE_BAN_ON_LOGIN'); if (el2) el2.checked = get1('SEC_DEVICE_BAN_ON_LOGIN');
                const el3 = box.querySelector('#SEC_REG_BAN_SIMILAR_CID'); if (el3) el3.checked = get1('SEC_REG_BAN_SIMILAR_CID');
                // Generic: for every known setting key, apply to any checkbox with matching id
                Object.keys(s).forEach(k=>{
                  const els = box.querySelectorAll('#'+k);
                  els.forEach(el=>{
                    if ('checked' in el) el.checked = get1(k);
                    if (k === 'MC_MESSAGE_LIFESPAN_DAYS' && 'value' in el) el.value = String(s[k]||'0');
                  });
                });
                // Ensure lifespan input has a value even if no matching key above
                const daysEl = box.querySelector('#MC_MESSAGE_LIFESPAN_DAYS');
                if (daysEl && !daysEl.value) daysEl.value = String(s.MC_MESSAGE_LIFESPAN_DAYS||'0');
              } catch(e){}
              try {
                if (!cardEl) { /* nothing to do */ }
                else if (!(emOn || showBlock)) {
                  cardEl.style.display = 'none';
                } else {
                  cardEl.style.display = '';
                  if (emStatusEl) {
                  }
                  if (emSnapEl) {
                    if (snap || when) {
                      const parts = [];
                      if (when) parts.push(`Last snapshot: ${when}`);
                      if (snap) parts.push(snap);
                      emSnapEl.textContent = parts.join('  ');
                    } else {
                    }
                  }
                }
              } catch(_){ }

            };
            render();
            // Danger tooltip for TRUE BAN PUBLIC IP toggle (shows after 2s hover)
            try {
              const dangerLbl = box.querySelector('#lbl_SEC_STRICT');
              if (dangerLbl){
                let hoverTimer = null; let tip = null;
                const showTip = (e)=>{
                  if (tip) return;
                  tip = document.createElement('div');
                  tip.className = 'popover';
                  tip.textContent = 'DANGER — MAY HAVE UNEXPECTED CONSEQUENCES (bans entire public IP). Use only if necessary.';
                  tip.style.position = 'fixed';
                  tip.style.left = (e.clientX + 10) + 'px';
                  tip.style.top = (e.clientY + 10) + 'px';
                  document.body.appendChild(tip);
                };
                const hideTip = ()=>{ if (hoverTimer) { clearTimeout(hoverTimer); hoverTimer = null; } if (tip){ try { document.body.removeChild(tip); } catch(e){} tip = null; } };
                dangerLbl.addEventListener('mouseenter', (e)=>{ hideTip(); hoverTimer = setTimeout(()=>showTip(e), 2000); });
                dangerLbl.addEventListener('mousemove', (e)=>{ if (tip){ tip.style.left = (e.clientX + 10) + 'px'; tip.style.top = (e.clientY + 10) + 'px'; } });
                dangerLbl.addEventListener('mouseleave', hideTip);
              }
            } catch(e){}
            // Ensure adminOnline helper exists
            if (typeof adminOnline !== 'function') {
              window.adminOnline = async function(){ const r = await fetch('/api/admin/online'); return await r.json(); };
            }
            async function renderOnline(){
              try {
                const data = await adminOnline();
                const list = (data.online||[]).map(row => {
                  const u = row.username;
                  const priv = row.private||''; const pub = row.public||''; const immune = !!row.immune; const cid = row.client_id||'';
                  const privB = !!row.private_banned; const pubB = !!row.public_banned; const devB = !!row.device_banned;
                  const badgeColor = immune ? '#6b21a8' : '#111827';
                  const badge = `<span style='display:inline-block;padding:2px 8px;border-radius:8px;background:${badgeColor};color:#fff;font-size:12px'>${u}</span>`;
                  const cidTag = cid ? `<span title='client_id' style='display:inline-block;padding:2px 8px;border-radius:8px;background:#0ea5e9;color:#fff;font-size:12px'>${cid}</span>` : '';
                  const ipPrivTag = priv ? `<span title='private' style='display:inline-block;padding:2px 8px;border-radius:8px;background:#6b7280;color:#fff;font-size:12px'>${priv}</span>` : '';
                  const ipPubTag = pub ? `<span title='public' style='display:inline-block;padding:2px 8px;border-radius:8px;background:#374151;color:#fff;font-size:12px'>${pub}</span>` : '';
                  const btnPriv = priv && !privB ? `<button data-ip='${priv}' data-user='${u}' class='btnBanPriv' style='padding:4px 8px;font-size:12px;background:#b45309;color:#fff;border-radius:6px'>Ban Private</button>` : '';
                  const btnPrivUn = priv && privB ? `<button data-ip='${priv}' class='btnUnbanPriv' style='padding:4px 8px;font-size:12px'>Unban Private</button>` : '';
                  const btnPub = pub && !pubB ? `<button data-ip='${pub}' data-user='${u}' class='btnBanPub' style='padding:4px 8px;font-size:12px;background:#b45309;color:#fff;border-radius:6px'>Ban Public</button>` : '';
                  const btnPubUn = pub && pubB ? `<button data-ip='${pub}' class='btnUnbanPub' style='padding:4px 8px;font-size:12px'>Unban Public</button>` : '';
                  const btnDev = cid && !devB ? `<button data-cid='${cid}' data-user='${u}' class='btnBanDevice' style='padding:4px 8px;font-size:12px;background:#ef4444;color:#fff;border-radius:6px'>Ban Device</button>` : '';
                  const btnDevUn = cid && devB ? `<button data-cid='${cid}' class='btnUnbanDevice' style='padding:4px 8px;font-size:12px'>Unban Device</button>` : '';
                  return `<div style='display:flex;gap:8px;align-items:center;justify-content:space-between;border:1px solid #e5e7eb;border-radius:8px;padding:6px;background:#f9fafb'>
                            <div style='display:flex;gap:6px;align-items:center'>${badge}${cidTag}${ipPrivTag}${ipPubTag}</div>
                            <div style='display:flex;gap:6px'>${btnPriv}${btnPrivUn}${btnPub}${btnPubUn}${btnDev}${btnDevUn}</div>
                          </div>`;
                }).join('') || '<span style=\"color:#666\">None</span>';
                box.querySelector('#admOnline').innerHTML = list;
                function wireBan(cls){
                  box.querySelectorAll(cls).forEach(el => {
                    el.onclick = async ()=>{
                      const ip = el.getAttribute('data-ip');
                      const user = el.getAttribute('data-user');
                      if (!ip) return;
                      const r2 = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type:'ip', action:'ban', value: ip, username: user })});
                      const d2 = await r2.json(); if (!r2.ok){ alert(d2.error||'Failed'); return; } alert('IP banned');
                      await refreshAll();
                    };
                  });
                }
                wireBan('.btnBanPriv'); wireBan('.btnBanPub');
                // Ban device by client_id
                box.querySelectorAll('.btnBanDevice').forEach(el => {
                  el.onclick = async ()=>{
                    const cid = el.getAttribute('data-cid'); const user = el.getAttribute('data-user');
                    if (!cid) return;
                    const r2 = await fetch('/api/admin/ban_device', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'ban', client_id: cid, username: user })});
                    const d2 = await r2.json(); if (!r2.ok){ alert(d2.error||'Failed'); return; } alert('Device banned');
                    await refreshAll();
                  };
                });
                // Unban IP/device buttons
                function wireUnban(cls, kind){
                  box.querySelectorAll(cls).forEach(el => {
                    el.onclick = async ()=>{
                      const ip = el.getAttribute('data-ip'); const cid = el.getAttribute('data-cid');
                      if (kind==='priv' || kind==='pub'){
                        if (!ip) return;
                        const r2 = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type:'ip', action:'unban', value: ip })});
                        const d2 = await r2.json(); if (!r2.ok){ alert(d2.error||'Failed'); return; } alert('IP unbanned');
                      } else if (kind==='dev'){
                        if (!cid) return;
                        const r2 = await fetch('/api/admin/ban_device', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'unban', client_id: cid })});
                        const d2 = await r2.json(); if (!r2.ok){ alert(d2.error||'Failed'); return; } alert('Device unbanned');
                      }
                      await refreshAll();
                    };
                  });
                }
                wireUnban('.btnUnbanPriv','priv'); wireUnban('.btnUnbanPub','pub'); wireUnban('.btnUnbanDevice','dev');
              } catch(e){ box.querySelector('#admOnline').textContent = 'Failed to load'; }
            }
            function wireTrueBan(){
              try {
                const btnTrueBan2 = box.querySelector('#btnTrueBan2');
                const btnTrueUnban2 = box.querySelector('#btnTrueUnban2');
                const tb2User = box.querySelector('#tb2User');
                const tb2CID = box.querySelector('#tb2CID');
                const btnSaveTrueBanToggles = box.querySelector('#btnSaveTrueBanToggles');
                if (btnTrueBan2) btnTrueBan2.onclick = async () => {
                  const user = (tb2User?.value||'').trim(); const client_id = (tb2CID?.value||'').trim();
                  if (!user) { showToast('Enter username', 'warn'); return; }
                  try {
                    const res = await fetch('/api/admin/true_ban', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user, client_id }) });
                    const j = await res.json().catch(()=>({}));
                    if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed', 'error'); return; }
                    showToast('True Ban applied', 'ok');
                    await refreshAll();
                  } catch(e) { showToast('Failed', 'error'); }
                };
                if (btnTrueUnban2) btnTrueUnban2.onclick = async () => {
                  const user = (tb2User?.value||'').trim(); const client_id = (tb2CID?.value||'').trim();
                  if (!user) { showToast('Enter username', 'warn'); return; }
                  try {
                    const res = await fetch('/api/admin/true_unban', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user, client_id }) });
                    const j = await res.json().catch(()=>({}));
                    if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed', 'error'); return; }
                    showToast('True Unban completed', 'ok');
                    await refreshAll();
                  } catch(e) { showToast('Failed', 'error'); }
                };
                if (btnSaveTrueBanToggles) btnSaveTrueBanToggles.onclick = async () => {
                  try {
                    const payload = {
                      SEC_STRICT_ASSOCIATED_BAN: box.querySelector('#SEC_STRICT_ASSOCIATED_BAN')?.checked ? '1' : '0',
                      SEC_DEVICE_BAN_ON_LOGIN: box.querySelector('#SEC_DEVICE_BAN_ON_LOGIN')?.checked ? '1' : '0',
                      SEC_REG_BAN_SIMILAR_CID: box.querySelector('#SEC_REG_BAN_SIMILAR_CID')?.checked ? '1' : '0',
                    };
                    const res = await fetch('/api/admin/toggles', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
                    const j = await res.json().catch(()=>({}));
                    if (!res.ok || !j.ok) { showToast((j && j.error) ? j.error : 'Failed to save toggles', 'error'); return; }
                    showToast('True Ban toggles saved', 'ok');
                  } catch(e) { showToast('Failed to save toggles', 'error'); }
                };
              } catch(e){}
            }
            wireTrueBan();

            // Ensure settings present; fetch persisted app settings for toggle states
            (async ()=>{
              try {
                const r = await fetch('/api/admin/app_settings');
                const j = await r.json().catch(()=>({}));
                if (r.ok && j && j.ok && j.settings){
                  info.settings = j.settings;
                  try {
                    const s = j.settings || {};
                    const ids = [
                      'PUBLIC_ENABLED','DM_ENABLED','GDM_ENABLED','MAINTENANCE_MODE','INVITE_ONLY_MODE','ANNOUNCEMENTS_ONLY',
                      'UM_BAN_USER','UM_TIMEOUT_USER','UM_SEARCH_USER','UM_TEMP_BAN','UM_GLOBAL_WARNING','UM_SHADOW_BAN',
                      'MC_DELETE_MESSAGES','MC_EDIT_MESSAGES','MC_SEARCH_MESSAGES','MC_PURGE_CHANNEL','MC_PIN_MESSAGE','MC_BROADCAST_MESSAGE','MC_VIEW_HISTORY','MC_MESSAGE_LIFESPAN',
                      'GD_LOCK_GROUP','GD_UNLOCK_GROUP','GD_REMOVE_USER','GD_TRANSFER_OWNERSHIP','GD_DELETE_GROUP','GD_CLOSE_ALL_DMS','GD_DM_AS_SYSTEM','GD_SAVE_DM_LOGS','GD_FORCE_LEAVE_GROUP',
                    ];
                    ids.forEach(id=>{ const el = box.querySelector('#'+id); if (el && 'checked' in el) el.checked = String(s[id]||'0')==='1'; });
                    const dr = box.querySelector('#DOWNTIME_REASON'); if (dr) dr.value = s.DOWNTIME_REASON || '';
                    const at = box.querySelector('#ALERTS_TEXT'); if (at) at.value = s.ALERTS_TEXT || '';
                  } catch(e){}
                  render();
                }
              } catch(e){}
            })();

            async function refreshAll(){
              try { const data = await adminOverview(); info = data; render(); } catch(e){}
              await renderOnline();
              // Banned devices list render
              const bd = (info.banned_devices||[]);
              const wrap = box.querySelector('#dtBannedList');
              if (wrap) {
                wrap.innerHTML = bd.map(x=>`<div style='display:flex;gap:6px;align-items:center;justify-content:space-between;border-bottom:1px dashed #e5e7eb;padding:4px 0'>
                  <span title='client_id'>${(x.client_id||'').slice(0,36)}</span>
                  <span title='username' style='color:#6b7280'>${x.username||''}</span>
                  <button class='btnUnbanDeviceRow' data-cid='${x.client_id||''}' style='padding:2px 6px'>Unban</button>
                </div>`).join('') || '<span style="color:#666">None</span>';
                wrap.querySelectorAll('.btnUnbanDeviceRow').forEach(el=>{
                  el.onclick = async ()=>{
                    const cid = el.getAttribute('data-cid'); if (!cid) return;
                    const r = await fetch('/api/admin/ban_device', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'unban', client_id: cid })});
                    const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Device unbanned'); await refreshAll();
                  };
                });
              }
            }
            box.querySelector('#admRefresh').onclick = refreshAll;
            // Save Message Lifespan
            try {
              const btnSaveLife = box.querySelector('#btnSaveLifespan');
              if (btnSaveLife) btnSaveLife.onclick = async ()=>{
                try{
                  const payload = {
                    MC_MESSAGE_LIFESPAN: box.querySelector('#MC_MESSAGE_LIFESPAN')?.checked ? '1' : '0',
                    MC_MESSAGE_LIFESPAN_DAYS: String(box.querySelector('#MC_MESSAGE_LIFESPAN_DAYS')?.value||'0'),
                  };
                  const r = await fetch('/api/admin/toggles', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
                  const j = await r.json().catch(()=>({}));
                  if (!r.ok || !j.ok) { showToast((j&&j.error)||'Failed to save lifespan', 'error'); return; }
                  showToast('Message lifespan saved', 'ok');
                  await refreshAll();
                } catch(e) { showToast('Failed to save lifespan', 'error'); }
              };
            } catch(e){}
            const btnCleanup = box.querySelector('#admCleanup'); if (btnCleanup) btnCleanup.onclick = async ()=>{
              try {
                const r = await fetch('/api/admin/cleanup_sockets', { method:'POST' });
                const d = await r.json().catch(()=>({}));
                if (!r.ok || !d.ok) { alert((d&&d.error)||'Failed'); return; }
                alert(`Disconnected: ${d.disconnected||0}, Pruned: ${d.pruned||0}`);
              } catch(e) { alert('Failed'); }
              await refreshAll();
            };
            // Group Tools wiring
            try {
              const q = (sel)=> box.querySelector(sel);
              const getTid = ()=> parseInt((q('#gtTid')?.value||'0'),10)||0;
              const getUser = ()=> (q('#gtUser')?.value||'').trim();
              const getNewOwner = ()=> (q('#gtNewOwner')?.value||'').trim();
              const call = async (url, payload)=>{
                try{
                  const r = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload||{}) });
                  const j = await r.json().catch(()=>({}));
                  if (!r.ok || !j.ok){ showToast((j&&j.error)||'Failed', 'error'); return false; }
                  showToast('Done', 'ok');
                  try { await loadGDMs(); } catch(e){}
                  return true;
                }catch(e){ showToast('Failed', 'error'); return false; }
              };
              const btnGtLock = q('#btnGtLock'); if (btnGtLock) btnGtLock.onclick = ()=>{ const tid=getTid(); if(!tid){showToast('Enter thread_id','warn');return;} call('/api/gdm/lock',{tid}); };
              const btnGtUnlock = q('#btnGtUnlock'); if (btnGtUnlock) btnGtUnlock.onclick = ()=>{ const tid=getTid(); if(!tid){showToast('Enter thread_id','warn');return;} call('/api/gdm/unlock',{tid}); };
              const btnGtRemove = q('#btnGtRemove'); if (btnGtRemove) btnGtRemove.onclick = ()=>{ const tid=getTid(); const u=getUser(); if(!tid||!u){showToast('Enter thread_id and username','warn');return;} call('/api/gdm/remove_member',{tid, username:u}); };
              const btnGtTransfer = q('#btnGtTransfer'); if (btnGtTransfer) btnGtTransfer.onclick = ()=>{ const tid=getTid(); const no=getNewOwner(); if(!tid||!no){showToast('Enter thread_id and new owner','warn');return;} call('/api/gdm/transfer',{tid, new_owner:no}); };
              const btnGtDelete = q('#btnGtDelete'); if (btnGtDelete) btnGtDelete.onclick = ()=>{ const tid=getTid(); if(!tid){showToast('Enter thread_id','warn');return;} if(!confirm('Delete this group?')) return; call('/api/gdm/delete',{tid}); };
              const btnGtForceLeave = q('#btnGtForceLeave'); if (btnGtForceLeave) btnGtForceLeave.onclick = ()=>{ const tid=getTid(); const u=getUser(); if(!tid||!u){showToast('Enter thread_id and username','warn');return;} call('/api/gdm/force_leave',{tid, username:u}); };
            } catch(e){}
            // actions
            // DB Editor
            try {
              const btnRunSQL = box.querySelector('#btnRunSQL');
              if (btnRunSQL) btnRunSQL.onclick = async ()=>{
                try{
                  const sql = (box.querySelector('#admSQL')?.value||'').trim();
                  if (!sql){ showToast('Enter SQL', 'warn'); return; }
                  const r = await fetch('/api/admin/sql_run', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ sql }) });
                  const j = await r.json().catch(()=>({}));
                  if (!r.ok || !j.ok){ showToast((j&&j.error)||'Failed', 'error'); return; }
                  box.querySelector('#sqlOut').textContent = JSON.stringify(j.rows||[], null, 2);
                }catch(e){ showToast('Failed', 'error'); }
              };
            } catch(e){}
            // Save All Toggles (including text settings)
            try {
              const btnSaveAll = box.querySelector('#btnSaveAllToggles');
              if (btnSaveAll) btnSaveAll.onclick = async ()=>{
                try{
                  const payload = {};
                  const ids = [
                    'PUBLIC_ENABLED','DM_ENABLED','GDM_ENABLED','MAINTENANCE_MODE','INVITE_ONLY_MODE','ANNOUNCEMENTS_ONLY',
                    'UM_BAN_USER','UM_TIMEOUT_USER','UM_SEARCH_USER','UM_TEMP_BAN','UM_GLOBAL_WARNING','UM_SHADOW_BAN',
                    'MC_DELETE_MESSAGES','MC_EDIT_MESSAGES','MC_SEARCH_MESSAGES','MC_PURGE_CHANNEL','MC_PIN_MESSAGE','MC_BROADCAST_MESSAGE','MC_VIEW_HISTORY','MC_MESSAGE_LIFESPAN',
                    'GD_LOCK_GROUP','GD_UNLOCK_GROUP','GD_REMOVE_USER','GD_TRANSFER_OWNERSHIP','GD_DELETE_GROUP','GD_CLOSE_ALL_DMS','GD_DM_AS_SYSTEM','GD_SAVE_DM_LOGS','GD_FORCE_LEAVE_GROUP',
                    'DOWNTIME_ENABLED','ALERTS_ENABLED'
                  ];
                  ids.forEach(id=>{ const el = box.querySelector('#'+id); if (el && 'checked' in el) payload[id] = el.checked? '1':'0'; });
                  payload['DOWNTIME_REASON'] = (box.querySelector('#DOWNTIME_REASON')?.value||'');
                  payload['ALERTS_TEXT'] = (box.querySelector('#ALERTS_TEXT')?.value||'');
                  let r = await fetch('/api/admin/toggles', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
                  let j = await r.json().catch(()=>({}));
                  if (!r.ok || !j.ok){
                    // Retry legacy shape {settings: payload}
                    r = await fetch('/api/admin/toggles', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ settings: payload }) });
                    j = await r.json().catch(()=>({}));
                  }
                  if (!r.ok || !j.ok){
                    // Final fallback: persist critical settings via /api/admin/settings
                    const subset = {
                      DOWNTIME_ENABLED: payload.DOWNTIME_ENABLED,
                      DOWNTIME_REASON: payload.DOWNTIME_REASON,
                      ALERTS_ENABLED: payload.ALERTS_ENABLED,
                      ALERTS_TEXT: payload.ALERTS_TEXT,
                    };
                    const r2 = await fetch('/api/admin/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(subset) });
                    const j2 = await r2.json().catch(()=>({}));
                    if (!r2.ok || !j2.ok){ showToast((j&&j.error)||'Failed', 'error'); return; }
                    showToast('Settings saved', 'ok');
                    // Immediately refresh on-screen alert if present
                    try { window.__refreshAlert && window.__refreshAlert(); } catch(e){}
                    return;
                  }
                  showToast('Toggles saved', 'ok');
                  // Immediately refresh on-screen alert if present
                  try { window.__refreshAlert && window.__refreshAlert(); } catch(e){}
                }catch(e){ showToast('Failed', 'error'); }
              };
            } catch(e){}
            // Broadcast
            try {
              const btnBroadcast = box.querySelector('#btnBroadcast');
              if (btnBroadcast) btnBroadcast.onclick = async ()=>{
                const scope = (box.querySelector('#mtBroadcastScope')?.value||'public');
                const text = (box.querySelector('#mtBroadcastText')?.value||'').trim();
                const thread_id = parseInt((box.querySelector('#mtBroadcastThreadId')?.value||'0'),10)||0;
                const to_user = (box.querySelector('#mtBroadcastToUser')?.value||'').trim();
                if (!text){ showToast('Enter message', 'warn'); return; }
                const payload = { scope, text };
                if (scope==='gdm') payload.thread_id = thread_id;
                if (scope==='dm') payload.to_user = to_user;
                try{
                  const r = await fetch('/api/admin/broadcast', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
                  const j = await r.json().catch(()=>({}));
                  if (!r.ok || !j.ok){ showToast((j&&j.error)||'Failed', 'error'); return; }
                  showToast('Broadcast sent', 'ok');
                  box.querySelector('#mtBroadcastText').value = '';
                }catch(e){ showToast('Failed', 'error'); }
              };
            } catch(e){}
            // History load
            try {
              const btnLoadHist = box.querySelector('#btnLoadHist');
              if (btnLoadHist) btnLoadHist.onclick = async ()=>{
                const kind = (box.querySelector('#mtHistType')?.value||'public');
                const thread_id = parseInt((box.querySelector('#mtHistThreadId')?.value||'0'),10)||0;
                const lim = parseInt((box.querySelector('#mtHistLimit')?.value||'50'),10)||50;
                const p = new URLSearchParams(); p.set('type', kind); p.set('limit', String(lim)); if (kind==='gdm' && thread_id) p.set('thread_id', String(thread_id));
                try{
                  const r = await fetch('/api/admin/history?'+p.toString()); const j = await r.json();
                  const out = box.querySelector('#mtHistOut'); if (!out){ return; }
                  if (!r.ok){ out.textContent = j.error||'Failed'; return; }
                  const items = j.items||[];
                  out.innerHTML = items.map(m=>`<div style='border-bottom:1px dashed #e5e7eb;padding:4px 0'>
                    <div style='font-size:12px;color:#6b7280'>#${m.id} — ${m.username} — ${m.created_at}</div>
                    <div>${m.text}</div>
                  </div>`).join('') || '<span style="color:#666">None</span>';
                }catch(e){ const out = box.querySelector('#mtHistOut'); if (out) out.textContent = 'Failed'; }
              };
            } catch(e){}
            box.querySelector('#btnAddAdmin').onclick = async ()=>{
              const u = box.querySelector('#admUser').value.trim(); if (!u) return;
              const r = await fetch('/api/admin/role', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'add', role:'admin', username:u })});
              const data = await r.json(); if (!r.ok){ alert(data.error||'Failed'); return;} info.admins = data.admins; render();
            };
            box.querySelector('#btnRmAdmin').onclick = async ()=>{
              const u = box.querySelector('#admUser').value.trim(); if (!u) return;
              const r = await fetch('/api/admin/role', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'remove', role:'admin', username:u })});
              const data = await r.json(); if (!r.ok){ alert(data.error||'Failed'); return;} info.admins = data.admins; render();
            };
            box.querySelector('#btnBanUser').onclick = async ()=>{
              const u = box.querySelector('#admBanUser').value.trim(); if (!u) return;
              const r = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type:'user', action:'ban', value:u })});
              const data = await r.json(); if (!r.ok){ alert(data.error||'Failed'); return;} await refreshAll();
            };
            box.querySelector('#btnUnbanUser').onclick = async ()=>{
              const u = box.querySelector('#admBanUser').value.trim(); if (!u) return;
              const r = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type:'user', action:'unban', value:u })});
              const data = await r.json(); if (!r.ok){ alert(data.error||'Failed'); return;} await refreshAll();
            };
            box.querySelector('#btnBanIP').onclick = async ()=>{
              const ip = (box.querySelector('#admBanIP').value||'').trim();
              const user = (box.querySelector('#admBanIPUser').value||'').trim();
              if (!ip && !user) { alert('Enter an IP or a username'); return; }
              const payload = { type:'ip', action:'ban', value: ip, username: user };
              const r = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
              const data = await r.json(); if (!r.ok){ alert(data.error||'Failed'); return;} await refreshAll();
            };
            box.querySelector('#btnUnbanIP').onclick = async ()=>{
              const ip = (box.querySelector('#admBanIP').value||'').trim();
              const user = (box.querySelector('#admBanIPUser').value||'').trim();
              if (!ip && !user) { alert('Enter an IP or a username'); return; }
              const payload = { type:'ip', action:'unban', value: ip, username: user };
              const r = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
              const data = await r.json(); if (!r.ok){ alert(data.error||'Failed'); return;}
              await refreshAll();
            };
            // User Management wiring
            const umSearch = box.querySelector('#umSearch');
            const umResults = box.querySelector('#umResults');
            const umUser = box.querySelector('#umUser');
            async function doSearch(){
              const q = (umSearch.value||'').trim();
              try{
                const r = await fetch('/api/admin/user_search?q='+encodeURIComponent(q));
                const d = await r.json();
                if (!r.ok) { umResults.textContent = d.error||'Failed'; return; }
                umResults.innerHTML = (d.users||[]).map(u=>`<button class='selUser' data-u='${u}' style='margin:2px;padding:4px 6px'>${u}</button>`).join('') || '<span style="color:#666">No results</span>';
                umResults.querySelectorAll('.selUser').forEach(el=>{ el.onclick = ()=>{ umUser.value = el.getAttribute('data-u')||''; } });
              }catch(e){ umResults.textContent = 'Failed'; }
            }
            if (umSearch) umSearch.oninput = ()=>{ window.clearTimeout(umSearch._t); umSearch._t = setTimeout(doSearch, 250); };
            function applyUMToggles(map){
              const setDis = (id, on)=>{ const el = box.querySelector(id); if (el) el.disabled = !on; };
              setDis('#btnUMBan', String(map.UM_BAN_USER||'1')==='1');
              setDis('#btnUMUnban', String(map.UM_BAN_USER||'1')==='1');
              // Remove timeout toggle from settings
              setDis('#btnUMWarn', String(map.UM_GLOBAL_WARNING||'1')==='1');
              setDis('#btnUMShadow', String(map.UM_SHADOW_BAN||'1')==='1');
              setDis('#btnUMUnshadow', String(map.UM_SHADOW_BAN||'1')==='1');
              setDis('#btnShadowTop', String(map.UM_SHADOW_BAN||'1')==='1');
              setDis('#btnUnshadowTop', String(map.UM_SHADOW_BAN||'1')==='1');
            }
            // Use toggles map when loaded
            let lastToggles = null;
            // Code editor actions (superadmin-only endpoint)
            const codeEl = ()=> box.querySelector('#admCode');
            const setDirty = (v)=>{ const el=box.querySelector('#codeDirty'); if(el) el.textContent = v? 'Unsaved changes' : 'Clean'; };
            const loadCode = async ()=>{
              try {
                const r = await fetch('/api/admin/code');
                const d = await r.json();
                if (!r.ok) { alert(d && d.error ? d.error : 'Failed to load code'); return; }
                codeEl().value = d.content || '';
                setDirty(false);
              } catch(e){ alert('Failed to load code'); }
            };
            // simple debounce to avoid rapid heavy saves
            let saving = false; let wrapOn=false; let editOn=false;
            const saveCode = async ()=>{
              if (saving) return; saving = true;
              try {
                const content = codeEl().value;
                const r = await fetch('/api/admin/code', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ content, restart: true }) });
                const d = await r.json();
                if (!r.ok || !d.ok) { alert(d && d.error ? d.error : 'Failed to save'); return; }
                alert('Saved. The server may need a manual restart to apply changes.');
                setDirty(false);
              } catch(e){ alert('Failed to save'); }
              finally { saving = false; }
            };
            const lc = box.querySelector('#btnLoadCode'); if (lc) lc.onclick = loadCode;
            const sc = box.querySelector('#btnSaveCode'); if (sc) sc.onclick = saveCode;
            const te = box.querySelector('#btnToggleEdit'); if (te) te.onclick = ()=>{ editOn=!editOn; codeEl().readOnly = !editOn; te.textContent = editOn? 'Readonly' : 'Edit'; if (editOn) codeEl().focus(); };
            const bw = box.querySelector('#btnWrap'); if (bw) bw.onclick = ()=>{ wrapOn=!wrapOn; codeEl().style.whiteSpace = wrapOn? 'pre-wrap':'pre'; bw.textContent = `Wrap: ${wrapOn?'On':'Off'}`; };
            // Mark dirty on edit, throttled with rAF
            let rafId = null;
            codeEl().addEventListener('input', ()=>{
              if (rafId) return; rafId = requestAnimationFrame(()=>{ setDirty(true); rafId=null; });
            });
            // Auto-load on open
            try { await loadCode(); } catch(e){}
            // Load all toggles generically
            async function loadAllToggles(){
              try {
                const r = await fetch('/api/admin/app_settings');
                const d = await r.json();
                if (!r.ok) return;
                Object.keys(d||{}).forEach(k=>{
                  const el = box.querySelector(`#${k}`);
                  if (el && el.type === 'checkbox') el.checked = String(d[k])==='1';
                });
                lastToggles = d;
                applyUMToggles(d||{});
              } catch(e){}
            }
            await loadAllToggles();
            // Device Tools wiring
            const btnBanDevOff = box.querySelector('#btnBanDeviceOffline'); if (btnBanDevOff) btnBanDevOff.onclick = async ()=>{
              const u = (box.querySelector('#dtUser').value||'').trim(); const cid = (box.querySelector('#dtClientId').value||'').trim();
              if (!u && !cid) { alert('Enter username or client_id'); return; }
              const payload = { action:'ban' }; if (cid) payload.client_id = cid; if (u) payload.username = u;
              const r = await fetch('/api/admin/ban_device', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Device banned'); await refreshAll();
            };
            const btnUnbanDevOff = box.querySelector('#btnUnbanDeviceOffline'); if (btnUnbanDevOff) btnUnbanDevOff.onclick = async ()=>{
              const u = (box.querySelector('#dtUser').value||'').trim(); const cid = (box.querySelector('#dtClientId').value||'').trim();
              if (!u && !cid) { alert('Enter username or client_id'); return; }
              if (cid){
                const r = await fetch('/api/admin/ban_device', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ action:'unban', client_id: cid })});
                const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Device unbanned'); await refreshAll();
              } else if (u){
                const r = await fetch('/api/admin/unban_devices_for_user', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username: u })});
                const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('All devices unbanned for user'); await refreshAll();
              }
            };
            const btnUnbanAllUser = box.querySelector('#btnUnbanAllDevicesUser'); if (btnUnbanAllUser) btnUnbanAllUser.onclick = async ()=>{
              const u = (box.querySelector('#dtUser').value||'').trim(); if (!u){ alert('Enter username'); return; }
              const r = await fetch('/api/admin/unban_devices_for_user', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username: u })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('All devices unbanned for user'); await refreshAll();
            };
            // UM buttons
            const btnUMBan = box.querySelector('#btnUMBan'); if (btnUMBan) btnUMBan.onclick = async ()=>{
              const u = (umUser.value||'').trim(); if (!u) return;
              const r = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type:'user', action:'ban', value: u })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Banned'); await refreshAll();
            };
            const btnUMUnban = box.querySelector('#btnUMUnban'); if (btnUMUnban) btnUMUnban.onclick = async ()=>{
              const u = (umUser.value||'').trim(); if (!u) return;
              const r = await fetch('/api/admin/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type:'user', action:'unban', value: u })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Unbanned'); await refreshAll();
            };
            const btnUMShadow = box.querySelector('#btnUMShadow'); if (btnUMShadow) btnUMShadow.onclick = async ()=>{
              const u = (umUser.value||'').trim(); if (!u) return;
              const r = await fetch('/api/admin/shadow', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user: u, action: 'add' })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Shadow banned');
            };
            const btnUMUnshadow = box.querySelector('#btnUMUnshadow'); if (btnUMUnshadow) btnUMUnshadow.onclick = async ()=>{
              const u = (umUser.value||'').trim(); if (!u) return;
              const r = await fetch('/api/admin/shadow', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user: u, action: 'remove' })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Unshadowed');
            };
            const btnUMWarn = box.querySelector('#btnUMWarn'); if (btnUMWarn) btnUMWarn.onclick = async ()=>{
              const u = (umUser.value||'').trim(); const msg = (box.querySelector('#umWarnMsg').value||'').trim(); if (!u || !msg) return;
              const r = await fetch('/api/admin/warn', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user: u, message: msg })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Warning sent');
            };
            // Top-level Shadow buttons (Banned Users card)
            const btnShadowTop = box.querySelector('#btnShadowTop'); if (btnShadowTop) btnShadowTop.onclick = async ()=>{
              const u = (box.querySelector('#admBanUser').value||'').trim(); if (!u) return;
              const r = await fetch('/api/admin/shadow', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user: u, action: 'add' })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Shadow banned');
            };
            const btnUnshadowTop = box.querySelector('#btnUnshadowTop'); if (btnUnshadowTop) btnUnshadowTop.onclick = async ()=>{
              const u = (box.querySelector('#admBanUser').value||'').trim(); if (!u) return;
              const r = await fetch('/api/admin/shadow', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user: u, action: 'remove' })});
              const d = await r.json(); if (!r.ok){ alert(d.error||'Failed'); return; } alert('Unshadowed');
            };
            // (Save All Toggles handler is wired earlier; no generic override here)
            // Messaging Tools wiring
            const btnBroadcast = box.querySelector('#btnBroadcast'); if (btnBroadcast) btnBroadcast.onclick = async ()=>{
              const scope = (box.querySelector('#mtScope').value||'public');
              const text = (box.querySelector('#mtBroadcastText').value||'').trim();
              const thread_id = parseInt((box.querySelector('#mtBroadcastThreadId').value||'0'),10)||0;
              const to_user = (box.querySelector('#mtBroadcastToUser').value||'').trim();
              if (!text) { alert('Enter message'); return; }
              const payload = { scope, text };
              if (scope==='gdm') payload.thread_id = thread_id;
              if (scope==='dm') payload.to_user = to_user;
              const r = await fetch('/api/admin/broadcast', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
              const d = await r.json().catch(()=>({}));
              if (!r.ok || !d.ok) { alert((d&&d.error)||'Failed'); return; }
              alert('Broadcast sent');
            };
            const btnPin = box.querySelector('#btnPin'); if (btnPin) btnPin.onclick = async ()=>{
              const type = (box.querySelector('#mtPinType').value||'public');
              const id = parseInt((box.querySelector('#mtPinMsgId').value||'0'),10)||0;
              const thread_id = parseInt((box.querySelector('#mtPinThreadId').value||'0'),10)||0;
              if (!id) { alert('Enter message id'); return; }
              const payload = { type, id, action:'pin' };
              if (type==='gdm') payload.thread_id = thread_id;
              const r = await fetch('/api/admin/pin', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
              const d = await r.json().catch(()=>({}));
              if (!r.ok || !d.ok) { alert((d&&d.error)||'Failed'); return; }
              alert('Pinned');
            };
            const btnUnpin = box.querySelector('#btnUnpin'); if (btnUnpin) btnUnpin.onclick = async ()=>{
              const type = (box.querySelector('#mtPinType').value||'public');
              const id = parseInt((box.querySelector('#mtPinMsgId').value||'0'),10)||0;
              const thread_id = parseInt((box.querySelector('#mtPinThreadId').value||'0'),10)||0;
              if (!id) { alert('Enter message id'); return; }
              const payload = { type, id, action:'unpin' };
              if (type==='gdm') payload.thread_id = thread_id;
              const r = await fetch('/api/admin/pin', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
              const d = await r.json().catch(()=>({}));
              if (!r.ok || !d.ok) { alert((d&&d.error)||'Failed'); return; }
              alert('Unpinned');
            };
            const btnLoadHist = box.querySelector('#btnLoadHist'); if (btnLoadHist) btnLoadHist.onclick = async ()=>{
              const type = (box.querySelector('#mtHistType').value||'public');
              const limit = parseInt((box.querySelector('#mtHistLimit').value||'50'),10)||50;
              const tid = parseInt((box.querySelector('#mtHistThreadId').value||'0'),10)||0;
              // If limit > 20, load from chat_messages.txt via log endpoint and open in popup
              if (limit > 20) {
                try {
                  const r = await fetch('/api/admin/history_log');
                  const txt = await r.text();
                  const win = window.open('', 'HistoryLog', 'width=900,height=600,scrollbars=yes');
                  if (win && win.document) {
                    win.document.write('<html><head><title>Chat History</title><style>body{font-family:monospace;white-space:pre-wrap;background:#111827;color:#e5e7eb;margin:0;padding:12px;} pre{margin:0;}</style></head><body><pre></pre></body></html>');
                    try {
                      win.document.body.querySelector('pre').textContent = txt || '(no history)';
                    } catch(_e) {}
                    win.document.close();
                  }
                } catch(e) {
                  alert('Failed to load history from log file');
                }
                return;
              }
              const qs = new URLSearchParams({ type, limit: String(limit) });
              if (type==='gdm' && tid>0) qs.set('thread_id', String(tid));
              const r = await fetch('/api/admin/history?'+qs.toString());
              const d = await r.json().catch(()=>({items:[]}));
              const out = (d.items||[]).map(m=>`#${m.id} <b>${(m.username||'')}</b>: <span>${(m.text||'')}</span> <i>${(m.created_at||'')}</i>`).join('<br>') || '<span style="color:#666">None</span>';
              box.querySelector('#mtHistOut').innerHTML = out;
            };
            const btnSaveLifespan = box.querySelector('#btnSaveLifespan'); if (btnSaveLifespan) btnSaveLifespan.onclick = async ()=>{
              const on = box.querySelector('#MC_MESSAGE_LIFESPAN').checked ? '1' : '0';
              const days = String(parseInt((box.querySelector('#MC_MESSAGE_LIFESPAN_DAYS').value||'0'),10)||0);
              const payload = { MC_MESSAGE_LIFESPAN: on, MC_MESSAGE_LIFESPAN_DAYS: days };
              const r = await fetch('/api/admin/app_settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
              const d = await r.json().catch(()=>({}));
              if (!r.ok || !d.ok) { alert((d&&d.error)||'Failed'); return; }
              alert('Lifespan saved');
            };
            const rb = box.querySelector('#admRestart'); if (rb) rb.onclick = async ()=>{
              if (!confirm('Restart the server now? Active connections will drop.')) return;
              try {
                const r = await fetch('/api/admin/restart', { method:'POST' });
                const d = await r.json().catch(()=>({}));
                if (!r.ok) { alert((d&&d.error)||'Failed'); return; }
                alert('Restarting in 1-2 seconds...');
              } catch(e){ alert('Failed'); }
            };
            await renderOnline();
          }
          // Bind buttons if present
          const b1 = document.getElementById('btnAdminDashHeader');
          const b2 = document.getElementById('btnAdminDashSettings');
          const b3 = document.getElementById('btnAdminDash');
          if (b1) b1.onclick = openAdminDashboard;
          if (b2) b2.onclick = openAdminDashboard;
          if (b3) b3.onclick = openAdminDashboard;
        })();
        {% endif %}
        document.getElementById('saveTheme').onclick = async () => {
            const theme = (document.getElementById('setTheme').value||'').trim().toLowerCase();
            const bio = document.getElementById('setBio') ? document.getElementById('setBio').value : '';
            const status = document.getElementById('setStatus') ? document.getElementById('setStatus').value : '';
            const payload = { theme, bio, status };
            const res = await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
            const info = await res.json();
            if (!res.ok) { alert(info && info.error ? info.error : 'Failed to save'); return; }
            alert('Settings saved');
            try { await getProfiles(true); } catch(e) {}
            try { await refreshRightOnline(); } catch(e) {}
        };
        // Explicit Save Profile button support (if present)
        (function(){
          const btn = document.getElementById('saveProfile');
          if (!btn) return;
          btn.onclick = async () => {
            const bio = document.getElementById('setBio') ? document.getElementById('setBio').value : '';
            const status = document.getElementById('setStatus') ? document.getElementById('setStatus').value : '';
            const payload = { bio, status };
            const res = await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
            const info = await res.json().catch(()=>null);
            if (!res.ok) { alert((info&&info.error)||'Failed to save profile'); return; }
            alert('Profile saved');
            try { await getProfiles(true); } catch(e) {}
            try { await refreshRightOnline(); } catch(e) {}
          };
        })();
        // Mark all as read
        (function(){
          const btn = document.getElementById('markAllReadBtn');
          if (!btn) return;
          btn.onclick = () => {
            try {
              localStorage.setItem('unreadDM','{}');
              localStorage.setItem('unreadGDM','{}');
            } catch(e) {}
            loadDMs();
            loadGDMs();
            updateTitleUnread();
            alert('All conversations marked as read');
          };
        })();
        // Clear all messages (admins only)
        (function(){
          const btn = document.getElementById('clearAllMsgs');
          if (!btn) return;
          try {
            btn.style.display = (isAdmin || SUPERADMINS.includes(me)) ? 'inline-block' : 'none';
          } catch(e) {}
          btn.onclick = async () => {
            if (!confirm('This will clear your DMs and group messages. If you are a superadmin, it will also clear public and all group messages. Continue?')) return;
            try {
              const res = await fetch('/api/clear/all', { method:'POST' });
              const info = await res.json().catch(()=>({}));
              if (!res.ok) { alert((info&&info.error)||'Failed to clear'); return; }
              try { localStorage.setItem('unreadDM','{}'); localStorage.setItem('unreadGDM','{}'); } catch(e) {}
              chatEl.innerHTML = '';
              messagesLoaded = false;
              switchToPublic();
              loadDMs();
              loadGDMs();
              updateTitleUnread();
              alert('Messages cleared');
            } catch(e) { alert('Failed'); }
          };
        })();
        // Avatar upload and delete handlers
        document.getElementById('avatarForm').onsubmit = async (ev) => {
            ev.preventDefault();
            const fileInput = document.getElementById('avatarFile');
            const submitBtn = ev.target.querySelector('button[type="submit"]');
            
            if (!fileInput.files || !fileInput.files[0]) {
                alert('Please select a file to upload');
                return;
            }
            
            // Show loading state
            submitBtn.disabled = true;
            submitBtn.textContent = 'Uploading...';
            
            try {
                const fd = new FormData(document.getElementById('avatarForm'));
                const res = await fetch('/api/upload/avatar', { method:'POST', body: fd });
                const info = await res.json();
                
                if (!res.ok) { 
                    alert(info && info.error ? info.error : 'Upload failed'); 
                    return; 
                }
                
                alert('Avatar updated successfully!');
                refreshRightOnline();
                fileInput.value = ''; // Clear file input
            } catch (error) {
                console.error('Upload error:', error);
                alert('Upload failed due to network error');
            } finally {
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.textContent = 'Upload';
            }
        };
        
        const delAvaBtn = document.getElementById('deleteAvatarBtn');
        if (delAvaBtn) {
            delAvaBtn.onclick = async () => {
                if (!confirm('Are you sure you want to delete your avatar?')) {
                    return;
                }
                
                delAvaBtn.disabled = true;
                delAvaBtn.textContent = 'Deleting...';
                
                try {
                    const res = await fetch('/api/delete/avatar', { method:'POST' });
                    if (!res.ok) { 
                        try { 
                            const info = await res.json(); 
                            alert(info.error||'Failed to delete avatar'); 
                        } catch(e) { 
                            alert('Failed to delete avatar'); 
                        } 
                        return; 
                    }
                    
                    alert('Avatar removed successfully!');
                    refreshRightOnline();
                } catch (error) {
                    console.error('Delete error:', error);
                    alert('Failed to delete avatar due to network error');
                } finally {
                    delAvaBtn.disabled = false;
                    delAvaBtn.textContent = 'Delete';
                }
            };
        }

        // Hide deprecated friends UI if present
        (function(){
          try {
            const el = document.getElementById('allowDmNonfriends');
            if (el) {
              const row = el.closest('div') || el.parentElement;
              if (row) row.style.display = 'none';
            }
          } catch(e) {}
        })();
        // Update online count on page load
        updateOnlineCount();
        refreshRightOnline();
        setInterval(refreshRightOnline, 5000);
        // No periodic refresh
        loadDMs();
        loadGDMs();
        // Auto-open group via ?tid=
        try {
            const qs = new URLSearchParams(location.search);
            const tidParam = parseInt(qs.get('tid'));
            if (tidParam) {
                // remove from closed if present
                const arr = JSON.parse(localStorage.getItem('closedGDMs')||'[]');
                const sid = String(tidParam);
                const idx = arr.indexOf(sid);
                if (idx >= 0) { arr.splice(idx,1); localStorage.setItem('closedGDMs', JSON.stringify(arr)); }
                setTimeout(()=>openGDM(tidParam), 0);
            }
        } catch(e) {}
        updateTitleUnread();
        document.addEventListener('visibilitychange', updateTitleUnread);

        // Resizable columns: left and right
        try {
            const container = document.body; // page wrapper
            // Left resizer
            const resizerLeft = document.createElement('div');
            resizerLeft.id = 'resizerLeft';
            resizerLeft.title = 'Drag to resize';
            Object.assign(resizerLeft.style, {
                width:'4px', cursor:'col-resize', backgroundImage:'linear-gradient(#bbb 50%, transparent 50%)', backgroundSize:'4px 8px', backgroundRepeat:'repeat-y',
                zIndex:'10001'
            });
            // Insert after leftbar
            leftbar.parentElement.insertBefore(resizerLeft, leftbar.nextSibling);
            const loadLeftWidth = () => {
                const w = parseInt(localStorage.getItem('leftbarWidth')||'0');
                if (w>120 && w<500) leftbar.style.width = w+'px';
            };
            loadLeftWidth();
            let draggingL = false;
            resizerLeft.addEventListener('mousedown', e => { draggingL = true; document.body.style.userSelect='none'; });
            window.addEventListener('mouseup', ()=>{ draggingL=false; document.body.style.userSelect=''; });
            window.addEventListener('mousemove', e => {
                if (!draggingL) return;
                const x = e.clientX;
                const min=120, max=500;
                let w = Math.max(min, Math.min(max, x));
                leftbar.style.width = w + 'px';
                localStorage.setItem('leftbarWidth', String(w));
            });

            // Right resizer
            const rightOnlineListEl = document.getElementById('rightOnlineList');
            const rightbar = document.getElementById('rightbar') || (rightOnlineListEl ? rightOnlineListEl.parentElement : null);
            if (rightbar) {
                const resizerRight = document.createElement('div');
                resizerRight.id = 'resizerRight';
                resizerRight.title = 'Drag to resize';
                Object.assign(resizerRight.style, {
                    width:'4px', cursor:'col-resize', backgroundImage:'linear-gradient(#bbb 50%, transparent 50%)', backgroundSize:'4px 8px', backgroundRepeat:'repeat-y',
                    zIndex:'10001'
                });
                rightbar.parentElement.insertBefore(resizerRight, rightbar);
                const loadRightWidth = () => {
                    const w = parseInt(localStorage.getItem('rightbarWidth')||'0');
                    if (w>160 && w<600) rightbar.style.width = w+'px';
                };
                loadRightWidth();
                let draggingR = false;
                resizerRight.addEventListener('mousedown', e => { draggingR = true; document.body.style.userSelect='none'; });
                window.addEventListener('mouseup', ()=>{ draggingR=false; document.body.style.userSelect=''; });
                window.addEventListener('mousemove', e => {
                    if (!draggingR) return;
                    const winW = window.innerWidth;
                    const x = e.clientX;
                    // width of rightbar = remaining space from mouse to right edge
                    const min=160, max=600;
                    let w = Math.max(min, Math.min(max, winW - x));
                    rightbar.style.width = w + 'px';
                    localStorage.setItem('rightbarWidth', String(w));
                });
            }
        } catch(e) { console.warn('Resizers init failed', e); }
// Reporting System Frontend Implementation

// Report modal HTML and functionality
function createReportModal() {
    const modalHTML = `
        <div id="reportModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:10000;">
            <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;min-width:400px;max-width:500px;">
                <h3 style="margin:0 0 15px 0;color:var(--primary);">Report Content</h3>
                <div id="reportContent">
                    <div style="margin-bottom:15px;">
                        <label style="display:block;margin-bottom:5px;color:var(--primary);">Reason:</label>
                        <select id="reportReason" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:4px;background:var(--card);color:var(--primary);">
                            <option value="">Select a reason...</option>
                            <option value="spam">Spam</option>
                            <option value="harassment">Harassment</option>
                            <option value="hate_speech">Hate Speech</option>
                            <option value="inappropriate">Inappropriate Content</option>
                            <option value="impersonation">Impersonation</option>
                            <option value="other">Other</option>
                        </select>
                    </div>
                    <div style="margin-bottom:15px;">
                        <label style="display:block;margin-bottom:5px;color:var(--primary);">Additional Details (optional):</label>
                        <textarea id="reportDetails" placeholder="Provide additional context..." style="width:100%;height:80px;padding:8px;border:1px solid var(--border);border-radius:4px;background:var(--card);color:var(--primary);resize:vertical;"></textarea>
                    </div>
                </div>
                <div style="display:flex;gap:10px;justify-content:flex-end;">
                    <button id="reportCancel" style="padding:8px 16px;border:1px solid var(--border);background:var(--card);color:var(--primary);border-radius:4px;cursor:pointer;">Cancel</button>
                    <button id="reportSubmit" style="padding:8px 16px;border:none;background:#dc2626;color:white;border-radius:4px;cursor:pointer;">Submit Report</button>
                </div>
            </div>
        </div>
    `;

    if (!document.getElementById('reportModal')) {
        document.body.insertAdjacentHTML('beforeend', modalHTML);

        // Event listeners
        document.getElementById('reportCancel').onclick = () => closeReportModal();
        document.getElementById('reportSubmit').onclick = () => submitReport();
        document.getElementById('reportModal').onclick = (e) => {
            if (e.target.id === 'reportModal') closeReportModal();
        };
    }
}

function showReportModal(type, data) {
    createReportModal();
    const modal = document.getElementById('reportModal');
    const reasonSelect = document.getElementById('reportReason');
    const detailsTextarea = document.getElementById('reportDetails');

    // Store report data
    modal.reportData = { type, ...data };

    // Update modal title and reason options based on type
    const title = modal.querySelector('h3');
    if (type === 'message') {
        title.textContent = `Report Message from @${data.target_username}`;
        // Remove impersonation option for message reports
        const impersonationOption = reasonSelect.querySelector('option[value="impersonation"]');
        if (impersonationOption) impersonationOption.style.display = 'none';
    } else {
        title.textContent = `Report User @${data.target_username}`;
        // Show impersonation option for user reports
        const impersonationOption = reasonSelect.querySelector('option[value="impersonation"]');
        if (impersonationOption) impersonationOption.style.display = 'block';
    }

    // Reset form
    reasonSelect.value = '';
    detailsTextarea.value = '';

    modal.style.display = 'block';
    reasonSelect.focus();
}

function closeReportModal() {
    const modal = document.getElementById('reportModal');
    if (modal) {
        modal.style.display = 'none';
        modal.reportData = null;
    }
}

function submitReport() {
    const modal = document.getElementById('reportModal');
    const reason = document.getElementById('reportReason').value;
    const details = document.getElementById('reportDetails').value.trim();

    if (!reason) {
        alert('Please select a reason for the report.');
        return;
    }

    const reportData = modal.reportData;
    if (!reportData) return;

    const payload = {
        reason,
        details,
        target_username: reportData.target_username
    };

    if (reportData.type === 'message') {
        payload.message_id = reportData.message_id;
        socket.emit('report_message', payload);
    } else {
        socket.emit('report_user', payload);
    }

    closeReportModal();
}

// User Search Implementation
function createUserSearchModal() {
    const modalHTML = `
        <div id="userSearchModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:10000;">
            <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;min-width:400px;max-width:500px;">
                <h3 style="margin:0 0 15px 0;color:var(--primary);">Start Direct Message</h3>
                <div style="margin-bottom:15px;">
                    <input id="userSearchInput" type="text" placeholder="Search for users..." style="width:100%;padding:10px;border:1px solid var(--border);border-radius:4px;background:var(--card);color:var(--primary);">
                </div>
                <div id="userSearchResults" style="max-height:300px;overflow-y:auto;border:1px solid var(--border);border-radius:4px;background:var(--card);">
                    <div style="padding:20px;text-align:center;color:var(--muted);">Type at least 2 characters to search...</div>
                </div>
                <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:15px;">
                    <button id="userSearchCancel" style="padding:8px 16px;border:1px solid var(--border);background:var(--card);color:var(--primary);border-radius:4px;cursor:pointer;">Cancel</button>
                </div>
            </div>
        </div>
    `;

    if (!document.getElementById('userSearchModal')) {
        document.body.insertAdjacentHTML('beforeend', modalHTML);

        // Event listeners
        document.getElementById('userSearchCancel').onclick = () => closeUserSearchModal();
        document.getElementById('userSearchModal').onclick = (e) => {
            if (e.target.id === 'userSearchModal') closeUserSearchModal();
        };

        // Search functionality
        let searchTimeout;
        const searchInput = document.getElementById('userSearchInput');
        const resultsDiv = document.getElementById('userSearchResults');

        searchInput.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            const query = e.target.value.trim();

            if (query.length < 2) {
                resultsDiv.innerHTML = '<div style="padding:20px;text-align:center;color:var(--muted);">Type at least 2 characters to search...</div>';
                return;
            }

            searchTimeout = setTimeout(() => searchUsers(query), 300);
        });
    }
}

async function searchUsers(query) {
    const resultsDiv = document.getElementById('userSearchResults');

    try {
        resultsDiv.innerHTML = '<div style="padding:20px;text-align:center;color:var(--muted);">Searching...</div>';

        const response = await fetch(`/api/users/search?q=${encodeURIComponent(query)}&limit=20`);
        const data = await response.json();

        if (data.users && data.users.length > 0) {
            resultsDiv.innerHTML = data.users.map(user => `
                <div class="user-search-result" data-username="${user.username}" style="display:flex;align-items:center;gap:10px;padding:10px;cursor:pointer;border-bottom:1px solid var(--border);">
                    <img src="${user.avatar || 'https://api.dicebear.com/7.x/initials/svg?seed=' + encodeURIComponent(user.username)}"
                         alt="" style="width:32px;height:32px;border-radius:50%;object-fit:cover;">
                    <div style="flex:1;">
                        <div style="font-weight:bold;color:var(--primary);">@${user.username}</div>
                        <div style="font-size:12px;color:var(--muted);">${user.status || 'offline'} • ${user.bio || 'No bio'}</div>
                    </div>
                    <div style="width:8px;height:8px;border-radius:50%;background:${getStatusColor(user.status)};"></div>
                </div>
            `).join('');

            // Add click handlers
            resultsDiv.querySelectorAll('.user-search-result').forEach(item => {
                item.addEventListener('click', () => {
                    const username = item.dataset.username;
                    closeUserSearchModal();
                    openDM(username);
                });

                item.addEventListener('mouseenter', () => {
                    item.style.background = 'var(--hover)';
                });

                item.addEventListener('mouseleave', () => {
                    item.style.background = 'transparent';
                });
            });
        } else {
            resultsDiv.innerHTML = '<div style="padding:20px;text-align:center;color:var(--muted);">No users found</div>';
        }
    } catch (error) {
        resultsDiv.innerHTML = '<div style="padding:20px;text-align:center;color:var(--error);">Search failed. Please try again.</div>';
    }
}

function getStatusColor(status) {
    switch (status) {
        case 'online': return '#22c55e';
        case 'idle': return '#f59e0b';
        case 'dnd': return '#ef4444';
        default: return '#6b7280';
    }
}

function showUserSearchModal() {
    createUserSearchModal();
    const modal = document.getElementById('userSearchModal');
    modal.style.display = 'block';
    document.getElementById('userSearchInput').focus();
}

function closeUserSearchModal() {
    const modal = document.getElementById('userSearchModal');
    if (modal) {
        modal.style.display = 'none';
        document.getElementById('userSearchInput').value = '';
        document.getElementById('userSearchResults').innerHTML = '<div style="padding:20px;text-align:center;color:var(--muted);">Type at least 2 characters to search...</div>';
    }
}

// Socket.IO event listeners for reporting
socket.on('report_success', (data) => {
    showToast('✅ Report submitted successfully', 'success');
});

socket.on('report_error', (data) => {
    showToast('❌ ' + data.message, 'error');
});

// Toast notification system
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        border-radius: 6px;
        color: white;
        font-weight: 500;
        z-index: 10001;
        max-width: 300px;
        word-wrap: break-word;
        transition: all 0.3s ease;
    `;

    switch (type) {
        case 'success':
            toast.style.background = '#22c55e';
            break;
        case 'error':
            toast.style.background = '#ef4444';
            break;
        default:
            toast.style.background = '#3b82f6';
    }

    toast.textContent = message;
    document.body.appendChild(toast);

    // Animate in
    setTimeout(() => {
        toast.style.transform = 'translateX(0)';
        toast.style.opacity = '1';
    }, 10);

    // Remove after 4 seconds
    setTimeout(() => {
        toast.style.transform = 'translateX(100%)';
        toast.style.opacity = '0';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }, 4000);
}

        // Reports Management Functions
        function openReportsPanel() {
          try {
            document.getElementById('reportsPanel').style.display = 'block';
            // Make panel draggable
            const panel = document.getElementById("reportsPanel");
            const header = panel.querySelector("div");
            let isDragging = false, startX, startY, initialX, initialY;
            header.onmousedown = (e) => {
              isDragging = true;
              startX = e.clientX; startY = e.clientY;
              const rect = panel.getBoundingClientRect();
              initialX = rect.left; initialY = rect.top;
              panel.style.transform = "none";
              panel.style.left = initialX + "px"; panel.style.top = initialY + "px";
            };
            document.onmousemove = (e) => {
              if (!isDragging) return;
              panel.style.left = (initialX + e.clientX - startX) + "px";
              panel.style.top = (initialY + e.clientY - startY) + "px";
            };
            document.onmouseup = () => { isDragging = false; };
            loadReports();
          } catch(e) {
            console.error('Error opening reports panel:', e);
          }
        }

        function closeReportsPanel() {
          try {
            document.getElementById('reportsPanel').style.display = 'none';
          } catch(e) {
            console.error('Error closing reports panel:', e);
          }
        }

        function loadReports(status = 'all', offset = 0, limit = 50) {
          try {
            // Show loading state
            document.getElementById('reportsLoading').style.display = 'block';
            document.getElementById('reportsEmpty').style.display = 'none';
            document.getElementById('reportsList').style.display = 'none';

            // Emit fetch request
            socket.emit('fetch_reports', {
              status: status,
              offset: offset,
              limit: limit
            });
          } catch(e) {
            console.error('Error loading reports:', e);
          }
        }

        function renderReports(data) {
          try {
            const reports = data.reports || [];
            const reportsLoading = document.getElementById('reportsLoading');
            const reportsEmpty = document.getElementById('reportsEmpty');
            const reportsList = document.getElementById('reportsList');

            // Hide loading
            reportsLoading.style.display = 'none';

            if (reports.length === 0) {
              reportsEmpty.style.display = 'block';
              reportsList.style.display = 'none';
              return;
            }

            // Show reports list
            reportsEmpty.style.display = 'none';
            reportsList.style.display = 'block';

            // Render each report
            reportsList.innerHTML = reports.map(report => renderReportItem(report)).join('');

            // Bind event handlers
            bindReportHandlers();
          } catch(e) {
            console.error('Error rendering reports:', e);
          }
        }

        function renderReportItem(report) {
          const statusColors = {
            'pending': '#f59e0b',
            'reviewed': '#3b82f6',
            'resolved': '#10b981',
            'dismissed': '#6b7280'
          };

          const statusColor = statusColors[report.status] || '#6b7280';
          const createdDate = new Date(report.created_at).toLocaleString();
          const resolvedInfo = report.resolved_at ?
            `<div style="font-size:11px;color:var(--muted);margin-top:4px">
              Resolved: ${new Date(report.resolved_at).toLocaleString()} by ${report.resolved_by}
            </div>` : '';

          return `
            <div class="report-item" data-report-id="${report.id}" style="border:1px solid var(--border);border-radius:6px;padding:8px;margin-bottom:8px;background:var(--card);font-size:12px;">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;">
                <div>
                  <span style="font-weight:bold;color:var(--primary);">${report.report_type.toUpperCase()}</span>
                  <span style="background:${statusColor};color:#fff;padding:1px 6px;border-radius:8px;font-size:10px;margin-left:6px;">${report.status.toUpperCase()}</span>
                </div>
                <div style="font-size:10px;color:var(--muted);">${createdDate}</div>
              </div>
              <div style="margin-bottom:6px;font-size:11px;">
                <strong>Target:</strong> ${report.target_username}<br>
                <strong>Reporter:</strong> ${report.reporter_username}<br>
                <strong>Reason:</strong> ${report.reason}
              </div>
              ${report.details ? `<div style="margin-bottom:6px;padding:6px;background:var(--muted);border-radius:3px;font-size:11px;">${report.details}</div>` : ''}
              ${report.admin_notes ? `<div style="margin-bottom:6px;font-size:11px;"><strong>Admin Notes:</strong><br><div style="padding:4px;background:var(--card);border:1px solid var(--border);border-radius:3px;">${report.admin_notes}</div></div>` : ''}
              ${resolvedInfo}
              <div style="display:flex;flex-direction:column;gap:4px;margin-top:8px;">
                <select class="report-status-select" style="padding:3px 6px;border:1px solid var(--border);border-radius:3px;font-size:11px;">
                  <option value="pending" ${report.status === 'pending' ? 'selected' : ''}>Pending</option>
                  <option value="reviewed" ${report.status === 'reviewed' ? 'selected' : ''}>Reviewed</option>
                  <option value="resolved" ${report.status === 'resolved' ? 'selected' : ''}>Resolved</option>
                  <option value="dismissed" ${report.status === 'dismissed' ? 'selected' : ''}>Dismissed</option>
                </select>
                <input class="report-notes-input" type="text" placeholder="Admin notes..." value="${report.admin_notes || ''}" style="padding:3px 6px;border:1px solid var(--border);border-radius:3px;font-size:11px;">
                <div style="display:flex;gap:4px;">
                  <button class="update-report-btn" type="button" style="flex:1;padding:3px 8px;background:#3b82f6;color:#fff;border:none;border-radius:3px;cursor:pointer;font-size:10px;">Update</button>
                  <button class="delete-report-btn" type="button" style="flex:1;padding:3px 8px;background:#dc2626;color:#fff;border:none;border-radius:3px;cursor:pointer;font-size:10px;">Delete</button>
                </div>
              </div>
            </div>
          `;
        }

        function bindReportHandlers() {
          try {
            // Update report handlers
            document.querySelectorAll('.update-report-btn').forEach(btn => {
              btn.onclick = function() {
                const reportItem = this.closest('.report-item');
                const reportId = reportItem.dataset.reportId;
                const status = reportItem.querySelector('.report-status-select').value;
                const notes = reportItem.querySelector('.report-notes-input').value;

                socket.emit('update_report_status', {
                  report_id: parseInt(reportId),
                  status: status,
                  admin_notes: notes
                });
              };
            });

            // Delete report handlers
            document.querySelectorAll('.delete-report-btn').forEach(btn => {
              btn.onclick = function() {
                const reportItem = this.closest('.report-item');
                const reportId = reportItem.dataset.reportId;

                if (confirm('Are you sure you want to delete this report? This action cannot be undone.')) {
                  socket.emit('delete_report', {
                    report_id: parseInt(reportId)
                  });
                }
              };
            });
          } catch(e) {
            console.error('Error binding report handlers:', e);
          }
        }

        // Socket.IO event listeners for reports
        socket.on('reports_data', renderReports);

        socket.on('reports_error', function(data) {
          try {
            document.getElementById('reportsLoading').style.display = 'none';
            showToast('Error loading reports: ' + (data.message || 'Unknown error'), 'error');
          } catch(e) {
            console.error('Error handling reports_error:', e);
          }
        });

        socket.on('report_update_success', function(data) {
          try {
            showToast('Report updated successfully!', 'ok');
            loadReports(); // Refresh the list
          } catch(e) {
            console.error('Error handling report_update_success:', e);
          }
        });

        socket.on('report_update_error', function(data) {
          try {
            showToast('Error updating report: ' + (data.message || 'Unknown error'), 'error');
          } catch(e) {
            console.error('Error handling report_update_error:', e);
          }
        });

        socket.on('report_delete_success', function(data) {
          try {
            showToast('Report deleted successfully!', 'ok');
            loadReports(); // Refresh the list
          } catch(e) {
            console.error('Error handling report_delete_success:', e);
          }
        });

        socket.on('report_delete_error', function(data) {
          try {
            showToast('Error deleting report: ' + (data.message || 'Unknown error'), 'error');
          } catch(e) {
            console.error('Error handling report_delete_error:', e);
          }
        });

        // Bind reports button click handler
        try {
          const reportsBtn = document.getElementById('btnReportsSettings');
          if (reportsBtn) {
            reportsBtn.onclick = openReportsPanel;
          }
        } catch(e) {
          console.error('Error binding reports button:', e);
        }

        // Bind panel close handlers
        try {
          const closeBtn = document.getElementById('closeReports');
          const refreshBtn = document.getElementById('refreshReports');

          if (closeBtn) closeBtn.onclick = closeReportsPanel;
          if (refreshBtn) refreshBtn.onclick = () => loadReports();
        } catch(e) {
          console.error('Error binding panel handlers:', e);
        }
    </script>

    <!-- Notification System JavaScript -->
    <script>
    class NotificationSystem {
        constructor() {
            this.container = document.getElementById('notificationContainer');
            this.notifications = new Set();

            // Auto-close notifications after 5 seconds by default
            this.autoClose = true;
            this.defaultDuration = 5000;
        }

        /**
         * Show a notification
         * @param {string} title - Notification title
         * @param {string} message - Notification message
         * @param {string} type - Notification type (success, error, info, warning)
         * @param {number} duration - Duration in milliseconds (0 for no auto-close)
         */
        show(title, message, type = 'info', duration = null) {
            if (duration === null) {
                duration = this.defaultDuration;
            }

            const notification = document.createElement('div');
            notification.className = `notification ${type}`;

            // Icons for different notification types
            const icons = {
                success: '✓',
                error: '✕',
                warning: '⚠',
                info: 'ℹ'
            };

            notification.innerHTML = `
                <span class="notification-icon">${icons[type] || icons.info}</span>
                <div class="notification-content">
                    <div class="notification-title">${title}</div>
                    <div class="notification-message">${message}</div>
                </div>
                <button class="notification-close">&times;</button>
                ${duration > 0 ? '<div class="progress-bar"></div>' : ''}
            `;

            // Add close event
            const closeBtn = notification.querySelector('.notification-close');
            closeBtn.addEventListener('click', () => this.close(notification));

            // Add to container
            this.container.appendChild(notification);

            // Trigger animation
            setTimeout(() => notification.classList.add('show'), 10);

            // Auto-close if duration is set
            if (duration > 0 && this.autoClose) {
                const progressBar = notification.querySelector('.progress-bar');
                if (progressBar) {
                    progressBar.style.transition = `transform ${duration}ms linear`;
                    setTimeout(() => {
                        if (progressBar) {
                            progressBar.style.transform = 'scaleX(0)';
                        }
                    }, 10);
                }

                const timer = setTimeout(() => this.close(notification), duration);
                notification._timer = timer;
            }

            // Add to tracking set
            this.notifications.add(notification);

            return notification;
        }

        /**
         * Close a notification
         * @param {HTMLElement} notification - The notification element to close
         */
        close(notification) {
            if (!notification) return;

            // Clear the auto-close timer if it exists
            if (notification._timer) {
                clearTimeout(notification._timer);
            }

            // Animate out
            notification.classList.remove('show');

            // Remove from DOM after animation
            setTimeout(() => {
                if (notification.parentNode === this.container) {
                    this.container.removeChild(notification);
                }
                this.notifications.delete(notification);
            }, 300);
        }

        // Convenience methods for different notification types
        success(title, message, duration = null) {
            return this.show(title, message, 'success', duration);
        }

        error(title, message, duration = null) {
            return this.show(title, message, 'error', duration);
        }

        info(title, message, duration = null) {
            return this.show(title, message, 'info', duration);
        }

        warning(title, message, duration = null) {
            return this.show(title, message, 'warning', duration);
        }
    }

    // Initialize notification system
    const notifications = new NotificationSystem();

    // Make it globally available
    window.notify = notifications;

    // Example usage:
    // notify.success('Success!', 'Your message has been sent successfully.');
    // notify.error('Error', 'Failed to send message. Please try again.');
    // notify.info('Info', 'This is an informational message.');
    // notify.warning('Warning', 'This action cannot be undone.');

    // Test notification system on page load
    document.addEventListener('DOMContentLoaded', () => {
        // Show a welcome notification
        setTimeout(() => {
            notifications.success('Welcome!', 'Chatter is functioning normally!');
        }, 1000);

        // Add notification for new messages
        if (typeof socket !== 'undefined') {
            socket.on('message', (data) => {
                if (data.username && data.username !== '{{ username }}') {
                    notifications.info('New Message', `${data.username}: ${data.message.substring(0, 50)}${data.message.length > 50 ? '...' : ''}`);
                }
            });

            // Add notification for mentions
            socket.on('gdm_message', (data) => {
                if (data.content && data.content.includes('@{{ username }}')) {
                    notifications.warning('Mention', `You were mentioned by ${data.sender} in ${data.thread_name}`);
                }
            });
        }
    });
    </script>
    <script>
        // Add to the end of your JavaScript
        console.log('Loaded at:', new Date().toISOString());
    </script>
</body>
</html>
"""

@app.context_processor
def inject():
    return dict(base_css=BASE_CSS)

# Serve uploaded files
@app.route('/uploads/<path:filename>')
def serve_uploaded_file(filename):
    """Serve uploaded files by filename"""
    try:
        # Security check - prevent directory traversal
        if '..' in filename or filename.startswith('/'):
            abort(404)
            
        # Check if file exists in uploads folder
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.exists(file_path):
            abort(404)
        
        # Serve the file
        return send_from_directory(UPLOAD_FOLDER, filename)
    except Exception:
        abort(404)

# Run the application
if __name__ == "__main__":
    with app.app_context():
        init_db()
        migrate_avatars_to_folder()  # Move existing avatars to avatars/ folder
        recover_failed_username_changes()  # Recover from any failed username changes
        load_banned_ips()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, allow_unsafe_werkzeug=True)
