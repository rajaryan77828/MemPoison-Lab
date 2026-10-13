"""
AegisMemory Lab - Input Validation & Defensive Sanitization
Authors: LO & ENI

Enforces strict input validation, file size limits, HTML escaping,
and path traversal prevention.
"""

import html
import json
import re
from typing import Tuple, Dict, Any, List

MAX_UPLOAD_SIZE_BYTES = 1024 * 1024 * 2 # 2 MB
MAX_ROWS_CSV = 500

def sanitize_for_display(text: str) -> str:
    """Escapes HTML and script tags to prevent stored XSS when rendering in Streamlit/HTML."""
    if not text:
        return ""
    # Standard HTML entity replacement
    return html.escape(text)

def validate_imported_json(json_str: str) -> Tuple[bool, Any, str]:
    """Validates uploaded scenario or memory JSON payloads."""
    if len(json_str.encode("utf-8")) > MAX_UPLOAD_SIZE_BYTES:
        return False, None, "File exceeds maximum allowed upload size (2 MB)."

    try:
        data = json.loads(json_str)
        return True, data, "JSON structure valid."
    except json.JSONDecodeError as e:
        return False, None, f"Invalid JSON format: {str(e)}"

def sanitize_identifier(ident: str) -> str:
    """Ensures user, tenant, and experiment IDs contain only safe alphanumeric characters."""
    return re.sub(r"[^a-zA-Z0-9_\-\.]", "", ident)
