#!/usr/bin/env python
# This file is part of Archivematica.
#
# Copyright 2010-2013 Artefactual Systems Inc. <http://artefactual.com>
#
# Archivematica is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Archivematica is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Archivematica.  If not, see <http://www.gnu.org/licenses/>.
import base64
import json
import os
import re
import shutil
import time
import uuid
import datetime
import hashlib

import django
import requests

# Simple in-process cache for Cognito token to avoid fetching for each file
_cognito_token_cache = {"access_token": None, "expiry_ts": 0}

django.setup()
from django.core.exceptions import ValidationError
from django.db import transaction

from archivematica.archivematicaCommon import bag
from archivematica.archivematicaCommon.archivematicaFunctions import OPTIONAL_FILES
from archivematica.archivematicaCommon.archivematicaFunctions import REQUIRED_DIRECTORIES
from archivematica.archivematicaCommon.archivematicaFunctions import create_structured_directory
from archivematica.archivematicaCommon.archivematicaFunctions import reconstruct_empty_directories
from archivematica.archivematicaCommon.custom_handlers import get_script_logger
from archivematica.dashboard.main.models import SIP, Transfer, UnitVariable, PACKAGE_STATUS_FAILED
from archivematica.archivematicaCommon import fileOperations
import errno

logger = get_script_logger("archivematica.mcp.client.restructureForCompliance")

# Small helper for iconified logs printed both to job output and the logger
_icons = {
    "info": "ℹ️",
    "success": "✅",
    "error": "❌",
    "warn": "⚠️",
    "debug": "🐛",
    "move": "➡️",
    "call": "🔁",
    "http": "🌐",
}


def _job_log(job, level, msg, icon_key=None, *args, **kwargs):
    """Print to job.pyprint and logger with an optional icon prefix.

    level: 'info', 'error', 'warn', 'debug', 'success'
    icon_key: key from _icons to choose an icon
    msg may be a format string; args/kwargs forwarded to logger
    """
    icon = _icons.get(icon_key) if icon_key else ""
    # Format message for job output (simple interpolation)
    try:
        job_msg = msg.format(*args, **kwargs) if args or kwargs else msg
    except Exception:
        job_msg = msg
    out = f"{icon} {job_msg}" if icon else job_msg
    try:
        job.pyprint(out)
    except Exception:
        # If job has no pyprint, still continue logging
        pass

    # Log to the configured logger at the requested level
    log_msg = out
    if level == "info":
        logger.info(log_msg)
    elif level == "error":
        logger.error(log_msg)
    elif level in ("warn", "warning"):
        logger.warning(log_msg)
    elif level == "debug":
        logger.debug(log_msg)
    elif level == "success":
        # map 'success' to info but keep icon
        logger.info(log_msg)
    else:
        logger.info(log_msg)


def _fetch_cognito_token(django_settings, job, timeout=None):
    """Fetch an OAuth2 token from Cognito using client_credentials.

    Uses an in-memory cache keyed to the process lifetime to avoid repeated
    token requests. Respects the `expires_in` field returned by Cognito if
    present.

    Returns the access_token string or None on failure.
    """
    # Defaults provided by the user (used only if settings are missing).
    DEFAULT_CLIENT_ID = getattr(
        django_settings, "IPDS_RE_PRESERVATION_COGNITO_CLIENT_ID", "4jheas80l5e79c4peue3gonh7m"
    )
    DEFAULT_CLIENT_SECRET = getattr(
        django_settings,
        "IPDS_RE_PRESERVATION_COGNITO_CLIENT_SECRET",
        "pc6n26cdc60efn99vi8ms8if636g6i0btaeuamo2ooho57qlouh",
    )
    DEFAULT_TOKEN_URL = getattr(
        django_settings,
        "IPDS_RE_PRESERVATION_COGNITO_TOKEN_URL",
        "https://api-auth-dev-logalty.auth.eu-west-1.amazoncognito.com/oauth2/token",
    )

    # Default scope for Cognito token requests (can be overridden in settings)
    DEFAULT_SCOPE = getattr(django_settings, "IPDS_RE_PRESERVATION_COGNITO_SCOPE", "dss/certificate-validation")

    client_id = getattr(django_settings, "IPDS_RE_PRESERVATION_COGNITO_CLIENT_ID", DEFAULT_CLIENT_ID)
    client_secret = getattr(django_settings, "IPDS_RE_PRESERVATION_COGNITO_CLIENT_SECRET", DEFAULT_CLIENT_SECRET)
    token_url = getattr(django_settings, "IPDS_RE_PRESERVATION_COGNITO_TOKEN_URL", DEFAULT_TOKEN_URL)
    scope = getattr(django_settings, "IPDS_RE_PRESERVATION_COGNITO_SCOPE", DEFAULT_SCOPE)

    # If any of the required bits are missing, skip token retrieval
    if not client_id or not client_secret or not token_url:
        return None

    # Return cached token if still valid
    now = time.time()
    cached = _cognito_token_cache
    if cached.get("access_token") and cached.get("expiry_ts", 0) > now + 5:
        _job_log(job, "info", "[ipds-re-preservation] using cached Cognito token", icon_key="debug")
        return cached["access_token"]

    try:
        _job_log(job, "info", "[ipds-re-preservation] obtaining Cognito token via client_credentials grant", icon_key="call")
        credentials = f"{client_id}:{client_secret}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {encoded}",
        }
        data = {"grant_type": "client_credentials"}
        if scope:
            data["scope"] = scope

        request_timeout = timeout or getattr(django_settings, "IPDS_RE_PRESERVATION_COGNITO_TIMEOUT", 10)
        verify = getattr(django_settings, "IPDS_RE_PRESERVATION_VERIFY", True)
        _job_log(job, "debug", "[ipds-re-preservation] sending request to cognito token endpoint with timeout={request_timeout} and verify={verify} and data={data}", icon_key="debug", request_timeout=request_timeout, verify=verify, data=data)
        resp = requests.post(token_url, data=data, headers=headers, timeout=request_timeout, verify=verify)
        resp.raise_for_status()
        j = resp.json()
        token = j.get("access_token")
        if not token:
            _job_log(job, "error", "[ipds-re-preservation] Cognito response did not include access_token", icon_key="error")
            return None

        # Cache token using expires_in when available
        expires_in = j.get("expires_in")
        if isinstance(expires_in, (int, float)) and expires_in > 0:
            expiry_ts = time.time() + float(expires_in)
        else:
            # default short lived cache (e.g., 55 seconds) to avoid refetch storms
            expiry_ts = time.time() + 55

        _cognito_token_cache["access_token"] = token
        _cognito_token_cache["expiry_ts"] = expiry_ts

        _job_log(job, "success", "[ipds-re-preservation] obtained Cognito access token", icon_key="success")
        return token
    except requests.exceptions.RequestException as exc:
        _job_log(job, "error", f"[ipds-re-preservation] error fetching Cognito token: {exc}", icon_key="error")
        logger.debug("Cognito token response content: %s", getattr(getattr(exc, 'response', None), "text", None))
        return None
    except Exception as exc:
        _job_log(job, "error", f"[ipds-re-preservation] unexpected error fetching Cognito token: {exc}", icon_key="error")
        return None


def _get_ipds_re_preservation(unit_uuid):
    """Read the ipds-re-preservation flag, ipds-doc-name and ipds-doc-id from UnitVariable misc_attributes.

    Returns a tuple (ipds_re_preservation: bool, ipds_doc_name: str, ipds_doc_id: str).

    Behavior: when multiple `misc_attributes` records exist, prefer the first one (by pk DESC)
    that contains the key 'ipds-re-preservation'. If none contains that key, fall back to
    the most recent misc_attributes (pk DESC) and extract values if present.
    """
    try:
        # Fetch all misc_attributes for both Transfer and SIP, preferring Transfer first then SIP
        for unit_type in ("Transfer", "SIP"):
            try:
                q = UnitVariable.objects.filter(unittype=unit_type, unituuid=unit_uuid, variable="misc_attributes").order_by("-pk")
            except Exception:
                q = []

            if not q:
                continue

            # Try to find an entry that explicitly contains the key 'ipds-re-preservation'
            chosen = None
            for uv in q:
                try:
                    raw = uv.variablevalue or "{}"
                    if isinstance(raw, (bytes, bytearray)):
                        raw = raw.decode("utf-8")
                    attrs = json.loads(raw)
                except Exception:
                    # Skip malformed JSON entries
                    continue

                if isinstance(attrs, dict) and "ipds-re-preservation" in attrs:
                    chosen = attrs
                    break

            # If none contained the key, fall back to the most recent entry
            if chosen is None:
                try:
                    raw = q[0].variablevalue or "{}"
                    if isinstance(raw, (bytes, bytearray)):
                        raw = raw.decode("utf-8")
                    chosen = json.loads(raw)
                except Exception:
                    chosen = {}

            if not isinstance(chosen, dict):
                chosen = {}

            # Normalize values
            def _to_bool(v):
                if isinstance(v, bool):
                    return v
                if v is None:
                    return False
                if isinstance(v, (int, float)):
                    return bool(v)
                if isinstance(v, str):
                    return v.strip().lower() in ("1", "true", "yes", "y")
                return False

            re_preservation = _to_bool(chosen.get("ipds-re-preservation"))
            doc_name = (chosen.get("ipds-doc-name") or "").strip()
            doc_id = (chosen.get("ipds-doc-id") or "").strip()

            if re_preservation or doc_name or doc_id:
                logger.info(
                    "ipds flags found in UnitVariable for %s %s: re_preservation=%s, doc_name=%s, doc_id=%s",
                    unit_type,
                    unit_uuid,
                    re_preservation,
                    doc_name or "(all files)",
                    doc_id or "",
                )
                return re_preservation, doc_name, doc_id
    except Exception:
        logger.exception("Error reading UnitVariable misc_attributes for %s", unit_uuid)

    return False, "", ""


# === START ADDED: validation helper functions ===

def _parse_dss_datetime(value):
    """Parse DSS date values.

    Supports:
    - ISO-8601 string, e.g. '2026-05-27T10:11:02Z'
    - epoch milliseconds as int/float

    Returns a timezone-aware UTC datetime or None.
    """
    try:
        if isinstance(value, (int, float)):
            return datetime.datetime.fromtimestamp(
                float(value) / 1000.0, tz=datetime.timezone.utc
            )

        if isinstance(value, str):
            s = value.strip()
            if not s:
                return None
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt
    except Exception:
        return None

    return None


def _extract_extension_period_max(resp_json):
    """Extract the earliest ExtensionPeriodMax from DSS validation JSON.

    Mirrors the Java DssService.extractExtensionPeriodMax():
    - read SimpleReport
    - get entries from signatureOrTimestampOrEvidenceRecord or signatureOrTimestamp
    - for each entry inspect Signature, then Timestamp, then EvidenceRecord
    - parse ExtensionPeriodMax
    - if none found, fall back to earliest certificate NotAfter from DiagnosticData
    """
    if not resp_json or not isinstance(resp_json, dict):
        logger.debug("_extract_extension_period_max: empty or invalid resp_json")
        return None

    simple_report = (
            resp_json.get("SimpleReport")
            or resp_json.get("simpleReport")
            or resp_json.get("simple_report")
    )

    if not isinstance(simple_report, dict):
        logger.debug("_extract_extension_period_max: SimpleReport missing or not a dict")
        return _extract_earliest_certificate_not_after(resp_json)

    entries = (
            simple_report.get("signatureOrTimestampOrEvidenceRecord")
            or simple_report.get("signatureOrTimestamp")
            or []
    )

    if isinstance(entries, dict):
        entries = [entries]
    elif not isinstance(entries, list):
        entries = []

    earliest = None
    parsed_count = 0

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        node = (
                entry.get("Signature")
                or entry.get("Timestamp")
                or entry.get("EvidenceRecord")
        )

        if not isinstance(node, dict):
            continue

        raw_value = node.get("ExtensionPeriodMax")
        if raw_value is None:
            continue

        candidate = _parse_dss_datetime(raw_value)
        if candidate is None:
            logger.warning("Could not parse ExtensionPeriodMax value: %r", raw_value)
            continue

        parsed_count += 1
        logger.debug(
            "_extract_extension_period_max: parsed ExtensionPeriodMax=%s",
            candidate.isoformat(),
        )

        if earliest is None or candidate < earliest:
            earliest = candidate

    logger.debug(
        "_extract_extension_period_max: entries inspected=%d, dates parsed=%d",
        len(entries),
        parsed_count,
    )

    if earliest is not None:
        logger.info(
            "_extract_extension_period_max: final earliest=%s",
            earliest.isoformat(),
        )
        return earliest

    logger.debug(
        "_extract_extension_period_max: no ExtensionPeriodMax found, trying certificate NotAfter fallback"
    )
    fallback = _extract_earliest_certificate_not_after(resp_json)
    if fallback is not None:
        logger.info(
            "_extract_extension_period_max: fallback earliest certificate NotAfter=%s",
            fallback.isoformat(),
        )
    else:
        logger.info("_extract_extension_period_max: no extension date found")
    return fallback


def _extract_earliest_certificate_not_after(resp_json):
    """Extract earliest certificate NotAfter from DSS DiagnosticData.

    Mirrors Java DssService.extractEarliestCertificateNotAfter():
    - DiagnosticData.UsedCertificates.Certificate[]
    - fallback to DiagnosticData.Certificate[]
    """
    if not resp_json or not isinstance(resp_json, dict):
        return None

    diagnostic = (
            resp_json.get("DiagnosticData")
            or resp_json.get("diagnosticData")
            or {}
    )

    if not isinstance(diagnostic, dict):
        return None

    certs = None

    used = diagnostic.get("UsedCertificates")
    if isinstance(used, dict):
        certs = used.get("Certificate")

    if certs is None:
        certs = diagnostic.get("Certificate")

    if isinstance(certs, dict):
        certs = [certs]
    elif not isinstance(certs, list):
        certs = []

    candidates = []

    for cert in certs:
        if not isinstance(cert, dict):
            continue

        raw = cert.get("NotAfter")
        dt = _parse_dss_datetime(raw)
        if dt is not None:
            candidates.append(dt)
            logger.debug(
                "_extract_earliest_certificate_not_after: parsed NotAfter=%s",
                dt.isoformat(),
            )

    if not candidates:
        logger.info("_extract_earliest_certificate_not_after: no certificate NotAfter found")
        return None

    earliest = min(candidates)
    logger.info(
        "_extract_earliest_certificate_not_after: earliest=%s",
        earliest.isoformat(),
    )
    return earliest

def _call_signature_extension_service(job, sip_path, sip_uuid=None, ipds_doc_name="", ipds_doc_id=""):
    """Send the original document bytes to the external re-preservation service.

    Settings:
      - IPDS_RE_PRESERVATION_SERVICE_URL (str)
      - IPDS_RE_PRESERVATION_SERVICE_HEADERS (dict)
      - IPDS_RE_PRESERVATION_SIGNATURE_LEVEL (str, default "PAdES_BASELINE_LTA")
      - IPDS_RE_PRESERVATION_TIMEOUT (int, seconds)
      - IPDS_RE_PRESERVATION_VERIFY (bool | str)

    The response JSON is expected to contain the extended document bytes in
    `bytes` (base64) at the top level or nested under `document.bytes`.

    Returns True if all targeted files were successfully replaced, False otherwise.
    """
    from django.conf import settings as django_settings

    # Locate objects dir
    objects_dir = os.path.join(sip_path, "objects")
    if not os.path.isdir(objects_dir):
        objects_dir = os.path.join(sip_path, "data", "objects")

    if not os.path.isdir(objects_dir):
        _job_log(job, "error", f"[ipds-re-preservation] objects directory not found under {sip_path}", icon_key="error")
        return False

    _job_log(job, "info", "[ipds-re-preservation] CALLING SIGNATURE EXTENSION EXTERNAL SERVICE (IPDS)!", icon_key="call")

    # Gather regular files sorted for deterministic order
    all_files = [
        os.path.join(objects_dir, f)
        for f in sorted(os.listdir(objects_dir))
        if os.path.isfile(os.path.join(objects_dir, f))
    ]

    if not all_files:
        _job_log(job, "warn", f"[ipds-re-preservation] no files found in objects directory: {objects_dir}", icon_key="warn")
        return False

    _job_log(job, "info", f"[ipds-re-preservation] found {len(all_files)} file(s) in objects directory", icon_key="info")
    for fp in all_files:
        _job_log(job, "debug", f"[ipds-re-preservation]   {fp}", icon_key="debug")

    # Filter by ipds_doc_name if provided
    if ipds_doc_name:
        logger.info(
            "[ipds-re-preservation] ipds-doc-name='%s', filtering to that file only",
            ipds_doc_name,
        )
        target_files = [
            fp for fp in all_files if os.path.basename(fp) == ipds_doc_name
        ]
        for fp in all_files:
            if os.path.basename(fp) != ipds_doc_name:
                _job_log(job, "debug", f"[ipds-re-preservation] skipping {os.path.basename(fp)} (does not match ipds-doc-name='{ipds_doc_name}')", icon_key="debug")
        if not target_files:
            _job_log(job, "error", f"[ipds-re-preservation] no file matching ipds-doc-name='{ipds_doc_name}' found in {objects_dir}", icon_key="error")
            return False
    else:
        target_files = all_files

    external_service_url = getattr(
        django_settings,
        "IPDS_RE_PRESERVATION_SERVICE_URL",
        "https://desarrollo.logalty.com/dss/services/rest/signature/one-document/extendDocument",
    )
    service_headers = getattr(django_settings, "IPDS_RE_PRESERVATION_SERVICE_HEADERS", None)
    signature_level = getattr(
        django_settings, "IPDS_RE_PRESERVATION_SIGNATURE_LEVEL", "PAdES_BASELINE_LTA"
    )
    configured_digest = getattr(django_settings, "IPDS_RE_PRESERVATION_DIGEST_ALGORITHM", "SHA256")
    timeout = getattr(django_settings, "IPDS_RE_PRESERVATION_TIMEOUT", 60)
    verify = getattr(django_settings, "IPDS_RE_PRESERVATION_VERIFY", True)

    # Build default headers for JSON
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if service_headers:
        headers.update(service_headers)

    # If no Authorization header provided in service_headers, obtain Cognito token and fail if not retrieved
    try:
        if "Authorization" not in {k.title(): v for k, v in headers.items()}:
            token = _fetch_cognito_token(django_settings, job, timeout=10)
            if not token:
                _job_log(job, "error", "[ipds-re-preservation] error: failed to obtain Cognito token; aborting request", icon_key="error")
                return False
            headers["Authorization"] = f"Bearer {token}"
            _job_log(job, "info", "[ipds-re-preservation] added Authorization: Bearer token to request headers", icon_key="info")
    except Exception as exc:
        # If anything unexpected happens while obtaining the token, fail the operation
        _job_log(job, "error", f"[ipds-re-preservation] error obtaining Cognito token: {exc}; aborting request", icon_key="error")
        logger.debug("Exception while fetching Cognito token", exc_info=exc)
        return False

    for file_path in target_files:
        file_name = os.path.basename(file_path)
        _job_log(job, "info", f"[ipds-re-preservation] sending '{file_name}' to {external_service_url}", icon_key="http")

        try:
            with open(file_path, "rb") as fh:
                file_bytes_b64 = base64.b64encode(fh.read()).decode("ascii")

            payload = {
                "toExtendDocument": {
                    "bytes": file_bytes_b64,
                    "name": file_name,
                },
                "parameters": {
                    "signatureLevel": signature_level,
                },
            }
            _job_log(job,"debug",f"[ipds-re-preservation] sending payload data name'{file_name}' and parameters signatureLevel '{signature_level}' to {external_service_url}")
            # Make the HTTP request with retries for transient server/network errors.
            max_retries = getattr(django_settings, "IPDS_RE_PRESERVATION_RETRIES", 2)
            backoff_base = getattr(django_settings, "IPDS_RE_PRESERVATION_BACKOFF_BASE", 5)
            attempt = 0
            resp = None
            while attempt < max_retries:
                attempt += 1
                try:
                    _job_log(job, "debug", f"[ipds-re-preservation] HTTP request attempt {attempt}/{max_retries} for file '{file_name}' to url '{external_service_url}'", icon_key="http")
                    resp = requests.post(
                        external_service_url,
                        json=payload,
                        headers=headers,
                        timeout=timeout,
                        verify=verify,
                    )
                    # If server returns 5xx, consider retrying
                    if 500 <= getattr(resp, "status_code", 0) < 600:
                        body = None
                        try:
                            body = resp.text
                        except Exception:
                            body = "<unable to read response body>"
                        _job_log(job, "warn", f"[ipds-re-preservation] HTTP {resp.status_code} response from external service for '{file_name}': {body[:1000]} (attempt {attempt})", icon_key="http")
                        if attempt < max_retries:
                            sleep_for = backoff_base * (2 ** (attempt - 1))
                            _job_log(job, "info", f"[ipds-re-preservation] retrying in {sleep_for}s...", icon_key="info")
                            time.sleep(sleep_for)
                            continue
                        else:
                            # give up after max_retries
                            resp.raise_for_status()
                    else:
                        # For non-5xx responses just check status and proceed
                        resp.raise_for_status()
                    # Successful response -> break the retry loop
                    break
                except requests.exceptions.RequestException as exc:
                    # Network error or HTTP error raised by raise_for_status()
                    if attempt < max_retries and (isinstance(exc, requests.exceptions.HTTPError) and getattr(resp, "status_code", 0) >= 500 or not isinstance(exc, requests.exceptions.HTTPError)):
                        sleep_for = backoff_base * (2 ** (attempt - 1))
                        _job_log(job, "warn", f"[ipds-re-preservation] request error for '{file_name}': {exc} (attempt {attempt}), retrying in {sleep_for}s", icon_key="http")
                        time.sleep(sleep_for)
                        continue
                    # No more retries — log response body if available and re-raise
                    body = None
                    try:
                        if resp is not None:
                            body = resp.text
                    except Exception:
                        body = "<unable to read response body>"
                    _job_log(job, "warn", f"[ipds-re-preservation] HTTP error from external service for '{file_name}': {exc} - response: {body[:1000]}", icon_key="http")
                    # Treat external service HTTP errors as fatal for the transfer
                    return False

            # Parse response — expect JSON with extended document bytes (base64)
            try:
                resp_json = resp.json()
            except Exception as exc:
                _job_log(job, "error", f"[ipds-re-preservation] failed to parse JSON response for '{file_name}': {exc}", icon_key="error")
                return False

            # Support both flat {"bytes": "..."} and nested {"document": {"bytes": "..."}}
            extended_b64 = (
                    resp_json.get("bytes")
                    or (resp_json.get("document") or {}).get("bytes")
            )
            # UNCOMMENT FOR TESTING WITHOUT EXTERNAL SERVICE: use hardcoded pdf
            #obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            #obj2 = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            #obj3 = b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
            #obj4 = b"4 0 obj\n<< /Length 36 >>\nstream\nBT\n/F1 24 Tf\n72 72 Td\n(TEST) Tj\nET\nendstream\nendobj\n"
            #obj5 = b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"

            #pdf_bytes = b"%PDF-1.4\n" + obj1 + obj2 + obj3 + obj4 + obj5

            #offset_1 = len(b"%PDF-1.4\n")
            #offset_2 = offset_1 + len(obj1)
            #offset_3 = offset_2 + len(obj2)
            #offset_4 = offset_3 + len(obj3)
            #offset_5 = offset_4 + len(obj4)
            #xref_offset = len(pdf_bytes)

                #pdf_bytes += (
                    #b"xref\n"
                    #b"0 6\n"
                    #b"0000000000 65535 f \n"
                    #+ f"{offset_1:010d} 00000 n \n".encode()
                    #+ f"{offset_2:010d} 00000 n \n".encode()
                    #+ f"{offset_3:010d} 00000 n \n".encode()
                    #+ f"{offset_4:010d} 00000 n \n".encode()
                    #+ f"{offset_5:010d} 00000 n \n".encode()
                    #+ b"trailer\n"
                    #  b"<< /Size 6 /Root 1 0 R >>\n"
                    #  b"startxref\n"
                    #+ str(xref_offset).encode()
                #+ b"\n%%EOF\n"
            #)

            #extended_b64 = base64.b64encode(pdf_bytes).decode("ascii")

            if not extended_b64:
                _job_log(job, "error", f"[ipds-re-preservation] unexpected response for '{file_name}': no 'bytes' field found. Response keys: {list(resp_json.keys())}", icon_key="error")
                # Treat missing bytes as fatal for the transfer
                return False

            try:
                extended_bytes = base64.b64decode(extended_b64)
            except Exception as exc:
                _job_log(job, "error", f"[ipds-re-preservation] failed to decode extended bytes for '{file_name}': {exc}", icon_key="error")
                return False
            # COPY extended bytes back to the original file, replacing it
            try:
                with open(file_path, "wb") as out_f:
                    out_f.write(extended_bytes)
            except OSError as exc:
                _job_log(job, "error", f"[ipds-re-preservation] I/O error while writing extended file for '{file_name}': {exc}", icon_key="error")
                logger.exception("I/O error while writing %s", file_name)
                return False

            _job_log(job, "success", f"[ipds-re-preservation] ✅✅✅ '{file_name}' replaced with extended-signature version ({len(extended_bytes)} bytes)", icon_key="success")

            # --- START: VALIDATE SIGNATURE AND EXTRACT ExtensionPeriodMax ---
            try:
                try:
                    from django.conf import settings as django_settings
                except Exception:
                    django_settings = None
                period = None
                try:
                    period = _validate_signature_and_extract_extension(job, extended_bytes, file_name, django_settings, headers=headers, timeout=timeout)
                    #period = datetime.datetime.now(datetime.timezone.utc)

                except Exception as exc:
                    _job_log(job, "error", f"[ipds-re-preservation] validation call failed for '{file_name}': {exc}", icon_key="error")
                    logger.exception("Validation call failed for %s", file_name)
                    # Treat exception as failure of validation: fail transfer immediately
                    return False

                if period:
                    try:
                        _job_log(job, "info", f"[ipds-re-preservation] ExtensionPeriodMax para '{file_name}': {period.isoformat()}", icon_key="info")
                    except Exception:
                        _job_log(job, "info", f"[ipds-re-preservation] ExtensionPeriodMax para '{file_name}': {period}", icon_key="info")
                else:
                    _job_log(job, "error", f"[ipds-re-preservation] No ExtensionPeriodMax found or could not extract it for '{file_name}'", icon_key="error")
                    # Treat missing period as fatal
                    return False
            except Exception as exc:
                _job_log(job, "error", f"[ipds-re-preservation] error validating signature for '{file_name}': {exc}", icon_key="error")
                logger.exception("Validation extraction failed for %s", file_name)
                return False
            # --- END: VALIDATE SIGNATURE ---

            # --- START: SEND EVENT TO IPDS ---
            # Send extension event; if it fails, fail the transfer
            try:
                # Compute hash and filesize of the extended document and send them with the event
                try:
                    # configured_digest is available in this scope from earlier in the function
                    algorithm = (configured_digest.lower().replace('-', '').replace('_', '')) if configured_digest else 'sha256'
                    h = hashlib.new(algorithm)
                    h.update(extended_bytes)
                    hash_hex = h.hexdigest()
                    file_size = len(extended_bytes)
                except Exception as exc:
                    _job_log(job, "warn", f"[ipds-re-preservation] could not compute hash/filesize for '{file_name}': {exc}", icon_key="warn")
                    hash_hex = None
                    file_size = None
                # Send the event using ipds_doc_id (if provided) instead of the AIP UUID
                sent = _send_extension_event_to_ipds(
                    job,
                    ipds_doc_id or sip_uuid,
                    period,
                    django_settings,
                    headers=headers,
                    timeout=timeout,
                    hash_value=hash_hex,
                    file_size=file_size,
                    digest_algorithm=configured_digest,
                )
                if not sent:
                    _job_log(job, "error", f"[ipds-re-preservation] failed to send extension event for '{file_name}'", icon_key="error")
                    return False
            except Exception as exc:
                _job_log(job, "error", f"[ipds-re-preservation] error sending extension event for '{file_name}': {exc}", icon_key="error")
                logger.exception("Error sending extension event for %s", file_name)
                return False
            # --- END: SEND EVENT TO IPDS ---
        except OSError as exc:
            _job_log(job, "error", f"[ipds-re-preservation] I/O error for '{file_name}': {exc}", icon_key="error")
            logger.exception("I/O error while handling %s", file_name)
            # Treat I/O errors as fatal for the transfer
            return False
        except requests.exceptions.RequestException as exc:
            # Try to extract response text from the exception if present for diagnosis
            resp_text = None
            try:
                resp_text = getattr(exc, "response", None).text if getattr(exc, "response", None) is not None else None
            except Exception:
                resp_text = "<unable to read response body>"
            _job_log(job, "error", f"[ipds-re-preservation] HTTP error for '{file_name}': {exc} - response: {resp_text}", icon_key="http")
            logger.exception("HTTP request to IPDS service failed for %s", file_name)
            # Treat external service HTTP errors as fatal for the transfer
            return False
        except (ValueError, KeyError) as exc:
            _job_log(job, "error", f"[ipds-re-preservation] response parse error for '{file_name}': {exc}", icon_key="error")
            # Treat parse errors as fatal
            return False
        except Exception as exc:
            _job_log(job, "error", f"[ipds-re-preservation] unexpected error for '{file_name}': {exc}", icon_key="error")
            logger.exception("Unexpected error while processing %s", file_name)
            # Any unexpected exception is considered fatal for the transfer
            return False

    _job_log(job, "success", "[ipds-re-preservation]✅✅✅ all targeted files replaced successfully", icon_key="success")
    return True


def _move_file(job, src, dst, exit_on_error=True):
    logger.info("Moving %s to %s", src, dst)
    try:
        shutil.move(src, dst)
        _job_log(job, "success", "✅ Moved: {src} ➡️ {dst}", icon_key="move", src=src, dst=dst)
    except OSError:
        _job_log(job, "error", f"Could not move {src}", icon_key="error")
        if exit_on_error:
            raise


def _create_sip_backup(job, sip_path):
    """Create a filesystem snapshot (copy) of sip_path to allow rollback.

    Returns the path to the backup directory or None if backup failed.
    """
    try:
        # Normalize sip_path and ensure we create the backup as a sibling of
        # the SIP directory (not inside it). If sip_path has a trailing slash
        # the naive f"{sip_path}.pre..." would place the backup inside the
        # SIP and cause the restore to delete the backup when removing the SIP.
        sip_abs = os.path.abspath(sip_path)
        sip_norm = sip_abs.rstrip(os.sep)
        parent_dir = os.path.dirname(sip_norm)
        base = os.path.basename(sip_norm)
        backup_dir = os.path.join(parent_dir, f"{base}.pre_restructure_backup_{uuid.uuid4()}")
        if os.path.exists(backup_dir):
            # Rare, but ensure it's unique
            backup_dir = f"{backup_dir}_{int(time.time())}"
        _job_log(job, "info", f"Creating SIP backup at {backup_dir}", icon_key="info")
        # Use copytree; may be slow for large transfers. We intentionally copy
        # so the original remains downloadable during processing.
        shutil.copytree(sip_norm, backup_dir, copy_function=shutil.copy2)
        return backup_dir
    except Exception as exc:
        _job_log(job, "warn", f"Could not create SIP backup: {exc}; proceeding without backup", icon_key="warn")
        logger.exception("SIP backup failed for %s", sip_path)
        return None


def _restore_sip_backup(job, sip_path, backup_dir):
    """Restore the backup by replacing sip_path with backup_dir.

    This attempts to remove any partially modified sip_path and move the
    backup into place.
    """
    try:
        _job_log(job, "info", f"Restoring SIP from backup {backup_dir} to {sip_path}", icon_key="info")
        # If the current SIP path exists, remove it first
        if os.path.exists(sip_path):
            shutil.rmtree(sip_path)
        # Move backup back into place
        shutil.move(backup_dir, sip_path)
        _job_log(job, "success", f"SIP restored from backup {backup_dir}", icon_key="success")
        return True
    except Exception as exc:
        _job_log(job, "error", f"Failed to restore SIP from backup: {exc}", icon_key="error")
        logger.exception("Failed to restore SIP from %s to %s", backup_dir, sip_path)
        return False


def _cleanup_sip_backup(job, backup_dir):
    try:
        if backup_dir and os.path.exists(backup_dir):
            _job_log(job, "info", f"Removing SIP backup {backup_dir}", icon_key="info")
            shutil.rmtree(backup_dir)
    except Exception:
        logger.exception("Failed to remove SIP backup %s", backup_dir)
        # Non-fatal

def restructure_transfer_aip(job, unit_path):
    """
    Restructure a transfer that comes from re-ingesting an Archivematica AIP.
    """
    old_bag = os.path.join(unit_path, "old_bag", "")
    os.makedirs(old_bag)

    # Move everything to old_bag
    for item in os.listdir(unit_path):
        if item == "old_bag":
            continue
        src = os.path.join(unit_path, item)
        _move_file(job, src, old_bag)

    # Create required directories
    # - "/logs" and "/logs/fileMeta"
    # - "/metadata" and "/metadata/submissionDocumentation"
    # - "/objects"
    create_structured_directory(unit_path, printing=True, printfn=job.pyprint)

    # Move /old_bag/data/METS.<UUID>.xml => /metadata/METS.<UUID>.xml
    p = re.compile(r"^METS\..*\.xml$", re.IGNORECASE)
    src = os.path.join(old_bag, "data")
    m = None
    for item in os.listdir(src):
        m = p.match(item)
        if m:
            break  # Stop trying after the first match
    if not m:
        raise FileNotFoundError(
            f"Could not find METS XML file in {src}"
        )
    src = os.path.join(src, m.group())
    dst = os.path.join(unit_path, "metadata")
    # After moving the METS file into the metadata directory, mets_file_path
    # should reference the actual METS file path inside the metadata dir.
    mets_file_path = os.path.join(dst, m.group())
    _move_file(job, src, dst)

    # Move /old_bag/data/objects/metadata/* => /metadata/
    src = os.path.join(old_bag, "data", "objects", "metadata")
    dst = os.path.join(unit_path, "metadata")
    if os.path.isdir(src):
        for item in os.listdir(src):
            item_path = os.path.join(src, item)
            _move_file(job, item_path, dst)
        shutil.rmtree(src)

    # Move /old_bag/data/objects/submissionDocumentation/* => /metadata/submissionDocumentation/
    src = os.path.join(old_bag, "data", "objects", "submissionDocumentation")
    dst = os.path.join(unit_path, "metadata", "submissionDocumentation")
    if os.path.isdir(src):
        for item in os.listdir(src):
            item_path = os.path.join(src, item)
            _move_file(job, item_path, dst)
        shutil.rmtree(src)

    # Move /old_bag/data/objects/* => /objects/
    src = os.path.join(old_bag, "data", "objects")
    objects_path = dst = os.path.join(unit_path, "objects")
    for item in os.listdir(src):
        item_path = os.path.join(src, item)
        _move_file(job, item_path, dst)

    # Move /old_bag/processingMCP.xml => /processingMCP.xml
    src = os.path.join(old_bag, "processingMCP.xml")
    dst = os.path.join(unit_path, "processingMCP.xml")
    if os.path.isfile(src):
        _move_file(job, src, dst)

    # Get rid of old_bag
    shutil.rmtree(old_bag)

    # Reconstruct any empty directories documented in the METS file under the
    # logical structMap labelled "Normative Directory Structure"
    reconstruct_empty_directories(mets_file_path, objects_path, logger=logger)

def restructure_transfer(job, unit_path):
    # Create required directories
    create_structured_directory(unit_path, printing=True, printfn=job.pyprint)

    # Move everything else to the objects directory
    for item in os.listdir(unit_path):
        src = os.path.join(unit_path, item)
        dst = os.path.join(unit_path, "objects", ".")
        if os.path.isdir(src) and item not in REQUIRED_DIRECTORIES:
            _move_file(job, src, dst)
        elif os.path.isfile(src) and item not in OPTIONAL_FILES:
            _move_file(job, src, dst)

def _is_bag_structure(unit_path):
    """Return True if the directory looks like a BagIt bag (has bagit.txt or data/)."""
    return os.path.isfile(os.path.join(unit_path, "bagit.txt")) or os.path.isdir(
        os.path.join(unit_path, "data")
    )

def call(jobs):
    with transaction.atomic():
        for job in jobs:
            # Capture sip_uuid early so we can act on failures after JobContext
            try:
                sip_uuid = job.args[2]
            except Exception:
                sip_uuid = None

            # Capture sip_path early so we can create a filesystem backup before
            # entering the JobContext. We may not have a backup (returns None).
            try:
                sip_path = job.args[1]
            except Exception:
                sip_path = None

            backup_dir = None
            if sip_path:
                try:
                    backup_dir = _create_sip_backup(job, sip_path)
                except Exception:
                    # _create_sip_backup already logs; ensure we don't fail here
                    logger.exception("Failed to create SIP backup for %s", sip_path)
                    backup_dir = None

            with job.JobContext(logger=logger):
                try:
                    # Ensure sip_path is available inside the JobContext
                    if not sip_path:
                        sip_path = job.args[1]
                    # sip_uuid already captured above

                    transfer = None
                    sip = None
                    try:
                        transfer = Transfer.objects.get(uuid=sip_uuid)
                    except (Transfer.DoesNotExist, ValidationError):
                        sip = SIP.objects.get(uuid=sip_uuid)

                    if transfer:
                        logger.info("Transfer.type=%s", transfer.type)
                    else:
                        logger.info("SIP.sip_type=%s", sip.sip_type)

                    # Check ipds-re-preservation flag from UnitVariable
                    ipds_re_preservation, ipds_doc_name, ipds_doc_id = _get_ipds_re_preservation(sip_uuid)

                    if transfer and transfer.type == "Archivematica AIP":
                        if not ipds_re_preservation:
                            logger.info("Archivematica AIP detected, verifying bag...")
                            if not bag.is_valid(sip_path, job.pyprint):
                                logger.info("Archivematica AIP: bag verification failed!")
                                job.set_status(1)
                                continue
                        else:
                            _job_log(job, "info", "ipds-re-preservation=True: skipping bag validation.", icon_key="info")

                        # If ipds re-preservation is requested, call the external
                        # signature extension service before restructuring the bag.
                        # This ensures we do not move or alter the original bag
                        # contents if the external service fails.
                        if ipds_re_preservation:
                            _job_log(job, "info", "ipds-re-preservation=True: calling external signature extension service before restructuring...", icon_key="call")
                            if not _call_signature_extension_service(job, sip_path, sip_uuid, ipds_doc_name, ipds_doc_id):
                                # Mark job and unit as failed; handle propagation after JobContext
                                job.set_status(1)
                                try:
                                    if transfer:
                                        transfer.status = PACKAGE_STATUS_FAILED
                                        transfer.save()
                                    else:
                                        sip.status = PACKAGE_STATUS_FAILED
                                        sip.save()
                                except Exception:
                                    logger.exception("Failed to update unit status to FAILED")
                                # Skip further processing of this job so the JobContext
                                # will trigger the transaction abort after the context.
                                continue

                        if not _is_bag_structure(sip_path):
                            logger.info(
                                "Transfer at %s already has compliance structure, skipping restructure.",
                                sip_path,
                            )
                            # Clean up any leftover old_bag/ from a previous failed restructure attempt.
                            old_bag_path = os.path.join(sip_path, "old_bag")
                            if os.path.isdir(old_bag_path):
                                logger.info("Removing leftover old_bag/ at %s", old_bag_path)
                                shutil.rmtree(old_bag_path)
                        else:
                            _job_log(job, "info", "Restructuring transfer (Archivematica AIP re-ingest)...", icon_key="info")
                            try:
                                restructure_transfer_aip(job, sip_path)
                            except Exception as exc:
                                # If DB-based moves fail (e.g. file record not found),
                                # attempt a safe filesystem-only fallback to put files
                                # into the required compliance structure so subsequent
                                # verification steps won't abort the workflow.
                                logger.exception("restructure_transfer_aip failed, attempting filesystem fallback: %s", exc)
                                _job_log(job, "warn", "Restructure (AIP) failed, attempting filesystem-only fallback.", icon_key="warn")
                                try:
                                    _fallback_physical_restructure(job, sip_path)
                                except Exception:
                                    logger.exception("Filesystem fallback also failed")
                                    raise

                        # Note: for ipds_re_preservation==True we already called the
                        # external service before restructuring; if it succeeded we
                        # proceed to restructure. If it failed we continued above and
                        # will exit the JobContext with a failure.
                    else:
                        _job_log(job, "info", "Restructuring transfer...", icon_key="info")
                        try:
                            restructure_transfer(job, sip_path)
                        except Exception as exc:
                            logger.exception("restructure_transfer failed, attempting filesystem fallback: %s", exc)
                            _job_log(job, "warn", "Restructure failed, attempting filesystem-only fallback.", icon_key="warn")
                            try:
                                _fallback_physical_restructure(job, sip_path)
                            except Exception:
                                logger.exception("Filesystem fallback also failed")
                                raise

                except OSError as err:
                    _job_log(job, "error", repr(err), icon_key="error")
                    job.set_status(1)

            # End of JobContext: if job failed, mark unit as failed and abort processing
            # If the job failed, attempt to restore the SIP from the backup (if available)
            exit_code = job.get_exit_code()
            if exit_code and exit_code != 0:
                if backup_dir:
                    try:
                        _job_log(job, "info", f"Restoring SIP from backup due to job failure: {backup_dir}", icon_key="info")
                        _restore_sip_backup(job, sip_path, backup_dir)
                    except Exception:
                        logger.exception("Failed to restore SIP from backup for %s", sip_path)
                else:
                    _job_log(job, "warn", f"No SIP backup available to restore for {sip_path}", icon_key="warn")

                try:
                    # Attempt to mark Transfer/SIP as failed in the DB
                    if sip_uuid:
                        try:
                            transfer = Transfer.objects.filter(uuid=sip_uuid).first()
                            if transfer:
                                transfer.status = PACKAGE_STATUS_FAILED
                                transfer.save()
                            else:
                                sip = SIP.objects.filter(uuid=sip_uuid).first()
                                if sip:
                                    sip.status = PACKAGE_STATUS_FAILED
                                    sip.save()
                        except Exception:
                            logger.exception("Failed to update unit status after job failure")
                finally:
                    # Ensure the job Task record is updated and raise to abort the transaction
                    try:
                        job.update_task_status()
                    except Exception:
                        logger.exception("Failed to update Task status for failed job")
                    raise RuntimeError("Aborting processing due to job failure")
            else:
                # Job succeeded: clean up the filesystem backup if present
                if backup_dir:
                    try:
                        _cleanup_sip_backup(job, backup_dir)
                    except Exception:
                        logger.exception("Failed to cleanup SIP backup %s", backup_dir)


def _fallback_physical_restructure(job, unit_path):
    """Perform a best-effort filesystem-only restructure into the compliance
    directory layout. This does not update the Dashboard DB; it moves files
    and directories into the standard `objects`, `metadata`, `logs`, etc.

    This fallback is used when DB-driven moves fail (missing DB records).
    """
    # Create required directories (safe if they already exist)
    create_structured_directory(unit_path, manual_normalization=True, printing=False)

    unit_path = os.path.join(unit_path, "")
    objects_path = os.path.join(unit_path, "objects")

    # Move top-level files into objects or metadata/submissionDocumentation
    for entry in os.listdir(unit_path):
        if entry in OPTIONAL_FILES or entry in REQUIRED_DIRECTORIES:
            continue
        src = os.path.join(unit_path, entry)
        if os.path.isfile(src):
            # Decide destination: manifest-like to metadata, others to objects
            if entry.startswith("manifest") or entry.endswith(".xml"):
                dst_dir = os.path.join(unit_path, "metadata")
            else:
                dst_dir = objects_path
            dst = os.path.join(dst_dir, entry)
            try:
                os.replace(src, dst)
                _job_log(job, "info", f"Moved (fallback): {src} -> {dst}", icon_key="move")
            except OSError as exc:
                # If destination exists, try to unlink and replace; otherwise raise
                if exc.errno == errno.EEXIST:
                    try:
                        os.remove(dst)
                        os.replace(src, dst)
                        _job_log(job, "info", f"Replaced existing (fallback): {dst}", icon_key="move")
                    except Exception:
                        _job_log(job, "error", f"Fallback move failed for {src}: {exc}", icon_key="error")
                        raise
                else:
                    _job_log(job, "error", f"Fallback move failed for {src}: {exc}", icon_key="error")
                    raise
        elif os.path.isdir(src):
            # Move directories except required ones into objects preserving name
            if entry in REQUIRED_DIRECTORIES:
                continue
            dst = os.path.join(objects_path, entry)
            try:
                # If dst exists, merge contents
                if os.path.isdir(dst):
                    for root, dirs, files in os.walk(src):
                        rel = os.path.relpath(root, src)
                        target_root = os.path.join(dst, rel) if rel != '.' else dst
                        os.makedirs(target_root, exist_ok=True)
                        for f in files:
                            s_f = os.path.join(root, f)
                            d_f = os.path.join(target_root, f)
                            if os.path.exists(d_f):
                                os.remove(d_f)
                            os.replace(s_f, d_f)
                    shutil.rmtree(src)
                else:
                    os.replace(src, dst)
                _job_log(job, "info", f"Moved dir (fallback): {src} -> {dst}", icon_key="move")
            except Exception as exc:
                _job_log(job, "error", f"Fallback move dir failed for {src}: {exc}", icon_key="error")
                raise

    # Ensure submissionDocumentation exists
    subm = os.path.join(unit_path, "metadata", "submissionDocumentation")
    os.makedirs(subm, exist_ok=True)
    _job_log(job, "success", "Filesystem-only fallback restructure completed", icon_key="success")


def _validate_signature_and_extract_extension(job, extended_bytes, file_name, django_settings=None, headers=None, timeout=60):
    """Enviar el documento firmado al endpoint de validación y devolver ExtensionPeriodMax más temprana o None.

    Esta versión añade logging detallado: tamaños, SHA256 de entrada y respuesta, cabeceras seguras,
    duración, y trazas en caso de excepción.
    """
    import base64 as _b64
    from requests.exceptions import RequestException
    import hashlib
    import time
    import traceback

    start_ts = time.time()
    try:
        _job_log(job, "info", f"[ipds-re-preservation] validate_signature_and_extract_extension START for '{file_name}'", icon_key="info")

        # Log basic info about the bytes we will send
        try:
            if isinstance(extended_bytes, (bytes, bytearray)):
                original_len = len(extended_bytes)
                original_sha = hashlib.sha256(extended_bytes).hexdigest()
                _job_log(job, "debug", f"[ipds-re-preservation] original extended bytes len={original_len} sha256={original_sha}", icon_key="debug")
            else:
                _job_log(job, "debug", f"[ipds-re-preservation] original extended bytes is not bytes (type={type(extended_bytes)})", icon_key="debug")
        except Exception:
            logger.exception("Failed to compute hash/len of original extended bytes")

        # Obtener base_url desde settings si se proporcionaron, si no usar fallback
        base_url = None
        if django_settings:
            try:
                base_url = getattr(django_settings, "IPDS_RE_PRESERVATION_SERVICE_URL", None)
            except Exception:
                base_url = None

        if base_url:
            validate_url = re.sub(r"/dss/services/rest/.+/extendDocument$", "/dss/services/rest/validation/validateSignature", base_url.rstrip("/"))
            if validate_url == base_url.rstrip("/"):
                validate_url = base_url.rstrip("/") + "/dss/services/rest/validation/validateSignature"
        else:
            validate_url = "https://desarrollo.logalty.com/dss/services/rest/validation/validateSignature"

        req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if headers:
            # copy headers but avoid accidentally exposing tokens in logs
            try:
                req_headers.update(headers)
            except Exception:
                logger.exception("Failed to update req_headers from provided headers")

        # Ensure Authorization header exists
        try:
            if not any(k.lower() == "authorization" for k in req_headers.keys()):
                token = None
                if django_settings:
                    try:
                        token = _fetch_cognito_token(django_settings, job, timeout=10)
                    except Exception as exc:
                        _job_log(job, "warn", f"[ipds-re-preservation] warning obtaining token for validation: {exc}", icon_key="warn")
                if token:
                    req_headers["Authorization"] = f"Bearer {token}"
                    # Log only a safe prefix of token
                    _job_log(job, "debug", f"[ipds-re-preservation] added Authorization header with token prefix {str(token)[:8]}...", icon_key="debug")
        except Exception as exc:
            _job_log(job, "warn", f"[ipds-re-preservation] warning obtaining token for validation: {exc}", icon_key="warn")

        # Prepare payload (base64-encoded bytes)
        try:
            encoded = _b64.b64encode(extended_bytes).decode("ascii") if isinstance(extended_bytes, (bytes, bytearray)) else str(extended_bytes)
        except Exception as exc:
            _job_log(job, "error", f"[ipds-re-preservation] failed to base64-encode extended bytes for '{file_name}': {exc}", icon_key="error")
            logger.exception("Base64 encode error for %s", file_name)
            return None

        payload = {
            "signedDocument": {
                "name": file_name,
                "bytes": encoded,
            }
        }

        # Log payload summary (size in chars of base64) but don't dump whole payload
        try:
            _job_log(job, "debug", f"[ipds-re-preservation] validation payload prepared for '{file_name}': base64_len={len(encoded)} chars", icon_key="debug")
        except Exception:
            logger.exception("Failed logging payload summary")

        max_retries = getattr(django_settings, "IPDS_RE_PRESERVATION_RETRIES", 2) if django_settings else 2
        backoff_base = getattr(django_settings, "IPDS_RE_PRESERVATION_BACKOFF_BASE", 5) if django_settings else 5
        attempt = 0
        resp = None
        # Determine verify flag
        verify_flag = getattr(django_settings, "IPDS_RE_PRESERVATION_VERIFY", True) if django_settings else True

        while attempt < max_retries:
            attempt += 1
            try:
                _job_log(job, "debug", f"[ipds-re-preservation] validation signature HTTP attempt {attempt}/{max_retries} for '{file_name}' to url '{validate_url}'", icon_key="http")
                resp = requests.post(validate_url, json=payload, headers=req_headers, timeout=timeout, verify=verify_flag)

                status = getattr(resp, "status_code", None)
                _job_log(job, "debug", f"[ipds-re-preservation] validation HTTP response status={status} for '{file_name}'", icon_key="debug")

                if 500 <= (status or 0) < 600:
                    body = None
                    try:
                        body = resp.text
                    except Exception:
                        body = "<unable to read response body>"
                    _job_log(job, "warn", f"[ipds-re-preservation] validation HTTP {status} for '{file_name}': {body[:1000]} (attempt {attempt})", icon_key="http")
                    if attempt < max_retries:
                        time.sleep(backoff_base * (2 ** (attempt - 1)))
                        continue
                    resp.raise_for_status()
                else:
                    resp.raise_for_status()
                break
            except RequestException as exc:
                if attempt < max_retries:
                    sleep_for = backoff_base * (2 ** (attempt - 1))
                    _job_log(job, "warn", f"[ipds-re-preservation] validation request error for '{file_name}': {exc} (attempt {attempt}), retrying in {sleep_for}s", icon_key="http")
                    time.sleep(sleep_for)
                    continue
                body = None
                try:
                    body = resp.text if resp is not None else None
                except Exception:
                    body = "<unable to read response body>"
                _job_log(job, "error", f"[ipds-re-preservation] validation HTTP error for '{file_name}': {exc} - response: {body[:1000]}", icon_key="http")
                logger.debug(traceback.format_exc())
                return None

        # At this point we have a successful response in resp
        try:
            resp_text = resp.text
            _job_log(job, "debug", f"[ipds-re-preservation] validation response text length={len(resp_text)} for '{file_name}'", icon_key="debug")
        except Exception:
            resp_text = None

        try:
            resp_json = resp.json()
            #_job_log(job, "debug", f"[ipds-re-preservation] validation response JSON '{file_name}': {resp_json}", icon_key="debug")
        # Log top-level keys of the JSON
            try:
                keys = list(resp_json.keys()) if isinstance(resp_json, dict) else [type(resp_json).__name__]
                _job_log(job, "debug", f"[ipds-re-preservation] validation response JSON keys for '{file_name}': {keys}", icon_key="debug")
            except Exception:
                logger.exception("Failed to list resp_json keys")
        except Exception:
            _job_log(job, "warn", f"[ipds-re-preservation] validation response not JSON for '{file_name}'", icon_key="warn")
            logger.debug(traceback.format_exc())
            return None

        # Extract earliest ExtensionPeriodMax using existing helper
        try:
            earliest = _extract_extension_period_max(resp_json)
            if earliest:
                _job_log(job, "info", f"[ipds-re-preservation] extracted ExtensionPeriodMax for '{file_name}': {earliest.isoformat()}", icon_key="info")
            else:
                _job_log(job, "warn", f"[ipds-re-preservation] no ExtensionPeriodMax found in validation response for '{file_name}'", icon_key="warn")
            elapsed = time.time() - start_ts
            _job_log(job, "debug", f"[ipds-re-preservation] validate_signature_and_extract_extension finished for '{file_name}' elapsed={elapsed:.3f}s", icon_key="debug")
            return earliest
        except Exception as exc:
            _job_log(job, "error", f"[ipds-re-preservation] error extracting ExtensionPeriodMax for '{file_name}': {exc}", icon_key="error")
            logger.exception("Error extracting ExtensionPeriodMax for %s", file_name)
            return None

    except Exception as exc:
        _job_log(job, "error", f"[ipds-re-preservation] Exception in validate_signature_and_extract_extension for '{file_name}': {exc}", icon_key="error")
        logger.debug(traceback.format_exc())
        return None


def _send_extension_event_to_ipds(job, aip_or_doc_id, period_dt, django_settings=None, headers=None, timeout=30, hash_value=None, file_size=None, digest_algorithm=None):
    """Enviar evento de extensión al servicio externo con aip uuid (legacy) o ipds-doc-id y periodo.

    Payload JSON: {"ipdsDocId": ..., "extensionPeriodMax": "ISO8601", "digestAlgorithm": ..., "hash": ..., "fileSize": ...}
    La URL puede configurarse en settings: IPDS_EXTENSION_EVENT_URL
    """
    import requests
    from requests.exceptions import RequestException

    if not aip_or_doc_id or not period_dt:
        _job_log(job, "debug", "[ipds-re-preservation] no doc id or period to send extension event", icon_key="debug")
        return False

    # Obtener URL desde settings si se proporcionaron
    event_url = None
    if django_settings:
        try:
            event_url = getattr(django_settings, "IPDS_EXTENSION_EVENT_URL", None)
        except Exception:
            event_url = None
    if not event_url:
        event_url = "https://ipds-dev.logalty.com/services/api/event/signature/extension"

    req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    # Ensure Authorization header exists
    try:
        if not any(k.lower() == "authorization" for k in req_headers.keys()):
            token = None
            if django_settings:
                try:
                    token = _fetch_cognito_token(django_settings, job, timeout=10)
                except Exception as exc:
                    _job_log(job, "warn", f"[ipds-re-preservation] warning obtaining token for event post: {exc}", icon_key="warn")
            if token:
                req_headers["Authorization"] = f"Bearer {token}"
    except Exception as exc:
        _job_log(job, "warn", f"[ipds-re-preservation] warning obtaining token for event post: {exc}", icon_key="warn")

    # Use ipdsDocId as the primary identifier for the extension event. Keep string form.
    payload = {"ipdsDocId": str(aip_or_doc_id), "extensionPeriodMax": period_dt.isoformat() if hasattr(period_dt, "isoformat") else str(period_dt)}
    # Include digest algorithm, hash and file size when available
    try:
        if hash_value:
            payload["hash"] = hash_value
        if file_size is not None:
            payload["fileSize"] = int(file_size)
    except Exception:
        # Non-fatal: continue without adding these fields if something unexpected occurs
        logger.exception("Failed to attach hash/filesize to payload for %s", aip_or_doc_id)

    max_retries = getattr(django_settings, "IPDS_EXTENSION_EVENT_RETRIES", 2) if django_settings else 2
    backoff_base = getattr(django_settings, "IPDS_EXTENSION_EVENT_BACKOFF_BASE", 5) if django_settings else 5
    verify_flag = getattr(django_settings, "IPDS_RE_PRESERVATION_VERIFY", True) if django_settings else True

    attempt = 0
    while attempt < max_retries:
        attempt += 1
        try:
            _job_log(job, "debug", f"[ipds-re-preservation] sending extension event attempt {attempt}/{max_retries} to {event_url}", icon_key="http")
            resp = requests.post(event_url, json=payload, headers=req_headers, timeout=timeout, verify=verify_flag)
            if 500 <= getattr(resp, "status_code", 0) < 600:
                _job_log(job, "warn", f"[ipds-re-preservation] event endpoint HTTP {resp.status_code}: {resp.text[:1000]} (attempt {attempt})", icon_key="http")
                if attempt < max_retries:
                    time.sleep(backoff_base * (2 ** (attempt - 1)))
                    continue
                resp.raise_for_status()
            else:
                # Treat non-2xx as warning but don't raise unless it's 4xx/5xx
                if resp.status_code >= 400:
                    _job_log(job, "warn", f"[ipds-re-preservation] event endpoint returned {resp.status_code}: {resp.text[:1000]}", icon_key="http")
                    return False
            _job_log(job, "info", f"[ipds-re-preservation] extension event sent for AIP {aip_or_doc_id}", icon_key="info")
            return True
        except RequestException as exc:
            if attempt < max_retries:
                sleep_for = backoff_base * (2 ** (attempt - 1))
                _job_log(job, "warn", f"[ipds-re-preservation] event post error: {exc} (attempt {attempt}), retrying in {sleep_for}s", icon_key="http")
                time.sleep(sleep_for)
                continue
            _job_log(job, "error", f"[ipds-re-preservation] event post failed: {exc}", icon_key="error")
            return False

    return False
