from __future__ import annotations

import struct
from typing import Any

SMB1_MAGIC = b"\xff\x53\x4d\x42"
SMB2_MAGIC = b"\xfe\x53\x4d\x42"
SSH_MAGIC = b"SSH-"


def detect_smb(payload: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "app_hint": None,
        "smb_version": None,
        "smb_command": None,
    }
    if len(payload) < 8:
        return result

    # NetBIOS session (RFC 1001/1002): first byte is message type
    # SMB over NetBIOS: Type 0x00 (session message)
    offset = 0
    if payload[0] == 0x00:
        nb_len = struct.unpack(">I", b"\x00" + payload[1:4])[0]
        if nb_len > 0 and nb_len <= len(payload) - 4:
            offset = 4

    smb_start = payload[offset:]

    if smb_start.startswith(SMB1_MAGIC):
        result["app_hint"] = "smb"
        result["smb_version"] = "1.0"
        if len(smb_start) >= 14:
            result["smb_command"] = smb_start[8]
    elif smb_start.startswith(SMB2_MAGIC):
        result["app_hint"] = "smb"
        result["smb_version"] = "2.x"
        if len(smb_start) >= 28:
            # SMB2 header: 4 bytes magic + 16 bytes header + 2 byte cmd
            struct_len = struct.unpack("<H", smb_start[4:6])[0]
            if struct_len >= 64:
                result["smb_command"] = smb_start[12]
                # SMB2 dialect from negotiate response: at offset 2 in the
                # SMB2 negotiate response body, 2-byte dialect revision
                dialect_offset = 64 + 4 + 2  # header + SMB2 header + struct size
                if dialect_offset + 2 <= len(smb_start):
                    dialect = struct.unpack("<H", smb_start[dialect_offset:dialect_offset+2])[0]
                    result["smb_dialect"] = dialect

    return result


def detect_ssh(payload: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "app_hint": None,
        "ssh_version": None,
    }
    if payload.startswith(SSH_MAGIC):
        result["app_hint"] = "ssh"
        banner = payload[:255]
        parts = banner.split(b"-", 2)
        if len(parts) >= 2:
            ver = parts[1].split(b"\r")[0].split(b"\n")[0]
            try:
                result["ssh_version"] = ver.decode("ascii")
            except UnicodeDecodeError:
                result["ssh_version"] = repr(ver)
    return result


def detect_kerberos(payload: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "app_hint": None,
        "kerberos_msg_type": None,
        "kerberos_realm": None,
    }
    if len(payload) < 8:
        return result

    # Kerberos over TCP uses 4-byte length prefix
    offset = 0
    if len(payload) >= 4:
        tcp_len = struct.unpack(">I", payload[:4])[0]
        if 4 + tcp_len <= len(payload) and tcp_len > 0:
            payload = payload[4:]

    # ASN.1 APPLICATION tag for Kerberos
    # Common tags: 0x6a (KRB_AS_REQ), 0x6b (KRB_AS_REP),
    #              0x6c (KRB_TGS_REQ), 0x6d (KRB_TGS_REP),
    #              0x6e (KRB_AP_REQ), 0x6f (KRB_AP_REP)
    if len(payload) < 2:
        return result

    app_tag = payload[0]
    if app_tag in {0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f}:
        result["app_hint"] = "kerberos"
        msg_map = {
            0x6a: "AS-REQ",
            0x6b: "AS-REP",
            0x6c: "TGS-REQ",
            0x6d: "TGS-REP",
            0x6e: "AP-REQ",
            0x6f: "AP-REP",
        }
        result["kerberos_msg_type"] = msg_map.get(app_tag)
        # Try to extract realm from AS-REQ body (rough heuristic)
        if app_tag in {0x6a, 0x6c} and len(payload) > 20:
            _try_extract_kerberos_realm(result, payload)
    return result


def _try_extract_kerberos_realm(result: dict[str, Any], payload: bytes) -> None:
    """Heuristic: find ASCII realm string in AS-REQ body."""
    try:
        text = payload.decode("latin-1")
    except UnicodeDecodeError:
        return
    import re

    # Look for realm in readable text (often after the kerberos type)
    # Match uppercase domain-style strings
    matches = re.findall(rb"([A-Z][A-Z0-9.-]+\.(?:COM|NET|ORG|LOCAL|INTERNAL|AD|CORP|IO|DEV))", payload)
    if matches:
        result["kerberos_realm"] = matches[0].decode("latin-1")


def detect_quic(payload: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "app_hint": None,
        "quic_version": None,
    }
    if len(payload) < 5:
        return result

    # QUIC v1 Initial packet: first byte 0xC0 (fixed bit + form bit + initial)
    # Long header packets start with 0xC0 to 0xCF
    if payload[0] & 0xF0 == 0xC0:
        # Long header: type in bits 0x30
        # 0xC0 = Initial, 0xC8 = 0-RTT, 0xD0 = Handshake, 0xD8 = Retry
        form_bit = payload[0] & 0x80
        fixed_bit = payload[0] & 0x40
        if form_bit and fixed_bit:
            result["app_hint"] = "quic"
            quic_type = (payload[0] >> 4) & 0x03
            type_names = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
            result["quic_type"] = type_names.get(quic_type, f"Long({quic_type})")
            # Version is bytes 1-4
            if len(payload) >= 5:
                ver_raw = struct.unpack(">I", payload[1:5])[0]
                ver_map = {
                    0x00000001: "1",
                    0x6b3343cf: "2",
                    0x51303433: "Q043",
                    0x51303436: "Q046",
                    0x51303530: "Q050",
                    0xff000000: "v1_draft_27",
                    0xff000001: "v1_draft_28",
                    0xff000002: "v1_draft_29",
                    0xff000003: "v1_draft_30",
                    0xff000004: "v1_draft_31",
                    0xff000005: "v1_draft_32",
                }
                result["quic_version"] = ver_map.get(ver_raw, f"0x{ver_raw:08x}")
    return result
