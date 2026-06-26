from __future__ import annotations

import struct

from packet_analyzer.protocols import detect_kerberos, detect_quic, detect_smb, detect_ssh


def test_detect_smb2():
    payload = b"\xfe\x53\x4d\x42"  # SMB2 magic
    payload += struct.pack("<HHI", 64, 0, 0)
    payload += struct.pack("<H", 0x0000)  # command = Negotiate
    payload += b"\x00" * 16
    payload += b"\x00" * 4
    payload += struct.pack("<H", 0x0311)  # dialect = 3.1.1

    result = detect_smb(payload)
    assert result["app_hint"] == "smb"
    assert result["smb_version"] == "2.x"


def test_detect_smb1():
    payload = b"\xff\x53\x4d\x42"  # SMB1 magic
    payload += b"\x00" * 8
    payload += b"\x72"  # command = Negotiate
    result = detect_smb(payload)
    assert result["app_hint"] == "smb"
    assert result["smb_version"] == "1.0"


def test_detect_smb_no_match():
    result = detect_smb(b"\x00" * 20)
    assert result["app_hint"] is None


def test_detect_ssh():
    result = detect_ssh(b"SSH-2.0-OpenSSH_8.9\r\n")
    assert result["app_hint"] == "ssh"
    assert result["ssh_version"] == "2.0"


def test_detect_ssh_no_match():
    result = detect_ssh(b"HTTP/1.1 200 OK\r\n")
    assert result["app_hint"] is None


def test_detect_kerberos_as_req():
    # Raw Kerberos (no TCP wrapper)
    payload = b"\x6a\x81\x82"
    payload += b"\x00" * 10
    payload += b"EXAMPLE.COM"
    result = detect_kerberos(payload)
    assert result["app_hint"] == "kerberos"
    assert result["kerberos_msg_type"] == "AS-REQ"


def test_detect_kerberos_tgs_req():
    payload = b"\x6c\x81"
    payload += b"\x00" * 10
    result = detect_kerberos(payload)
    assert result["app_hint"] == "kerberos"
    assert result["kerberos_msg_type"] == "TGS-REQ"


def test_detect_kerberos_no_match():
    result = detect_kerberos(b"\x00" * 20)
    assert result["app_hint"] is None


def test_detect_quic_initial():
    payload = b"\xc0"
    payload += struct.pack(">I", 0x00000001)
    payload += b"\x00" * 20
    result = detect_quic(payload)
    assert result["app_hint"] == "quic"
    assert result["quic_version"] == "1"


def test_detect_quic_v2():
    payload = b"\xc0"
    payload += struct.pack(">I", 0x6b3343cf)  # QUIC v2
    payload += b"\x00" * 20
    result = detect_quic(payload)
    assert result["app_hint"] == "quic"
    assert result["quic_version"] == "2"


def test_detect_quic_short_header():
    payload = b"\x40"
    payload += b"\x00" * 20
    result = detect_quic(payload)
    assert result["app_hint"] is None


def test_detect_quic_no_match():
    result = detect_quic(b"\x00" * 20)
    assert result["app_hint"] is None
