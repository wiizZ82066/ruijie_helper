"""Version-locked offline patch for the user's locally installed RG-SU 6.61.

Never searches for signatures in an unknown binary and never patches in place.
See analysis/native_static_findings.json and native_static_evidence.txt.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

ORIGINAL_SHA256 = "e8061b2a454d8e8472a7d01b08023e2c7108da44fab7913dc0b129444ef9e039"


@dataclass(frozen=True)
class Patch:
    name: str
    offset: int
    expected: bytes
    replacement: bytes


PATCHES = (
    Patch("CheckHomeShare", 0x3B908, bytes.fromhex("558bec6aff68f312590064a100000000"), bytes.fromhex("31c0c3")),
    Patch("CheckMulNICDevice", 0x432BF, bytes.fromhex("6a34b8c31f5900e8a72a1100894de88b"), bytes.fromhex("31c0c3")),
    # Keep the existing disable/cleanup branch; normal EAP receive setup remains.
    Patch("SetProxyDetect-disable-branch", 0x37C87, bytes.fromhex("7529"), bytes.fromhex("9090")),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch_bytes(original: bytes) -> tuple[bytes, dict]:
    if digest(original) != ORIGINAL_SHA256:
        raise ValueError("认证核心版本不匹配；已拒绝修改。请重新分析此版本。")
    patched = bytearray(original)
    records = []
    for patch in PATCHES:
        observed = original[patch.offset:patch.offset + len(patch.expected)]
        if observed != patch.expected:
            raise ValueError(f"{patch.name} 原始指令不匹配；已拒绝修改。")
        patched[patch.offset:patch.offset + len(patch.replacement)] = patch.replacement
        records.append({"name": patch.name, "file_offset": hex(patch.offset),
                        "virtual_address": hex(0x400000 + patch.offset),
                        "before": original[patch.offset:patch.offset + len(patch.replacement)].hex(),
                        "after": patch.replacement.hex()})
    output = bytes(patched)
    return output, {"original_sha256": digest(original), "patched_sha256": digest(output),
                    "patches": records, "byte_changes": sum(a != b for a, b in zip(original, output)),
                    "scope": "Local multi-adapter/shared-service enforcement and anti-proxy enable branch; authentication and heartbeat code retained.",
                    "runtime_verified": False}


def create_patched_copy(source: Path, destination: Path) -> dict:
    source, destination = source.resolve(), destination.resolve()
    if source == destination:
        raise ValueError("禁止覆盖原认证核心；必须选择新的副本路径。")
    patched, manifest = patch_bytes(source.read_bytes())
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.read_bytes() != patched:
            raise FileExistsError("目标已有不同文件；请先保留或检查该文件。")
    else:
        with destination.open("xb") as stream:
            stream.write(patched)
    if digest(destination.read_bytes()) != manifest["patched_sha256"]:
        raise IOError("写入后校验失败")
    return manifest


def verify_copy(path: Path, manifest_path: Path) -> bool:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return digest(path.read_bytes()) == manifest["patched_sha256"]
