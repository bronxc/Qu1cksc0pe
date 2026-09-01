"""Side-effect-free JavaScript behavior emulation for suspicious scripts.

This module deliberately does *not* hand attacker-controlled source to Node,
QuickJS, Python ``eval`` or another executable JavaScript engine.  It performs
bounded abstract interpretation of common browser, WSH and Node.js malware
idioms and records the effects against fake, in-memory APIs.

The goal is behavioral IOC recovery, not standards-compliant JavaScript
execution.  Unsupported expressions remain symbolic and never become host
operations.
"""

from __future__ import annotations

import base64
import ast
import functools
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import time
import urllib.parse
from collections import deque


# Some real-world WSH droppers pad their source past 15-20M characters
# specifically to defeat 8MB-class static analysis caps (junk-character
# interleaving around an embedded base64 payload, thousands of decoy
# statements, etc.). MAX_SOURCE_CHARS was raised from 8_000_000 to clear
# that bar; MAX_WORKER_MEMORY_BYTES was raised alongside it from 256MB to
# 1536MB because a source this size held as a Python str already needs
# 2-4 bytes/char (more once it contains non-BMP filler codepoints), and
# MAX_TOTAL_VALUE_CHARS alone (48M chars) already implies ~192MB of live
# variable data before counting the source, prepared/masked copies, or
# regex temporaries -- 256MB was undersized relative to the module's own
# stated per-run budget and caused legitimate large samples to MemoryError
# before emitting any events. The limit is still a hard RLIMIT_AS ceiling
# enforced on an isolated worker process, so this only widens how much a
# single analysis run is allowed to hold, not what it's allowed to do.
MAX_SOURCE_CHARS = 20_000_000
MAX_VALUE_CHARS = 4_000_000
MAX_TOTAL_VALUE_CHARS = 48_000_000
MAX_VARIABLES = 10_000
MAX_EVENTS = 4_000
MAX_STATEMENTS = 100_000
MAX_DECODED_LAYERS = 8
MAX_ENCRYPTED_LAYER_BYTES = 2_000_000
MAX_EMBEDDED_PAYLOAD_BYTES = 2_000_000
MAX_PARENTHESES_UNWRAP = 256
MAX_STATIC_REPLACEMENTS = 20_000
MAX_STATIC_EXPRESSION_DEPTH = 64
MAX_LOOKUP_ITEMS = 10_000
MAX_WORKER_MEMORY_BYTES = 1536 * 1024 * 1024
WORKER_STARTUP_GRACE_SECONDS = 0.75
DEFAULT_TIMEOUT_SECONDS = 15

_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"
_DOTTED = rf"{_IDENT}(?:\s*\.\s*{_IDENT})*"
_ASSIGN_RE = re.compile(
    rf"(?:^|[{{;]\s*)(?:(?:var|let|const)\s+)?({_IDENT})\s*(\+?=)\s*(.+)$",
    re.IGNORECASE | re.DOTALL,
)
_OBJECT_ASSIGN_RE = re.compile(
    rf"(?:^|[{{;]\s*)({_DOTTED})\s*=\s*(.+)$",
    re.IGNORECASE | re.DOTALL,
)
_REQUIRE_ASSIGN_RE = re.compile(
    rf"(?:var|let|const)\s+({_IDENT})\s*=\s*require\s*\((.+)\)",
    re.IGNORECASE | re.DOTALL,
)
_REQUIRE_MEMBER_ASSIGN_RE = re.compile(
    rf"(?:var|let|const)\s+({_IDENT})\s*=\s*require\s*\((.+?)\)\s*\.\s*({_IDENT})",
    re.IGNORECASE | re.DOTALL,
)
_DESTRUCTURED_REQUIRE_RE = re.compile(
    r"(?:var|let|const)\s*\{([^}]+)\}\s*=\s*require\s*\((.+)\)",
    re.IGNORECASE | re.DOTALL,
)
_NEW_OBJECT_RE = re.compile(
    rf"(?:var|let|const)\s+({_IDENT})\s*=\s*new\s+({_DOTTED})\s*\((.*)\)",
    re.IGNORECASE | re.DOTALL,
)
_ACTIVEX_ASSIGN_RE = re.compile(
    rf"(?:var|let|const)\s+({_IDENT})\s*=\s*(?:new\s+)?(?:ActiveXObject|WScript\.CreateObject)\s*\((.*)\)",
    re.IGNORECASE | re.DOTALL,
)
# WMI process creation (``GetObject("winmgmts:...")`` -> ``.Get("Win32_Process")``
# -> ``.Create(cmdline, ...)``) is a distinct COM surface from ActiveXObject/
# WScript.Shell and just as common a WSH-dropper launch primitive; these two
# track it through the same variable->kind chain ``_ACTIVEX_ASSIGN_RE`` uses.
_GETOBJECT_ASSIGN_RE = re.compile(
    rf"(?:var|let|const)\s+({_IDENT})\s*=\s*GetObject\s*\((.*)\)",
    re.IGNORECASE | re.DOTALL,
)
_WMI_GET_ASSIGN_RE = re.compile(
    rf"(?:var|let|const)\s+({_IDENT})\s*=\s*({_IDENT})\s*\.\s*Get\s*\((.*)\)",
    re.IGNORECASE | re.DOTALL,
)
# The ubiquitous Dean-Edwards-style "packer" (packer.js / most
# javascript-obfuscator.io "compact" presets): parameter names are always
# literally p, a, c, k, e, d -- a reliable, low-false-positive signature.
_PACKER_HEAD_RE = re.compile(
    r"\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)\s*\{",
    re.IGNORECASE,
)
_PACKER_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
# A bare "ident = ident" declarator, anywhere (not just right after a fresh
# ``var``/``let``/``const``).  The lookbehind rejects ``obj.ident = ident``
# (a property write, not an alias declaration); the lookahead requires the
# right-hand identifier to stand alone (not ``= ident(...)``/``= ident.prop``)
# so only genuine bare-name-to-bare-name aliasing matches.
_TOPLEVEL_ALIAS_RE = re.compile(rf"(?<![.\w$])({_IDENT})\s*=\s*({_IDENT})\s*(?=[,;)}}])")
# ``String.prototype.NAME = function(key){ ... }`` -- a monkey-patched
# instance method, as opposed to a free function or object property.  Some
# malware builders use exactly one recurring shape for this: a per-hex-digit
# lookup table concatenated together and suffixed with the string it was
# called on (``"".getX(0x1a2)``), used to assemble ProgIDs/class names a
# byte at a time.  Restricted to standard built-in prototypes to avoid
# matching an unrelated user-defined ``.prototype`` assignment.
_PROTOTYPE_METHOD_RE = re.compile(
    rf"\b(?:String|Array|Object|Number)\.prototype\s*\.\s*({_IDENT})\s*=\s*function\s*\(\s*({_IDENT})\s*\)\s*\{{",
)
# javascript-obfuscator.io "control flow flattening": real statement order is
# hidden behind ``while (COND) { switch (ORDER[IDX++]) { case 'N': ...; } }``,
# where ORDER is a delimited string split into per-case dispatch labels at
# runtime. ``_DISPATCH_SWITCH_RE`` finds the switch itself; the declaration of
# ORDER/IDX is looked up separately (see ``_unflatten_dispatch_switches``)
# since it always precedes the switch but at a variable distance.
_DISPATCH_SWITCH_RE = re.compile(
    rf"switch\s*\(\s*({_IDENT})\s*\[\s*({_IDENT})\+\+\s*\]\s*\)\s*\{{"
)
# The split-equivalent call's own selector (a literal ``.split``, a
# ``['split']`` bracket, or a still-obfuscated ``[decoderCall(...)]``) is not
# required to already read as "split" -- only that it is a member call
# (preceded by ``]`` or an identifier char) taking exactly one short quoted
# delimiter, immediately followed by the paired index declarator. In this
# obfuscation family every *other* decoder call takes two arguments, so a
# lone 1-4-char single-quoted argument is already a distinctive, low-noise
# signal without needing to confirm the callee resolves to "split".
_DISPATCH_ORDER_DECL_TEMPLATE = (
    r"(?:var\s+)?{order}\s*=\s*(.+?[\]\w])\(\s*'([^'\\]{{1,4}})'\s*\)"
    r"\s*,\s*{idx}\s*=\s*0x?0\b"
)
_DISPATCH_CASE_RE = re.compile(r"case\s*'([^']*)'\s*:(.*?)(?=case\s*'[^']*'\s*:|\Z)", re.DOTALL)
# A second, distinct control-flow-flattening idiom seen in the wild
# (MassLogger and others): the dispatch key is a bare numeric variable
# threaded through the case bodies themselves, not a precomputed order
# array -- ``var v = 207249; while (v != 114781) { switch (v) { case
# 586622: ...; v = 309072; break; case 309072: ...; v = 899896; break; ...
# } }``. The while's own ``!=`` exit test doubles as an unambiguous,
# low-false-positive anchor: an ordinary switch on a loop-control variable
# essentially never has that exact shape.
_NUMERIC_STATE_SWITCH_RE = re.compile(
    rf"while\s*\(\s*({_IDENT})\s*!=\s*(\d+)\s*\)\s*\{{\s*switch\s*\(\s*\1\s*\)\s*\{{"
)
_NUMERIC_STATE_CASE_RE = re.compile(r"case\s*(\d+)\s*:(.*?)(?=case\s*\d+\s*:|\Z)", re.DOTALL)
# ``for (var i = 0; i < src.length; i++) { acc += src[i]; }`` -- see
# ``_handle_accumulator_loop``. ``_split_statements`` splits this into the
# header (up to the loop's own ``{``, since braces reset paren/bracket
# depth) and the body as separate statements, so only the header needs
# matching here; the body is matched separately once the header is pending.
_ACCUMULATOR_LOOP_HEADER_RE = re.compile(
    rf"^for\s*\(\s*(?:var\s+)?({_IDENT})\s*=\s*0\s*;\s*\1\s*<\s*({_IDENT})\.length\s*;\s*\1\+\+\s*\)\s*\{{\s*\Z"
)
_ACCUMULATOR_LOOP_BODY_RE = re.compile(
    rf"^({_IDENT})\s*\+=\s*({_IDENT})\s*\[\s*({_IDENT})\s*\]\s*\Z"
)
# A per-character "alphabet lookup by shifted code point" string decoder --
# ``function(s){var out=[],i;for(i=0;i<s.length;i++)out.push(ALPHABET.charAt(
# s.charCodeAt(i)-OFFSET));return out.join("")}`` -- seen wrapping literal
# text encoded into an unrelated Unicode block (Arabic presentation forms in
# one real MassLogger sample) specifically so it displays as inert-looking
# junk rather than recognizable escapes. Its loop body means neither the
# lookup-decoder discovery (expects an array-index factory) nor
# ``_collect_pure_lookup_wrappers`` (expects a single return expression, no
# loop) recognize it; this pattern is matched and evaluated directly instead.
_CHARCODE_LOOKUP_FUNCTION_RE = re.compile(
    rf"function\s*\(\s*({_IDENT})\s*\)\s*\{{\s*"
    rf"var\s+({_IDENT})\s*=\s*\[\s*\]\s*,\s*({_IDENT})\s*;\s*"
    rf"for\s*\(\s*\3\s*=\s*0\s*;\s*\3\s*<\s*\1\.length\s*;\s*\3\+\+\s*\)\s*"
    rf"\2\.push\s*\(\s*({_IDENT})\.charAt\s*\(\s*\1\.charCodeAt\s*\(\s*\3\s*\)\s*([+-])\s*(\d+)\s*\)\s*\)\s*;\s*"
    rf"return\s+\2\.join\s*\(\s*[\"']{{2}}\s*\)\s*\}}"
)
# A plain "shift every code point" string decoder -- ``function(s){var
# out="",i,tmp,K=1760;for(i=0;i<s.length;i++){tmp=s.charCodeAt(i)-K;
# out+=String.fromCharCode(tmp)}return out}`` -- the same reachability gap
# as ``_CHARCODE_LOOKUP_FUNCTION_RE`` (a loop body, so neither lookup-decoder
# discovery nor ``_collect_pure_lookup_wrappers`` sees it) but without an
# alphabet indirection: the shift constant alone recovers the plaintext.
# Seen wrapping literal property/API names hidden in an unrelated Unicode
# block specifically so they don't read as recognizable escapes.
_CHARCODE_SHIFT_FUNCTION_RE = re.compile(
    rf"function\s*\(\s*({_IDENT})\s*\)\s*\{{\s*"
    rf"var\s+({_IDENT})\s*=\s*[\"']{{2}}\s*,\s*({_IDENT})\s*,\s*({_IDENT})\s*,\s*({_IDENT})\s*=\s*(\d+)\s*;\s*"
    rf"for\s*\(\s*\3\s*=\s*0\s*;\s*\3\s*<\s*\1\.length\s*;\s*\3\+\+\s*\)\s*\{{\s*"
    rf"\4\s*=\s*\1\.charCodeAt\s*\(\s*\3\s*\)\s*([+-])\s*\5\s*;\s*"
    rf"\2\s*\+=\s*String\.fromCharCode\s*\(\s*\4\s*\)\s*"
    rf"\}}\s*return\s+\2\s*\}}"
)
# "Indirect eval" -- ``(0, this)["eval"](payload)`` and its siblings
# (``window["eval"]``, ``this["e"+"val"]``, plain ``(0, eval)(...)``) --
# obtains the eval function through a computed member lookup specifically
# to dodge naive ``eval(`` name-matching. ``_iter_call_heads`` cannot see
# it at all: its callee grammar requires a bare-identifier receiver, and
# here the receiver starts with ``(``. This finds only the candidate
# receiver position; the bracketed key still has to evaluate to exactly
# "eval" (case-sensitive, matching real JS lookup) before it's trusted --
# see ``_handle_indirect_eval``.
_INDIRECT_EVAL_RECEIVER_RE = re.compile(
    r"(?:\(\s*0\s*,\s*)?\b(?:this|window|self|globalThis)\b\s*\)?\s*\[",
    re.IGNORECASE,
)
# A 64-data-char + 1-padding-char quoted literal is the base64 alphabet a
# decoder's ``atob``-equivalent helper uses -- distinctive enough on its own
# (see ``_detect_rc4_string_array``) without needing to also confirm it's a
# permutation of the standard alphabet at the regex stage.
_RC4_ALPHABET_RE = re.compile(r"'([A-Za-z0-9+/]{64}=)'")
_RC4_KSA_LOOP_RE = re.compile(r"for\s*\([^;]*;\s*" + _IDENT + r"\s*<\s*0x100\s*;")
_SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".com", ".scr", ".bat", ".cmd", ".ps1", ".hta",
    ".vbs", ".js", ".jse", ".msi", ".lnk", ".sys",
}
_PROCESS_METHODS = {
    "exec", "execsync", "spawn", "spawnsync", "execfile", "fork", "run",
    "shellexecute", "create", "start",
}
_WRITE_METHODS = {
    "writefile", "writefilesync", "appendfile", "appendfilesync", "savetofile",
    "createtextfile", "opentextfile", "write", "writetext",
}
_READ_METHODS = {
    "readfile", "readfilesync", "readtextfile", "readall", "loadfromfile",
}
_DELETE_METHODS = {"unlink", "unlinksync", "rm", "rmsync", "deletefile", "deletefolder"}

_KNOWN_MEMBER_NAMES = {
    "appendfile", "appendfilesync", "buildpath", "charat", "close", "concat",
    "create", "createelement", "createobject", "createtextfile", "deletefile",
    "deletefolder", "exec", "fileexists", "folderexists", "get", "getparentfoldername",
    "join", "loadfromfile", "open", "opentextfile", "post", "readall", "readfile",
    "readfilesync", "regwrite", "replace", "request", "reverse", "run", "save",
    "savetofile", "send", "shellexecute", "shift", "slice", "spawn", "split",
    "start", "substring", "substr", "write", "writefile", "writefilesync", "writetext",
}

# AES primitives used only for recognizing/decrypting the tightly-scoped WSH
# Rijndael envelope below.  Keeping this small implementation in the trusted
# worker preserves ``python -I`` isolation instead of importing attacker-side
# runtimes or weakening the worker's module search path.
_AES_SBOX = (
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
)
_AES_INV_SBOX = tuple(_AES_SBOX.index(value) for value in range(256))


def _aes_gf_mul(left, right):
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        left = ((left << 1) ^ (0x11B if left & 0x80 else 0)) & 0xFF
        right >>= 1
    return result


_AES_MUL = {factor: tuple(_aes_gf_mul(value, factor) for value in range(256)) for factor in (9, 11, 13, 14)}


def _aes256_round_keys(key):
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    words = [list(key[index:index + 4]) for index in range(0, 32, 4)]
    rcon = 1
    while len(words) < 60:
        index = len(words)
        temp = words[-1][:]
        if index % 8 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_AES_SBOX[value] for value in temp]
            temp[0] ^= rcon
            rcon = _aes_gf_mul(rcon, 2)
        elif index % 8 == 4:
            temp = [_AES_SBOX[value] for value in temp]
        words.append([words[index - 8][offset] ^ temp[offset] for offset in range(4)])
    return [sum(words[index:index + 4], []) for index in range(0, 60, 4)]


def _aes256_decrypt_block(block, round_keys):
    state = list(block)

    def add_round_key(round_index):
        key = round_keys[round_index]
        for index in range(16):
            state[index] ^= key[index]

    def inverse_shift_rows():
        original = state[:]
        for row in range(4):
            values = [original[column * 4 + row] for column in range(4)]
            values = values[-row:] + values[:-row] if row else values
            for column, value in enumerate(values):
                state[column * 4 + row] = value

    def inverse_mix_columns():
        for column in range(4):
            offset = column * 4
            a, b, c, d = state[offset:offset + 4]
            state[offset] = _AES_MUL[14][a] ^ _AES_MUL[11][b] ^ _AES_MUL[13][c] ^ _AES_MUL[9][d]
            state[offset + 1] = _AES_MUL[9][a] ^ _AES_MUL[14][b] ^ _AES_MUL[11][c] ^ _AES_MUL[13][d]
            state[offset + 2] = _AES_MUL[13][a] ^ _AES_MUL[9][b] ^ _AES_MUL[14][c] ^ _AES_MUL[11][d]
            state[offset + 3] = _AES_MUL[11][a] ^ _AES_MUL[13][b] ^ _AES_MUL[9][c] ^ _AES_MUL[14][d]

    add_round_key(14)
    for round_index in range(13, 0, -1):
        inverse_shift_rows()
        state[:] = [_AES_INV_SBOX[value] for value in state]
        add_round_key(round_index)
        inverse_mix_columns()
    inverse_shift_rows()
    state[:] = [_AES_INV_SBOX[value] for value in state]
    add_round_key(0)
    return bytes(state)


def _aes256_cbc_decrypt(ciphertext, key, iv):
    if len(iv) != 16 or not ciphertext or len(ciphertext) % 16:
        raise ValueError("invalid AES-CBC input")
    round_keys = _aes256_round_keys(key)
    output = bytearray()
    previous = iv
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16]
        plain = _aes256_decrypt_block(block, round_keys)
        output.extend(left ^ right for left, right in zip(plain, previous))
        previous = block
    return bytes(output)


def _aes256_ecb_decrypt(ciphertext, key):
    """Decrypt complete AES-256 ECB blocks without importing host packages."""
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("invalid AES-ECB input")
    round_keys = _aes256_round_keys(key)
    return b"".join(
        _aes256_decrypt_block(ciphertext[offset:offset + 16], round_keys)
        for offset in range(0, len(ciphertext), 16)
    )


def _pkcs7_unpad(value):
    if not value:
        return None
    padding = value[-1]
    if not (1 <= padding <= 16 and value.endswith(bytes([padding]) * padding)):
        return None
    return value[:-padding]


# javascript-obfuscator.io's "rc4" stringArrayEncoding: each array entry is
# base64 (with a per-build custom, always-case-swapped-or-shuffled alphabet)
# of RC4(plaintext_utf8_bytes, key), further wrapped so the RC4 ciphertext
# survives as a JS string -- the generated decoder does
# ``decodeURIComponent(percent-escape(customBase64Decode(entry)))`` before
# RC4, which (given the encoder built that string one ciphertext byte at a
# time via ``String.fromCharCode``) round-trips to one code unit per
# original ciphertext byte, not a merged multi-byte decode.
_STANDARD_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="


def _rc4_crypt(data, key):
    """Textbook RC4 KSA+PRGA. Self-inverse: also used for decryption."""
    key_bytes = key if isinstance(key, (bytes, bytearray)) else str(key).encode("latin-1", errors="ignore")
    if not data or not key_bytes:
        return None
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key_bytes[i % len(key_bytes)]) % 256
        state[i], state[j] = state[j], state[i]
    i = j = 0
    out = bytearray(len(data))
    for index, byte in enumerate(data):
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        out[index] = byte ^ state[(state[i] + state[j]) % 256]
    return bytes(out)


def _base64_decode_custom_alphabet(text, alphabet):
    if len(alphabet) != 65 or len(set(alphabet)) != 65:
        return None
    cleaned = re.sub(rf"[^{re.escape(alphabet)}]", "", text)
    if not cleaned:
        return None
    translated = cleaned.translate(str.maketrans(alphabet, _STANDARD_BASE64_ALPHABET))
    try:
        return base64.b64decode(translated + "=" * ((-len(translated)) % 4), validate=False)
    except (ValueError, TypeError):
        return None


def _binary_strings(data):
    """Return bounded ASCII and UTF-16LE strings from an in-memory payload."""
    if not isinstance(data, bytes) or len(data) > MAX_EMBEDDED_PAYLOAD_BYTES:
        return []
    found = []
    seen = set()
    for pattern, encoding in (
        (rb"[\x20-\x7e]{4,}", "ascii"),
        (rb"(?:[\x20-\x7e]\x00){4,}", "utf-16le"),
    ):
        for match in re.finditer(pattern, data):
            if len(found) >= 4_000:
                return found
            try:
                value = match.group(0).decode(encoding)
            except UnicodeError:
                continue
            if value not in seen:
                seen.add(value)
                found.append(value)
    return found


def _valid_network_host(value):
    if not value or len(value) > 253 or any(ch.isspace() for ch in value):
        return False
    if _extension(value) in _SUSPICIOUS_EXTENSIONS:
        return False
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        return all(int(part) <= 255 for part in value.split("."))
    return bool(re.fullmatch(
        r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,63}",
        value,
    ))


def _recover_xworm_config(payload):
    """Recover the encrypted network config used by embedded XWorm stubs.

    This is deliberately a data parser, not a CLR loader.  It requires the
    family-specific .NET string/API markers, derives candidate Rijndael keys
    from embedded strings and accepts a result only when the same key yields
    both valid hostnames and a valid TCP port.
    """
    strings = _binary_strings(payload)
    lowered = {value.lower() for value in strings}
    required = ("rijndaelmanaged", "clientsocket", "beginconnect", "hosts", "port")
    if not all(any(marker in value for value in lowered) for marker in required):
        return None

    ciphertexts = []
    for value in strings:
        if not re.fullmatch(r"[A-Za-z0-9+/]{16,}={0,2}", value) or len(value) > 256:
            continue
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            continue
        if decoded and len(decoded) % 16 == 0:
            ciphertexts.append(decoded)
    ciphertexts = list(dict.fromkeys(ciphertexts))[:128]
    if not ciphertexts:
        return None

    password_candidates = [
        value for value in strings
        if 8 <= len(value) <= 64
        and re.fullmatch(r"[A-Za-z0-9_.!@#$%^&*+\-=]+", value)
    ][:1_000]
    for password in password_candidates:
        digest = hashlib.md5(password.encode("utf-8", errors="ignore")).digest()
        # Most stubs duplicate the MD5 hash.  One widespread builder copies
        # the second hash at offset 15, leaving byte 31 zero; model both exact
        # algorithms observed in emitted IL.
        overlapped = bytearray(32)
        overlapped[:16] = digest
        overlapped[15:31] = digest
        for key in (digest + digest, bytes(overlapped)):
            plaintexts = []
            for ciphertext in ciphertexts:
                try:
                    unpadded = _pkcs7_unpad(_aes256_ecb_decrypt(ciphertext, key))
                except (TypeError, ValueError):
                    continue
                if unpadded is None:
                    continue
                try:
                    text = unpadded.decode("utf-8")
                except UnicodeError:
                    continue
                if text and all(ch.isprintable() for ch in text):
                    plaintexts.append(text)
            hosts = []
            for value in plaintexts:
                parts = [part.strip() for part in value.split(",")]
                if parts and all(_valid_network_host(part) for part in parts):
                    hosts.extend(parts)
            ports = [int(value) for value in plaintexts if value.isdigit() and 0 < int(value) <= 65535]
            if hosts and ports:
                return {
                    "family": "XWorm-compatible .NET client",
                    "hosts": list(dict.fromkeys(hosts))[:32],
                    "port": ports[0],
                    "config_strings": plaintexts[:32],
                    "password_sha256": hashlib.sha256(password.encode()).hexdigest(),
                }
    return None


def _recover_vipkeylogger_config(payload):
    """Recover literal panel endpoints and capabilities from VIPKeylogger."""
    strings = _binary_strings(payload)
    lowered = {value.lower() for value in strings}
    required = ("keylogger", "vip recovery", "%$panelconnectionapi$%", "webclient")
    if not all(any(marker in value for value in lowered) for marker in required):
        return None

    panel_urls = []
    direct_urls = []
    for value in strings:
        if value.count("http://") + value.count("https://") >= 2 and "," in value:
            candidates = [item.strip() for item in value.split(",")]
            if candidates and all(re.fullmatch(r"https?://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[^\s]*)?", item) for item in candidates):
                panel_urls.extend(candidates)
        for match in re.finditer(r"https?://[^\s,\x00\"'<>]+", value):
            direct_urls.append(match.group(0).rstrip(".,);]"))
    panel_urls = list(dict.fromkeys(panel_urls))[:32]
    direct_urls = list(dict.fromkeys(direct_urls))[:64]
    if not panel_urls:
        return None
    return {
        "family": "VIPKeylogger-compatible .NET client",
        "panel_urls": panel_urls,
        "direct_urls": direct_urls,
        "download_capability": (
            any("downloads" in value for value in lowered)
            and any("httpwebrequest" in value or "ftpwebrequest" in value for value in lowered)
        ),
        "telegram_capability": any("https://api.telegram.org/bot" in value for value in strings),
    }


def _pe_rva_to_offset(sections, rva):
    for virtual_address, raw_size, raw_pointer in sections:
        # A section's on-disk (raw) size can be smaller than its in-memory
        # (virtual) size -- padding/BSS -- so membership must be tested
        # against the raw size actually available to read, not the RVA
        # range the section occupies once loaded.
        if virtual_address <= rva < virtual_address + raw_size:
            return raw_pointer + (rva - virtual_address)
    return None


def _find_named_pe_resource(payload, type_id, resource_name):
    """Return the raw bytes of a named resource (e.g. Remcos's ``SETTINGS``
    ``RT_RCDATA`` entry) without a PE parsing library, matching this
    worker's "no attacker-adjacent runtime" isolation.  Every offset is
    bounds-checked against ``payload``; any structural surprise aborts
    (returns ``None``) rather than trusting attacker-controlled fields.
    """
    try:
        if len(payload) < 0x40 or payload[:2] != b"MZ":
            return None
        pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
        if pe_offset + 24 > len(payload) or payload[pe_offset:pe_offset + 4] != b"PE\0\0":
            return None
        num_sections, _timestamp, _symtab, _numsym, opt_header_size, _characteristics = (
            struct.unpack_from("<HIIIHH", payload, pe_offset + 6)
        )
        opt_header_offset = pe_offset + 24
        if opt_header_size < 2 or opt_header_offset + opt_header_size > len(payload):
            return None
        magic = struct.unpack_from("<H", payload, opt_header_offset)[0]
        data_dir_offset = opt_header_offset + (96 if magic == 0x10B else 112 if magic == 0x20B else -1)
        if data_dir_offset < 0 or data_dir_offset + 16 > len(payload):
            return None
        resource_rva, _resource_size = struct.unpack_from("<II", payload, data_dir_offset + 16)
        if not resource_rva:
            return None

        section_offset = opt_header_offset + opt_header_size
        sections = []
        for index in range(min(num_sections, 96)):
            entry = section_offset + index * 40
            if entry + 40 > len(payload):
                break
            _virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
                "<IIII", payload, entry + 8
            )
            sections.append((virtual_address, raw_size, raw_pointer))
        resource_base = _pe_rva_to_offset(sections, resource_rva)
        if resource_base is None:
            return None

        def read_directory_entries(directory_offset):
            if directory_offset + 16 > len(payload):
                return []
            named, ids = struct.unpack_from("<HH", payload, directory_offset + 12)
            total = named + ids
            if total > 4_096:
                return []
            entries = []
            for index in range(total):
                entry = directory_offset + 16 + index * 8
                if entry + 8 > len(payload):
                    break
                name_or_id, offset_to_data = struct.unpack_from("<II", payload, entry)
                entries.append((name_or_id, offset_to_data))
            return entries

        def resource_entry_name(name_or_id):
            if not (name_or_id & 0x80000000):
                return name_or_id
            name_offset = resource_base + (name_or_id & 0x7FFFFFFF)
            if name_offset + 2 > len(payload):
                return None
            length = struct.unpack_from("<H", payload, name_offset)[0]
            end = name_offset + 2 + length * 2
            if length > 260 or end > len(payload):
                return None
            try:
                return payload[name_offset + 2:end].decode("utf-16-le")
            except UnicodeError:
                return None

        for name_or_id, offset_to_data in read_directory_entries(resource_base):
            if name_or_id != type_id:
                continue
            if not (offset_to_data & 0x80000000):
                continue
            for name_entry, name_offset in read_directory_entries(resource_base + (offset_to_data & 0x7FFFFFFF)):
                if resource_entry_name(name_entry) != resource_name:
                    continue
                if not (name_offset & 0x80000000):
                    continue
                language_dir = resource_base + (name_offset & 0x7FFFFFFF)
                for _lang_id, data_offset in read_directory_entries(language_dir):
                    if data_offset & 0x80000000:
                        continue
                    data_entry = resource_base + data_offset
                    if data_entry + 16 > len(payload):
                        continue
                    data_rva, data_size = struct.unpack_from("<II", payload, data_entry)
                    if data_size > MAX_EMBEDDED_PAYLOAD_BYTES:
                        continue
                    file_offset = _pe_rva_to_offset(sections, data_rva)
                    if file_offset is None or file_offset + data_size > len(payload):
                        continue
                    return payload[file_offset:file_offset + data_size]
        return None
    except (struct.error, IndexError, UnicodeError):
        return None


_POLYGLOT_COMMENT_PREFIX_RE = re.compile(
    r"^//([A-Z0-9]{8,20})(?:@echo\s+off|setlocal|rem\s|::)", re.MULTILINE | re.IGNORECASE
)


def _recover_js_bat_polyglot_loader(source):
    """Identify a JS/BAT polyglot self-extracting loader.

    Every line of the embedded batch script is prefixed with the same
    ``//TOKEN`` so a JS/WSH engine reads the whole thing as one giant
    comment (a no-op) while a PowerShell one-liner elsewhere in the file
    re-reads the script's own source file, strips that exact prefix off
    each matching line, writes the result out, and runs it -- recovering
    the *technique*, not the final payload, since the actual command a
    dropper built this way runs is typically assembled from dozens of
    ``set`` substring fragments in the extracted batch script itself (a
    different language/interpreter this JS-only worker does not parse).
    Confirmed observed shared verbatim, including this exact self-
    extraction idiom, across independently-flagged AgentTesla and
    RemcosRAT samples -- a loader-kit fingerprint, not a payload-family
    one; downstream payload identity still varies per build.
    """
    match = _POLYGLOT_COMMENT_PREFIX_RE.search(source)
    if not match:
        return None
    marker = f"//{match.group(1)}"
    hidden_lines = source.count(marker)
    if hidden_lines < 20:
        return None
    return {
        "family": "JS/BAT polyglot self-extracting loader",
        "comment_prefix": marker,
        "hidden_line_count": hidden_lines,
    }


def _recover_remcos_signature(payload):
    """Identify an embedded Remcos RAT payload and surface its encrypted
    configuration resource for offline follow-up.

    Remcos's on-disk decoy/loader banner and its BreakingSecurity.net
    attribution are literal, unobfuscated strings in every build observed,
    making family identification reliable from strings alone. Its
    ``RT_RCDATA`` resource named ``SETTINGS`` holds the actual C2/campaign
    configuration, but it is encrypted with a per-build key that (per
    published incident write-ups) is *not* derived from the resource bytes
    themselves -- recovering it needs the specific key material from the
    binary's code, which this static-strings/PE-structure worker does not
    disassemble. Returning the located ciphertext (not a guessed plaintext)
    keeps this honest: a wrong decrypt would misreport a C2 address.
    """
    strings = _binary_strings(payload)
    lowered = {value.lower() for value in strings}
    if not any("breakingsecurity.net" in value for value in lowered):
        return None
    if not any(value.lower() == "remcos" or value.lower().startswith("remcos v") for value in strings):
        return None
    settings = _find_named_pe_resource(payload, 10, "SETTINGS")
    return {
        "family": "Remcos RAT",
        "settings_resource_present": settings is not None,
        "settings_resource_size": len(settings) if settings else None,
        "settings_resource_sha256": hashlib.sha256(settings).hexdigest() if settings else None,
    }


def _recover_lua_polyrot_shellcode(payload):
    """Decode the bounded Lua/PolyRot wrapper used by WSH shellcode droppers.

    The wrapper stores a permuted, reversed Base64 string and contains the
    permutation table plus the inverse PolyRot transform in clear Lua.  This
    parser reproduces only those deterministic data transforms in Python; it
    never invokes Lua/LuaJIT or any code from the sample.
    """
    if not isinstance(payload, bytes) or not payload.startswith(b"local "):
        return None
    try:
        text = payload.decode("utf-8")
    except UnicodeError:
        return None
    literal = re.match(
        r'local\s+[A-Za-z_]\w*\s*=\s*"([^"\\]*(?:\\.[^"\\]*)*)"',
        text,
        re.DOTALL,
    )
    reverse_function = re.search(
        r"function\s+reverse_string\s*\([^)]*\)(.{0,2000}?)return\s*\(",
        text,
        re.DOTALL,
    )
    table_name_match = re.search(
        r"local\s+[A-Za-z_]\w*\s*=\s*([A-Za-z_]\w*)\s*\[[A-Za-z_]\w*\s*\+\s*1\]",
        reverse_function.group(1) if reverse_function else "",
    )
    table = None
    if table_name_match:
        table = re.search(
            rf"local\s+{re.escape(table_name_match.group(1))}\s*=\s*(\{{\{{.*?\}}\}})",
            text,
            re.DOTALL,
        )
    if not literal or not table:
        return None
    encoded = literal.group(1)
    if not (1_000 <= len(encoded) <= MAX_EMBEDDED_PAYLOAD_BYTES * 2) or not encoded.startswith("|"):
        return None

    rows = []
    for raw_row in re.findall(r"\{([^{}]*)\}", table.group(1)):
        values = []
        for raw_value in re.findall(r'"((?:\\.|[^"\\])*)"', raw_row):
            value = re.sub(
                r"\\(\d{1,3})",
                lambda match: chr(int(match.group(1))),
                raw_value,
            )
            values.append(value)
        if values:
            rows.append(values)
    mode_char = encoded[1:2]
    if "0" <= mode_char <= "9":
        mode = ord(mode_char) - ord("0")
    elif "A" <= mode_char <= "O":
        mode = 10 + ord(mode_char) - ord("A")
    else:
        return None
    if mode >= len(rows) or len(rows[mode]) < 10:
        return None

    alphabet = "ABCDEFabcd"
    translation = {rows[mode][index]: alphabet[index] for index in range(10)}
    reversed_base64 = "".join(translation.get(char, char) for char in encoded[2:])[::-1]
    if len(reversed_base64) > MAX_EMBEDDED_PAYLOAD_BYTES * 2:
        return None
    try:
        polyrot = base64.b64decode(
            reversed_base64 + "=" * ((-len(reversed_base64)) % 4),
            validate=True,
        )
    except (ValueError, TypeError):
        return None
    if len(polyrot) < 2 or not 128 <= polyrot[0] <= 221:
        return None
    shift = polyrot[0] - 128
    inverse = 94 - shift
    decoded = bytes(
        33 + ((value - 33 + inverse) % 94) if 33 <= value <= 126 else value
        for value in polyrot[1:]
    )
    return decoded if 64 <= len(decoded) <= MAX_EMBEDDED_PAYLOAD_BYTES else None


def _rotr32(value, count):
    return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF


def _donut_chaskey_block(key, block):
    """Donut's fixed 16-round Chaskey permutation for one CTR block."""
    if len(key) != 16 or len(block) != 16:
        return None
    key_words = list(struct.unpack("<4I", key))
    words = [value ^ key_words[index] for index, value in enumerate(struct.unpack("<4I", block))]
    for _ in range(16):
        words[0] = (words[0] + words[1]) & 0xFFFFFFFF
        words[1] = _rotr32(words[1], 27) ^ words[0]
        words[2] = (words[2] + words[3]) & 0xFFFFFFFF
        words[3] = _rotr32(words[3], 24) ^ words[2]
        words[2] = (words[2] + words[1]) & 0xFFFFFFFF
        words[0] = (_rotr32(words[0], 16) + words[3]) & 0xFFFFFFFF
        words[3] = _rotr32(words[3], 19) ^ words[0]
        words[1] = _rotr32(words[1], 25) ^ words[2]
        words[2] = _rotr32(words[2], 16)
    return struct.pack("<4I", *(words[index] ^ key_words[index] for index in range(4)))


def _recover_donut_payload(shellcode):
    """Recover a Donut v1 instance/module from data without loading it."""
    if not isinstance(shellcode, bytes) or len(shellcode) < 6_000 or shellcode[:1] != b"\xE8":
        return None
    instance_len = struct.unpack_from("<I", shellcode, 5)[0]
    if not (4_744 <= instance_len <= min(len(shellcode) - 5, MAX_EMBEDDED_PAYLOAD_BYTES)):
        return None
    instance = bytearray(shellcode[5:5 + instance_len])
    if struct.unpack_from("<I", instance, 0)[0] != instance_len:
        return None

    # DONUT_INSTANCE v1 keeps len/key/IV/API hashes and the three option
    # integers in clear; encryption begins at api_cnt (offset 572 on x64).
    encrypted_offset = 572
    if len(instance) <= encrypted_offset:
        return None
    key = bytes(instance[4:20])
    counter = bytearray(instance[20:36])
    for offset in range(encrypted_offset, len(instance), 16):
        stream = _donut_chaskey_block(key, counter)
        if stream is None:
            return None
        take = min(16, len(instance) - offset)
        for index in range(take):
            instance[offset + index] ^= stream[index]
        for index in range(15, -1, -1):
            counter[index] = (counter[index] + 1) & 0xFF
            if counter[index]:
                break

    api_count = struct.unpack_from("<i", instance, encrypted_offset)[0]
    dll_names = bytes(instance[576:832]).split(b"\0", 1)[0]
    if not (1 <= api_count <= 64 and b";" in dll_names):
        return None

    # This layout corresponds to the v1 instance containing 15 GUIDs and a
    # MAX_PATH*2 decoy buffer.  Validate every size/type before trusting it.
    instance_type_offset = 2336
    server_offset = 2340
    request_offset = 3108
    module_length_offset = 3416
    module_offset = 3424
    module_data_offset = module_offset + 1320
    if module_data_offset > len(instance):
        return None
    instance_type = struct.unpack_from("<i", instance, instance_type_offset)[0]
    if instance_type not in (1, 2, 3):
        return None
    server = bytes(instance[server_offset:server_offset + 256]).split(b"\0", 1)[0].decode(
        "utf-8", errors="replace"
    )
    request = bytes(instance[request_offset:request_offset + 8]).split(b"\0", 1)[0].decode(
        "ascii", errors="ignore"
    ) or "GET"
    module_length = struct.unpack_from("<Q", instance, module_length_offset)[0]
    result = {
        "instance_type": instance_type,
        "server": server,
        "request": request,
        "module_length": module_length,
    }
    if instance_type != 1:
        return result
    if not (1_328 <= module_length <= len(instance) - module_offset):
        return None

    module_type, thread, compression = struct.unpack_from("<iii", instance, module_offset)
    compressed_len, real_len = struct.unpack_from("<II", instance, module_offset + 1312)
    if module_type not in range(1, 7) or compression not in range(1, 5):
        return None
    stored_len = real_len if compression == 1 else compressed_len
    if not (0 < stored_len <= MAX_EMBEDDED_PAYLOAD_BYTES):
        return None
    if module_data_offset + stored_len > len(instance):
        return None
    result.update({
        "module_type": module_type,
        "thread": thread,
        "compression": compression,
        "compressed_length": compressed_len,
        "real_length": real_len,
        "module": bytes(instance[module_data_offset:module_data_offset + stored_len]),
        "module_complete": compression == 1,
    })
    return result


class _FunctionRef:
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return f"<function:{self.name}>"


class _JSRegex:
    """A ``/pattern/flags`` literal, kept unevaluated until it is actually
    used by a modeled method (``.replace``, ``.test``, ...).  Only a
    conservative subset of patterns can be translated to Python's ``re``
    (see ``_compile_js_regex``); this class just carries the source text so
    that translation only happens where it is needed.
    """
    __slots__ = ("pattern", "flags")

    def __init__(self, pattern, flags):
        self.pattern = pattern
        self.flags = flags

    def __str__(self):
        return f"/{self.pattern}/{self.flags}"


class _CharArray:
    """Compact representation of JavaScript ``text.split('')``."""
    __slots__ = ("text",)

    def __init__(self, text):
        self.text = _cap(text)

    def __str__(self):
        return self.text


class _SplitText:
    """Lazy representation of a very large ``text.split(separator)``.

    Materializing attacker-controlled split results into a Python list both
    wastes memory and used to truncate payload reconstruction at
    ``MAX_VARIABLES`` items.  Keeping the original text plus its separator is
    enough to model the overwhelmingly common ``split(x).join(y)`` idiom
    exactly and without exposing an unbounded host allocation.
    """
    __slots__ = ("text", "separator", "part_count")

    def __init__(self, text, separator, part_count):
        self.text = text
        self.separator = separator
        self.part_count = part_count

    def __len__(self):
        return self.part_count

    def __str__(self):
        return f"<split-text:{self.part_count} parts>"


class _BinaryValue:
    """Opaque in-memory bytes recovered from a modeled script data flow."""
    __slots__ = ("data", "sha256", "complete", "encoding")

    def __init__(self, data, *, complete=True, encoding="binary"):
        self.data = bytes(data[:MAX_EMBEDDED_PAYLOAD_BYTES])
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        self.complete = bool(complete) and len(data) <= MAX_EMBEDDED_PAYLOAD_BYTES
        self.encoding = encoding

    def __len__(self):
        return len(self.data)

    def __str__(self):
        state = "complete" if self.complete else "partial"
        return f"<binary:{len(self.data)} bytes sha256={self.sha256} {state}>"


def _safe_event_value(value, depth=0):
    """Bound recursively structured attacker-controlled event fields."""
    if depth > 3:
        return "<depth-limit>"
    if isinstance(value, (_Unknown, _BinaryValue, _SplitText, str)):
        return _safe_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        bounded = [_safe_event_value(item, depth + 1) for item in value[:32]]
        if len(value) > 32:
            bounded.append(f"<{len(value) - 32} more items>")
        return bounded
    if isinstance(value, dict):
        bounded = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 32:
                bounded["<truncated>"] = f"<{len(value) - 32} more items>"
                break
            bounded[_safe_text(key, 128)] = _safe_event_value(item, depth + 1)
        return bounded
    return _safe_text(value)


def _safe_numeric_eval(expression, names=None):
    """Evaluate arithmetic only; calls, attributes and subscripts are rejected."""
    text = str(expression or "").strip()
    if not text or len(text) > 4096:
        return None
    try:
        tree = ast.parse(text, mode="eval")
    except (SyntaxError, ValueError, MemoryError):
        return None
    values = names or {}

    def visit(node, depth=0):
        if depth > 64:
            raise ValueError
        if isinstance(node, ast.Expression):
            return visit(node.body, depth + 1)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.Name) and node.id in values and isinstance(values[node.id], (int, float)):
            return values[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            value = visit(node.operand, depth + 1)
            return value if isinstance(node.op, ast.UAdd) else -value
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod)):
            left = visit(node.left, depth + 1)
            right = visit(node.right, depth + 1)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Div):
                if right == 0:
                    raise ValueError
                return left / right
            if right == 0:
                raise ValueError
            return left % right
        raise ValueError

    try:
        result = visit(tree)
    except (ArithmeticError, TypeError, ValueError, OverflowError):
        return None
    if isinstance(result, float) and result.is_integer():
        return int(result)
    return result if isinstance(result, (int, float)) else None


def _js_parse_int(value):
    match = re.match(r"^[\s]*([+-]?(?:0[xX][0-9a-fA-F]+|\d+))", str(value))
    if not match:
        return None
    token = match.group(1)
    try:
        sign = -1 if token.startswith("-") else 1
        unsigned = token.lstrip("+-")
        return sign * int(unsigned, 16 if unsigned.lower().startswith("0x") else 10)
    except ValueError:
        return None


_REGEX_LITERAL_FLAG_CHARS = "gimsuy"
_REGEX_OPERAND_CONTEXT_WORDS = frozenset((
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "case", "yield", "do", "else", "throw",
))


def _looks_like_regex_literal_start(text, slash_index):
    """Best-effort operand-vs-operator disambiguation for a bare ``/`` seen
    outside any active quote (JS's classic regex-literal-vs-division
    ambiguity): a regex literal can only start where an *operand* is
    expected, never right after one.

    This existed nowhere in the module before: every quote-tracking scan
    here (``_extract_balanced``, ``_split_statements``, ...) tracked only
    ``'``/``"``/backtick, so a bare ``'``/``"`` *inside* a regex literal
    (e.g. ``/\\'/g``, seen in real samples building a PowerShell
    quote-escaper) was read as opening a real string. Everything after
    that misread quote -- including genuine code -- then stayed
    misclassified as string data until some later, unrelated quote
    happened to resync it, corrupting paren/brace matching for the rest
    of the statement.
    """
    index = slash_index - 1
    while index >= 0 and text[index] in " \t\r\n":
        index -= 1
    if index < 0:
        return True
    ch = text[index]
    if ch in "([{,;=!&|?:+-*%^~<>":
        return True
    if ch.isalnum() or ch in "_$":
        word_end = index + 1
        word_start = word_end
        while word_start > 0 and (text[word_start - 1].isalnum() or text[word_start - 1] in "_$"):
            word_start -= 1
        return text[word_start:word_end] in _REGEX_OPERAND_CONTEXT_WORDS
    return False


def _regex_literal_end(text, slash_index):
    """Index just past a ``/pattern/flags`` literal's flags, given
    ``text[slash_index] == '/'`` and an operand context already confirmed
    by ``_looks_like_regex_literal_start``. Returns ``None`` if the span
    doesn't close like a valid regex literal (never a guess: callers must
    fall back to treating the ``/`` as plain division on ``None``).
    """
    index = slash_index + 1
    length = len(text)
    in_class = False
    escaped = False
    while index < length:
        ch = text[index]
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "/" and not in_class:
            end = index + 1
            while end < length and text[end] in _REGEX_LITERAL_FLAG_CHARS:
                end += 1
            return end
        elif ch in "\r\n":
            return None
        index += 1
    return None


_JS_REGEX_FLAG_MAP = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}


def _compile_js_regex(pattern, flags):
    """Best-effort translation of a ``/pattern/flags`` literal to a Python
    ``re.Pattern``. JS and Python regex syntax agree closely enough for the
    escapes/classes/quantifiers obfuscators actually use (most commonly a
    single escaped character, e.g. ``/\\'/g`` to double up quotes before
    re-embedding a string). Returns ``None`` -- never a guess -- for
    anything that doesn't compile under Python's engine or that is long
    enough to be a plausible ReDoS pattern rather than a real literal.
    """
    if len(pattern) > 200:
        return None
    py_flags = 0
    for flag in flags:
        py_flags |= _JS_REGEX_FLAG_MAP.get(flag, 0)
    try:
        return re.compile(pattern, py_flags)
    except re.error:
        return None


def _extract_balanced(text, open_index, opener="{", closer="}"):
    depth = 0
    quote = None
    escaped = False
    skip_until = 0
    for index in range(open_index, len(text)):
        if index < skip_until:
            continue
        ch = text[index]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == "/" and _looks_like_regex_literal_start(text, index):
            regex_end = _regex_literal_end(text, index)
            if regex_end is not None:
                skip_until = regex_end
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[open_index + 1:index], index
    return None, None


class _Unknown:
    __slots__ = ("text",)

    def __init__(self, text=""):
        self.text = _cap(str(text), 512)

    def __str__(self):
        return self.text or "<unknown>"


def _cap(value, limit=MAX_VALUE_CHARS):
    text = str(value)
    if len(text) > limit:
        return text[:limit] + "...<truncated>"
    return text


def _is_unknown(value):
    return isinstance(value, _Unknown)


def _safe_text(value, limit=4096):
    if value is None:
        return ""
    return _cap(str(value), limit)


def _strip_comments(source):
    """Remove comments with a linear scanner while preserving quoted text."""
    out = []
    index = 0
    quote = None
    escaped = False
    length = len(source)
    while index < length:
        ch = source[index]
        nxt = source[index + 1] if index + 1 < length else ""
        if quote:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            index += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(ch)
            index += 1
            continue
        if ch == "/" and nxt not in ("/", "*") and _looks_like_regex_literal_start(source, index):
            regex_end = _regex_literal_end(source, index)
            if regex_end is not None:
                out.append(source[index:regex_end])
                index = regex_end
                continue
        if ch == "/" and nxt == "/":
            index += 2
            while index < length and source[index] not in "\r\n":
                index += 1
            out.append("\n")
            continue
        if ch == "/" and nxt == "*":
            index += 2
            while index + 1 < length and source[index:index + 2] != "*/":
                out.append("\n" if source[index] == "\n" else " ")
                index += 1
            index = min(index + 2, length)
            continue
        out.append(ch)
        index += 1
    return "".join(out)


def _split_top_level(text, delimiter=","):
    parts = []
    start = 0
    paren = bracket = brace = 0
    quote = None
    escaped = False
    skip_until = 0
    for index, ch in enumerate(text):
        if index < skip_until:
            continue
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == "/" and _looks_like_regex_literal_start(text, index):
            regex_end = _regex_literal_end(text, index)
            if regex_end is not None:
                skip_until = regex_end
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(paren - 1, 0)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(bracket - 1, 0)
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(brace - 1, 0)
        elif ch == delimiter and paren == bracket == brace == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    parts.append(text[start:].strip())
    return parts


def _split_top_level_ternary(text):
    """Return ``condition, truthy, falsy`` for one top-level ternary."""
    paren = bracket = brace = 0
    quote = None
    escaped = False
    question = None
    nested = 0
    skip_until = 0
    for index, ch in enumerate(text):
        if index < skip_until:
            continue
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == "/" and _looks_like_regex_literal_start(text, index):
            regex_end = _regex_literal_end(text, index)
            if regex_end is not None:
                skip_until = regex_end
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(paren - 1, 0)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(bracket - 1, 0)
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(brace - 1, 0)
        elif paren == bracket == brace == 0:
            if ch == "?":
                if question is None:
                    question = index
                else:
                    nested += 1
            elif ch == ":" and question is not None:
                if nested:
                    nested -= 1
                else:
                    return text[:question], text[question + 1:index], text[index + 1:]
    return None


def _split_statements(source):
    """Split enough JavaScript for bounded abstract interpretation.

    Curly braces intentionally do not prevent splitting: function and branch
    bodies are inspected conservatively even when reachability is unknown.
    Every ``{`` therefore pushes the enclosing paren/bracket depth and
    resets both to zero, so a block body starts a fresh statement sequence
    regardless of parens still open around it (an IIFE wrapper -- almost
    every obfuscator's top-level shape, ``(function(){ ...body... }())`` --
    would otherwise keep ``paren`` above zero for the *entire* body, hiding
    every statement inside behind one opaque blob); ``}`` pops back to
    whatever was open immediately outside the block.
    """
    statements = []
    start = 0
    paren = bracket = 0
    brace_stack = []
    quote = None
    escaped = False
    skip_until = 0
    for index, ch in enumerate(source):
        if index < skip_until:
            continue
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == "/" and _looks_like_regex_literal_start(source, index):
            regex_end = _regex_literal_end(source, index)
            if regex_end is not None:
                skip_until = regex_end
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(paren - 1, 0)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(bracket - 1, 0)
        elif ch == "{":
            brace_stack.append((paren, bracket))
            paren = bracket = 0
        elif ch == "}":
            if brace_stack:
                paren, bracket = brace_stack.pop()
        elif ch in ";\n" and paren == bracket == 0:
            part = source[start:index].strip()
            if part:
                statements.append(part)
            start = index + 1
    tail = source[start:].strip()
    if tail:
        statements.append(tail)
    return statements


def _split_function_top_level(source):
    """Split only statements in the current function body.

    Unlike :func:`_split_statements`, braces remain part of the nesting
    depth.  This is used for tiny pure-function models where assignments in
    nested decoy functions must not leak into the caller's local scope.
    """
    statements = []
    start = 0
    paren = bracket = brace = 0
    quote = None
    escaped = False
    skip_until = 0
    for index, ch in enumerate(source):
        if index < skip_until:
            continue
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == "/" and _looks_like_regex_literal_start(source, index):
            regex_end = _regex_literal_end(source, index)
            if regex_end is not None:
                skip_until = regex_end
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(paren - 1, 0)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(bracket - 1, 0)
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(brace - 1, 0)
        elif ch == ";" and paren == bracket == brace == 0:
            part = source[start:index].strip()
            if part:
                statements.append(part)
            start = index + 1
    tail = source[start:].strip()
    if tail:
        statements.append(tail)
    return statements


_DECLARATION_HEAD_RE = re.compile(r"^(var|let|const)\s+", re.IGNORECASE)


def _expand_declarator_statements(statements):
    """Split ``var a = X, b = new Y(), c = Z;`` into one statement per
    declarator (``var a = X``, ``var b = new Y()``, ``var c = Z``).

    Minifiers and obfuscators overwhelmingly bundle many declarators into a
    single ``var`` statement.  Every assignment-shaped regex in this module
    (``_ASSIGN_RE``, ``_NEW_OBJECT_RE``, ``_ACTIVEX_ASSIGN_RE``, the
    ``require`` family) anchors on a ``var``/``let``/``const`` keyword
    immediately before the identifier it captures, so only the *first*
    declarator in such a statement was ever recognized -- every later one
    (very often the interesting one: a second ``ActiveXObject``, a
    ``require`` call, ...) was silently invisible.  Splitting first, so each
    piece again looks like an ordinary single-declarator statement, fixes
    this for every consumer at once instead of patching each regex.  A top
    level, paren/bracket/brace-aware comma split is safe here: JavaScript's
    grammar only allows a bare comma directly in a declaration list to mean
    "next declarator".
    """
    expanded = []
    for statement in statements:
        head = _DECLARATION_HEAD_RE.match(statement)
        if not head:
            expanded.append(statement)
            continue
        parts = _split_top_level(statement[head.end():], ",")
        if len(parts) <= 1:
            expanded.append(statement)
            continue
        keyword = head.group(1)
        for part in parts:
            part = part.strip()
            if part:
                expanded.append(f"{keyword} {part}")
    return expanded


_CONTROL_HEAD_RE = re.compile(
    r"^(?:for|while|if|switch|function|catch|else|do)\b", re.IGNORECASE
)


def _expand_comma_assignment_chains(statements):
    """Split a bare (no ``var``/``let``/``const``) comma-chained sequence of
    assignments -- ``a.prop = X, b[k] = Y, c()`` -- into one statement per
    piece, mirroring ``_expand_declarator_statements`` for declarations.

    Minifiers chain plain assignments with the comma operator just as
    often as they chain declarators. Every assignment-shaped regex in this
    module anchors its own ``(.+)$``/DOTALL capture to the *statement's*
    end, so a later chained assignment was previously swallowed whole into
    the first assignment's "value" (silently corrupting it) and never
    itself evaluated. A top-level comma split is safe outside declarations
    too: JavaScript's comma *operator* just means "evaluate each in order,
    keep only the last value", so splitting into separately-observed
    statements changes nothing about which side effects happen or when.
    Skipped for control-flow headers, whose own top-level-looking commas
    (``for (var i = 0, j = 10; ...)``) are guarded by
    ``_expand_declarator_statements`` already handling the ``var`` case
    and are otherwise nested inside that header's own parens (not actually
    top-level) -- this guard is only extra insurance.
    """
    expanded = []
    for statement in statements:
        if _DECLARATION_HEAD_RE.match(statement) or _CONTROL_HEAD_RE.match(statement.strip()):
            expanded.append(statement)
            continue
        parts = _split_top_level(statement, ",")
        if len(parts) <= 1:
            expanded.append(statement)
            continue
        for part in parts:
            part = part.strip()
            if part:
                expanded.append(part)
    return expanded


_DUPLICATE_SELF_APPEND_RE = re.compile(rf"^({_IDENT})\s*=\s*\1\s*\+\s*(.+)$", re.DOTALL)


def _collapse_duplicate_accumulation_runs(statements, threshold=3):
    """Collapse a long run of byte-identical consecutive ``X = X + EXPR``
    statements into one ``X = X + (EXPR).repeat(N)`` statement.

    Seen as deliberate padding purely to exhaust a static analyzer's
    statement budget: every sample with this shape repeats the *exact
    same* call, byte-for-byte, thousands of times in a row (``EXPR`` never
    varies -- no loop counter, no index, nothing). Since ``EXPR`` cannot
    reference ``X``'s own growing value (that would not match this regex,
    which requires the RHS to start with the literal ``X +``) or anything
    else that changes between repeats, evaluating it once and repeating the
    resulting string ``N`` times is exactly equivalent to executing the
    statement ``N`` times -- just without the ``N`` statement ticks.
    """
    out = []
    index = 0
    total = len(statements)
    while index < total:
        stmt = statements[index]
        end = index + 1
        while end < total and statements[end] == stmt:
            end += 1
        run_length = end - index
        if run_length >= threshold:
            match = _DUPLICATE_SELF_APPEND_RE.match(stmt.strip())
            if match:
                name, expr = match.groups()
                out.append(f"{name}={name}+({expr}).repeat({run_length})")
                index = end
                continue
        out.append(stmt)
        index += 1
    return out


def _balanced_outer_parentheses(text):
    if len(text) < 2 or text[0] != "(" or text[-1] != ")":
        return False
    depth = 0
    quote = None
    escaped = False
    for index, ch in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and index != len(text) - 1:
                return False
    return depth == 0


@functools.lru_cache(maxsize=64)
def _decode_js_string(token):
    # Pure function of ``token`` -- cached because the static-deobfuscation
    # fixed-point loop (see ``_extract_factory_values``'s callers in
    # ``_prepare_static_deobfuscation``) can legitimately re-decode the
    # *same* multi-megabyte array-literal item several times across passes
    # while the underlying source is still stable. Found via profiling a
    # real 18MB sample: one 7.45M-char token was decoded 3 times and a
    # 1.36M-char token 6 times, accounting for ~21s of a run that otherwise
    # produced zero events (it never got past the first statement). A
    # small ``maxsize`` is enough -- this is about not redoing the same
    # few large decodes repeatedly within one run, not caching broadly.
    quote = token[0]
    body = token[1:-1]
    out = []
    index = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
    while index < len(body) and len(out) < MAX_VALUE_CHARS:
        ch = body[index]
        if ch != "\\" or index + 1 >= len(body):
            out.append(ch)
            index += 1
            continue
        nxt = body[index + 1]
        index += 2
        if nxt in escapes:
            out.append(escapes[nxt])
        elif nxt == "x" and index + 2 <= len(body):
            try:
                out.append(chr(int(body[index:index + 2], 16)))
                index += 2
            except ValueError:
                out.append("x")
        elif nxt == "u":
            if index < len(body) and body[index] == "{":
                end = body.find("}", index + 1, index + 10)
                if end != -1:
                    try:
                        out.append(chr(int(body[index + 1:end], 16)))
                        index = end + 1
                        continue
                    except (ValueError, OverflowError):
                        pass
            if index + 4 <= len(body):
                try:
                    out.append(chr(int(body[index:index + 4], 16)))
                    index += 4
                except ValueError:
                    out.append("u")
            else:
                out.append("u")
        elif nxt in "\r\n":
            if nxt == "\r" and index < len(body) and body[index] == "\n":
                index += 1
        else:
            out.append(nxt)
    value = "".join(out)
    if quote == "`":
        value = re.sub(
            rf"\$\{{\s*({_IDENT})\s*\}}",
            lambda match: "${" + match.group(1) + "}",
            value,
        )
    return _cap(value)


def _string_literal_end(text, quote):
    """Index of the unescaped closing quote for a literal starting at ``text[0]``."""
    index = 1
    escaped = False
    length = len(text)
    while index < length:
        ch = text[index]
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == quote:
            return index
        index += 1
    return None


def _encode_packer_token(value, radix):
    """Re-implementation of packer.js's own public ``e(c)`` base-``radix``
    keyword-index encoder (digits ``0-9a-z`` then ``A-Z`` up to base 62)."""
    if value < radix:
        return _PACKER_ALPHABET[value] if value < 36 else chr(value + 29)
    digits = []
    remaining = value
    while remaining > 0:
        remainder = remaining % radix
        digits.append(_PACKER_ALPHABET[remainder] if remainder < 36 else chr(remainder + 29))
        remaining //= radix
    return "".join(reversed(digits))


def _unpack_packer_payload(payload, radix, count, keywords):
    """Statically re-run packer.js's own keyword-substitution algorithm.

    This is the tool's well-known, public decode routine -- a bounded,
    deterministic string substitution -- re-implemented in pure Python so the
    packed payload never needs to reach a JavaScript engine.
    """
    if count <= 0 or count > MAX_LOOKUP_ITEMS or radix < 2 or radix > 62:
        return None
    mapping = {}
    for index in range(count):
        word = keywords[index] if index < len(keywords) else ""
        if not word:
            continue
        mapping[_encode_packer_token(index, radix)] = word
    if not mapping:
        return payload
    tokens = sorted(mapping, key=len, reverse=True)
    pattern = re.compile(r"\b(" + "|".join(re.escape(token) for token in tokens) + r")\b")
    return pattern.sub(lambda match: mapping[match.group(1)], payload)


def _extract_call(text, open_index):
    depth = 0
    quote = None
    escaped = False
    skip_until = 0
    for index in range(open_index, len(text)):
        if index < skip_until:
            continue
        ch = text[index]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == "/" and _looks_like_regex_literal_start(text, index):
            regex_end = _regex_literal_end(text, index)
            if regex_end is not None:
                skip_until = regex_end
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1:index], index
    return None, None


def _iter_call_heads(text, limit=256):
    """Yield nested dotted calls while ignoring attacker-controlled strings."""
    index = 0
    emitted = 0
    length = len(text)
    while index < length and emitted < limit:
        ch = text[index]
        if ch in ("'", '"', "`"):
            quote = ch
            index += 1
            escaped = False
            while index < length:
                current = text[index]
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    index += 1
                    break
                index += 1
            continue
        if not (ch.isalpha() or ch in "_$"):
            index += 1
            continue
        start = index
        index += 1
        while index < length and (text[index].isalnum() or text[index] in "_$"):
            index += 1
        while True:
            probe = index
            while probe < length and text[probe].isspace():
                probe += 1
            if probe >= length or text[probe] != ".":
                break
            probe += 1
            while probe < length and text[probe].isspace():
                probe += 1
            if probe >= length or not (text[probe].isalpha() or text[probe] in "_$"):
                break
            index = probe + 1
            while index < length and (text[index].isalnum() or text[index] in "_$"):
                index += 1
        open_index = index
        while open_index < length and text[open_index].isspace():
            open_index += 1
        if open_index < length and text[open_index] == "(":
            raw_args, end_index = _extract_call(text, open_index)
            if raw_args is not None:
                yield re.sub(r"\s+", "", text[start:index]), raw_args, open_index, end_index
                emitted += 1
                # Continue inside the arguments so APIs nested in ``if(...)``
                # or wrapper calls remain observable.
                index = open_index + 1
                continue
        index = max(index, start + 1)


def _collect_global_string_literals(source):
    """Best-effort ``{name: "literal"}`` map for simple top-level
    ``var NAME = "a"+"b"+...;`` string declarations.

    Used only to resolve an extra layer of indirection obfuscators commonly
    add over property names -- ``obj[NAME]`` where ``NAME`` is itself a
    module-level constant like ``var NAME = "length";`` -- before
    ``_normalize_computed_members`` runs; that method's own expression
    evaluator has no visibility into sibling top-level declarations on its
    own.  A name assigned more than once to different literal values is
    dropped rather than guessed: that is far more likely to be per-scope
    shadowing (a different local of the same name) than a real global
    constant, and guessing wrong here would corrupt property names instead
    of just leaving them unresolved.
    """
    found = {}
    ambiguous = set()
    for match in re.finditer(
        r"\bvar\s+(" + _IDENT + r')\s*=\s*((?:[\'"][^\'"]{0,64}[\'"]\s*\+\s*)*[\'"][^\'"]{0,64}[\'"])\s*;',
        source,
    ):
        name, expr = match.groups()
        if name in ambiguous:
            continue
        value = "".join(re.findall(r"['\"]([^'\"]{0,64})['\"]", expr))
        if name in found and found[name] != value:
            del found[name]
            ambiguous.add(name)
            continue
        found[name] = value
    return found


def _extension(path):
    clean = str(path).split("?", 1)[0].split("#", 1)[0].lower()
    dot = clean.rfind(".")
    slash = max(clean.rfind("/"), clean.rfind("\\"))
    return clean[dot:] if dot > slash else ""


class JavaScriptEmulator:
    def __init__(self, source, origin="script.js", timeout_seconds=DEFAULT_TIMEOUT_SECONDS):
        self.origin = _safe_text(origin, 512)
        source_text = str(source or "")
        self.source = source_text[:MAX_SOURCE_CHARS]
        self.source_truncated = len(source_text) > MAX_SOURCE_CHARS
        self.timeout_seconds = max(1, min(int(timeout_seconds or DEFAULT_TIMEOUT_SECONDS), 30))
        self.started = time.monotonic()
        self.deadline = self.started + self.timeout_seconds
        self.step_count = 0
        self.events = []
        self.variables = {
            "__dirname": "C:\\Users\\User\\AppData\\Local\\Temp",
            "__filename": f"C:\\Users\\User\\AppData\\Local\\Temp\\{self.origin}",
        }
        self._stored_value_chars = sum(len(str(value)) for value in self.variables.values())
        # ``_split_statements`` splits on every top-level newline, not just
        # ``;`` -- a multi-line object literal (``x = {\n 'a': ...,\n 'b':
        # ...\n}``) therefore arrives as one statement per property, each
        # missing the ``owner = {`` prefix that named it. This carries that
        # owner across the statements between the opener and its closing
        # ``}`` so ``_handle_object_literal_com_creation`` can still attribute
        # a bundled ``new ActiveXObject(...)`` property to it.
        self._pending_object_literal_owner = None
        self._pending_accumulator_loop = None
        self.objects = {}
        self.modules = {}
        self.aliases = {}
        # General bare-name-to-bare-name aliasing (``var b = a;``), distinct
        # from ``lookup_aliases`` (decoder *function* names only) and
        # ``aliases`` (Node module re-exports only). Populated in
        # ``_record_assignment`` and consulted by the dotted-member lookup in
        # ``_eval_expr`` so ``b.prop`` still finds a value recorded under
        # ``a.prop`` -- dispatch-table/COM-wrapper variables are frequently
        # aliased this way to add noise without changing behavior.
        self.object_aliases = {}
        self.xhr_state = {}
        self.virtual_files = {}
        self.registry = {}
        self.decoded_layers = []
        self.errors = []
        self.timed_out = False
        self.statement_limit_hit = False
        self._event_keys = set()
        self._layer_hashes = set()
        self.lookup_decoders = {}
        self.lookup_aliases = {}
        self.pure_functions = {}
        self.charcode_lookup_functions = {}
        self.charcode_shift_functions = {}
        self._factory_ranges = []
        self._prepared_source = None
        self._packer_layers = []
        self._encrypted_layers = []
        self._embedded_payloads = []
        self._embedded_payload_hashes = set()
        self._stored_binary_bytes = 0
        self.dispatch_objects = {}
        self.prototype_hex_methods = {}

    @staticmethod
    def _local_assignments(body):
        """Collect bounded, deterministic top-level local assignments."""
        # A named helper declaration is terminated by its closing brace, not
        # a semicolon.  Without masking it, the following top-level ``var``
        # statement is glued to the helper by the lightweight statement
        # splitter and its data flow disappears.  Mask only *named* nested
        # declarations; anonymous functions in object literals remain intact
        # for the existing object-model extractor.
        masked_body = body
        nested_ranges = []
        for match in re.finditer(rf"\bfunction\s+{_IDENT}\s*\([^)]*\)\s*\{{", body):
            open_index = body.find("{", match.start(), match.end())
            nested, end_index = _extract_balanced(body, open_index)
            if nested is None:
                continue
            nested_ranges.append((match.start(), end_index + 1))
            if len(nested_ranges) >= 256:
                break
        for start, end in reversed(nested_ranges):
            masked_body = masked_body[:start] + (" " * (end - start)) + masked_body[end:]

        assignments = []
        for statement in _split_function_top_level(masked_body):
            declaration = _DECLARATION_HEAD_RE.match(statement)
            parts = _split_top_level(statement[declaration.end():], ",") if declaration else [statement]
            for part in parts:
                match = re.fullmatch(rf"\s*({_IDENT})\s*=\s*(.+?)\s*", part, re.DOTALL)
                if not match:
                    continue
                expression = match.group(2).strip()
                # Object literals are already represented by ``objects``;
                # function/IIFE initializers are deliberately outside this
                # pure-data model.  Large expressions are also rejected.
                if len(expression) > 4096 or expression.startswith("{") or "function" in expression:
                    continue
                assignments.append((match.group(1), expression))
                if len(assignments) >= 256:
                    return assignments
        # Branch-local decoder aliases are safe and useful even though the
        # surrounding branch itself is modeled separately as a ternary.
        # Restrict this second pass to bare identifier aliases so arbitrary
        # nested expressions are never interpreted out of scope.
        present = {name for name, _ in assignments}
        for match in re.finditer(rf"\b(?:var|let|const)\s+({_IDENT})\s*=\s*({_IDENT})\s*(?=[,;])", body):
            if match.group(1) not in present:
                assignments.append((match.group(1), match.group(2)))
                present.add(match.group(1))
                if len(assignments) >= 256:
                    break
        return assignments

    @staticmethod
    def _needed_assignments(assignments, return_expression):
        """Keep only locals that can contribute to a pure return value."""
        needed = set(re.findall(_IDENT, return_expression or ""))
        selected = []
        for name, expression in reversed(assignments):
            if name not in needed:
                continue
            selected.append((name, expression))
            needed.update(re.findall(_IDENT, expression))
        selected.reverse()
        return selected

    def _find_function(self, source, name):
        match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\(([^)]*)\)\s*\{{", source)
        if not match:
            return None
        open_index = source.find("{", match.start())
        body, end_index = _extract_balanced(source, open_index)
        if body is None:
            return None
        params = [part.strip() for part in _split_top_level(match.group(1)) if re.fullmatch(_IDENT, part.strip())]
        return {"name": name, "params": params, "body": body, "start": match.start(), "end": end_index + 1}

    def _decoder_value(self, name, argument, rotation=None, key=None):
        canonical = self.lookup_aliases.get(name, name)
        spec = self.lookup_decoders.get(canonical)
        if not spec or not isinstance(argument, (int, float)):
            return _Unknown(f"{name}({argument})")
        index = int(argument) - spec["offset"]
        values = spec.get("values") or []
        if not values:
            return _Unknown(f"{name}({argument})")
        alphabet = spec.get("rc4_alphabet")
        if alphabet and key:
            decoded = self._decode_rc4_value(values[index % len(values)], key, alphabet)
            if decoded is not None:
                return decoded
        selected_rotation = spec.get("rotation", 0) if rotation is None else rotation
        return values[(index + selected_rotation) % len(values)]

    def _basic_static_value(self, expression, local_objects=None, rotations=None, depth=0):
        if depth > 24:
            return _Unknown("<static-depth>")
        expr = str(expression or "").strip().rstrip(";")
        if not expr:
            return ""
        while _balanced_outer_parentheses(expr):
            expr = expr[1:-1].strip()
        if len(expr) >= 2 and expr[0] in ("'", '"', "`") and expr[-1] == expr[0]:
            return _decode_js_string(expr)
        number = _safe_numeric_eval(expr)
        if number is not None:
            return number

        call = re.match(rf"^({_IDENT})\s*\(", expr)
        if call:
            open_index = expr.find("(", call.start())
            raw_args, end_index = _extract_call(expr, open_index)
            if raw_args is not None and not expr[end_index + 1:].strip():
                args = [self._basic_static_value(arg, local_objects, rotations, depth + 1)
                        for arg in _split_top_level(raw_args)] if raw_args.strip() else []
                name = call.group(1)
                canonical = self.lookup_aliases.get(name, name)
                if canonical in self.lookup_decoders and args and isinstance(args[0], (int, float)):
                    override = (rotations or {}).get(canonical)
                    key = args[1] if len(args) > 1 and isinstance(args[1], str) else None
                    return self._decoder_value(canonical, args[0], override, key=key)

        member = re.fullmatch(rf"({_IDENT})\s*\[\s*(.+)\s*\]", expr, re.DOTALL)
        if member and local_objects and member.group(1) in local_objects:
            key = self._basic_static_value(member.group(2), local_objects, rotations, depth + 1)
            if not _is_unknown(key):
                return local_objects[member.group(1)].get(str(key), _Unknown(f"{member.group(1)}[{key}]"))
        dotted = re.fullmatch(rf"({_IDENT})\.({_IDENT})", expr)
        if dotted and local_objects and dotted.group(1) in local_objects:
            return local_objects[dotted.group(1)].get(dotted.group(2), _Unknown(expr))
        return _Unknown(expr)

    def _parse_object_properties(self, raw_object, objects=None, rotations=None):
        properties = {}
        for item in _split_top_level(raw_object):
            prop_match = re.match(rf"\s*(?:'([^']+)'|\"([^\"]+)\"|({_IDENT}))\s*:\s*(.+)\s*$", item, re.DOTALL)
            if not prop_match:
                continue
            key = prop_match.group(1) or prop_match.group(2) or prop_match.group(3)
            value_expr = prop_match.group(4).strip()
            function_match = re.match(r"function\s*\(([^)]*)\)\s*\{", value_expr)
            if function_match:
                function_open = value_expr.find("{", function_match.start())
                function_body, _ = _extract_balanced(value_expr, function_open)
                return_expr = self._root_return_expression(function_body or "")
                local_assignments = self._local_assignments(function_body or "")
                properties[key] = {
                    "params": [part.strip() for part in _split_top_level(function_match.group(1)) if re.fullmatch(_IDENT, part.strip())],
                    "return": return_expr,
                    "assignments": self._needed_assignments(local_assignments, return_expr),
                }
            else:
                properties[key] = self._basic_static_value(value_expr, objects or {}, rotations)
        return properties

    def _extract_local_objects(self, body, rotations=None):
        objects = {}
        cursor = 0
        pattern = re.compile(rf"\b({_IDENT})\s*=\s*\{{")
        while cursor < len(body) and len(objects) < 64:
            match = pattern.search(body, cursor)
            if not match:
                break
            open_index = body.find("{", match.start())
            raw_object, end_index = _extract_balanced(body, open_index)
            if raw_object is None:
                break
            objects[match.group(1)] = self._parse_object_properties(raw_object, objects, rotations)
            cursor = end_index + 1
        return objects

    def _discover_dispatch_objects(self, source):
        """Model small object-literal "dispatch tables" that many obfuscators
        use to hide operators and calls behind randomly-named properties,
        e.g. ``_0xb55e0a = {'lUQiI': function(a, b) { return a(b); }, ...}``
        then ``_0xb55e0a['lUQiI'](callee, arg)``.  Bounded to small literals
        so large unrelated data tables are left alone.
        """
        pattern = re.compile(rf"\b({_IDENT})\s*=\s*\{{")
        cursor = 0
        found = 0
        attempts = 0
        while cursor < len(source) and found < 16:
            attempts += 1
            if attempts % 64 == 0 and time.monotonic() > self.deadline:
                break
            match = pattern.search(source, cursor)
            if not match:
                break
            open_index = source.find("{", match.start())
            raw_object, end_index = _extract_balanced(source, open_index)
            if raw_object is None:
                break
            cursor = end_index + 1
            if len(raw_object) <= 65_536 and "function" in raw_object:
                # Pass the dispatch objects already discovered so a property
                # value that references a *sibling* dispatch object
                # (``'RUbvI': _0x72b416[decoderCall(...)]``, one dispatch
                # table pointing into another -- an extra indirection layer
                # obfuscators add specifically on top of the single-level
                # wrapper idiom this method is named for) can resolve
                # instead of ``_basic_static_value`` seeing an empty
                # ``local_objects`` and giving up immediately.
                self.dispatch_objects[match.group(1)] = self._parse_object_properties(raw_object, self.dispatch_objects)
                found += 1

    def _discover_prototype_hex_table_methods(self, source):
        """Model ``String.prototype.NAME = function(key){ ... }`` when its
        body is the recurring "hex-digit indexed lookup table" shape: build a
        literal string array, then for each hex digit of ``key`` concatenate
        ``table[digit]``, finally appending the string the method was called
        on (``result + this``).  Seen used to assemble ProgIDs/.NET class
        names a byte at a time (e.g. ``"".getX(0x1a2)`` ->
        ``"System.IO.MemoryStream"``) without a literal string anywhere in
        the source.  Deliberately narrow: only this exact, deterministic
        shape is modeled, not general prototype methods or loops.
        """
        for match in _PROTOTYPE_METHOD_RE.finditer(source):
            method_name, param = match.group(1), match.group(2)
            open_index = source.find("{", match.start())
            body, _ = _extract_balanced(source, open_index)
            if body is None or len(body) > 4_000:
                continue
            array_match = re.search(rf"\bvar\s+({_IDENT})\s*=\s*\[", body)
            if not array_match:
                continue
            array_open = body.find("[", array_match.start())
            raw_array, array_end = _extract_balanced(body, array_open, "[", "]")
            if raw_array is None:
                continue
            data_var = array_match.group(1)
            items = _split_top_level(raw_array) if raw_array.strip() else []
            if not items or len(items) > 64:
                continue
            table = []
            for item in items:
                item = item.strip()
                if not (len(item) >= 2 and item[0] in ("'", '"') and item[-1] == item[0]):
                    table = None
                    break
                table.append(_decode_js_string(item))
            if table is None:
                continue
            result_match = re.search(rf"\bvar\s+({_IDENT})\s*=\s*(?:\"\"|'')\s*;", body[array_end:])
            if not result_match:
                continue
            result_var = result_match.group(1)
            accumulate_re = re.compile(
                rf"\b{re.escape(result_var)}\s*\+=\s*{re.escape(data_var)}\s*\[\s*parseInt\s*\(\s*"
                rf"{re.escape(param)}(?:\.toString\(\))?\s*\.\s*(?:substr|charAt)\s*\([^)]*\)\s*,\s*16\s*\)\s*\]"
            )
            if not accumulate_re.search(body):
                continue
            return_re = re.compile(rf"\breturn\s+{re.escape(result_var)}\s*\+\s*this(?:\.toString\(\))?\s*;")
            if not return_re.search(body):
                continue
            self.prototype_hex_methods[method_name.lower()] = table

    def _invoke_hex_table_method(self, table, receiver_value, args):
        if not args or _is_unknown(args[0]):
            return _Unknown("<unresolved-hex-key>")
        pieces = []
        for ch in str(args[0]):
            try:
                digit = int(ch, 16)
            except ValueError:
                return _Unknown("<hex-table-sentinel>")
            if digit >= len(table):
                return _Unknown("<hex-table-sentinel>")
            pieces.append(table[digit])
        suffix = "" if _is_unknown(receiver_value) else str(receiver_value)
        return _cap("".join(pieces) + suffix)

    @staticmethod
    def _root_return_expression(body):
        def branch_return(position):
            while position < len(body) and body[position].isspace():
                position += 1
            if position < len(body) and body[position] == "{":
                block, end = _extract_balanced(body, position)
                if block is None:
                    return None, position
                return JavaScriptEmulator._root_return_expression(block), end + 1
            if not body.startswith("return", position):
                return None, position
            start = position + 6
            end = start
            paren = bracket = 0
            quote = None
            escaped = False
            while end < len(body):
                ch = body[end]
                if quote:
                    if escaped:
                        escaped = False
                    elif ch == "\\":
                        escaped = True
                    elif ch == quote:
                        quote = None
                elif ch in ("'", '"', "`"):
                    quote = ch
                elif ch == "(":
                    paren += 1
                elif ch == ")":
                    paren = max(paren - 1, 0)
                elif ch == "[":
                    bracket += 1
                elif ch == "]":
                    bracket = max(bracket - 1, 0)
                elif ch == ";" and paren == bracket == 0:
                    return body[start:end].strip(), end + 1
                end += 1
            return None, position

        # Preserve the real branch of opaque-predicate wrappers such as
        # ``if (decoder(x) !== decoder(x)) return decoy; else { return real; }``.
        # Representing it as a ternary lets the bounded static evaluator pick
        # the branch after resolving the comparison.
        depth = 0
        quote = None
        escaped = False
        index = 0
        while index < len(body):
            ch = body[index]
            if quote:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                index += 1
                continue
            if ch in ("'", '"', "`"):
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth = max(depth - 1, 0)
            elif depth == 0 and body.startswith("if", index) and (
                index == 0 or not re.match(r"[A-Za-z0-9_$]", body[index - 1])
            ):
                probe = index + 2
                while probe < len(body) and body[probe].isspace():
                    probe += 1
                if probe < len(body) and body[probe] == "(":
                    condition, condition_end = _extract_call(body, probe)
                    if condition is not None:
                        truthy, truthy_end = branch_return(condition_end + 1)
                        else_probe = truthy_end
                        while else_probe < len(body) and body[else_probe].isspace():
                            else_probe += 1
                        if body.startswith("else", else_probe):
                            falsy, _ = branch_return(else_probe + 4)
                            if truthy and falsy:
                                return f"({condition}) ? ({truthy}) : ({falsy})"
            index += 1

        candidates = []
        index = 0
        brace = paren = bracket = 0
        quote = None
        escaped = False
        while index < len(body):
            ch = body[index]
            if quote:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                index += 1
                continue
            if ch in ("'", '"', "`"):
                quote = ch
                index += 1
                continue
            if ch == "{":
                brace += 1
            elif ch == "}":
                brace = max(0, brace - 1)
            elif ch == "(":
                paren += 1
            elif ch == ")":
                paren = max(0, paren - 1)
            elif ch == "[":
                bracket += 1
            elif ch == "]":
                bracket = max(0, bracket - 1)
            elif brace == 0 and body.startswith("return", index) and (index == 0 or not re.match(r"[A-Za-z0-9_$]", body[index - 1])):
                start = index + 6
                end = start
                local_paren = local_bracket = 0
                local_quote = None
                local_escaped = False
                while end < len(body):
                    current = body[end]
                    if local_quote:
                        if local_escaped:
                            local_escaped = False
                        elif current == "\\":
                            local_escaped = True
                        elif current == local_quote:
                            local_quote = None
                    elif current in ("'", '"', "`"):
                        local_quote = current
                    elif current == "(":
                        local_paren += 1
                    elif current == ")":
                        local_paren = max(0, local_paren - 1)
                    elif current == "[":
                        local_bracket += 1
                    elif current == "]":
                        local_bracket = max(0, local_bracket - 1)
                    elif current == ";" and local_paren == local_bracket == 0:
                        break
                    end += 1
                candidates.append(body[start:end].strip())
                index = end
            index += 1
        return candidates[-1] if candidates else None

    def _build_pure_function(self, source, name):
        if name in self.pure_functions:
            return self.pure_functions[name]
        found = self._find_function(source, name)
        if not found:
            return None
        for alias_match in re.finditer(rf"\b(?:var\s+)?({_IDENT})\s*=\s*({_IDENT})", found["body"]):
            canonical = self.lookup_aliases.get(alias_match.group(2))
            if canonical:
                self.lookup_aliases[alias_match.group(1)] = canonical
        return_expression = self._root_return_expression(found["body"])
        model = {
            "params": found["params"],
            "objects": self._extract_local_objects(found["body"]),
            "return": return_expression,
            "assignments": self._needed_assignments(
                self._local_assignments(found["body"]), return_expression
            ),
        }
        self.pure_functions[name] = model
        return model

    def _resolve_static_properties(self, expression, env, objects, rotations, depth):
        text = expression
        pattern = re.compile(rf"({_IDENT})\s*\[")
        cursor = 0
        out = []
        replacements = 0
        while cursor < len(text):
            match = pattern.search(text, cursor)
            if not match or (
                match.group(1) not in objects and match.group(1) not in self.dispatch_objects
            ) or replacements > 128:
                out.append(text[cursor:])
                break
            open_index = text.find("[", match.start())
            raw_key, end_index = _extract_balanced(text, open_index, "[", "]")
            if raw_key is None:
                out.append(text[cursor:])
                break
            key = self._eval_static_expression(raw_key, env, objects, rotations, depth + 1)
            owner = objects.get(match.group(1), self.dispatch_objects.get(match.group(1), {}))
            value = owner.get(str(key), _Unknown(raw_key)) if not _is_unknown(key) else _Unknown(raw_key)
            out.append(text[cursor:match.start()])
            if isinstance(value, (int, float)):
                out.append(str(value))
            elif isinstance(value, str):
                # Property lookups used inside subtraction/multiplication are
                # coerced to numbers by JavaScript.  Keep ordinary strings
                # quoted, but expose strict numeric-string constants to the
                # arithmetic-only evaluator below.
                numeric_string = _safe_numeric_eval(value) if re.fullmatch(r"[+\-]?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?)", value.strip()) else None
                out.append(str(numeric_string) if numeric_string is not None else json.dumps(value))
            else:
                out.append(text[match.start():end_index + 1])
            cursor = end_index + 1
            replacements += 1
        return "".join(out)

    def _resolve_static_decoder_calls(self, expression, env, objects, rotations, depth):
        """Fold nested lookup calls inside otherwise arithmetic expressions."""
        text = expression
        call_pattern = re.compile(rf"\b({_IDENT})\s*\(([^()]*)\)")
        for _ in range(16):
            changed = False

            def replace(match):
                nonlocal changed
                canonical = self.lookup_aliases.get(match.group(1), match.group(1))
                if canonical not in self.lookup_decoders:
                    return match.group(0)
                raw_call_args = _split_top_level(match.group(2))
                if not raw_call_args:
                    return match.group(0)
                argument = self._eval_static_expression(raw_call_args[0], env, objects, rotations, depth + 1)
                if not isinstance(argument, (int, float)) or isinstance(argument, bool):
                    return match.group(0)
                key = None
                if len(raw_call_args) > 1:
                    key_value = self._eval_static_expression(raw_call_args[1], env, objects, rotations, depth + 1)
                    if isinstance(key_value, str):
                        key = key_value
                value = self._decoder_value(canonical, argument, (rotations or {}).get(canonical), key=key)
                changed = True
                if isinstance(value, (int, float)):
                    return str(value)
                value_text = str(value)
                before = text[:match.start()].rstrip()[-1:] or ""
                after = text[match.end():].lstrip()[:1]
                if (before in "-*/%" or after in "-*/%") and re.fullmatch(
                    r"[+\-]?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?)", value_text.strip()
                ):
                    number = _safe_numeric_eval(value_text)
                    return str(number) if number is not None else json.dumps(value_text)
                return json.dumps(value_text)

            reduced = call_pattern.sub(replace, text)
            text = reduced
            if not changed:
                break
        return text

    def _eval_static_expression(self, expression, env=None, objects=None, rotations=None, depth=0):
        if depth > MAX_STATIC_EXPRESSION_DEPTH:
            return _Unknown("<static-expression-depth>")
        env = env or {}
        objects = objects or {}
        expr = str(expression or "").strip().rstrip(";")
        while _balanced_outer_parentheses(expr):
            expr = expr[1:-1].strip()
        # JavaScript's comma operator evaluates left-to-right and returns the
        # final expression.  Obfuscator-generated wrappers commonly put an
        # anti-debug IIFE before the real lookup call in exactly this form.
        comma_parts = _split_top_level(expr, ",")
        if len(comma_parts) > 1:
            return self._eval_static_expression(comma_parts[-1], env, objects, rotations, depth + 1)
        ternary = _split_top_level_ternary(expr)
        if ternary:
            condition, truthy, falsy = ternary
            condition = condition.strip()
            while _balanced_outer_parentheses(condition):
                condition = condition[1:-1].strip()
            comparison = re.fullmatch(r"\s*(.+?)\s*(===|!==|==|!=)\s*(.+?)\s*", condition, re.DOTALL)
            decision = None
            if comparison:
                left = self._eval_static_expression(comparison.group(1), env, objects, rotations, depth + 1)
                right = self._eval_static_expression(comparison.group(3), env, objects, rotations, depth + 1)
                if not _is_unknown(left) and not _is_unknown(right):
                    equal = type(left) is type(right) and left == right if comparison.group(2) in ("===", "!==") else str(left) == str(right)
                    decision = not equal if comparison.group(2) in ("!==", "!=") else equal
            if decision is not None:
                return self._eval_static_expression(
                    truthy if decision else falsy, env, objects, rotations, depth + 1
                )
        if len(expr) >= 2 and expr[0] in ("'", '"', "`") and expr[-1] == expr[0]:
            return _decode_js_string(expr)
        if expr[:1] in ("+", "-") and re.match(rf"^\s*{_IDENT}\s*\(", expr[1:]):
            operand = self._eval_static_expression(expr[1:], env, objects, rotations, depth + 1)
            if isinstance(operand, (int, float)) and not isinstance(operand, bool):
                return operand if expr[0] == "+" else -operand
        if re.fullmatch(_IDENT, expr):
            if expr in env:
                return env[expr]
            canonical = self.lookup_aliases.get(expr, expr)
            if canonical in self.lookup_decoders or expr in self.pure_functions or expr in ("parseInt", "parseFloat"):
                return _FunctionRef(expr)
        member = re.fullmatch(rf"({_IDENT})\s*(?:\.\s*({_IDENT})|\[\s*(.+)\s*\])", expr, re.DOTALL)
        if member:
            # Fall back to a globally-discovered dispatch table when the
            # owner isn't a locally-scoped object (e.g. ``dispatch['key']``
            # used as a bracket key/callee, not just a plain call statement).
            owner = objects.get(member.group(1))
            if owner is None:
                owner = self.dispatch_objects.get(member.group(1))
            if owner is not None:
                key = member.group(2)
                if key is None:
                    key_value = self._eval_static_expression(member.group(3), env, objects, rotations, depth + 1)
                    key = str(key_value) if not _is_unknown(key_value) else None
                return owner.get(key, _Unknown(expr)) if key else _Unknown(expr)

        call_open = None
        quote = None
        escaped = False
        bracket_depth = 0
        for index, ch in enumerate(expr):
            if quote:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                continue
            if ch in ("'", '"', "`"):
                quote = ch
            elif ch == "[":
                bracket_depth += 1
            elif ch == "]":
                bracket_depth = max(0, bracket_depth - 1)
            elif ch == "(" and bracket_depth == 0:
                call_open = index
                break
        if call_open is not None:
            raw_args, end_index = _extract_call(expr, call_open)
            if raw_args is not None and not expr[end_index + 1:].strip():
                callee_expr = expr[:call_open].strip()
                args = [self._eval_static_expression(arg, env, objects, rotations, depth + 1)
                        for arg in _split_top_level(raw_args)] if raw_args.strip() else []
                value_method = re.fullmatch(
                    rf"({_IDENT})\s*(?:\.\s*({_IDENT})|\[\s*(.+)\s*\])",
                    callee_expr,
                    re.DOTALL,
                )
                if value_method and value_method.group(1) in env:
                    method_name = value_method.group(2)
                    if method_name is None:
                        resolved_method = self._eval_static_expression(
                            value_method.group(3), env, objects, rotations, depth + 1
                        )
                        method_name = str(resolved_method) if not _is_unknown(resolved_method) else None
                    if method_name:
                        result = self._apply_value_method(env[value_method.group(1)], method_name, args)
                        if not _is_unknown(result):
                            return result
                callee = self._eval_static_expression(callee_expr, env, objects, rotations, depth + 1)
                if isinstance(callee, _FunctionRef):
                    if callee.name in ("parseInt", "parseFloat") and args and not _is_unknown(args[0]):
                        if callee.name == "parseInt":
                            parsed = _js_parse_int(args[0])
                            return parsed if parsed is not None else _Unknown(f"parseInt({args[0]})")
                        match = re.match(r"^[\s]*([+-]?(?:\d+(?:\.\d*)?|\.\d+))", str(args[0]))
                        try:
                            return float(match.group(1)) if match else _Unknown(f"parseFloat({args[0]})")
                        except (TypeError, ValueError, OverflowError):
                            return _Unknown(f"parseFloat({args[0]})")
                    canonical = self.lookup_aliases.get(callee.name, callee.name)
                    if canonical in self.lookup_decoders and args and isinstance(args[0], (int, float)):
                        override = (rotations or {}).get(canonical)
                        key = args[1] if len(args) > 1 and isinstance(args[1], str) else None
                        return self._decoder_value(canonical, args[0], override, key=key)
                    model = self.pure_functions.get(callee.name)
                    if model:
                        return self._invoke_pure_model(model, args, rotations, depth + 1)
                if isinstance(callee, dict):
                    return self._invoke_pure_model(callee, args, rotations, depth + 1)

        # Tiny dispatch wrappers frequently express addition/concatenation as
        # ``return left + right``.  Resolve only the two bare parameters here;
        # broader JavaScript coercion remains intentionally unsupported.
        simple_addition = re.fullmatch(rf"\s*({_IDENT})\s*\+\s*({_IDENT})\s*", expr)
        if simple_addition:
            left = env.get(simple_addition.group(1), _Unknown(expr))
            right = env.get(simple_addition.group(2), _Unknown(expr))
            if not _is_unknown(left) and not _is_unknown(right):
                if (
                    isinstance(left, (int, float)) and not isinstance(left, bool)
                    and isinstance(right, (int, float)) and not isinstance(right, bool)
                ):
                    return left + right
                return _cap(str(left) + str(right))

        # JavaScript coerces numeric strings for arithmetic operators other
        # than ``+``.  Obfuscators commonly keep lookup-table constants as
        # strings and subtract them inside tiny wrapper functions.  Model
        # that narrow, deterministic case without inheriting JavaScript's
        # much broader (and riskier) implicit-conversion surface.
        coercing_arithmetic = re.fullmatch(
            rf"\s*({_IDENT})\s*([*/%\-])\s*({_IDENT}|[+\-]?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?))\s*",
            expr,
        )
        if coercing_arithmetic:
            left = env.get(coercing_arithmetic.group(1), _Unknown(expr))
            right_token = coercing_arithmetic.group(3)
            right = env.get(right_token, _Unknown(expr)) if re.fullmatch(_IDENT, right_token) else _safe_numeric_eval(right_token)

            def js_number(value):
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    return value
                if isinstance(value, str):
                    stripped = value.strip()
                    if stripped:
                        return _safe_numeric_eval(stripped)
                return None

            lhs = js_number(left)
            rhs = js_number(right)
            if lhs is not None and rhs is not None:
                operator = coercing_arithmetic.group(2)
                if operator == "-":
                    return lhs - rhs
                if operator == "*":
                    return lhs * rhs
                if operator == "/" and rhs != 0:
                    return lhs / rhs
                if operator == "%" and rhs != 0:
                    return lhs % rhs

        numeric_text = self._resolve_static_decoder_calls(expr, env, objects, rotations, depth)
        numeric_text = self._resolve_static_properties(numeric_text, env, objects, rotations, depth)
        numeric_names = {key: value for key, value in env.items() if isinstance(value, (int, float))}
        if len(_split_top_level(numeric_text, "+")) == 1 and re.search(r"[*/%\-]", numeric_text):
            for key, value in env.items():
                if isinstance(value, str) and re.fullmatch(r"[+\-]?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?)", value.strip()):
                    converted = _safe_numeric_eval(value)
                    if converted is not None:
                        numeric_names[key] = converted
        number = _safe_numeric_eval(numeric_text, numeric_names)
        return number if number is not None else _Unknown(expr)

    def _invoke_pure_model(self, model, args, rotations=None, depth=0):
        if not model or not model.get("return") or depth > MAX_STATIC_EXPRESSION_DEPTH:
            return _Unknown("<pure-function>")
        env = {name: args[index] if index < len(args) else _Unknown(name)
               for index, name in enumerate(model.get("params", []))}
        for name, expression in model.get("assignments", []):
            value = self._eval_static_expression(
                expression, env, model.get("objects", {}), rotations, depth + 1
            )
            env[name] = value
        return self._eval_static_expression(model["return"], env, model.get("objects", {}), rotations, depth + 1)

    @staticmethod
    def _is_subtraction_model(model):
        params = model.get("params") if isinstance(model, dict) else None
        if not params or len(params) != 2:
            return False
        return re.sub(r"\s+", "", model.get("return") or "") == f"{params[0]}-{params[1]}"

    def _resolve_dispatch_offset(self, body, param_name):
        """Find ``{param} = DISPATCH[key](args)`` where the dispatch
        property (via ``self.dispatch_objects``) is a plain two-argument
        subtraction, and return the second argument as the decoder's
        numeric offset.  ``key`` may be a literal string/dot property, or --
        as some samples do -- itself an obfuscated decoder call; when the key
        cannot be read directly, a dispatch object with exactly one
        subtraction-shaped property is treated as unambiguous."""
        call_re = re.compile(rf"\b{re.escape(param_name)}\s*=\s*({_IDENT})\s*\[")
        for match in call_re.finditer(body):
            properties = self.dispatch_objects.get(match.group(1))
            if not properties:
                continue
            bracket_open = match.end() - 1
            raw_key, bracket_end = _extract_balanced(body, bracket_open, "[", "]")
            if raw_key is None:
                continue
            call_lead = re.match(r"\s*\(", body[bracket_end + 1:])
            if not call_lead:
                continue
            call_open = bracket_end + 1 + call_lead.end() - 1
            raw_args, _ = _extract_call(body, call_open)
            if raw_args is None:
                continue
            args = _split_top_level(raw_args)
            if len(args) != 2:
                continue
            key_literal = re.fullmatch(r"\s*(?:'([^']+)'|\"([^\"]+)\")\s*", raw_key)
            subtraction_keys = [key for key, model in properties.items() if self._is_subtraction_model(model)]
            if key_literal:
                key = key_literal.group(1) or key_literal.group(2)
                if key not in subtraction_keys:
                    continue
            elif len(subtraction_keys) != 1:
                continue
            offset = _safe_numeric_eval(args[1])
            if isinstance(offset, (int, float)) and 0 <= offset <= 100_000:
                return int(offset)
        return None

    def _detect_rc4_string_array(self, body):
        """Best-effort detection of javascript-obfuscator.io's ``rc4``
        stringArrayEncoding inside a decoder function's own body: a
        self-contained base64-with-custom-alphabet decode followed by a
        textbook RC4 key-scheduling loop (256-entry swap) and an XOR
        keystream applied via ``charCodeAt``/``fromCharCode``.  Each array
        value then decodes only given the *second* argument the decoder is
        called with (the RC4 key) -- see ``_decode_rc4_value``.  Returns the
        detected base64 alphabet, or ``None`` when the shape doesn't match
        closely enough to trust (never a guess: a wrong alphabet would just
        make every decode fail cleanly via ``_decode_rc4_value``, but a
        false-positive detection on ordinary code would be wasted work on
        every call, so the two structural markers below are required).
        """
        if "charCodeAt" not in body or "fromCharCode" not in body or "0x100" not in body:
            return None
        if not _RC4_KSA_LOOP_RE.search(body):
            return None
        alphabet_match = _RC4_ALPHABET_RE.search(body)
        if not alphabet_match:
            return None
        alphabet = alphabet_match.group(1)
        if sorted(alphabet) != sorted(_STANDARD_BASE64_ALPHABET):
            return None
        return alphabet

    def _decode_rc4_value(self, raw_value, key, alphabet):
        if not isinstance(raw_value, str) or not isinstance(key, str) or not key:
            return None
        decoded_bytes = _base64_decode_custom_alphabet(raw_value, alphabet)
        if not decoded_bytes:
            return None
        try:
            ciphertext_units = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if any(ord(unit) > 0xFF for unit in ciphertext_units):
            return None
        plaintext_bytes = _rc4_crypt(bytes(ord(unit) for unit in ciphertext_units), key)
        if not plaintext_bytes:
            return None
        try:
            return plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def _discover_lookup_decoders(self, source):
        candidates = []
        for scan_index, match in enumerate(re.finditer(rf"\bfunction\s+({_IDENT})\s*\(([^)]*)\)\s*\{{", source)):
            # A large, heavily-padded sample can have thousands of candidate
            # function declarations to screen here, each doing real regex/
            # balanced-scan work -- and this runs entirely before the main
            # loop's own ``_tick()`` deadline checks exist. Bail out with
            # whatever's already been found rather than let this single
            # discovery pass burn the sample's whole wall-clock budget.
            if scan_index % 128 == 0 and time.monotonic() > self.deadline:
                break
            params = [part.strip() for part in _split_top_level(match.group(2)) if re.fullmatch(_IDENT, part.strip())]
            if not params:
                continue
            # Lookup decoders are tiny.  Reject ordinary functions from a
            # bounded preview before doing a balanced-body scan; large
            # obfuscated samples commonly contain thousands of decoy helpers.
            preview = source[match.end():match.end() + 2_000]
            first = params[0]
            if not re.search(rf"\[\s*{re.escape(first)}\s*\]", preview):
                continue
            if not (
                re.search(rf"=\s*{_IDENT}\s*\(\s*\)", preview)
                or re.search(rf"\(\s*{_IDENT}\s*\)", preview)
            ):
                continue
            open_index = source.find("{", match.start())
            body, end_index = _extract_balanced(source, open_index)
            if body is None or len(body) > 12_000:
                continue
            factory_match = re.search(rf"=\s*({_IDENT})\s*\(\s*\)", body)
            if not factory_match:
                array_source = re.search(
                    rf"\b({_IDENT})\s*=\s*(.+?)[,;].*?\b\1\s*\[\s*{re.escape(first)}\s*\]",
                    body,
                    re.DOTALL,
                )
                factory_name = None
                if array_source:
                    for possible in reversed(re.findall(_IDENT, array_source.group(2))):
                        possible_function = self._find_function(source, possible)
                        if possible_function and re.search(rf"\b(?:var\s+)?{_IDENT}\s*=\s*\[", possible_function["body"]):
                            factory_name = possible
                            break
                if not factory_name:
                    continue
            else:
                factory_name = factory_match.group(1)
            offset = None
            direct = re.search(rf"\b{re.escape(first)}\s*=\s*{re.escape(first)}\s*-\s*(.+?)\s*;", body, re.DOTALL)
            if direct:
                offset = _safe_numeric_eval(direct.group(1))
            if offset is None:
                assignment = re.search(rf"\b{re.escape(first)}\s*=\s*(.+?)\s*;", body, re.DOTALL)
                if assignment:
                    numeric_runs = re.findall(r"(?<![A-Za-z0-9_$])[+\-]?\d+(?:\s*[+*/-]\s*[+\-]?\d+)+(?![A-Za-z0-9_$])", assignment.group(1))
                    for numeric_run in reversed(numeric_runs):
                        value = _safe_numeric_eval(numeric_run)
                        if isinstance(value, (int, float)) and 0 <= value <= 100_000:
                            offset = int(value)
                            break
            if offset is None:
                # Some samples hide even a "primary" decoder's own offset
                # subtraction behind a dispatch-table proxy instead of a
                # literal ``-`` in source (``i = dispatch['x'](i, 0xb1)``
                # where ``dispatch.x`` is modeled as ``return p0 - p1``).
                offset = self._resolve_dispatch_offset(body, first)
            if offset is None:
                continue
            rc4_alphabet = self._detect_rc4_string_array(body)
            candidates.append((match.start(), match.group(1), factory_name, int(offset), rc4_alphabet))
        for _, name, factory, offset, rc4_alphabet in sorted(candidates):
            self.lookup_decoders[name] = {
                "factory": factory,
                "offset": offset,
                "values": [],
                "rotation": 0,
                "rotation_solved": False,
                "rc4_alphabet": rc4_alphabet,
            }
            self.lookup_aliases[name] = name
        # Obfuscators overwhelmingly declare these aliases as later
        # declarators in one shared ``var a = ..., b = X, c = X`` statement
        # (no repeated ``var`` keyword, comma- not semicolon-terminated), and
        # frequently chain them (``b = X`` then, elsewhere, ``c = b``).  A
        # bounded fixed-point pass over the lenient bare-assignment pattern
        # resolves both; the lookbehind still rejects property assignments
        # (``obj.b = X``) so unrelated code cannot be mistaken for aliasing.
        for _ in range(4):
            changed = False
            for match in _TOPLEVEL_ALIAS_RE.finditer(source):
                target = self.lookup_aliases.get(match.group(2), match.group(2))
                if target in self.lookup_decoders and self.lookup_aliases.get(match.group(1)) != target:
                    self.lookup_aliases[match.group(1)] = target
                    changed = True
            if not changed:
                break

    def _extract_factory_values(self, source, spec):
        found = self._find_function(source, spec["factory"])
        if not found:
            return None
        array_match = re.search(rf"\b(?:var\s+)?{_IDENT}\s*=\s*\[", found["body"])
        if not array_match:
            return None
        open_index = found["body"].find("[", array_match.start())
        raw_array, _ = _extract_balanced(found["body"], open_index, "[", "]")
        if raw_array is None:
            return None
        items = _split_top_level(raw_array)
        if len(items) > MAX_LOOKUP_ITEMS:
            return None
        prefix = found["body"][:open_index]
        changed = True
        while changed:
            changed = False
            for alias_match in re.finditer(rf"\b(?:var\s+)?({_IDENT})\s*=\s*({_IDENT})", prefix):
                canonical = self.lookup_aliases.get(alias_match.group(2))
                if canonical and self.lookup_aliases.get(alias_match.group(1)) != canonical:
                    self.lookup_aliases[alias_match.group(1)] = canonical
                    changed = True
        objects = self._extract_local_objects(prefix)
        values = []
        # This runs entirely during static prep, *before* the main
        # per-statement loop's own ``_tick()`` deadline checks ever fire --
        # and is itself called once per lookup-decoder factory, so a large
        # array on a multi-megabyte sample can otherwise burn the sample's
        # entire wall-clock budget several times over with zero statements
        # ever processed (confirmed via profiling: 18s of a 25s run on one
        # 18MB sample, in this loop alone). Once the deadline is gone,
        # further items are left unresolved rather than computed -- an
        # ``Unknown`` placeholder here is exactly what a value this method
        # never got to would already look like, so nothing about downstream
        # decoding logic needs to special-case a short array.
        deadline_hit = False
        for index, item in enumerate(items):
            # Checked every item, not sampled: an individual item can itself
            # be large enough (multi-KB/MB) that ``_basic_static_value``'s
            # own decode/extract work dominates, so a coarser sampling
            # interval could let the loop run well past the deadline before
            # the next check ever fires. ``time.monotonic()`` itself is
            # negligible next to that per-item cost.
            if not deadline_hit and time.monotonic() > self.deadline:
                deadline_hit = True
            if deadline_hit:
                values.append(_Unknown(f"<static-deadline-exceeded:{index}>"))
                continue
            value = self._basic_static_value(item, objects)
            values.append(str(value) if not isinstance(value, (int, float)) else value)
        factory_range = (found["start"], found["end"], spec["factory"])
        if factory_range not in self._factory_ranges:
            self._factory_ranges.append(factory_range)
        return values

    def _solve_simple_rotation(self, source, decoder_name, spec):
        if spec.get("rc4_alphabet"):
            # RC4-encoded string arrays aren't shuffled by rotation at all --
            # each value decrypts independently given its own call-site key
            # (see ``_decode_rc4_value``) -- so this heuristic doesn't apply.
            return False
        factory = re.escape(spec["factory"])
        calls = list(re.finditer(rf"\}}\s*\(\s*{factory}\s*,\s*([^\n;]+?)\s*\)\s*(?:\)|,)", source))
        if not calls or not spec.get("values"):
            return False
        for call in calls[:4]:
            target = _safe_numeric_eval(call.group(1))
            if target is None:
                continue
            start = source.rfind("(function", max(0, call.start() - 30_000), call.start())
            if start < 0:
                continue
            body_open = source.find("{", start, call.start())
            body, body_end = _extract_balanced(source, body_open)
            if body is None or body_end > call.start() + 2:
                continue
            aliases = {decoder_name}
            aliases.update(alias for alias, canonical in self.lookup_aliases.items() if canonical == decoder_name)
            changed = True
            while changed:
                changed = False
                for alias_match in re.finditer(rf"\b(?:var\s+)?({_IDENT})\s*=\s*({_IDENT})", body):
                    if alias_match.group(2) in aliases and alias_match.group(1) not in aliases:
                        aliases.add(alias_match.group(1))
                        changed = True
            expressions = [match.group(2) for match in re.finditer(rf"\bvar\s+({_IDENT})\s*=\s*(.+?)\s*;", body, re.DOTALL)]
            expressions = [expr for expr in expressions if "parseInt" in expr and any(re.search(rf"\b{re.escape(alias)}\s*\(", expr) for alias in aliases)]
            for expression in expressions:
                parse_pattern = re.compile(rf"parseInt\s*\(\s*({'|'.join(re.escape(alias) for alias in sorted(aliases, key=len, reverse=True))})\s*\(([^()]*)\)\s*\)")
                for rotation in range(len(spec["values"])):
                    failed = False

                    def replace(match):
                        nonlocal failed
                        argument = _safe_numeric_eval(match.group(2))
                        if argument is None:
                            failed = True
                            return "0"
                        value = self._decoder_value(decoder_name, argument, rotation)
                        parsed = _js_parse_int(value)
                        if parsed is None:
                            failed = True
                            return "0"
                        return str(parsed)

                    reduced = parse_pattern.sub(replace, expression)
                    if failed:
                        continue
                    result = _safe_numeric_eval(reduced)
                    if result is not None and abs(float(result) - float(target)) < 1e-9:
                        spec["rotation"] = rotation
                        spec["rotation_solved"] = True
                        return True
        return False

    def _discover_charcode_lookup_functions(self, source):
        """Recognize ``var NAME = function(s){...alphabet.charAt(s.charCodeAt(i)
        +/-N)...}`` decoders -- see ``_CHARCODE_LOOKUP_FUNCTION_RE``. Only the
        assignment target's name and the shift's sign/magnitude are recorded
        here; the alphabet string itself is looked up from ``self.variables``
        at call time (see ``_resolve_charcode_lookup_call``), since it is
        ordinary sample data, not something this pass needs to resolve.
        """
        for match in re.finditer(rf"\b({_IDENT})\s*=\s*(?=function)", source):
            name = match.group(1)
            func_match = _CHARCODE_LOOKUP_FUNCTION_RE.match(source, match.end())
            if not func_match:
                continue
            alphabet_var, op, offset = func_match.group(4), func_match.group(5), func_match.group(6)
            self.charcode_lookup_functions[name] = {
                "alphabet": alphabet_var,
                "op": op,
                "offset": int(offset),
            }

    def _resolve_charcode_lookup_call(self, name, text):
        spec = self.charcode_lookup_functions.get(name)
        if not spec:
            return None
        alphabet = self.variables.get(spec["alphabet"])
        if not isinstance(alphabet, str) or not alphabet:
            return None
        out = []
        for ch in text:
            index = ord(ch) + spec["offset"] if spec["op"] == "+" else ord(ch) - spec["offset"]
            if not (0 <= index < len(alphabet)):
                return None
            out.append(alphabet[index])
        return _cap("".join(out))

    def _discover_charcode_shift_functions(self, source):
        """Recognize ``var NAME = function(s){...s.charCodeAt(i) +/- N...}``
        decoders -- see ``_CHARCODE_SHIFT_FUNCTION_RE``.
        """
        for match in re.finditer(rf"\b({_IDENT})\s*=\s*(?=function)", source):
            name = match.group(1)
            func_match = _CHARCODE_SHIFT_FUNCTION_RE.match(source, match.end())
            if not func_match:
                continue
            shift, op = int(func_match.group(6)), func_match.group(7)
            self.charcode_shift_functions[name] = {"op": op, "shift": shift}

    def _resolve_charcode_shift_call(self, name, text):
        spec = self.charcode_shift_functions.get(name)
        if not spec:
            return None
        delta = spec["shift"] if spec["op"] == "+" else -spec["shift"]
        try:
            return _cap("".join(chr(ord(ch) + delta) for ch in text))
        except ValueError:
            return None

    def _collect_pure_lookup_wrappers(self, source):
        decoder_names = set(self.lookup_decoders)
        lexical_objects = []
        for scan_index, match in enumerate(re.finditer(rf"\bfunction\s+({_IDENT})\s*\(([^)]*)\)\s*\{{", source)):
            if scan_index % 128 == 0 and time.monotonic() > self.deadline:
                break
            name = match.group(1)
            preview = source[match.end():match.end() + 20_000]
            # Wrappers often pass a decoder as a first-class function to a
            # tiny local helper instead of calling it directly.  A token
            # reference is therefore significant even without an immediate
            # opening parenthesis.
            if not any(re.search(rf"\b{re.escape(decoder)}\b", preview) for decoder in decoder_names):
                continue
            open_index = source.find("{", match.start())
            body, end_index = _extract_balanced(source, open_index)
            if body is None or len(body) > 20_000:
                continue
            if not any(re.search(rf"\b{re.escape(decoder)}\b", body) for decoder in decoder_names):
                continue
            for alias_match in re.finditer(rf"\b(?:var\s+)?({_IDENT})\s*=\s*({_IDENT})", body):
                canonical = self.lookup_aliases.get(alias_match.group(2))
                if canonical:
                    self.lookup_aliases[alias_match.group(1)] = canonical
            return_expression = self._root_return_expression(body)
            local_objects = self._extract_local_objects(body)
            self.pure_functions[name] = {
                "params": [part.strip() for part in _split_top_level(match.group(2)) if re.fullmatch(_IDENT, part.strip())],
                "objects": local_objects,
                "return": return_expression,
                "assignments": self._needed_assignments(
                    self._local_assignments(body), return_expression
                ),
            }
            if local_objects:
                nested = set(re.findall(rf"\bfunction\s+({_IDENT})\s*\(", body))
                if nested:
                    lexical_objects.append((nested, local_objects))
        for nested_names, inherited in lexical_objects:
            for nested_name in nested_names:
                model = self.pure_functions.get(nested_name)
                if model:
                    model.setdefault("objects", {}).update(
                        {key: value for key, value in inherited.items() if key not in model["objects"]}
                    )

    def _infer_lookup_rotations(self, source):
        unresolved = [(name, spec) for name, spec in self.lookup_decoders.items()
                      if spec.get("values") and not spec.get("rotation_solved")]
        if not unresolved:
            return
        # This whole heuristic is a "nice to have" that is entirely allowed
        # to come back partial: an unsolved rotation just leaves that
        # decoder's values symbolic (existing, already-handled behavior).
        # Its cost is O(decoders x rotation-range x call-sites) though, and
        # runs during static prep -- *before* the main per-statement loop's
        # own ``_tick()`` deadline checks ever run -- so on a decoder with a
        # large lookup table and many call sites it can otherwise silently
        # burn the sample's *entire* emulation budget and get the whole
        # worker hard-killed with zero statements ever processed.  Give it a
        # firm, small slice of wall-clock time instead.
        # Build the bounded wrapper models first.  They are also consumed by
        # the main abstract evaluator, so treating that one-time discovery as
        # part of the rotation scorer's tiny allowance made the scorer return
        # before inspecting any candidate on large but valid inputs.
        self._collect_pure_lookup_wrappers(source)
        now = time.monotonic()
        remaining = max(0.0, self.deadline - now)
        # Relative to *now*, not to when the emulator was constructed: static
        # prep steps before this one (packer/dispatch/decoder discovery,
        # factory-array extraction) already have their own real cost, and
        # anchoring to construction time would let their cost silently eat
        # this step's entire allowance before it runs a single iteration.
        soft_deadline = now + min(3.0, remaining * 0.8)

        bracket_call = re.compile(rf"\[\s*({_IDENT})\s*\(")
        sites = []
        for index, match in enumerate(bracket_call.finditer(source)):
            # Every match, not sampled -- see the identical reasoning on the
            # ``coarse_scores`` loop below; a bracket-call match followed
            # through to a resolved arg list is not free, and this source
            # can have many thousands of them before the ``sites`` cap ever
            # kicks in.
            if time.monotonic() > soft_deadline:
                break
            wrapper = match.group(1)
            if wrapper not in self.pure_functions:
                continue
            open_index = source.find("(", match.start())
            raw_args, call_end = _extract_call(source, open_index)
            if raw_args is None or call_end + 1 >= len(source) or source[call_end + 1:].lstrip()[:1] != "]":
                continue
            args = [self._eval_static_expression(arg) for arg in _split_top_level(raw_args)] if raw_args.strip() else []
            line_start = source.rfind("\n", 0, match.start()) + 1
            receiver_prefix = source[line_start:match.start()]
            after_call = source[call_end + 1:]
            close_offset = len(after_call) - len(after_call.lstrip())
            after_member = after_call[close_offset + 1:] if after_call.lstrip().startswith("]") else ""
            invoked_with_string = bool(re.match(r"\s*\(\s*(['\"])", after_member))
            sites.append((wrapper, args, receiver_prefix[-512:], invoked_with_string))
            if len(sites) >= 2_000:
                break
        if not sites or time.monotonic() > soft_deadline:
            return

        for name, spec in unresolved:
            if time.monotonic() > soft_deadline:
                break
            dependent_sites = []
            for site in sites:
                wrapper, args, _receiver_prefix, _invoked_with_string = site
                model = self.pure_functions[wrapper]
                # Dependency is visible in the bounded pure model itself.
                # Evaluating every site twice merely to rediscover that fact
                # was the dominant cost on multi-megabyte droppers and could
                # exhaust this heuristic's deadline before it reached the
                # correct rotation.  Alias declarations have already been
                # canonicalized by ``_collect_pure_lookup_wrappers``.
                model_text = str(model.get("return") or "")
                model_text += " " + " ".join(
                    expression for _local, expression in model.get("assignments", [])
                )
                if re.search(rf"\b{re.escape(name)}\b", model_text):
                    dependent_sites.append(site)
            # Cheap wrappers provide enough semantic constraints (join,
            # split, CreateObject, ...) without multiplying the full set of
            # sites by every possible rotation.
            dependent_sites.sort(key=lambda item: len(str(self.pure_functions[item[0]].get("return") or "")))
            scoring_sites = dependent_sites[:4] or sites[:4]

            def semantic_score(rotation, candidates):
                rotations = {name: rotation}
                score = 0
                for wrapper, args, receiver_prefix, invoked_with_string in candidates:
                    value = self._invoke_pure_model(self.pure_functions[wrapper], args, rotations)
                    if isinstance(value, str) and value.lower() in _KNOWN_MEMBER_NAMES:
                        score += 1
                        # A very common string-table idiom is
                        # ``text.split(delimiter)[decoder](separator)``.  If
                        # the decoded member is called with a string, ``join``
                        # is the only compatible standard Array operation.
                        if value.lower() == "join" and invoked_with_string and re.search(r"\.split\s*\([^)]*\)\s*$", receiver_prefix):
                            score += 64
                return score

            coarse_scores = []
            for rotation in range(len(spec["values"])):
                # Checked every rotation, not sampled: ``semantic_score``
                # calls ``_invoke_pure_model`` per candidate site, and that
                # cost varies a lot with how deep the modeled wrapper
                # function is -- on a large lookup table (thousands of
                # candidate rotations) a coarser sampling interval let this
                # overshoot ``soft_deadline`` by seconds before the next
                # check, the dominant cost of a 47s static-prep run on one
                # 18MB sample. ``time.monotonic()`` itself is negligible
                # next to a single ``semantic_score`` call.
                if time.monotonic() > soft_deadline:
                    break
                coarse_scores.append((semantic_score(rotation, scoring_sites), rotation))
            if not coarse_scores:
                continue
            coarse_best = max(score for score, _rotation in coarse_scores)
            tied = [rotation for score, rotation in coarse_scores if score == coarse_best]
            # Four cheap sites are a fast discriminator, but decoy lookup
            # tables can deliberately contain several plausible method names.
            # Resolve only the tied leaders against the broader evidence set;
            # this is much cheaper than scoring every site for every rotation.
            if coarse_best >= 1 and 1 < len(tied) <= 64 and time.monotonic() < soft_deadline:
                finalists = []
                for rotation in tied:
                    if time.monotonic() > soft_deadline:
                        break
                    finalists.append((semantic_score(rotation, dependent_sites), rotation))
            else:
                finalists = coarse_scores
            finalists.sort(reverse=True)
            best_score, best_rotation = finalists[0]
            runner_up = finalists[1][0] if len(finalists) > 1 else -1
            if best_score >= 2 and best_score > runner_up:
                spec["rotation"] = best_rotation
                spec["rotation_solved"] = True

    def _normalize_computed_members(self, source):
        global_literals = _collect_global_string_literals(source)
        out = []
        cursor = 0
        index = 0
        quote = None
        escaped = False
        replacements = 0
        attempts = 0
        while index < len(source):
            ch = source[index]
            if quote:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                index += 1
                continue
            if ch in ("'", '"', "`"):
                quote = ch
                index += 1
                continue
            if ch != "[" or replacements >= MAX_STATIC_REPLACEMENTS:
                index += 1
                continue
            # Only checked on the expensive branch (an actual ``[`` needing a
            # balanced-scan plus a static-expression evaluation), not every
            # character -- the plain scan above is already cheap per byte.
            # Counts *attempts*, not successful ``replacements``: heavily
            # obfuscated sources can fail to resolve most brackets, which
            # would otherwise let this run unbounded while ``replacements``
            # never advances.
            attempts += 1
            if attempts % 128 == 0 and time.monotonic() > self.deadline:
                break
            raw_member, end_index = _extract_balanced(source, index, "[", "]")
            if raw_member is None:
                break
            if len(raw_member) <= 4096:
                value = self._eval_static_expression(raw_member, global_literals)
                # ``receiver[key](args)`` where ``key`` resolves (only via
                # ``global_literals``, i.e. an indirection through some
                # unrelated ``var status = "CreateObject";``) to exactly
                # "CreateObject"/"GetObject" is handled *better* left alone:
                # ``_handle_computed_member_call`` already recognizes this
                # bracket shape at runtime and, critically, also records the
                # assignment target as the new COM object regardless of what
                # ``receiver`` even is -- a generic dotted
                # ``receiver.CreateObject(...)`` has no equivalent rule
                # (only the literal ``ActiveXObject``/``WScript.CreateObject``
                # receivers are recognized there), so normalizing away the
                # brackets here would silently regress a call that already
                # resolves correctly.
                stripped_member = raw_member.strip()
                indirect_via_global = (
                    stripped_member in global_literals
                    and isinstance(value, str)
                    and value.lower() in ("createobject", "getobject")
                )
                if isinstance(value, str) and re.fullmatch(_IDENT, value) and not indirect_via_global:
                    out.append(source[cursor:index])
                    out.append("." + value)
                    cursor = end_index + 1
                    index = end_index + 1
                    replacements += 1
                    continue
            # Unresolved here does not mean unresolvable: ``outer[inner[x]]``
            # (and, notably, ``outer[inner[x]](args)`` -- a dispatch-object
            # member being both looked up *and* called, the common shape for
            # a wrapped decoder call) frequently fails as one expression
            # while its own nested ``[...]`` is independently resolvable.
            # Stepping in by one character, instead of skipping straight to
            # ``end_index``, lets the scan re-enter and normalize that inner
            # bracket on its own in a later iteration.
            index += 1
        out.append(source[cursor:])
        return "".join(out), replacements

    def _resolve_dispatch_source_literal(self, source, target_expr):
        """Best-effort static resolution of ``target_expr = "literal"`` (or
        ``target_expr = decoderCall(...)``) written anywhere in ``source``.

        Used only to recover a control-flow-flattening dispatch-order string
        before the normal, order-sensitive interpretation pass runs -- at
        that point ``self.variables`` has no runtime-assigned values yet, so
        this deliberately re-scans raw source text instead of relying on it.
        Returns ``None`` (never a guess) when no literal assignment for the
        exact target -- or its ``this``-alias, if ``target_expr`` is
        ``alias.prop`` and ``var alias = this;`` appears earlier -- can be
        found.
        """
        candidates = [target_expr]
        alias_match = re.fullmatch(rf"({_IDENT})\.({_IDENT})", target_expr)
        if alias_match:
            alias, prop = alias_match.groups()
            if re.search(rf"\bvar\s+{re.escape(alias)}\s*=\s*this\b", source):
                candidates.append(f"this.{prop}")
        for candidate in candidates:
            match = re.search(
                re.escape(candidate) + r"\s*=\s*(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|_0x[0-9a-fA-F]+\([^;()]*\))",
                source,
            )
            if not match:
                continue
            raw = match.group(1)
            if raw[0] in "\"'":
                return _decode_js_string(raw)
            value = self._eval_static_expression(raw)
            if isinstance(value, str):
                return value
        return None

    def _unflatten_dispatch_switches(self, source):
        """Reorder javascript-obfuscator.io "control flow flattening" blocks.

        These hide real statement order behind
        ``while (COND) { switch (ORDER[IDX++]) { case 'N': ...; continue; } }``,
        where ORDER is a delimited string split at runtime into per-case
        dispatch labels -- the textual order of the ``case`` bodies is *not*
        the execution order.  This pass only rewrites a block when ORDER can
        be resolved to a concrete literal string and every dispatched label
        has a matching ``case``; otherwise it leaves that block untouched
        rather than guess at an order and risk corrupting an otherwise
        emulatable statement sequence.  Rewriting replaces just the
        ``switch (...) { ... }`` construct with the case bodies concatenated
        in resolved order (their own ``continue``/trailing ``break`` dropped,
        since the enclosing ``while`` is never actually looped by this
        emulator -- statements are executed once, in sequence); the ``while``
        wrapper itself is left in place and is harmless.
        """
        matches = list(_DISPATCH_SWITCH_RE.finditer(source))
        if not matches:
            return source, 0
        edits = []
        for match in matches:
            order_var, idx_var = match.group(1), match.group(2)
            switch_brace = match.end() - 1
            body, body_end = _extract_balanced(source, switch_brace, "{", "}")
            if body is None:
                continue
            window_start = max(0, match.start() - 4000)
            window = source[window_start:match.start()]
            decl_re = re.compile(
                _DISPATCH_ORDER_DECL_TEMPLATE.format(order=re.escape(order_var), idx=re.escape(idx_var)),
                re.DOTALL,
            )
            decl_match = None
            for candidate in decl_re.finditer(window):
                decl_match = candidate
            if decl_match is None:
                continue
            src_expr, delimiter = decl_match.group(1).strip(), decl_match.group(2)
            # group(1) includes the split-equivalent method's own selector
            # (``.split`` / ``['split']`` / a still-obfuscated ``[call(...)]``)
            # since the template does not require identifying it; strip that
            # one trailing member-access segment to get the object the
            # method was called on, which is what actually needs resolving.
            src_expr = re.sub(rf"(?:\.{_IDENT}|\[[^\[\]]*\])\Z", "", src_expr)
            if re.fullmatch(r"'[^'\\]*'", src_expr) or re.fullmatch(r'"[^"\\]*"', src_expr):
                order_string = _decode_js_string(src_expr)
            else:
                order_string = self._resolve_dispatch_source_literal(source, src_expr)
            if not order_string:
                continue
            order_labels = order_string.split(delimiter)
            if not (2 <= len(order_labels) <= 2000):
                continue
            cases = {}
            for case_match in _DISPATCH_CASE_RE.finditer(body):
                label, case_body = case_match.groups()
                cases.setdefault(label, case_body)
            if not cases or any(label not in cases for label in order_labels):
                continue
            pieces = []
            for label in order_labels:
                piece = re.sub(r"\bcontinue\s*;\s*\Z", "", cases[label].strip()).strip()
                piece = re.sub(r"\bbreak\s*;\s*\Z", "", piece).strip()
                if piece:
                    pieces.append(piece)
            edits.append((match.start(), body_end + 1, "\n".join(pieces)))
        if not edits:
            return source, 0
        out = []
        cursor = 0
        for start, end, replacement in sorted(edits):
            if start < cursor:
                continue
            out.append(source[cursor:start])
            out.append(replacement)
            cursor = end
        out.append(source[cursor:])
        return "".join(out), len(edits)

    def _unflatten_numeric_state_switches(self, source):
        """Reorder the numeric-state-variable control-flow-flattening idiom.

        Distinct from ``_unflatten_dispatch_switches``'s order-array
        version: here the *next* case to run is threaded through the case
        bodies themselves rather than precomputed --
        ``var v = 207249; while (v != 114781) { switch (v) { case 586622:
        ...; v = 309072; break; case 309072: ...; v = 899896; break; ... }
        }``. Walking the chain (entry state from the declaration right
        before the ``while``, each case's own trailing ``v = NEXT;``,
        stopping at the while's exit literal) recovers real order without
        needing an external array at all. Bails out -- leaving the block
        untouched -- the moment any step of the chain doesn't resolve
        cleanly (missing case, no trailing assignment, cycle, chain longer
        than the switch has cases), rather than guess.
        """
        matches = list(_NUMERIC_STATE_SWITCH_RE.finditer(source))
        if not matches:
            return source, 0
        edits = []
        for match in matches:
            state_var, exit_state = match.group(1), match.group(2)
            switch_brace = match.end() - 1
            body, body_end = _extract_balanced(source, switch_brace, "{", "}")
            if body is None:
                continue
            window_start = max(0, match.start() - 2000)
            window = source[window_start:match.start()]
            entry_re = re.compile(rf"(?:var\s+)?{re.escape(state_var)}\s*=\s*(\d+)\s*;")
            entry_match = None
            for candidate in entry_re.finditer(window):
                entry_match = candidate
            if entry_match is None:
                continue
            entry_state = entry_match.group(1)
            cases = {}
            for case_match in _NUMERIC_STATE_CASE_RE.finditer(body):
                label, case_body = case_match.groups()
                cases.setdefault(label, case_body)
            if not cases:
                continue
            transition_re = re.compile(
                rf"\b{re.escape(state_var)}\s*=\s*(\d+)\s*;\s*(?:continue|break)\s*;?\s*\Z"
            )
            pieces = []
            current = entry_state
            visited = set()
            ok = True
            while current != exit_state:
                if current in visited or current not in cases or len(visited) > len(cases):
                    ok = False
                    break
                visited.add(current)
                case_body = cases[current].strip()
                transition = transition_re.search(case_body)
                if not transition:
                    ok = False
                    break
                piece = case_body[:transition.start()].strip()
                if piece:
                    pieces.append(piece)
                current = transition.group(1)
            if not ok:
                continue
            edits.append((match.start(), body_end + 1, "\n".join(pieces)))
        if not edits:
            return source, 0
        out = []
        cursor = 0
        for start, end, replacement in sorted(edits):
            if start < cursor:
                continue
            out.append(source[cursor:start])
            out.append(replacement)
            cursor = end
        out.append(source[cursor:])
        return "".join(out), len(edits)

    def _unpack_classic_packers(self, source):
        """Statically resolve ``eval(function(p,a,c,k,e,d){...}(...))``.

        This wrapper (packer.js / Dean Edwards's "packer", also emitted by
        many online obfuscators) is extremely common in malicious HTML/HTA/JS
        droppers.  Its decode step is a public, deterministic keyword
        substitution -- re-implemented in ``_unpack_packer_payload`` -- so the
        packed payload can be recovered without ever executing it.  Matched
        wrappers are masked out of the returned source (replaced with a
        harmless ``0``) so they are not also re-scanned as plain statements;
        recovered payloads are returned separately for queued re-processing.
        """
        masked = source
        layers = []
        search_from = 0
        for _ in range(8):
            head = _PACKER_HEAD_RE.search(masked, search_from)
            if not head:
                break
            body_open = masked.rfind("{", head.start(), head.end())
            body, body_end = _extract_balanced(masked, body_open)
            if body is None:
                break
            after_body = masked[body_end + 1:]
            call_lead = re.match(r"\s*\(", after_body)
            if not call_lead:
                search_from = body_end + 1
                continue
            call_open = body_end + 1 + call_lead.end() - 1
            raw_args, call_end = _extract_call(masked, call_open)
            if raw_args is None:
                search_from = body_end + 1
                continue
            close_lead = re.match(r"\s*\)", masked[call_end + 1:])
            if not close_lead:
                search_from = call_end + 1
                continue
            eval_end = call_end + 1 + close_lead.end()
            args = _split_top_level(raw_args)
            resolved = None
            if len(args) >= 4:
                payload_value = self._eval_expr(args[0])
                radix_value = self._eval_expr(args[1])
                keywords_value = self._eval_expr(args[3])
                if (
                    isinstance(payload_value, str)
                    and isinstance(radix_value, (int, float))
                    and not isinstance(radix_value, bool)
                    and isinstance(keywords_value, list)
                ):
                    keywords = [
                        _safe_text(item) if not _is_unknown(item) else ""
                        for item in keywords_value
                    ]
                    resolved = _unpack_packer_payload(
                        payload_value, int(radix_value), len(keywords), keywords
                    )
            if resolved:
                layers.append(resolved)
                masked = masked[:head.start()] + "0" + masked[eval_end:]
                search_from = head.start() + 1
            else:
                search_from = eval_end
        return masked, layers

    def _decrypt_rijndael_script_layers(self, source):
        """Recover a tightly-scoped WSH Rijndael/AES script envelope.

        The supported loader stores key (32 bytes), IV (16 bytes), then CBC
        ciphertext in a quoted two-hex-digit array and passes slices through
        ``RijndaelManaged``/``TransformFinalBlock``.  Only that complete
        signature is accepted; decrypted bytes are never executed and are
        queued solely for this abstract interpreter.
        """
        if not (
            re.search(r"RijndaelManaged", source, re.IGNORECASE)
            and re.search(r"TransformFinalBlock", source, re.IGNORECASE)
            and re.search(r"nodeTypedValue", source, re.IGNORECASE)
        ):
            return source, []
        layers = []
        masks = []
        array_pattern = re.compile(rf"\b(?:var|let|const)\s+({_IDENT})\s*=\s*\[")
        for match in array_pattern.finditer(source):
            if len(layers) >= MAX_DECODED_LAYERS:
                break
            variable = match.group(1)
            open_index = source.find("[", match.start())
            raw_array, end_index = _extract_balanced(source, open_index, "[", "]")
            if raw_array is None or len(raw_array) > MAX_ENCRYPTED_LAYER_BYTES * 8:
                continue
            suffix = source[end_index + 1:end_index + 96]
            if not re.match(r"\s*\.\s*join\s*\(", suffix):
                continue
            nearby = source[end_index + 1:min(len(source), end_index + 8_000)]
            node_ref = rf"{re.escape(variable)}\s*\.\s*nodeTypedValue"
            if len(re.findall(node_ref, nearby, re.IGNORECASE)) < 3:
                continue
            if not re.search(rf"pipeLine\s*\(\s*{node_ref}\s*,\s*0\s*,\s*32\s*\)", nearby, re.IGNORECASE):
                continue
            if not re.search(rf"pipeLine\s*\(\s*{node_ref}\s*,\s*32\s*,\s*16\s*\)", nearby, re.IGNORECASE):
                continue
            octets = re.findall(r"(?:'|\")([0-9a-fA-F]{2})(?:'|\")", raw_array)
            if not (64 <= len(octets) <= MAX_ENCRYPTED_LAYER_BYTES):
                continue
            packed = bytes.fromhex("".join(octets))
            ciphertext = packed[48:]
            if len(ciphertext) == 0 or len(ciphertext) % 16:
                continue
            try:
                plaintext = _aes256_cbc_decrypt(ciphertext, packed[:32], packed[32:48])
            except (ValueError, TypeError):
                continue
            padding = plaintext[-1]
            if not (1 <= padding <= 16 and plaintext.endswith(bytes([padding]) * padding)):
                continue
            plaintext = plaintext[:-padding]
            decoded = None
            for encoding in ("utf-8-sig", "utf-16le"):
                try:
                    candidate = plaintext.decode(encoding)
                except UnicodeError:
                    continue
                sample = candidate[:8_192]
                printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in sample)
                if sample and printable / len(sample) >= 0.90:
                    decoded = candidate
                    break
            if not decoded or not re.search(
                r"\b(?:var|function|WScript|ActiveXObject|eval|fetch|XMLHttpRequest)\b", decoded
            ):
                continue
            layers.append(decoded[:MAX_SOURCE_CHARS])
            masks.append((open_index, end_index + 1))
            self._emit(
                "encrypted_layer_deobfuscation",
                cipher="AES-256-CBC",
                encrypted_size=len(ciphertext),
                decrypted_size=len(decoded),
            )
        masked = source
        for start, end in reversed(masks):
            masked = masked[:start] + "[]" + masked[end:]
        return masked, layers

    def _analyze_embedded_powershell_payloads(self, source):
        """Peel bounded JS -> PowerShell -> XOR -> .NET loader chains.

        All transformations operate on byte strings in the isolated worker.
        The recovered PE is inspected as data only; it is never written,
        imported, loaded by the CLR, or handed to another executable.
        """
        masks = []
        long_base64 = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{100000,}={0,2})(?![A-Za-z0-9+/])")
        for match in long_base64.finditer(source):
            if len(self._embedded_payloads) >= MAX_DECODED_LAYERS:
                break
            encoded = match.group(1)
            if len(encoded) > MAX_EMBEDDED_PAYLOAD_BYTES * 2:
                continue
            try:
                first_bytes = base64.b64decode(encoded + "=" * ((-len(encoded)) % 4), validate=True)
            except (ValueError, TypeError):
                continue
            if len(first_bytes) > MAX_EMBEDDED_PAYLOAD_BYTES:
                continue
            try:
                powershell = first_bytes.decode("utf-8-sig")
            except UnicodeError:
                continue
            if not all(token.lower() in powershell.lower() for token in (
                "$encryptedHexData", "$decryptionHexKey", "Invoke-HexDecryption"
            )):
                continue

            def here_string(name):
                found = re.search(
                    rf"\${name}\s*=\s*@'\s*([0-9a-fA-F\s]+?)\s*'@",
                    powershell,
                    re.IGNORECASE | re.DOTALL,
                )
                return re.sub(r"\s+", "", found.group(1)) if found else None

            encrypted_hex = here_string("encryptedHexData")
            key_hex = here_string("decryptionHexKey")
            if not encrypted_hex or not key_hex:
                continue
            try:
                encrypted = bytes.fromhex(encrypted_hex)
                xor_key = bytes.fromhex(key_hex)
            except ValueError:
                continue
            if not xor_key or len(encrypted) > MAX_EMBEDDED_PAYLOAD_BYTES:
                continue
            second_bytes = bytes(value ^ xor_key[index % len(xor_key)] for index, value in enumerate(encrypted))
            try:
                second_stage = second_bytes.decode("utf-8-sig")
            except UnicodeError:
                continue

            numeric_payload = re.search(
                r"\[Byte\[\]\]\s*\$payloadBytes\s*=\s*\(([^)]{10000,})\)",
                second_stage,
                re.IGNORECASE | re.DOTALL,
            )
            if not numeric_payload:
                continue
            numbers = re.findall(r"\d{1,3}", numeric_payload.group(1))
            if not numbers or len(numbers) > MAX_EMBEDDED_PAYLOAD_BYTES:
                continue
            try:
                payload = bytes(int(value) for value in numbers)
            except ValueError:
                continue
            if not payload.startswith(b"MZ"):
                continue

            digest = hashlib.sha256(payload).hexdigest()
            self._embedded_payloads.append({"sha256": digest, "size": len(payload), "type": "PE/.NET"})
            masks.append((match.start(1), match.end(1)))
            self._emit(
                "embedded_payload_deobfuscation",
                layers="Base64 -> PowerShell hex-XOR -> PE/.NET",
                payload_size=len(payload),
                payload_sha256=digest,
            )
            config = _recover_xworm_config(payload)
            if not config:
                continue
            self._emit(
                "embedded_payload_config",
                family=config["family"],
                hosts=", ".join(config["hosts"]),
                port=config["port"],
            )
            for host in config["hosts"]:
                self._record_network(
                    f"tcp://{host}:{config['port']}",
                    method="TCP_CONNECT",
                    api="embedded-dotnet:ClientSocket.BeginConnect",
                )
            if any("downloadfile" in value.lower() for value in _binary_strings(payload)):
                self._emit(
                    "network_download_capability",
                    api="embedded-dotnet:System.Net.WebClient.DownloadFile",
                    url="<C2-supplied at runtime>",
                )

        masked = source
        for start, end in reversed(masks):
            masked = masked[:start] + "AA==" + masked[end:]
        return masked

    def _prepare_static_deobfuscation(self, source):
        source = self._analyze_embedded_powershell_payloads(source)
        source, self._encrypted_layers = self._decrypt_rijndael_script_layers(source)
        source, self._packer_layers = self._unpack_classic_packers(source)
        if self._packer_layers:
            self._emit("packer_deobfuscation", layers=len(self._packer_layers))
        # Dispatch-table discovery runs first: a second-generation decoder is
        # sometimes itself built entirely out of dispatch-wrapped operations
        # (offset subtraction, niladic factory call) instead of the plain
        # inline arithmetic the primary decoder heuristic looks for, so
        # ``_discover_lookup_decoders`` needs the dispatch models already
        # available to see through that wrapping.
        self._discover_dispatch_objects(source)
        self._discover_prototype_hex_table_methods(source)
        self._discover_charcode_lookup_functions(source)
        self._discover_lookup_decoders(source)
        # Each of the discovery/refinement stages below individually bounds
        # its own internal loop against ``self.deadline`` where it does
        # meaningful repeated work, but a large enough source can still make
        # several individually-modest stages add up past the wall-clock
        # budget in total -- checked between stages too, so the *sum* is
        # bounded, not just each stage's own worst case.
        # Lookup factories may depend on an earlier lookup decoder (an array
        # whose entries are ``object[primaryDecoder(...)]``).  Iterate to a
        # small fixed point so declaration order does not leave the outer
        # factory permanently symbolic.
        for _ in range(4):
            if time.monotonic() > self.deadline:
                break
            changed = False
            for name, spec in reversed(list(self.lookup_decoders.items())):
                if time.monotonic() > self.deadline:
                    break
                old_values = spec.get("values", [])
                old_symbolic = sum(
                    bool(re.search(rf"\b{_IDENT}\s*[\[(]", str(value)))
                    for value in old_values
                )
                # A concrete table is stable.  A table containing unresolved
                # calls must be rebuilt after its dependency's rotation is
                # solved (multi-stage obfuscators commonly nest two or three
                # such factories).
                if old_values and not old_symbolic:
                    continue
                values = self._extract_factory_values(source, spec)
                if not values:
                    continue
                new_symbolic = sum(
                    bool(re.search(rf"\b{_IDENT}\s*[\[(]", str(value)))
                    for value in values
                )
                if not old_values or new_symbolic < old_symbolic:
                    spec["values"] = values
                    changed = True
                self._solve_simple_rotation(source, name, spec)
            if not changed:
                break
        # Decoder-backed property keys can now be materialized before the
        # rotation heuristic builds/evaluates the tiny wrapper functions.
        if time.monotonic() <= self.deadline:
            self._discover_dispatch_objects(source)
            self._infer_lookup_rotations(source)
        # Re-run now that every decoder's values/rotation are known: a
        # dispatch object's *plain* (non-function) properties are frequently
        # themselves decoder calls (``'key': _0x3ef4(0x12a)``), which were
        # unresolvable on the first pass above since no decoder had values
        # yet.  Re-parsing is idempotent and cheap; it only improves values,
        # never removes information the first pass already had.
        if time.monotonic() <= self.deadline:
            self._discover_dispatch_objects(source)

        masked = source
        for start, end, factory in sorted(self._factory_ranges, reverse=True):
            masked = masked[:start] + f"function {factory}(){{return [];}}" + masked[end:]
        normalized, replacements = self._normalize_computed_members(masked)
        # Needs the just-normalized (dotted) form: an extra layer of
        # bracket-computed-property indirection over ``.charCodeAt``/
        # ``String.fromCharCode`` is exactly what ``_normalize_computed_members``
        # exists to strip, and this decoder shape is common enough with that
        # extra layer that discovering it against raw ``source`` would miss it.
        if time.monotonic() <= self.deadline:
            self._discover_charcode_shift_functions(normalized)
        if time.monotonic() <= self.deadline:
            normalized, unflattened = self._unflatten_dispatch_switches(normalized)
            normalized, unflattened_numeric = self._unflatten_numeric_state_switches(normalized)
        else:
            unflattened = unflattened_numeric = 0
        if unflattened or unflattened_numeric:
            self._emit(
                "control_flow_unflattened",
                switch_blocks=unflattened + unflattened_numeric,
            )
        resolved_strings = set()
        for spec in self.lookup_decoders.values():
            for value in spec.get("values", []):
                if not isinstance(value, str):
                    continue
                compact = value.replace("%", "")
                if len(compact) <= 128 and (
                    compact.lower() in _KNOWN_MEMBER_NAMES
                    or re.search(r"(?:wscript\.shell|scripting\.filesystemobject|adodb\.stream|microsoft\.xml|xmlhttp)", compact, re.IGNORECASE)
                ):
                    resolved_strings.add(compact)
        if self.lookup_decoders:
            self._emit(
                "static_deobfuscation",
                lookup_tables=len(self.lookup_decoders),
                solved_rotations=sum(1 for spec in self.lookup_decoders.values() if spec.get("rotation_solved")),
                resolved_members=replacements,
                masked_bytes=max(0, len(source) - len(masked)),
                recovered_strings=", ".join(sorted(resolved_strings, key=str.lower)[:64]),
            )
        return normalized

    def _tick(self):
        self.step_count += 1
        if self.step_count > MAX_STATEMENTS:
            self.statement_limit_hit = True
            raise TimeoutError("JavaScript emulation statement budget exceeded")
        if time.monotonic() > self.deadline:
            self.timed_out = True
            raise TimeoutError("JavaScript emulation wall-clock budget exceeded")

    def _emit(self, category, **fields):
        if len(self.events) >= MAX_EVENTS:
            return
        clean = {key: _safe_event_value(value) for key, value in fields.items()}
        key = (category, tuple(sorted((name, repr(value)) for name, value in clean.items())))
        if key in self._event_keys:
            return
        self._event_keys.add(key)
        self.events.append({
            "ts": round(time.monotonic() - self.started, 6),
            "category": category,
            **clean,
        })

    def _environment_value(self, key):
        values = {
            "temp": "C:\\Users\\User\\AppData\\Local\\Temp",
            "tmp": "C:\\Users\\User\\AppData\\Local\\Temp",
            "appdata": "C:\\Users\\User\\AppData\\Roaming",
            "localappdata": "C:\\Users\\User\\AppData\\Local",
            "userprofile": "C:\\Users\\User",
            "username": "User",
            "computername": "DESKTOP-SANDBOX",
            "windir": "C:\\Windows",
            "home": "/home/user",
        }
        normalized = str(key).strip("%'\"[]").lower()
        self._emit("environment_access", name=normalized or "<unknown>")
        return values.get(normalized, f"<env:{normalized}>")

    def _store_variable(self, name, value):
        """Store a symbolic value without allowing assignment-based RAM bombs."""
        def storage_size(item):
            if isinstance(item, (_CharArray, _SplitText)):
                return len(item.text)
            if isinstance(item, _BinaryValue):
                return len(item)
            return len(str(item))

        name = _safe_text(name, 256)
        old = self.variables.get(name)
        old_size = storage_size(old) if old is not None else 0
        if old is None and len(self.variables) >= MAX_VARIABLES:
            self._emit("resource_limit", resource="variables", limit=MAX_VARIABLES)
            return
        value_size = storage_size(value)
        projected = self._stored_value_chars - old_size + value_size
        if projected > MAX_TOTAL_VALUE_CHARS:
            value = _Unknown(f"<{name}:value-budget-exceeded>")
            value_size = len(str(value))
            projected = self._stored_value_chars - old_size + value_size
            self._emit("resource_limit", resource="stored_value_chars", limit=MAX_TOTAL_VALUE_CHARS)
        self.variables[name] = value
        self._stored_value_chars = max(projected, 0)

    def _interpolate_template(self, value):
        def replace(match):
            resolved = self._eval_expr(match.group(1))
            return str(resolved) if not _is_unknown(resolved) else match.group(0)
        return _cap(re.sub(r"\$\{([^{}]{1,512})\}", replace, value))

    def _eval_expr(self, expression):
        self._tick()
        expr = str(expression or "").strip().rstrip(";")
        if not expr:
            return ""
        if expr.startswith("(" * (MAX_PARENTHESES_UNWRAP + 1)):
            self._emit(
                "resource_limit",
                resource="parentheses_unwrap",
                limit=MAX_PARENTHESES_UNWRAP,
            )
            return _Unknown("<parentheses-depth-exceeded>")
        unwrap_count = 0
        while _balanced_outer_parentheses(expr):
            if unwrap_count >= MAX_PARENTHESES_UNWRAP:
                self._emit(
                    "resource_limit",
                    resource="parentheses_unwrap",
                    limit=MAX_PARENTHESES_UNWRAP,
                )
                return _Unknown("<parentheses-depth-exceeded>")
            expr = expr[1:-1].strip()
            unwrap_count += 1
            if unwrap_count % 16 == 0:
                self._tick()

        if expr and expr[0] in ("'", '"', "`"):
            close_index = _string_literal_end(expr, expr[0])
            if close_index is not None:
                suffix = expr[close_index + 1:].strip()
                # Only treat this as "literal, then a method/index chain".
                # Anything else after the closing quote (``+``, ``,`` inside
                # an argument list, ...) must fall through to the operator
                # handling below instead of silently discarding it.
                if not suffix or suffix[0] in (".", "["):
                    token = expr[:close_index + 1]
                    value = _decode_js_string(token)
                    if expr[0] == "`":
                        value = self._interpolate_template(value)
                    return self._eval_suffix(value, suffix) if suffix else value

        if expr and expr[0] == "/" and _looks_like_regex_literal_start(expr, 0):
            close_index = _regex_literal_end(expr, 0)
            if close_index is not None:
                flag_start = close_index
                while flag_start > 0 and expr[flag_start - 1] in _REGEX_LITERAL_FLAG_CHARS:
                    flag_start -= 1
                # ``flag_start`` now sits just past the pattern-closing ``/``
                # (flags are letters only, never ``/``, so this walk-back
                # can't be fooled by a ``/`` inside the pattern itself).
                return _JSRegex(expr[1:flag_start - 1], expr[flag_start:close_index])

        # A parenthesized sub-expression immediately followed by a
        # method/index chain (``(a + b.replace(...) + c).split(x).join(y)``)
        # -- as opposed to the whole-expression-is-one-paren-group case
        # unwrapped above, where nothing trails the matching ``)``.  Without
        # this, the balanced group is never evaluated and the entire
        # expression falls through to the raw-source ``_Unknown`` fallback.
        if expr and expr[0] == "(":
            body, end_index = _extract_balanced(expr, 0, "(", ")")
            if body is not None:
                suffix = expr[end_index + 1:].strip()
                if suffix and suffix[0] in (".", "["):
                    inner = self._eval_expr(body)
                    return self._eval_suffix(inner, suffix)

        lower = expr.lower()
        if lower in ("true", "false"):
            return lower == "true"
        if lower in ("null", "undefined", "nan"):
            return ""
        if re.fullmatch(r"-?(?:0x[0-9a-f]+|\d+(?:\.\d+)?)", expr, re.IGNORECASE):
            try:
                return int(expr, 0) if "." not in expr else float(expr)
            except ValueError:
                return _Unknown(expr)

        # Unary numeric coercion is commonly applied directly to an
        # obfuscated lookup call (``-decoder(0x123)``).  Resolve the call as
        # data, then accept only a strict numeric result; arbitrary unary
        # JavaScript semantics remain outside this abstract model.
        if expr[:1] in ("+", "-") and re.match(rf"^\s*(?:new\s+)?{_DOTTED}\s*\(", expr[1:], re.IGNORECASE):
            operand = self._eval_expr(expr[1:])
            number = operand if isinstance(operand, (int, float)) and not isinstance(operand, bool) else None
            if number is None and isinstance(operand, str) and re.fullmatch(
                r"[+\-]?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?)", operand.strip()
            ):
                number = _safe_numeric_eval(operand.strip())
            if number is not None:
                return number if expr[0] == "+" else -number
            return _Unknown(expr)

        # ``_safe_numeric_eval``'s own AST visitor already type-checks each
        # variable it actually looks up (only names appearing in ``expr``'s
        # parsed tree, never the whole dict) -- pre-filtering every call's
        # variable dict down to numeric-only entries here was pure waste on
        # top of that, and with thousands of tracked variables and tens of
        # thousands of recursive ``_eval_expr`` calls on some samples, this
        # rebuild-per-call was the single largest cost in the entire
        # interpreter (confirmed by profiling: ~90M redundant ``isinstance``
        # calls on one 9K-statement sample that never finished emulating
        # before this fix).
        numeric_value = _safe_numeric_eval(expr, self.variables)
        if numeric_value is not None:
            return numeric_value

        plus_parts = _split_top_level(expr, "+")
        if len(plus_parts) > 1:
            values = [self._eval_expr(part) for part in plus_parts]
            if any(_is_unknown(value) for value in values):
                known = "".join(str(value) for value in values)
                return _Unknown(known)
            if any(isinstance(value, str) for value in values):
                return _cap("".join(str(value) for value in values))
            try:
                return sum(values)
            except TypeError:
                return _Unknown(expr)

        if re.fullmatch(_IDENT, expr):
            if expr in self.variables:
                return self.variables[expr]
            # A bare reference to a decoder/pure-function name (including
            # through an obfuscator's local alias, e.g. ``b = decoderFn``)
            # is meaningful when it is later *invoked* -- most commonly
            # through a dispatch-table proxy such as
            # ``dispatch['apply'](decoderAlias, index)``.  Surface it as a
            # callable marker instead of an opaque unknown so that call
            # resolution (``_eval_pure_call``) can still recover the value.
            canonical = self.lookup_aliases.get(expr, expr)
            if canonical in self.lookup_decoders or expr in self.pure_functions:
                return _FunctionRef(expr)
            return _Unknown(expr)

        env_match = re.fullmatch(rf"process\.env(?:\.({_IDENT})|\[['\"]([^'\"]+)['\"]\])", expr, re.IGNORECASE)
        if env_match:
            return self._environment_value(env_match.group(1) or env_match.group(2))

        call_match = re.match(rf"(?:new\s+)?({_DOTTED})\s*\(", expr, re.IGNORECASE)
        if call_match:
            open_index = expr.find("(", call_match.start())
            raw_args, end_index = _extract_call(expr, open_index)
            if raw_args is not None:
                args = [self._eval_expr(arg) for arg in _split_top_level(raw_args)] if raw_args.strip() else []
                name = re.sub(r"\s+", "", call_match.group(1))
                result = self._eval_pure_call(name, args, raw_args)
                suffix = expr[end_index + 1:].strip() if end_index is not None else ""
                if suffix:
                    result = self._eval_suffix(result, suffix)
                return result

        # Obfuscators frequently rebuild strings/commands from a character or
        # keyword array (``["p","o","w"].join("")``,
        # ``["cmd","/c",cmd][1]``).  Evaluate the literal as a real list so a
        # trailing ``.method(...)``/``[index]`` chain can operate on it.
        if expr and expr[0] == "[":
            body, end_index = _extract_balanced(expr, 0, "[", "]")
            if body is not None:
                items_raw = _split_top_level(body) if body.strip() else []
                if len(items_raw) <= MAX_VARIABLES:
                    items = [self._eval_expr(item) for item in items_raw]
                    suffix = expr[end_index + 1:].strip()
                    return self._eval_suffix(items, suffix) if suffix else items

        member_match = re.fullmatch(rf"({_IDENT})\.({_IDENT})", expr)
        if member_match:
            owner, prop = member_match.groups()
            key = f"{owner}.{prop}"
            if key in self.variables:
                return self.variables[key]
            resolved_owner = owner
            seen_owners = set()
            while resolved_owner in self.object_aliases and resolved_owner not in seen_owners:
                seen_owners.add(resolved_owner)
                resolved_owner = self.object_aliases[resolved_owner]
                alias_key = f"{resolved_owner}.{prop}"
                if alias_key in self.variables:
                    return self.variables[alias_key]
            if prop.lower() in ("responsetext", "responsebody") and owner in self.xhr_state:
                return _Unknown(f"<{owner}.{prop}>")
            if owner.lower() == "document" and prop.lower() == "cookie":
                self._emit("credential_access", source="document.cookie")
                return "<document.cookie>"
            dispatch_value = self.dispatch_objects.get(owner, {}).get(prop)
            if isinstance(dispatch_value, (str, int, float)) and not isinstance(dispatch_value, bool):
                return dispatch_value

        # ``variable[index]`` (optionally followed by more chained calls or
        # indexing) on an already-known array/string value.  Computed member
        # access that resolves to an *identifier* is folded into plain dotted
        # access earlier during static deobfuscation; this covers the
        # remaining numeric/dynamic-index case at evaluation time.
        ident_bracket = re.match(rf"^({_IDENT})\s*\[", expr)
        if ident_bracket and ident_bracket.group(1) in self.variables:
            owner = ident_bracket.group(1)
            open_index = expr.find("[", ident_bracket.end() - 1)
            raw_index, end_index = _extract_balanced(expr, open_index, "[", "]")
            if raw_index is not None:
                index_value = self._eval_expr(raw_index)
                suffix = expr[end_index + 1:].strip()
                if isinstance(index_value, str) and re.fullmatch(_IDENT, index_value):
                    # The bracket key only resolved to a property *name* at
                    # runtime (a dispatch-object-wrapped decoder call, most
                    # commonly), so the static "fold into dotted access"
                    # pass above never got a chance at it -- ``owner[prop]``
                    # is otherwise identical to ``owner.prop`` here,
                    # including walking ``object_aliases`` the same way the
                    # dotted branch above does, since a "computed object
                    # literal" like ``target = {}; target[key] = value;`` is
                    # stored as flat ``"target.key"`` entries, not a real
                    # nested object ``target`` could be indexed into.
                    prop = index_value
                    key = f"{owner}.{prop}"
                    if key in self.variables:
                        result = self.variables[key]
                        return self._eval_suffix(result, suffix) if suffix else result
                    resolved_owner = owner
                    seen_owners = set()
                    while resolved_owner in self.object_aliases and resolved_owner not in seen_owners:
                        seen_owners.add(resolved_owner)
                        resolved_owner = self.object_aliases[resolved_owner]
                        alias_key = f"{resolved_owner}.{prop}"
                        if alias_key in self.variables:
                            result = self.variables[alias_key]
                            return self._eval_suffix(result, suffix) if suffix else result
                base = self.variables[owner]
                result = self._apply_index(base, index_value)
                if suffix and not _is_unknown(result):
                    result = self._eval_suffix(result, suffix)
                return result

        return _Unknown(expr)

    def _apply_index(self, value, index):
        if _is_unknown(index) or isinstance(index, bool):
            return _Unknown("<index>")
        try:
            position = int(index)
        except (TypeError, ValueError):
            return _Unknown("<index>")
        if isinstance(value, _CharArray) and -len(value.text) <= position < len(value.text):
            return value.text[position]
        if isinstance(value, _SplitText) and -value.part_count <= position < value.part_count:
            # Resolve a single requested field without materializing every
            # split component.  Negative indices mirror Python's helper
            # semantics used elsewhere in this abstract model.
            if abs(position) > MAX_VARIABLES:
                return _Unknown("<large-split-index>")
            if position < 0:
                parts = value.text.rsplit(value.separator, -position)
                return parts[position] if len(parts) >= -position else _Unknown("<index>")
            parts = value.text.split(value.separator, position + 1)
            return parts[position] if len(parts) > position else _Unknown("<index>")
        if isinstance(value, (list, str)) and -len(value) <= position < len(value):
            return value[position]
        return _Unknown("<index>")

    def _eval_suffix(self, value, suffix):
        current = value
        rest = suffix
        while rest:
            if rest[0] == ".":
                match = re.match(rf"^\.({_IDENT})\s*\(", rest)
                if not match:
                    break
                open_index = rest.find("(", match.start())
                raw_args, end_index = _extract_call(rest, open_index)
                if raw_args is None:
                    break
                args = [self._eval_expr(arg) for arg in _split_top_level(raw_args)] if raw_args.strip() else []
                current = self._apply_value_method(current, match.group(1).lower(), args)
            elif rest[0] == "[":
                raw_index, end_index = _extract_balanced(rest, 0, "[", "]")
                if raw_index is None:
                    break
                current = self._apply_index(current, self._eval_expr(raw_index))
            else:
                break
            remaining = rest[end_index + 1:].strip()
            if _is_unknown(current):
                # The already-consumed portion of ``rest`` produced the
                # unknown result; only genuinely unresolved trailing chain
                # is worth keeping in the placeholder text.
                return _Unknown(f"{current}{remaining}") if remaining else current
            rest = remaining
        return current

    def _apply_value_method(self, value, method, args):
        method = method.lower()
        if _is_unknown(value) or isinstance(value, _FunctionRef):
            # Never run string transforms against an ``_Unknown`` placeholder's
            # debug text (e.g. the raw source of an unresolved call) -- doing
            # so can fabricate plausible-looking but meaningless "recovered"
            # strings instead of honestly propagating unresolved-ness.  A bare
            # callable reference that was never invoked is equally not real
            # string/array data.
            return _Unknown(f"<unresolved:{method}()>")
        hex_table = self.prototype_hex_methods.get(method)
        if hex_table is not None:
            return self._invoke_hex_table_method(hex_table, value, args)
        if method == "tostring":
            return str(value)
        if method == "trim":
            return str(value).strip()
        if method == "tolowercase":
            return str(value).lower()
        if method == "touppercase":
            return str(value).upper()
        if method == "replace" and len(args) >= 2 and isinstance(args[0], _JSRegex) and not _is_unknown(args[1]):
            compiled = _compile_js_regex(args[0].pattern, args[0].flags)
            if compiled is None:
                return _Unknown(f"<unresolved:replace(/{args[0].pattern}/)>")
            replacement = str(args[1])
            count = 0 if "g" in args[0].flags else 1
            try:
                return _cap(compiled.sub(lambda m: replacement, str(value), count=count))
            except re.error:
                return _Unknown(f"<unresolved:replace(/{args[0].pattern}/)>")
        if method == "replace" and len(args) >= 2 and not any(_is_unknown(arg) for arg in args[:2]):
            return _cap(str(value).replace(str(args[0]), str(args[1])))
        if method == "repeat" and args and isinstance(args[0], (int, float)) and not isinstance(args[0], bool):
            count = int(args[0])
            if count < 0:
                return _Unknown(f"<invalid-repeat-count:{count}>")
            text = str(value)
            # Bound the multiplication itself, not just its result: a huge
            # ``count`` (this method exists specifically to collapse
            # thousands-of-repeats padding) must not build the full string
            # in memory before ``_cap`` gets a chance to truncate it.
            needed = min(count, (MAX_VALUE_CHARS // max(len(text), 1)) + 1)
            return _cap(text * needed)
        if method == "concat":
            if isinstance(value, _CharArray):
                return _CharArray(value.text + "".join(str(arg) for arg in args))
            if isinstance(value, list):
                return (value + args)[:MAX_VARIABLES]
            return _cap(str(value) + "".join(str(arg) for arg in args))
        if method == "split" and (not args or not _is_unknown(args[0])):
            separator = str(args[0]) if args else None
            if separator == "":
                return _CharArray(value)
            text = str(value)
            if separator is not None:
                part_count = text.count(separator) + 1
                if part_count > MAX_VARIABLES:
                    return _SplitText(text, separator, part_count)
            return text.split(separator)[:MAX_VARIABLES]
        if method == "join" and isinstance(value, _CharArray) and (not args or not _is_unknown(args[0])):
            separator = str(args[0]) if args else ","
            return _cap(value.text if separator == "" else separator.join(value.text))
        if method == "join" and isinstance(value, _SplitText) and (not args or not _is_unknown(args[0])):
            separator = str(args[0]) if args else ","
            # ``separator.join(text.split(original))`` is exactly equivalent
            # to this fixed-string replacement and does not allocate a list
            # with attacker-controlled cardinality.
            return _cap(value.text.replace(value.separator, separator))
        if method == "join" and isinstance(value, list) and (not args or not _is_unknown(args[0])):
            separator = str(args[0]) if args else ","
            return _cap(separator.join(str(item) for item in value))
        if method == "reverse":
            if isinstance(value, _CharArray):
                return _CharArray(value.text[::-1])
            if isinstance(value, _SplitText):
                return _Unknown("<large-split-reverse>")
            return list(reversed(value)) if isinstance(value, list) else str(value)[::-1]
        if method in ("slice", "substring", "substr") and not any(_is_unknown(arg) for arg in args[:2]):
            try:
                start = int(args[0]) if args else 0
                if method == "substr" and len(args) > 1:
                    end = start + int(args[1])
                else:
                    end = int(args[1]) if len(args) > 1 else None
                return value[start:end]
            except (TypeError, ValueError, OverflowError):
                return _Unknown(f"<unresolved:{method}()>")
        if method == "charat" and args and not _is_unknown(args[0]):
            try:
                index = int(args[0])
                return str(value)[index] if 0 <= index < len(str(value)) else ""
            except (TypeError, ValueError, OverflowError):
                return _Unknown("<unresolved:charAt()>")
        return _Unknown(f"<unresolved:{method}()>")

    def _eval_pure_call(self, name, args, raw_args=""):
        lower = name.lower()
        canonical = self.lookup_aliases.get(name, name)
        if canonical in self.lookup_decoders and args and isinstance(args[0], (int, float)):
            key = args[1] if len(args) > 1 and isinstance(args[1], str) else None
            return self._decoder_value(canonical, args[0], key=key)
        if name in self.pure_functions:
            return self._invoke_pure_model(self.pure_functions[name], args)
        if name in self.charcode_lookup_functions and args and isinstance(args[0], str):
            value = self._resolve_charcode_lookup_call(name, args[0])
            if value is not None:
                return value
        if name in self.charcode_shift_functions and args and isinstance(args[0], str):
            value = self._resolve_charcode_shift_call(name, args[0])
            if value is not None:
                return value
        if "." in name:
            receiver, method = name.rsplit(".", 1)
            # Obfuscators frequently hide operators and calls behind a small
            # object-literal "dispatch table" keyed by random property names
            # (``dispatch['apply'](decoderAlias, index)`` instead of a direct
            # call).  ``_discover_dispatch_objects`` already modeled each
            # function-valued property the same way a plain pure function is
            # modeled, so it can be invoked identically.
            dispatch_model = self.dispatch_objects.get(receiver, {}).get(method)
            if isinstance(dispatch_model, dict):
                value = self._invoke_pure_model(dispatch_model, args)
                if not _is_unknown(value):
                    return value
            if receiver in self.variables and not _is_unknown(self.variables[receiver]):
                value = self._apply_value_method(self.variables[receiver], method, args)
                if not _is_unknown(value):
                    return value
        if lower in ("string", "string.raw"):
            return str(args[0]) if args else ""
        if lower in ("parseint", "number") and args and not _is_unknown(args[0]):
            try:
                return int(str(args[0]), 0)
            except ValueError:
                return _Unknown(str(args[0]))
        if lower in ("atob", "window.atob") and args and not _is_unknown(args[0]):
            try:
                raw = base64.b64decode(str(args[0]) + "===", validate=False)
                return _cap(raw.decode("utf-8", errors="replace"))
            except Exception:
                return _Unknown(raw_args)
        if lower in ("btoa", "window.btoa") and args and not _is_unknown(args[0]):
            return base64.b64encode(str(args[0]).encode()).decode()
        if lower in ("unescape", "window.unescape") and args and not _is_unknown(args[0]):
            return _cap(urllib.parse.unquote(str(args[0])))
        if lower in ("decodeuri", "decodeuricomponent") and args and not _is_unknown(args[0]):
            return _cap(urllib.parse.unquote(str(args[0])))
        if lower in ("encodeuri", "encodeuricomponent") and args and not _is_unknown(args[0]):
            return _cap(urllib.parse.quote(str(args[0])))
        if lower in ("string.fromcharcode", "string.fromcodepoint"):
            chars = []
            for arg in args[:65536]:
                try:
                    chars.append(chr(int(arg) & (0xFFFF if lower.endswith("charcode") else 0x10FFFF)))
                except (TypeError, ValueError, OverflowError):
                    return _Unknown(raw_args)
            return _cap("".join(chars))
        if lower == "buffer.from" and args:
            encoding = str(args[1]).lower() if len(args) > 1 else "utf8"
            if _is_unknown(args[0]):
                return _Unknown(raw_args)
            if encoding in ("base64", "base64url"):
                try:
                    payload = str(args[0]).replace("-", "+").replace("_", "/")
                    raw = base64.b64decode(payload + "===", validate=False)
                    return _cap(raw.decode("utf-8", errors="replace"))
                except Exception:
                    return _Unknown(raw_args)
            if encoding in ("hex", "base16"):
                try:
                    return _cap(bytes.fromhex(str(args[0])).decode("utf-8", errors="replace"))
                except (ValueError, TypeError):
                    return _Unknown(raw_args)
            return _cap(str(args[0]))
        if lower in ("path.join", "path.resolve"):
            return _cap("\\".join(str(arg).strip("/\\") for arg in args if str(arg)))
        if lower.endswith(".environment") and args:
            return self._environment_value(args[0])
        if lower == "require" and args:
            return f"<module:{args[0]}>"
        return _Unknown(f"{name}({raw_args})")

    def _resolve_args(self, raw_args):
        if not raw_args.strip():
            return []
        return [self._eval_expr(arg) for arg in _split_top_level(raw_args)]

    def _handle_accumulator_loop(self, statement):
        """Recognize ``for (var i = 0; i < src.length; i++) { acc += src[i]; }``.

        This emulator never actually executes a loop body more than once
        (every statement is visited exactly once, in text order, by
        design) -- so a *real* character-by-character reassembly loop like
        this previously left ``acc`` holding only its first element,
        rather than the full concatenation the sample builds at runtime.
        For this specific, extremely common shape (plain append, no
        per-element transform) the loop's net effect is provably just
        "append the whole source to the accumulator", so it is computed
        directly instead of simulated -- correct without needing general
        loop execution. ``self._pending_accumulator_loop`` bridges the
        header and body across the two statements ``_split_statements``
        splits this into (see ``_pending_object_literal_owner`` for the
        same bridging technique on a different idiom).
        """
        stripped = statement.strip()
        header = _ACCUMULATOR_LOOP_HEADER_RE.match(stripped)
        if header:
            self._pending_accumulator_loop = {"idx": header.group(1), "source": header.group(2)}
            return False
        pending = self._pending_accumulator_loop
        if not pending:
            return False
        if stripped == "}":
            self._pending_accumulator_loop = None
            return False
        body = _ACCUMULATOR_LOOP_BODY_RE.match(stripped)
        self._pending_accumulator_loop = None
        if not body or body.group(2) != pending["source"] or body.group(3) != pending["idx"]:
            return False
        # This is the accumulator body line: claim it (return True) so the
        # caller skips the generic ``+=`` handling in ``_record_assignment``
        # for this statement -- that generic path evaluates ``src[idx]`` as
        # a computed-member read with an unresolved loop counter and would
        # clobber the accumulator with an ``Unknown`` placeholder *before*
        # this method ever runs, since it used to run first.
        acc_name, source_name = body.group(1), pending["source"]
        source_value = self.variables.get(source_name)
        if isinstance(source_value, (str, _CharArray)):
            appended = str(source_value)
        elif isinstance(source_value, _SplitText):
            appended = source_value.text
        elif isinstance(source_value, list) and len(source_value) <= MAX_VARIABLES:
            appended = "".join(str(item) for item in source_value)
        else:
            return True
        old = self.variables.get(acc_name, "")
        if _is_unknown(old):
            return True
        self._store_variable(acc_name, _cap(str(old) + appended))
        return True

    def _handle_object_literal_com_creation(self, statement):
        """Track ``new ActiveXObject(...)`` bundled as an object-literal
        property (``var helper = {'client': new ActiveXObject(progid), ...}``)
        instead of a direct ``var X = new ActiveXObject(...)`` assignment.

        ``_ACTIVEX_ASSIGN_RE`` cannot see this shape at all -- there is no
        top-level ``var IDENT = new ActiveXObject`` here, ``ActiveXObject``
        is a property *value*. Worse, ``_split_statements`` splits on every
        top-level newline, so a real, multi-line object literal never
        reaches here as one statement either: it arrives as one statement
        per property line, each missing the ``owner = {`` prefix that named
        it (verified against real samples -- ``"x = {"`` and each
        ``"'prop': new ActiveXObject(...),"`` line are separate entries in
        ``_split_statements``'s output). ``self._pending_object_literal_owner``
        bridges that gap across the statement loop. Registers the result
        under the same compound ``receiver.prop`` key ``_handle_call``
        already derives from a later ``helper.client.someMethod(...)`` call
        (via ``compact.rsplit(".", 1)``), so no downstream changes are
        needed for method dispatch on it to work once this fires.
        """
        # Neither an ``owner = {`` opener nor a ``'prop': new
        # ActiveXObject(...)`` property line is ever legitimately large --
        # bound *before* either regex below runs, not just the second one.
        # A pending object literal's property *values* are ordinary
        # statements too, and one of them being a many-megabyte embedded
        # blob (a base64 payload, seen in a real sample) turned the first
        # regex's ``\Z``-anchored search across the whole thing into a
        # multi-minute hang on its own -- confirmed via profiling/direct
        # reproduction, the dominant cost (in one case, an outright hang
        # past any reasonable wall-clock budget) of that run.
        if len(statement) > 2048:
            return
        stripped = statement.strip()
        opener = re.search(rf"({_IDENT})\s*=\s*\{{\s*\Z", stripped)
        if opener:
            self._pending_object_literal_owner = opener.group(1)
            return
        if not self._pending_object_literal_owner:
            return
        if re.match(r"\}", stripped):
            self._pending_object_literal_owner = None
            return
        prop_match = re.match(
            rf"\s*(?:'([^']*)'|\"([^\"]*)\"|({_IDENT}))\s*:\s*(?:new\s+)?"
            rf"(?:ActiveXObject|WScript\.CreateObject)\s*\((.*)\)\s*,?\s*\Z",
            statement,
            re.IGNORECASE | re.DOTALL,
        )
        if not prop_match:
            return
        prop = prop_match.group(1) or prop_match.group(2) or prop_match.group(3)
        progid = self._eval_expr(prop_match.group(4))
        target = f"{self._pending_object_literal_owner}.{prop}"
        self.objects[target] = f"activex:{str(progid).lower()}"
        self._emit("com_create", progid=progid, variable=target)

    def _record_assignment(self, statement):
        require_match = _REQUIRE_ASSIGN_RE.search(statement)
        if require_match:
            variable = require_match.group(1)
            module = self._eval_expr(require_match.group(2))
            if not _is_unknown(module):
                self.modules[variable] = str(module).lower()
                self.objects[variable] = f"node:{str(module).lower()}"
                self._emit("module_load", module=module, variable=variable)

        member_require = _REQUIRE_MEMBER_ASSIGN_RE.search(statement)
        if member_require:
            variable, module_expr, exported = member_require.groups()
            module = self._eval_expr(module_expr)
            if not _is_unknown(module):
                self.aliases[variable] = (str(module).lower(), exported.lower())

        destructured = _DESTRUCTURED_REQUIRE_RE.search(statement)
        if destructured:
            module = self._eval_expr(destructured.group(2))
            for item in _split_top_level(destructured.group(1)):
                bits = [part.strip() for part in item.split(":", 1)]
                exported = bits[0]
                local = bits[-1]
                if re.fullmatch(_IDENT, local):
                    self.aliases[local] = (str(module).lower(), exported.lower())
            if not _is_unknown(module):
                self._emit("module_load", module=module, variable="<destructured>")

        active_match = _ACTIVEX_ASSIGN_RE.search(statement)
        if active_match:
            variable = active_match.group(1)
            progid = self._eval_expr(active_match.group(2))
            kind = f"activex:{str(progid).lower()}"
            self.objects[variable] = kind
            self._emit("com_create", progid=progid, variable=variable)

        getobject_match = _GETOBJECT_ASSIGN_RE.search(statement)
        if getobject_match:
            variable = getobject_match.group(1)
            moniker = self._eval_expr(getobject_match.group(2))
            kind = "wmi:services" if "winmgmts" in str(moniker).lower() else f"comobject:{str(moniker).lower()}"
            self.objects[variable] = kind
            self._emit("com_create", progid=moniker, variable=variable)

        wmi_get_match = _WMI_GET_ASSIGN_RE.search(statement)
        if wmi_get_match:
            variable, receiver, raw_class = wmi_get_match.groups()
            if self.objects.get(receiver, "").startswith("wmi:"):
                class_name = self._eval_expr(raw_class)
                if isinstance(class_name, str) and not _is_unknown(class_name):
                    self.objects[variable] = f"wmi:class:{class_name.lower()}"

        new_match = _NEW_OBJECT_RE.search(statement)
        if new_match and not active_match:
            variable, constructor, raw_args = new_match.groups()
            args = self._resolve_args(raw_args)
            kind = constructor.lower().replace(" ", "")
            self.objects[variable] = kind
            if kind.endswith("xmlhttprequest"):
                self.xhr_state.setdefault(variable, {})
                self._emit("object_create", object_type="XMLHttpRequest", variable=variable)
            elif kind.endswith("websocket"):
                url = args[0] if args else _Unknown(raw_args)
                self._record_network(url, method="WEBSOCKET", api="WebSocket")
            elif kind.endswith("image"):
                self._emit("object_create", object_type="Image", variable=variable)

        assign_match = _ASSIGN_RE.search(statement)
        if assign_match:
            name, operator, expression = assign_match.groups()
            value = self._eval_expr(expression)
            if operator == "+=":
                old = self.variables.get(name, "")
                if not _is_unknown(old) and not _is_unknown(value):
                    value = _cap(str(old) + str(value))
                else:
                    value = _Unknown(f"{old}{value}")
            self._store_variable(name, value)
            if operator == "=" and re.fullmatch(_IDENT, expression.strip()):
                self.object_aliases[name] = expression.strip()
            if name.lower() == "location":
                self._record_network(value, method="NAVIGATE", api="location")
                self._emit("browser_redirect", url=value, api="location")

        object_match = _OBJECT_ASSIGN_RE.search(statement)
        if object_match:
            target, expression = object_match.groups()
            if "." in target:
                value = self._eval_expr(expression)
                compact_target = re.sub(r"\s+", "", target)
                self._store_variable(compact_target, value)
                self._handle_property_assignment(compact_target, value)

    def _handle_property_assignment(self, target, value):
        owner, prop = target.rsplit(".", 1)
        prop_lower = prop.lower()
        owner_lower = owner.lower()
        if prop_lower in ("href", "location") and owner_lower in ("location", "window", "window.location", "document", "document.location"):
            self._record_network(value, method="NAVIGATE", api=target)
            self._emit("browser_redirect", url=value, api=target)
        elif prop_lower == "src":
            kind = self.objects.get(owner, "")
            if kind.endswith("image") or owner_lower in ("document", "window.location"):
                self._record_network(value, method="GET", api=f"{kind or owner}.src")
        elif prop_lower == "cookie" and owner_lower == "document":
            self._emit("cookie_write", value=value)
        elif prop_lower == "datatype":
            # MSXML DOM nodes expose ``dataType = 'bin.base64'`` plus
            # ``nodeTypedValue`` as the standard WSH Base64 decoding idiom.
            if str(value).strip().lower() == "bin.base64":
                self.objects[owner] = "msxml:base64-node"
        elif prop_lower == "text" and (
            self.objects.get(owner) == "msxml:base64-node"
            or str(self.variables.get(f"{owner}.dataType", "")).strip().lower() == "bin.base64"
        ):
            self._decode_base64_node(owner, value)

    def _record_network(self, url, method="GET", api=""):
        text = _safe_text(url)
        self._emit("network_request", method=method, url=text, api=api)

    def _record_process(self, command, api=""):
        self._emit("process_create", command=_safe_text(command), api=api)
        # A resolved command line is exactly as trustworthy a place to find a
        # literal C2 URL as the embedded-binary scan below -- most commonly
        # a deobfuscated PowerShell downloader string, once statements like
        # ``.split(junk).join("")``/regex-quote-escaping have been unwound.
        self._emit_url_indicators(str(command), source="process_create")

    def _emit_url_indicators(self, text, source):
        for match in re.finditer(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,2048}", text):
            for url in re.split(r",(?=https?://)", match.group(0)):
                self._emit("network_indicator", url=url.rstrip(".,);]'"), source=source)

    def _record_file(self, category, path, content="", api=""):
        path_text = _safe_text(path)
        event = {"path": path_text, "api": api}
        if category == "filesystem_write":
            content_text = _safe_text(content, 1024)
            self.virtual_files[path_text.lower()] = content_text
            event["size_hint"] = len(content) if isinstance(content, _BinaryValue) else len(str(content))
            if isinstance(content, _BinaryValue):
                event["sha256"] = content.sha256
                event["content_complete"] = content.complete
                for payload in self._embedded_payloads:
                    if payload.get("sha256") == content.sha256 and "path" not in payload:
                        payload["path"] = path_text
            event["suspicious_ext"] = _extension(path_text) in _SUSPICIOUS_EXTENSIONS
        self._emit(category, **event)

    @staticmethod
    def _declared_pe_extent(payload):
        """Return the largest PE raw-section end, or ``None`` if malformed."""
        if len(payload) < 0x100 or payload[:2] != b"MZ":
            return None
        try:
            pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
            if pe_offset + 24 > len(payload) or payload[pe_offset:pe_offset + 4] != b"PE\0\0":
                return None
            section_count = struct.unpack_from("<H", payload, pe_offset + 6)[0]
            optional_size = struct.unpack_from("<H", payload, pe_offset + 20)[0]
            if not 0 < section_count <= 96:
                return None
            table = pe_offset + 24 + optional_size
            if table + section_count * 40 > len(payload):
                return None
            extent = table + section_count * 40
            for index in range(section_count):
                raw_size, raw_offset = struct.unpack_from("<II", payload, table + index * 40 + 16)
                extent = max(extent, raw_offset + raw_size)
            return extent
        except (IndexError, struct.error, ValueError):
            return None

    def _analyze_embedded_binary(self, binary, source="script:base64"):
        """Inspect recovered bytes as data and emit only bounded metadata/IOCs."""
        if not isinstance(binary, _BinaryValue) or binary.sha256 in self._embedded_payload_hashes:
            return
        self._embedded_payload_hashes.add(binary.sha256)
        payload = binary.data
        payload_type = "binary"
        if payload.startswith(b"MZ"):
            payload_type = "PE"
        elif re.match(rb"\s*local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*['\"]", payload):
            payload_type = "Lua/config blob"
        declared_extent = self._declared_pe_extent(payload) if payload_type == "PE" else None
        complete = binary.complete and not (declared_extent and declared_extent > len(payload))
        # Keep the value's state consistent for downstream fake file writes.
        # A syntactically complete Base64 string can still contain only the
        # beginning of a PE when its section table references missing bytes.
        binary.complete = complete
        summary = {
            "sha256": binary.sha256,
            "size": len(payload),
            "type": payload_type,
            "complete": complete,
            "source": source,
        }
        if declared_extent and declared_extent > len(payload):
            summary["declared_size"] = declared_extent
        self._embedded_payloads.append(summary)
        self._emit(
            "embedded_payload_deobfuscation",
            layers=binary.encoding,
            payload_type=payload_type,
            payload_size=len(payload),
            payload_sha256=binary.sha256,
            complete=complete,
        )
        if not complete:
            self._emit(
                "embedded_payload_truncated",
                payload_sha256=binary.sha256,
                recovered_size=len(payload),
                declared_size=declared_extent or "unknown",
            )

        # Literal HTTP(S) IOCs are safe to recover from either binary or text
        # payloads.  Keep the character class conservative so trailing binary
        # bytes/punctuation cannot be mistaken for part of the URL.
        for match in re.finditer(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,2048}", payload):
            try:
                matched_urls = re.split(
                    r",(?=https?://)",
                    match.group(0).decode("ascii"),
                )
            except UnicodeError:
                continue
            for url in matched_urls:
                self._emit(
                    "network_indicator",
                    url=url.rstrip(".,);]\'"),
                    source=f"embedded:{payload_type}",
                )

        config = _recover_xworm_config(payload) if payload_type == "PE" else None
        if config:
            self._emit(
                "embedded_payload_config",
                family=config["family"],
                hosts=", ".join(config["hosts"]),
                port=config["port"],
            )
            for host in config["hosts"]:
                self._record_network(
                    f"tcp://{host}:{config['port']}",
                    method="TCP_CONNECT",
                    api="embedded-dotnet:ClientSocket.BeginConnect",
                )

        vip_config = _recover_vipkeylogger_config(payload) if payload_type == "PE" else None
        if vip_config:
            self._emit(
                "embedded_payload_config",
                family=vip_config["family"],
                panels=", ".join(vip_config["panel_urls"]),
            )
            for url in vip_config["panel_urls"]:
                self._record_network(
                    url,
                    method="C2_CONNECT",
                    api="embedded-dotnet:VIPKeylogger.PanelConnectionApi",
                )
            for url in vip_config["direct_urls"]:
                if "checkip.dyndns.org" in url or "reallyfreegeoip.org" in url:
                    self._record_network(
                        url,
                        method="GET",
                        api="embedded-dotnet:external-IP lookup",
                    )
                elif "_send_.php" in url:
                    self._record_network(
                        url,
                        method="C2_EXFIL",
                        api="embedded-dotnet:VIPKeylogger",
                    )
            if vip_config["download_capability"]:
                self._emit(
                    "network_download_capability",
                    api="embedded-dotnet:System.Net.WebClient/HttpWebRequest",
                    url="<C2-supplied at runtime>",
                )
            if vip_config["telegram_capability"]:
                self._emit(
                    "network_c2_capability",
                    api="embedded-dotnet:Telegram Bot API",
                    url="https://api.telegram.org/bot<TOKEN>/<METHOD>",
                )

        remcos_config = _recover_remcos_signature(payload) if payload_type == "PE" else None
        if remcos_config:
            self._emit(
                "embedded_payload_config",
                family=remcos_config["family"],
                settings_resource_present=remcos_config["settings_resource_present"],
                settings_resource_size=remcos_config["settings_resource_size"],
                settings_resource_sha256=remcos_config["settings_resource_sha256"],
            )
            if remcos_config["settings_resource_present"]:
                self._emit(
                    "network_c2_capability",
                    api="Remcos RAT (RT_RCDATA/SETTINGS resource, per-build encrypted)",
                    url="<encrypted -- key is not derivable from static strings or PE structure alone>",
                )

        if payload_type == "Lua/config blob":
            shellcode = _recover_lua_polyrot_shellcode(payload)
            if shellcode:
                shellcode_hash = hashlib.sha256(shellcode).hexdigest()
                if shellcode_hash not in self._embedded_payload_hashes:
                    self._embedded_payload_hashes.add(shellcode_hash)
                    self._embedded_payloads.append({
                        "sha256": shellcode_hash,
                        "size": len(shellcode),
                        "type": "Donut-compatible shellcode",
                        "complete": True,
                        "source": f"{source}:Lua-PolyRot",
                    })
                    self._emit(
                        "embedded_payload_deobfuscation",
                        layers="Lua reverse/permutation -> Base64 -> PolyRot",
                        payload_type="Donut-compatible shellcode",
                        payload_size=len(shellcode),
                        payload_sha256=shellcode_hash,
                        complete=True,
                    )
                donut = _recover_donut_payload(shellcode)
                if donut:
                    self._emit(
                        "embedded_payload_config",
                        family="Donut v1",
                        instance_type=donut["instance_type"],
                        module_type=donut.get("module_type", "remote"),
                        compression=donut.get("compression", "unknown"),
                    )
                    if donut.get("server"):
                        self._record_network(
                            donut["server"],
                            method=donut.get("request", "GET"),
                            api="embedded-donut:HTTP-stager",
                        )
                    module = donut.get("module")
                    if module:
                        embedded_module = _BinaryValue(
                            module,
                            complete=donut.get("module_complete", False),
                            encoding="Lua PolyRot -> Donut embedded module",
                        )
                        self._stored_binary_bytes += len(embedded_module)
                        self._analyze_embedded_binary(
                            embedded_module,
                            source=f"{source}:Donut-module",
                        )
                    elif donut.get("compression", 1) != 1:
                        self._emit(
                            "embedded_payload_unsupported",
                            format=f"Donut compression {donut.get('compression')}",
                        )

        strings = _binary_strings(payload)
        lowered = [value.lower() for value in strings]
        if any("downloadfile" in value for value in lowered):
            self._emit(
                "network_download_capability",
                api="embedded:System.Net.WebClient.DownloadFile",
                url="<runtime-supplied>",
            )

    def _decode_base64_node(self, owner, value):
        if not isinstance(value, str):
            return None
        compact = re.sub(r"\s+", "", value)
        if not compact or len(compact) > MAX_EMBEDDED_PAYLOAD_BYTES * 2:
            return None
        # A Base64 stream with length mod 4 == 1 cannot be complete.  Decode
        # its largest valid prefix for forensic metadata, but explicitly mark
        # it partial instead of inventing missing bytes.
        complete = len(compact) % 4 != 1
        candidate = compact if complete else compact[:-1]
        try:
            decoded = base64.b64decode(candidate + "=" * ((-len(candidate)) % 4), validate=True)
        except (ValueError, TypeError):
            return None
        if not decoded or len(decoded) > MAX_EMBEDDED_PAYLOAD_BYTES:
            return None
        if self._stored_binary_bytes + len(decoded) > MAX_EMBEDDED_PAYLOAD_BYTES * 4:
            self._emit("resource_limit", resource="embedded_binary_bytes", limit=MAX_EMBEDDED_PAYLOAD_BYTES * 4)
            return None
        binary = _BinaryValue(decoded, complete=complete, encoding="MSXML bin.base64")
        self._stored_binary_bytes += len(binary)
        self._store_variable(f"{owner}.nodeTypedValue", binary)
        self._analyze_embedded_binary(binary, source=f"{owner}.nodeTypedValue")
        return binary

    def _queue_dynamic_layer(self, code, source, depth, queue):
        if _is_unknown(code):
            self._emit("dynamic_code", api=source, resolved=False, code=_safe_text(code, 512))
            return
        text = str(code)
        if not text.strip():
            return
        self._emit("dynamic_code", api=source, resolved=True, size=len(text))
        digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        if digest in self._layer_hashes or len(self.decoded_layers) >= MAX_DECODED_LAYERS:
            return
        self._layer_hashes.add(digest)
        preview = _cap("".join(ch if ch.isprintable() else "?" for ch in text), 512)
        self.decoded_layers.append({
            "source": source,
            "depth": depth,
            "sha256": digest,
            "size": len(text),
            "preview": preview,
        })
        if depth <= MAX_DECODED_LAYERS:
            queue.append((text[:MAX_SOURCE_CHARS], depth, source))

    def _handle_indirect_eval(self, statement, depth, queue):
        """Recognize ``(0, this)["eval"](payload)``-shaped indirect eval.

        ``_iter_call_heads`` only matches bare-identifier-led call chains,
        so a call whose receiver starts with ``(`` -- the entire point of
        this idiom -- is otherwise invisible to the interpreter. Every
        candidate position is verified end-to-end (bracket key evaluates to
        exactly ``"eval"``, immediately followed by a real call) before the
        argument is queued, so this cannot misfire on ordinary
        ``this[...]``/``window[...]`` property access.
        """
        for receiver_match in _INDIRECT_EVAL_RECEIVER_RE.finditer(statement):
            bracket_index = receiver_match.end() - 1
            raw_key, key_end = _extract_balanced(statement, bracket_index, "[", "]")
            if raw_key is None:
                continue
            key = self._eval_expr(raw_key)
            if key != "eval":
                continue
            call_open = key_end + 1
            while call_open < len(statement) and statement[call_open].isspace():
                call_open += 1
            if call_open >= len(statement) or statement[call_open] != "(":
                continue
            raw_args, _call_end = _extract_call(statement, call_open)
            if raw_args is None:
                continue
            args = self._resolve_args(raw_args)
            self._queue_dynamic_layer(args[0] if args else _Unknown(raw_args), "indirect-eval", depth + 1, queue)

    def _handle_computed_member_call(self, statement, depth, queue):
        """Recognize ``receiver[computedExpr](args)`` -- a call whose method
        name is a bracket expression, not a literal identifier -- when
        ``computedExpr`` only resolves at *runtime*, not during static prep.

        ``_iter_call_heads`` requires a dotted-identifier callee, so this
        shape is invisible to it entirely. ``_normalize_computed_members``
        (static prep, before ``self.variables`` holds anything) cannot help
        either: real samples build the method name from a *plain string
        variable* (``WScript[PYLM.charAt(2215)+PYLM.charAt(2216)+...]``,
        not a lookup-decoder call), which is only a known value once its
        own ``var PYLM = "..."`` statement has actually been interpreted.
        Once resolved to a clean identifier, re-dispatches through
        ``_handle_call`` under that name so every existing method-dispatch
        rule (ActiveXObject, process/network methods, ...) applies without
        duplicating logic here.
        """
        for receiver_match in re.finditer(rf"\b({_IDENT})\s*\[", statement):
            receiver = receiver_match.group(1)
            bracket_index = receiver_match.end() - 1
            raw_key, key_end = _extract_balanced(statement, bracket_index, "[", "]")
            if raw_key is None:
                continue
            call_open = key_end + 1
            while call_open < len(statement) and statement[call_open].isspace():
                call_open += 1
            if call_open >= len(statement) or statement[call_open] != "(":
                continue
            key = self._eval_expr(raw_key)
            if not isinstance(key, str) or not re.fullmatch(_IDENT, key):
                continue
            raw_args, _call_end = _extract_call(statement, call_open)
            if raw_args is None:
                continue
            # A "transparent" global-object receiver (mirroring the same set
            # ``_INDIRECT_EVAL_RECEIVER_RE`` treats as such) makes
            # ``this["GetObject"](...)``/``window["ActiveXObject"](...)``
            # exactly equivalent to the bare global call -- dispatch under
            # the bare name so the existing bare-name rules below (``lower
            # == "getobject"``, ``"activexobject"``, ...) still match,
            # instead of a synthetic ``"this.getobject"`` none of them
            # anticipate.
            dispatch_name = key if receiver in ("this", "window", "self", "globalThis") else f"{receiver}.{key}"
            self._handle_call(dispatch_name, raw_args, statement, depth, queue)
            # ``_handle_call`` only emits the side-effect event; it has no
            # way to know whether *this specific* call is the RHS of an
            # assignment (it only sees the callee/args). A resolved
            # ``TARGET = receiver[key](args)`` that constructs a COM object
            # (``CreateObject``/``GetObject``, the object-returning methods
            # these WScript-based droppers reach this way) needs that
            # assignment tracked too, or the *next* computed call on TARGET
            # can never resolve -- exactly the failure this method exists to
            # fix.
            if key.lower() in ("createobject", "getobject"):
                assign_match = re.match(
                    rf"^\s*(?:var|let|const)?\s*({_IDENT})\s*=\s*\Z",
                    statement[:receiver_match.start()],
                )
                if assign_match:
                    args = self._resolve_args(raw_args)
                    progid = args[0] if args else _Unknown(raw_args)
                    self.objects[assign_match.group(1)] = f"activex:{str(progid).lower()}"

    def _handle_call(self, name, raw_args, statement, depth, queue):
        compact = re.sub(r"\s+", "", name)
        lower = compact.lower()
        args = self._resolve_args(raw_args)
        receiver, method = (compact.rsplit(".", 1) if "." in compact else ("", compact))
        method_lower = method.lower()
        receiver_kind = self.objects.get(receiver, "")
        module = self.modules.get(receiver, "")
        alias = self.aliases.get(compact)
        effective_method = alias[1] if alias else method_lower

        if lower in ("eval", "window.eval", "globaleval"):
            self._queue_dynamic_layer(args[0] if args else _Unknown(raw_args), compact, depth + 1, queue)
            return
        # JavaScript's Function constructor is case-sensitive.  A lowercase
        # ``function (...)`` token is a declaration/callback, not dynamic code.
        if compact in ("Function", "window.Function"):
            self._queue_dynamic_layer(args[-1] if args else _Unknown(raw_args), compact, depth + 1, queue)
            return
        if lower in ("settimeout", "setinterval", "window.settimeout", "window.setinterval"):
            callback = args[0] if args else _Unknown(raw_args)
            delay = args[1] if len(args) > 1 else 0
            self._emit("timer_schedule", api=compact, delay=delay)
            if isinstance(callback, str):
                self._queue_dynamic_layer(callback, compact, depth + 1, queue)
            return

        if lower in ("fetch", "window.fetch"):
            url = args[0] if args else _Unknown(raw_args)
            method_value = "GET"
            method_match = re.search(r"\bmethod\s*:\s*([^,}]+)", raw_args, re.IGNORECASE)
            if method_match:
                resolved = self._eval_expr(method_match.group(1))
                if not _is_unknown(resolved):
                    method_value = str(resolved).upper()
            self._record_network(url, method=method_value, api=compact)
            body_match = re.search(r"\bbody\s*:\s*([^,}]+)", raw_args, re.IGNORECASE)
            if body_match:
                self._emit("network_send", url=url, body=self._eval_expr(body_match.group(1)), api=compact)
            return
        if lower in ("websocket", "window.websocket"):
            url = args[0] if args else _Unknown(raw_args)
            self._record_network(url, method="WEBSOCKET", api=compact)
            return
        if lower in ("navigator.sendbeacon", "window.open"):
            url = args[0] if args else _Unknown(raw_args)
            self._record_network(url, method="POST" if lower.endswith("sendbeacon") else "NAVIGATE", api=compact)
            if len(args) > 1 and lower.endswith("sendbeacon"):
                self._emit("network_send", url=url, body=args[1], api=compact)
            return

        node_network = module in ("http", "https", "node:http", "node:https", "axios", "request")
        alias_network = alias and alias[0] in ("http", "https", "node:http", "node:https", "axios", "request")
        if effective_method in ("get", "request", "post", "put", "delete") and (node_network or alias_network):
            url = args[0] if args else _Unknown(raw_args)
            self._record_network(url, method=effective_method.upper(), api=compact)
            return

        if lower in ("activexobject", "wscript.createobject"):
            # Assignment handling already records the concrete variable and
            # ProgID; avoid a second "temporary" event for the same call.
            if _ACTIVEX_ASSIGN_RE.search(statement):
                return
            progid = args[0] if args else _Unknown(raw_args)
            self._emit("com_create", progid=progid, variable="<temporary>")
            return

        if lower == "getobject":
            if _GETOBJECT_ASSIGN_RE.search(statement):
                return
            moniker = args[0] if args else _Unknown(raw_args)
            self._emit("com_create", progid=moniker, variable="<temporary>")
            return

        if method_lower == "create" and receiver_kind == "wmi:class:win32_process":
            command = args[0] if args else _Unknown(raw_args)
            self._record_process(command, api=compact)
            return

        network_object = "xmlhttp" in receiver_kind or "winhttprequest" in receiver_kind
        if method_lower == "open" and (receiver in self.xhr_state or network_object):
            method_value = args[0] if args else "GET"
            url = args[1] if len(args) > 1 else _Unknown(raw_args)
            self.xhr_state.setdefault(receiver, {}).update({"method": str(method_value), "url": str(url)})
            self._emit("network_open", method=method_value, url=url, api=f"{receiver}.open")
            return
        if method_lower == "send" and (receiver in self.xhr_state or network_object):
            state = self.xhr_state.get(receiver, {})
            url = state.get("url", "<unknown>")
            method_value = state.get("method", "GET")
            self._record_network(url, method=method_value, api=f"{receiver}.send")
            if args:
                self._emit("network_send", url=url, body=args[0], api=f"{receiver}.send")
            return
        # ``MSXML2.DOMDocument``/``Microsoft.XMLDOM`` objects also fetch a
        # remote resource with a single ``.load(url)`` call -- no separate
        # open/send pair.  This is a well-known JScript/HTA download
        # primitive distinct from XMLHTTP, and was previously invisible here.
        if method_lower == "load" and ("domdocument" in receiver_kind or "xmldom" in receiver_kind):
            url = args[0] if args else _Unknown(raw_args)
            self._record_network(url, method="LOAD", api=f"{receiver}.load")
            return

        process_call = (
            method_lower in _PROCESS_METHODS
            and ("wscript.shell" in receiver_kind or "shell.application" in receiver_kind or module in ("child_process", "node:child_process"))
        ) or (alias and alias[0] in ("child_process", "node:child_process") and alias[1] in _PROCESS_METHODS)
        if process_call:
            command = args[0] if args else _Unknown(raw_args)
            if effective_method in ("spawn", "spawnsync") and len(args) > 1:
                command = _cap(f"{command} {args[1]}")
            self._record_process(command, api=compact)
            return

        if method_lower == "regwrite" and "wscript.shell" in receiver_kind:
            key = args[0] if args else _Unknown(raw_args)
            value = args[1] if len(args) > 1 else ""
            key_text = _safe_text(key)
            self.registry[key_text.lower()] = _safe_text(value)
            persistence = bool(re.search(r"currentversion[\\/]+run|winlogon|startup", key_text, re.IGNORECASE))
            self._emit("registry_write", key=key, value=value, persistence=persistence)
            return

        if method_lower in ("fileexists", "folderexists") and "filesystemobject" in receiver_kind:
            path = args[0] if args else _Unknown(raw_args)
            self._record_file("filesystem_probe", path, api=compact)
            return

        node_fs = module in ("fs", "node:fs") or (alias and alias[0] in ("fs", "node:fs"))
        adodb_stream = "adodb.stream" in receiver_kind
        activex_stream = adodb_stream or "filesystemobject" in receiver_kind or "textstream" in receiver_kind
        if method_lower in ("write", "writetext") and adodb_stream:
            content = args[0] if args else _Unknown(raw_args)
            self._store_variable(f"{receiver}.buffer", content)
            self._emit(
                "stream_write",
                api=compact,
                size_hint=len(content) if isinstance(content, _BinaryValue) else len(str(content)),
                sha256=content.sha256 if isinstance(content, _BinaryValue) else "",
            )
            return
        if method_lower == "savetofile" and adodb_stream:
            path = args[0] if args else _Unknown(raw_args)
            content = self.variables.get(f"{receiver}.buffer", "")
            self._record_file("filesystem_write", path, content, compact)
            return
        if effective_method in _WRITE_METHODS and (node_fs or activex_stream):
            path = args[0] if args else self.variables.get(f"{receiver}.filename", _Unknown(raw_args))
            content = args[1] if len(args) > 1 else self.variables.get(f"{receiver}.buffer", "")
            self._record_file("filesystem_write", path, content, compact)
            return
        if effective_method in _READ_METHODS and (node_fs or activex_stream):
            path = args[0] if args else _Unknown(raw_args)
            self._record_file("filesystem_read", path, api=compact)
            return
        if effective_method in _DELETE_METHODS and (node_fs or activex_stream):
            path = args[0] if args else _Unknown(raw_args)
            self.virtual_files.pop(_safe_text(path).lower(), None)
            self._record_file("filesystem_delete", path, api=compact)
            return

        if lower in ("document.write", "document.writeln"):
            content = args[0] if args else _Unknown(raw_args)
            self._emit("document_write", content=_safe_text(content, 1024))
            if not _is_unknown(content) and "<script" in str(content).lower():
                blocks = re.findall(r"<script[^>]*>(.*?)</script\s*>", str(content), re.IGNORECASE | re.DOTALL)
                for block in blocks:
                    self._queue_dynamic_layer(block, compact, depth + 1, queue)
            return
        if lower in ("localstorage.setitem", "sessionstorage.setitem"):
            self._emit("browser_storage_write", storage=compact.split(".", 1)[0], key=args[0] if args else "", value=args[1] if len(args) > 1 else "")
            return

    def _handle_direct_require_chains(self, statement):
        """Model ``require('module').method(...)`` without executing it."""
        cursor = 0
        require_head = re.compile(r"\brequire\s*\(", re.IGNORECASE)
        while cursor < len(statement):
            match = require_head.search(statement, cursor)
            if not match:
                return
            open_index = statement.find("(", match.start())
            module_expr, require_end = _extract_call(statement, open_index)
            if module_expr is None:
                return
            suffix = statement[require_end + 1:]
            method_match = re.match(rf"\s*\.\s*({_IDENT})\s*\(", suffix)
            if not method_match:
                cursor = require_end + 1
                continue
            method_open = require_end + 1 + suffix.find("(", method_match.start())
            raw_args, method_end = _extract_call(statement, method_open)
            if raw_args is None:
                return
            module = self._eval_expr(module_expr)
            args = self._resolve_args(raw_args)
            module_lower = str(module).lower()
            method = method_match.group(1).lower()
            api = f"require({module}).{method_match.group(1)}"
            if module_lower in ("child_process", "node:child_process") and method in _PROCESS_METHODS:
                self._record_process(args[0] if args else _Unknown(raw_args), api=api)
            elif module_lower in ("fs", "node:fs") and method in _WRITE_METHODS:
                self._record_file("filesystem_write", args[0] if args else _Unknown(raw_args), args[1] if len(args) > 1 else "", api)
            elif module_lower in ("fs", "node:fs") and method in _READ_METHODS:
                self._record_file("filesystem_read", args[0] if args else _Unknown(raw_args), api=api)
            elif module_lower in ("http", "https", "node:http", "node:https", "axios", "request") and method in ("get", "request", "post", "put", "delete"):
                self._record_network(args[0] if args else _Unknown(raw_args), method=method.upper(), api=api)
            cursor = method_end + 1

    def _process_layer(self, source, depth, queue):
        cleaned = _strip_comments(source)
        statements = _expand_comma_assignment_chains(_expand_declarator_statements(_split_statements(cleaned)))
        statements = _collapse_duplicate_accumulation_runs(statements)
        if len(statements) > MAX_STATEMENTS:
            statements = statements[:MAX_STATEMENTS]
            self.statement_limit_hit = True

        # A small fixed-point pass resolves common out-of-order string aliases
        # without executing any source.  Only plain '=' assignments participate;
        # '+=' remains order-sensitive in the main pass.
        for _ in range(3):
            changed = False
            for statement in statements:
                self._tick()
                match = _ASSIGN_RE.search(statement)
                if not match or match.group(2) != "=":
                    continue
                name, _, expression = match.groups()
                value = self._eval_expr(expression)
                old = self.variables.get(name)
                if not _is_unknown(value) and old != value:
                    self._store_variable(name, value)
                    changed = True
            if not changed:
                break

        for statement in statements:
            self._tick()
            if self._handle_accumulator_loop(statement):
                continue
            self._record_assignment(statement)
            self._handle_direct_require_chains(statement)
            # Property reads such as ``document.cookie;`` have observable
            # behavior even when their result is not assigned or passed to a
            # call.  Evaluate only a plain dotted member expression here so
            # arbitrary statement handling stays conservative and bounded.
            if re.fullmatch(_DOTTED, statement.strip()):
                self._eval_expr(statement)
            for call_name, raw_args, _open_index, _end_index in _iter_call_heads(statement):
                self._handle_call(call_name, raw_args, statement, depth, queue)
            # No cheap literal-"eval" pre-filter here: the entire point of
            # this idiom is commonly to keep that substring out of the raw
            # source (``eval``, ``"e"+"val"``, ...).
            if "[" in statement:
                self._handle_indirect_eval(statement, depth, queue)
                self._handle_computed_member_call(statement, depth, queue)
            # No presence guard here: a bundled property line
            # (``'client': new ActiveXObject(...),``) carries no ``{`` of
            # its own once ``_split_statements`` has broken the literal up
            # -- see ``_handle_object_literal_com_creation``.
            self._handle_object_literal_com_creation(statement)

    def _build_findings(self):
        categories = {event["category"] for event in self.events}
        findings = []

        def add(rule_id, severity, title, description):
            findings.append({
                "rule_id": rule_id,
                "severity": severity,
                "title": title,
                "description": description,
            })

        if {"network_request", "filesystem_write", "process_create"}.issubset(categories):
            add("JS_DOWNLOAD_WRITE_EXECUTE", "high", "Download/write/execute behavior",
                "The emulated script combines a network request, file creation and process execution.")
        elif "process_create" in categories:
            add("JS_PROCESS_EXECUTION", "high", "Process execution attempt",
                "The script attempts to start a command or child process through a modeled API.")
        if "registry_write" in categories and any(event.get("persistence") for event in self.events if event["category"] == "registry_write"):
            add("JS_REGISTRY_PERSISTENCE", "high", "Registry persistence attempt",
                "The script writes to a registry location commonly used for persistence.")
        if categories & {"network_request", "network_download_capability", "network_c2_capability"}:
            add("JS_NETWORK_ACTIVITY", "medium", "Network activity",
                "The script or a recovered embedded payload attempts network communication.")
        elif "network_indicator" in categories:
            add("JS_NETWORK_INDICATOR", "info", "Embedded network indicator",
                "A literal network indicator was recovered from embedded data, without evidence that this path requested it.")
        if "embedded_payload_truncated" in categories:
            add("JS_EMBEDDED_PAYLOAD_INCOMPLETE", "info", "Embedded payload is incomplete",
                "An embedded executable was recovered only partially; exact downstream network behavior cannot be determined from the available bytes.")
        if "filesystem_write" in categories:
            severity = "high" if any(event.get("suspicious_ext") for event in self.events if event["category"] == "filesystem_write") else "medium"
            add("JS_FILE_WRITE", severity, "File creation attempt",
                "The script writes content through a modeled Node.js or ActiveX filesystem API.")
        if "dynamic_code" in categories:
            add("JS_DYNAMIC_CODE", "medium", "Dynamic JavaScript execution",
                "The script passes generated or decoded content to eval, Function or a string timer.")
        if "credential_access" in categories:
            add("JS_BROWSER_CREDENTIAL_ACCESS", "medium", "Browser credential/session access",
                "The script reads browser session material such as document.cookie.")
        if self.timed_out or self.statement_limit_hit or "resource_limit" in categories:
            add("JS_EMULATION_LIMIT", "info", "Emulation safety limit reached",
                "The bounded emulator reached a time, statement, variable or memory-safety budget.")
        return findings

    def run(self):
        loader = _recover_js_bat_polyglot_loader(self.source)
        if loader:
            self._emit(
                "embedded_payload_config",
                family=loader["family"],
                comment_prefix=loader["comment_prefix"],
                hidden_line_count=loader["hidden_line_count"],
            )
        try:
            self._prepared_source = self._prepare_static_deobfuscation(self.source)
        except TimeoutError:
            raise
        except Exception as exc:
            self.errors.append(f"Static deobfuscation: {type(exc).__name__}: {exc}")
            self._emit("deobfuscation_error", error=f"{type(exc).__name__}: {exc}")
            self._prepared_source = self.source
        queue = deque([(self._prepared_source, 0, "entry")])
        for unpacked in self._packer_layers:
            self._queue_dynamic_layer(unpacked, "packer:eval", 1, queue)
        for decrypted in self._encrypted_layers:
            self._queue_dynamic_layer(decrypted, "rijndael:decrypt", 1, queue)
        try:
            while queue:
                source, depth, source_name = queue.popleft()
                layer_size = len(self.source) if source_name == "entry" else len(source)
                self._emit("script_layer", source=source_name, depth=depth, size=layer_size)
                self._process_layer(source, depth, queue)
        except TimeoutError as exc:
            self.errors.append(str(exc))
            self._emit("emulation_timeout", error=str(exc))
        except Exception as exc:  # Malformed samples must not abort static analysis.
            self.errors.append(f"{type(exc).__name__}: {exc}")
            self._emit("emulation_error", error=f"{type(exc).__name__}: {exc}")

        findings = self._build_findings()
        network_requests = [
            {key: value for key, value in event.items() if key not in ("ts", "category")}
            for event in self.events if event["category"] == "network_request"
        ]
        process_attempts = [
            {key: value for key, value in event.items() if key not in ("ts", "category")}
            for event in self.events if event["category"] == "process_create"
        ]
        dropped_files = [
            {key: value for key, value in event.items() if key not in ("ts", "category")}
            for event in self.events if event["category"] == "filesystem_write"
        ]
        registry_changes = [
            {key: value for key, value in event.items() if key not in ("ts", "category")}
            for event in self.events if event["category"] == "registry_write"
        ]
        return {
            "engine": "native-abstract-js",
            "isolated": True,
            "side_effects": "in-memory-only",
            "origin": self.origin,
            "elapsed_seconds": round(time.monotonic() - self.started, 4),
            "step_count": self.step_count,
            "source_truncated": self.source_truncated,
            "statement_limit_hit": self.statement_limit_hit,
            "timed_out": self.timed_out,
            "findings": findings,
            "ioc_events": self.events,
            "network_requests": network_requests,
            "process_attempts": process_attempts,
            "dropped_files": dropped_files,
            "registry_changes": registry_changes,
            "decoded_layers": self.decoded_layers,
            "embedded_payloads": self._embedded_payloads,
            "errors": self.errors,
        }


def _bounded_timeout(timeout_seconds):
    try:
        requested = int(timeout_seconds or DEFAULT_TIMEOUT_SECONDS)
    except (TypeError, ValueError, OverflowError):
        requested = DEFAULT_TIMEOUT_SECONDS
    return max(1, min(requested, 30))


def _failure_result(origin, elapsed, error, *, timed_out=False, source_truncated=False):
    category = "emulation_timeout" if timed_out else "emulation_error"
    description = (
        "The isolated JavaScript worker reached its hard wall-clock limit."
        if timed_out else
        "The isolated JavaScript worker exited without a valid result."
    )
    return {
        "engine": "native-abstract-js",
        "isolated": True,
        "side_effects": "in-memory-only",
        "hard_timeout_enforced": True,
        "worker_memory_limit_bytes": MAX_WORKER_MEMORY_BYTES if os.name == "posix" else None,
        "origin": _safe_text(origin, 512),
        "elapsed_seconds": round(elapsed, 4),
        "step_count": 0,
        "source_truncated": source_truncated,
        "statement_limit_hit": False,
        "timed_out": timed_out,
        "findings": [{
            "rule_id": "JS_EMULATION_LIMIT",
            "severity": "info",
            "title": "Emulation safety limit reached" if timed_out else "Emulation worker error",
            "description": description,
        }],
        "ioc_events": [{"ts": round(elapsed, 6), "category": category, "error": _safe_text(error)}],
        "network_requests": [],
        "process_attempts": [],
        "dropped_files": [],
        "registry_changes": [],
        "decoded_layers": [],
        "embedded_payloads": [],
        "errors": [_safe_text(error)],
    }


def _apply_worker_limits(timeout_seconds):
    """Best-effort OS limits for the trusted Python worker on POSIX hosts."""
    if os.name != "posix":
        return
    try:
        import resource

        resource.setrlimit(
            resource.RLIMIT_AS,
            (MAX_WORKER_MEMORY_BYTES, MAX_WORKER_MEMORY_BYTES),
        )
        cpu_limit = _bounded_timeout(timeout_seconds) + 2
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
    except (ImportError, OSError, ValueError):
        pass


def _worker_main():
    timeout_seconds = _bounded_timeout(sys.argv[2] if len(sys.argv) > 2 else DEFAULT_TIMEOUT_SECONDS)
    origin = sys.argv[3] if len(sys.argv) > 3 else "script.js"
    _apply_worker_limits(timeout_seconds)
    max_input_bytes = MAX_SOURCE_CHARS * 4
    source_bytes = sys.stdin.buffer.read(max_input_bytes + 1)
    source_truncated = len(source_bytes) > max_input_bytes
    source = source_bytes[:max_input_bytes].decode("utf-8", errors="replace")
    result = JavaScriptEmulator(source, origin=origin, timeout_seconds=timeout_seconds).run()
    result["source_truncated"] = bool(result.get("source_truncated") or source_truncated)
    result["hard_timeout_enforced"] = True
    result["worker_memory_limit_bytes"] = MAX_WORKER_MEMORY_BYTES if os.name == "posix" else None
    payload = json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def emulate_javascript(source, origin="script.js", timeout_seconds=DEFAULT_TIMEOUT_SECONDS):
    """Emulate suspicious JavaScript in a resource-limited Python worker.

    Attacker-controlled source is never handed to a JavaScript runtime or a
    command shell.  The child executes this trusted abstract interpreter only;
    sample network/process/filesystem APIs remain fake in-memory models.  A
    parent-side subprocess timeout provides a hard boundary even if a parser
    helper fails to check its cooperative deadline.
    """
    timeout_seconds = _bounded_timeout(timeout_seconds)
    origin = _safe_text(origin, 512).replace("\x00", "?")
    source_text = str(source or "")
    source_truncated = len(source_text) > MAX_SOURCE_CHARS
    source_text = source_text[:MAX_SOURCE_CHARS]
    started = time.monotonic()
    command = [
        sys.executable,
        "-I",
        os.path.abspath(__file__),
        "--worker",
        str(timeout_seconds),
        origin,
    ]
    try:
        completed = subprocess.run(
            command,
            input=source_text.encode("utf-8", errors="replace"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds + WORKER_STARTUP_GRACE_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - started
        return _failure_result(
            origin,
            elapsed,
            f"JavaScript emulation hard timeout exceeded ({timeout_seconds}s)",
            timed_out=True,
            source_truncated=source_truncated,
        )
    except OSError as exc:
        return _failure_result(
            origin,
            time.monotonic() - started,
            f"Worker launch failed: {exc}",
            source_truncated=source_truncated,
        )

    elapsed = time.monotonic() - started
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace")[-2048:].strip()
        return _failure_result(
            origin,
            elapsed,
            f"Worker exited with status {completed.returncode}: {stderr or 'no diagnostic output'}",
            source_truncated=source_truncated,
        )
    try:
        result = json.loads(completed.stdout.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _failure_result(
            origin,
            elapsed,
            f"Worker returned invalid JSON: {exc}",
            source_truncated=source_truncated,
        )
    result["source_truncated"] = bool(result.get("source_truncated") or source_truncated)
    result["hard_timeout_enforced"] = True
    return result


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--worker":
    _worker_main()


__all__ = ["JavaScriptEmulator", "emulate_javascript"]
