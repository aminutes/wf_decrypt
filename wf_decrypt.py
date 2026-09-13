import os
import sys
import io
import re
import csv
import json
import zlib
import hashlib
import pickle
import struct
import time
import shutil
import base64
from collections import deque, defaultdict
from functools import partial
from concurrent.futures import ProcessPoolExecutor, as_completed

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BUNDLE_DIR = os.path.join(BASE_DIR, "bundle")
DOWNLOAD_DIR = os.path.join(BASE_DIR, "download")
INTERMEDIATE_DIR = os.path.join(BASE_DIR, "intermediate")
UNMAPPED_DIR = os.path.join(BASE_DIR, "Unmapped")
ENCRYPTED_DIR = os.path.join(BASE_DIR, "Encrypted")
CODE_PATH_TXT = os.path.join(BASE_DIR, "CodePath.txt")
ASSET_PATH_TXT = os.path.join(BASE_DIR, "AssetPath.txt")
OLD_PATH_TXT = os.path.join(BASE_DIR, "OldPath.txt")
RECORD_PKL = os.path.join(BASE_DIR, ".wf_record.pkl")

SALT = "K6R9T9Hz22OpeIGEWB0ui6c6PYFQnJGy"


MODE_DECRYPT = 0
MODE_ENCRYPT = 1

MP3_BITRATE_V1 = [0, 32000, 40000, 48000, 56000, 64000, 80000, 96000,
                  122000, 128000, 160000, 192000, 224000, 256000, 320000]
MP3_BITRATE_V2 = [0, 8000, 16000, 24000, 32000, 40000, 48000, 56000,
                  64000, 80000, 96000, 112000, 128000, 144000, 160000]
MP3_SAMPLERATE_V1 = [44100, 48000, 32000]
MP3_SAMPLERATE_V2 = [22050, 24000, 16000]
MP3_SAMPLERATE_V25 = [11025, 12000, 8000]
MP3_BITRATE_BY_VER = (MP3_BITRATE_V2, None, MP3_BITRATE_V2, MP3_BITRATE_V1)
MP3_SAMPLERATE_BY_VER = (MP3_SAMPLERATE_V25, None, MP3_SAMPLERATE_V2, MP3_SAMPLERATE_V1)

HASHED_PATH_CACHE = {}


def normalize_path(p):
    if "\\" in p:
        p = p.replace("\\", "/")
    while "//" in p:
        p = p.replace("//", "/")
    return p.lstrip("/")


def get_hashed_rel(path, cached=True):
    if not cached:
        p = normalize_path(path)
        d = hashlib.sha1((p + SALT).encode("utf-8")).hexdigest()
        return d[:2] + "/" + d[2:]
    v = HASHED_PATH_CACHE.get(path)
    if v is None:
        p = normalize_path(path)
        d = hashlib.sha1((p + SALT).encode("utf-8")).hexdigest()
        v = d[:2] + "/" + d[2:]
        HASHED_PATH_CACHE[path] = v
    return v


def read_path_list(txt_path):
    out = []
    if os.path.isfile(txt_path):
        with open(txt_path, "r", encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(normalize_path(line))
    return out


def append_unique_lines(txt_path, new_paths):
    old = []
    if os.path.isfile(txt_path):
        with open(txt_path, "r", encoding="utf-8-sig", errors="replace") as f:
            old = [x.strip() for x in f if x.strip()]
    seen = set(old)
    added = 0
    with open(txt_path, "a", encoding="utf-8", newline="\n") as f:
        for p in new_paths:
            if p not in seen:
                f.write(p + "\n")
                seen.add(p)
                added += 1
    return added


class Progress:
    def __init__(self, total, label):
        self.total = total
        self.done = 0
        self.label = label
        self.t0 = time.time()
        self.last_print = 0

    def step(self, n=1):
        self.done += n
        now = time.time()
        if now - self.last_print > 0.5 or self.done >= self.total:
            self.last_print = now
            el = max(now - self.t0, 1e-6)
            rate = self.done / el
            sys.stdout.write("\r%s %d/%d (%.0f/s, %.1fs)   "
                             % (self.label, self.done, self.total, rate, el))
            sys.stdout.flush()

    def finish(self):
        sys.stdout.write("\n")
        sys.stdout.flush()


def load_record():
    rec = {"hash_map": {}, "file_states": {}}
    if os.path.isfile(RECORD_PKL):
        try:
            with open(RECORD_PKL, "rb") as f:
                data = pickle.load(f)
            if isinstance(data, dict):
                rec.update(data)
        except Exception:
            pass
    return rec


def save_record(rec):
    tmp = RECORD_PKL + ".tmp"
    for attempt in range(5):
        try:
            with open(tmp, "wb") as f:
                pickle.dump(rec, f, protocol=pickle.HIGHEST_PROTOCOL)
            os.replace(tmp, RECORD_PKL)
            return
        except PermissionError:
            time.sleep(0.2 * (attempt + 1))
    try:
        os.remove(tmp)
    except OSError:
        pass


def build_hash_map():
    hash_map = {}
    counts = {}
    roots = [("bundle", BUNDLE_DIR), ("download", DOWNLOAD_DIR)]
    entries = []
    for root_name, root_dir in roots:
        n = 0
        if os.path.isdir(root_dir):
            for dp, dn, fn in os.walk(root_dir):
                for name in fn:
                    rel = os.path.relpath(os.path.join(dp, name), BASE_DIR).replace("\\", "/")
                    parts = rel.split("/")
                    if len(parts) < 3:
                        continue
                    entries.append((root_name, parts[-2] + "/" + parts[-1], rel))
                    n += 1
        counts[root_name] = n
    progress = Progress(len(entries), "[hash_map]")
    for root_name, key, rel in entries:
        hash_map.setdefault(key, []).append(rel)
        progress.step()
    progress.finish()
    for lst in hash_map.values():
        lst.sort(key=_source_priority)
    return hash_map, counts


def _source_priority(src_rel):
    parts = src_rel.split("/")
    root_rank = 0 if parts[0] == "bundle" else 1
    scale_rank = 1
    platform_rank = 1
    if len(parts) >= 3:
        variant = parts[2]
        if "medium" in variant:
            scale_rank = 0
        elif "small" in variant:
            scale_rank = 2
        if variant.startswith("android"):
            platform_rank = 0
        elif variant.startswith("ios"):
            platform_rank = 2
    return (root_rank, scale_rank, platform_rank)


def ensure_hash_map(rec):
    if rec.get("hash_map"):
        return False
    print("构建 hash_map（仅目录遍历，不读取内容）...")
    hash_map, counts2 = build_hash_map()
    rec["hash_map"] = hash_map
    save_record(rec)
    print("hash_map 完成：%d 个哈希键" % len(hash_map))
    return True


def pick_source(hash_map, logical_path):
    cands = hash_map.get(get_hashed_rel(logical_path))
    if not cands:
        return None
    for rel in cands:
        if os.path.isfile(os.path.join(BASE_DIR, rel)):
            return rel
    return None


def _mp3_frame_info(header):
    version = (header >> 19) & 3
    layer = (header >> 17) & 3
    bitrate_index = (header >> 12) & 0x0F
    samplerate_index = (header >> 10) & 3
    padding = (header >> 9) & 1
    if version == 1:
        raise ValueError("version is set to reserve value")
    if layer == 0:
        raise ValueError("layer is set to reserve value")
    if layer != 1:
        raise ValueError("this project is MPEG layer 3 only")
    if bitrate_index == 15:
        raise ValueError("bitrate index is set to reserve value")
    if bitrate_index == 0:
        raise ValueError("this project is CBR only")
    if samplerate_index == 3:
        raise ValueError("samplingrate index is set to reserve value")
    return version, bitrate_index, samplerate_index, padding


def _mp3_unsynchsafe(v):
    r = 0
    mask = 2130706432
    while mask != 0:
        r >>= 1
        r |= v & mask
        mask >>= 8
    return r


def mp3_format(data, cur_first_byte, new_first_byte):
    buf = bytearray(data)
    pos = 0
    n = len(buf)
    while pos < n:
        b = buf[pos]
        if b == 73:
            if buf[pos + 1:pos + 3] != b"D3":
                raise ValueError("this file isnt MP3 file or is corrupted")
            if pos + 10 > n:
                break
            v = (buf[pos + 6] << 24) | (buf[pos + 7] << 16) | (buf[pos + 8] << 8) | buf[pos + 9]
            pos += _mp3_unsynchsafe(v) + 10
            continue
        if b == 84:
            if buf[pos + 1:pos + 3] != b"AG":
                raise ValueError("this file isnt MP3 file or is corrupted")
            pos += 128
            continue
        if b != cur_first_byte:
            raise ValueError("this file isnt an MP3 file or is corrupted")
        if pos + 4 > n:
            break
        if (buf[pos + 1] >> 5) & 7 != cur_first_byte & 7:
            raise ValueError("this file isnt MP3 file or is corrupted")
        header = (buf[pos] << 24) | (buf[pos + 1] << 16) | (buf[pos + 2] << 8) | buf[pos + 3]
        version, br_idx, sr_idx, padding = _mp3_frame_info(header)
        buf[pos] = new_first_byte & 0xFF
        bitrate = MP3_BITRATE_BY_VER[version][br_idx]
        samplerate = MP3_SAMPLERATE_BY_VER[version][sr_idx]
        frame_size = int(144 * bitrate / samplerate + padding + 1e-10 + 1e-10)
        if frame_size <= 0:
            raise ValueError("invalid frame size")
        pos += frame_size
    return buf


def mp3_decode(data):
    return mp3_format(data, 0x7F, 0xFF)


def mp3_encode(data):
    return mp3_format(data, 0xFF, 0x7F)


def raw_inflate(data):
    return zlib.decompressobj(-15).decompress(data)


def raw_deflate(data):
    co = zlib.compressobj(6, zlib.DEFLATED, -15)
    return co.compress(data) + co.flush()


class AMF3Error(Exception):
    pass


_AMF_UNDEF, _AMF_NULL, _AMF_FALSE, _AMF_TRUE = 0x00, 0x01, 0x02, 0x03
_AMF_INT, _AMF_DOUBLE, _AMF_STRING, _AMF_DATE = 0x04, 0x05, 0x06, 0x08
_AMF_ARRAY, _AMF_OBJECT = 0x09, 0x0A
_AMF_XML, _AMF_BYTES = 0x0B, 0x0C
_AMF_VINT, _AMF_VUINT, _AMF_VDOUBLE, _AMF_VOBJ, _AMF_DICT = 0x0D, 0x0E, 0x0F, 0x10, 0x11


class AMF3Reader:
    __slots__ = ("d", "i", "obj_refs", "str_refs", "trait_refs")

    def __init__(self, data):
        self.d = data
        self.i = 0
        self.obj_refs = []
        self.str_refs = []
        self.trait_refs = []

    def _u29(self):
        d, i = self.d, self.i
        b = d[i]
        i += 1
        if b < 0x80:
            self.i = i
            return b
        r = (b & 0x7F) << 7
        b = d[i]
        i += 1
        if b < 0x80:
            self.i = i
            return r | b
        r = (r | (b & 0x7F)) << 7
        b = d[i]
        i += 1
        if b < 0x80:
            self.i = i
            return r | b
        r = (r | (b & 0x7F)) << 8
        b = d[i]
        i += 1
        self.i = i
        return r | b

    def _read_string(self):
        v = self._u29()
        if v & 1 == 0:
            idx = v >> 1
            if idx >= len(self.str_refs):
                raise AMF3Error("bad string ref")
            return self.str_refs[idx]
        ln = v >> 1
        s = self.d[self.i:self.i + ln]
        self.i += ln
        sv = s.decode("utf-8", "replace")
        if ln != 0:
            self.str_refs.append(sv)
        return sv

    def read_value(self):
        t = self.d[self.i]
        self.i += 1
        if t == _AMF_UNDEF or t == _AMF_NULL:
            return None
        if t == _AMF_FALSE:
            return False
        if t == _AMF_TRUE:
            return True
        if t == _AMF_INT:
            v = self._u29()
            if v & 0x10000000:
                v -= 0x20000000
            return v
        if t == _AMF_DOUBLE:
            v = struct.unpack_from(">d", self.d, self.i)[0]
            self.i += 8
            return v
        if t == _AMF_STRING:
            return self._read_string()
        if t == _AMF_DATE:
            v = self._u29()
            if v & 1:
                ms = struct.unpack_from(">d", self.d, self.i)[0]
                self.i += 8
                self.obj_refs.append(ms)
                return {"__date_ms__": ms}
            return self.obj_refs[v >> 1]
        if t == _AMF_ARRAY:
            return self._read_array()
        if t == _AMF_OBJECT:
            return self._read_object()
        if t in (_AMF_XML, _AMF_XML + 1, _AMF_BYTES):
            return self._read_bytes_like()
        if t in (_AMF_VINT, _AMF_VUINT):
            return self._read_vector("i" if t == _AMF_VINT else "I", 4)
        if t == _AMF_VDOUBLE:
            return self._read_vector("d", 8)
        if t == _AMF_VOBJ:
            return self._read_vector_object()
        if t == _AMF_DICT:
            return self._read_dictionary()
        raise AMF3Error("unknown marker 0x%02x @%d" % (t, self.i - 1))

    def _read_bytes_like(self):
        v = self._u29()
        if v & 1 == 0:
            return self.obj_refs[v >> 1]
        ln = v >> 1
        b = bytes(self.d[self.i:self.i + ln])
        self.i += ln
        wrapped = {"__bytes_b64__": base64.b64encode(b).decode("ascii")}
        self.obj_refs.append(wrapped)
        return wrapped

    def _read_array(self):
        v = self._u29()
        if v & 1 == 0:
            return self.obj_refs[v >> 1]
        dense = v >> 1
        arr = []
        self.obj_refs.append(arr)
        while True:
            key = self._read_string()
            if key == "":
                break
            arr.append([key, self.read_value()])
        assoc = {}
        for kv in arr:
            assoc[kv[0]] = kv[1]
        for _ in range(dense):
            arr.append(self.read_value())
        if assoc:
            arr.insert(0, {"__assoc__": assoc})
        return arr

    def _read_object(self):
        v = self._u29()
        if v & 1 == 0:
            return self.obj_refs[v >> 1]
        if v & 2 == 0:
            traits = self.trait_refs[v >> 2]
        else:
            ext = bool(v & 4)
            dyn = bool(v & 8)
            count = v >> 4
            cls = self._read_string()
            members = [self._read_string() for _ in range(count)]
            traits = (cls, members, dyn, ext)
            self.trait_refs.append(traits)
        cls, members, dyn, ext = traits
        obj = {}
        self.obj_refs.append(obj)
        if cls:
            obj["__class__"] = cls
        if ext:
            raw = self._read_bytes_like()
            obj["__externalizable_b64__"] = raw.get("__bytes_b64__", "")
            return obj
        for m in members:
            obj[m] = self.read_value()
        if dyn:
            while True:
                key = self._read_string()
                if key == "":
                    break
                obj[key] = self.read_value()
        return obj

    def _read_vector(self, fmtc, size):
        v = self._u29()
        if v & 1 == 0:
            return self.obj_refs[v >> 1]
        count = v >> 1
        self.i += 1
        out = list(struct.unpack_from("<%d%s" % (count, fmtc), self.d, self.i))
        self.i += count * size
        self.obj_refs.append(out)
        return out

    def _read_vector_object(self):
        v = self._u29()
        if v & 1 == 0:
            return self.obj_refs[v >> 1]
        count = v >> 1
        self.i += 1
        out = []
        self.obj_refs.append(out)
        for _ in range(count):
            out.append(self.read_value())
        return out

    def _read_dictionary(self):
        v = self._u29()
        if v & 1 == 0:
            return self.obj_refs[v >> 1]
        count = v >> 1
        self.i += 1
        entries = []
        self.obj_refs.append(entries)
        for _ in range(count):
            k = self.read_value()
            val = self.read_value()
            entries.append([k, val])
        return {"__dict__": entries}


def amf3_decode(data):
    return AMF3Reader(data).read_value()


def _w_u29(out, v):
    if v < 0x80:
        out.append(v)
    elif v < 0x4000:
        out.append((v >> 7) | 0x80)
        out.append(v & 0x7F)
    elif v < 0x200000:
        out.append((v >> 14) | 0x80)
        out.append(((v >> 7) & 0x7F) | 0x80)
        out.append(v & 0x7F)
    elif v < 0x40000000:
        out.append((v >> 22) | 0x80)
        out.append(((v >> 15) & 0x7F) | 0x80)
        out.append(((v >> 8) & 0x7F) | 0x80)
        out.append(v & 0xFF)
    else:
        raise AMF3Error("u29 overflow")


def _w_string(out, s):
    b = s.encode("utf-8")
    _w_u29(out, (len(b) << 1) | 1)
    out.extend(b)


def amf3_encode(value):
    out = bytearray()

    def wr(v):
        if v is None:
            out.append(_AMF_NULL)
        elif v is True:
            out.append(_AMF_TRUE)
        elif v is False:
            out.append(_AMF_FALSE)
        elif isinstance(v, int) and -0x10000000 <= v < 0x10000000:
            out.append(_AMF_INT)
            _w_u29(out, v & 0x1FFFFFFF)
        elif isinstance(v, (int, float)):
            out.append(_AMF_DOUBLE)
            out.extend(struct.pack(">d", float(v)))
        elif isinstance(v, str):
            out.append(_AMF_STRING)
            _w_string(out, v)
        elif isinstance(v, list):
            items = v
            assoc = None
            if items and isinstance(items[0], dict) and "__assoc__" in items[0]:
                assoc = items[0]["__assoc__"]
                items = items[1:]
            out.append(_AMF_ARRAY)
            _w_u29(out, (len(items) << 1) | 1)
            if assoc:
                for k, val in assoc.items():
                    _w_string(out, k)
                    wr(val)
            _w_string(out, "")
            for it in items:
                wr(it)
        elif isinstance(v, dict):
            if "__bytes_b64__" in v:
                out.append(_AMF_BYTES)
                b = base64.b64decode(v["__bytes_b64__"])
                _w_u29(out, (len(b) << 1) | 1)
                out.extend(b)
                return
            if "__date_ms__" in v:
                out.append(_AMF_DATE)
                _w_u29(out, 1)
                out.extend(struct.pack(">d", float(v["__date_ms__"])))
                return
            out.append(_AMF_OBJECT)
            _w_u29(out, 0x0B)
            _w_string(out, "")
            for k, val in v.items():
                if k == "__class__":
                    continue
                _w_string(out, str(k))
                wr(val)
            _w_string(out, "")
        elif isinstance(v, (bytes, bytearray)):
            out.append(_AMF_BYTES)
            _w_u29(out, (len(v) << 1) | 1)
            out.extend(v)
        else:
            raise AMF3Error("cannot encode %r" % type(v))

    wr(value)
    return bytes(out)


class OMError(Exception):
    pass


def _om_parse_index(blob):
    if len(blob) < 4:
        raise OMError("index too short")
    count = struct.unpack_from("<i", blob, 0)[0]
    if count < 0 or 4 + count * 8 > len(blob):
        raise OMError("bad index count")
    key_ends, val_ends = [], []
    p = 4
    for _ in range(count):
        a, b = struct.unpack_from("<ii", blob, p)
        p += 8
        key_ends.append(a)
        val_ends.append(b)
    keys = []
    prev = 0
    base = 4 + count * 8
    for e in key_ends:
        if e < prev or base + e > len(blob):
            raise OMError("bad key offsets")
        keys.append(blob[base + prev:base + e].decode("utf-8"))
        prev = e
    return keys, val_ends


def _om_doc_slices(slice_bytes):
    mv = memoryview(slice_bytes)
    out = []
    pos = 0
    n = len(mv)
    while pos < n:
        if pos + 5 > n:
            raise OMError("doc header truncated @%d" % pos)
        clen = struct.unpack_from("<i", mv, pos)[0]
        if clen <= 0 or pos + 4 + clen > n:
            raise OMError("doc header mismatch @%d" % pos)
        try:
            idx = zlib.decompress(mv[pos + 4:pos + 4 + clen])
        except zlib.error as e:
            raise OMError("index zlib fail @%d: %s" % (pos, e))
        keys, val_ends = _om_parse_index(idx)
        start = pos + 4 + clen
        rows = mv[start:]
        if not val_ends:
            pos = start
            continue
        if val_ends[-1] > len(rows):
            raise OMError("inner size mismatch")
        prev = 0
        for name, end in zip(keys, val_ends):
            out.append((name, rows[prev:end]))
            prev = end
        pos = start + val_ends[-1]
    return out


def _om_leaf_rows(slice_bytes):
    do = zlib.decompressobj()
    try:
        out = do.decompress(slice_bytes) + do.flush()
    except Exception:
        raise OMError("leaf not zlib")
    if not do.eof or do.unused_data:
        raise OMError("leaf not a single zlib stream")
    try:
        txt = out.decode("utf-8")
    except Exception:
        raise OMError("leaf not utf8 csv")
    if "\x00" in txt[:64]:
        raise OMError("leaf not csv text")
    return list(csv.reader(io.StringIO(txt)))


def om_parse(data, chain):
    if not chain:
        raise OMError("no route")
    layers, term = chain.split(":")
    cur = [((), data)]
    for _ in layers:
        nxt = []
        for path, s in cur:
            for k, sub in _om_doc_slices(s):
                nxt.append((path + (k,), sub))
        cur = nxt
    records = []
    for path, s in cur:
        rows = _om_leaf_rows(s)
        key = path[0] if path else ""
        sub = "/".join(path[1:]) if len(path) > 1 else None
        for r in rows:
            records.append({"key": key, "sub_key": sub, "cells": r})
    return records


def om_parse_generic(data, max_depth=4):
    last = None
    for d in range(max_depth + 1):
        try:
            return om_parse(data, "S" * d + ":R")
        except Exception as e:
            last = e
    raise last


def om_build(records_by_key, n_layers):
    if n_layers <= 0:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\r\n")
        for _key, subs in records_by_key.items():
            for _sk, rows in subs.items():
                for row in rows:
                    w.writerow(row)
        return zlib.compress(buf.getvalue().encode("utf-8"), 9)

    def build(recs, d):
        groups = {}
        for parts, rows in recs:
            groups.setdefault(parts[d], []).append((parts, rows))
        idx_items = []
        regions = []
        for key in groups:
            items = groups[key]
            if d == n_layers - 1:
                buf = io.StringIO()
                w = csv.writer(buf, lineterminator="\r\n")
                for _p, rows in items:
                    for row in rows:
                        w.writerow(row)
                region = zlib.compress(buf.getvalue().encode("utf-8"), 9)
            else:
                region = build(items, d + 1)
            kb = str(key).encode("utf-8")
            idx_items.append((kb, len(region)))
            regions.append(region)
        ib = io.BytesIO()
        ib.write(struct.pack("<i", len(idx_items)))
        kend = 0
        vend = 0
        for kb, cl in idx_items:
            kend += len(kb)
            vend += cl
            ib.write(struct.pack("<ii", kend, vend))
        for kb, _cl in idx_items:
            ib.write(kb)
        comp = zlib.compress(ib.getvalue(), 9)
        return struct.pack("<i", len(comp)) + comp + b"".join(regions)

    flat = []
    for key, subs in records_by_key.items():
        for sk, rows in subs.items():
            parts = [key]
            if n_layers > 1:
                parts.extend(str(sk).split("/") if sk is not None else [])
            while len(parts) < n_layers:
                parts.append("")
            flat.append((parts[:n_layers], rows))
    return build(flat, 0)


_SCHEMA_JSON_CACHE = {}


def _schema_json(logical_name):
    base = logical_name
    if base.endswith(".orderedmap"):
        base = base[:-len(".orderedmap")]
    if base.startswith("master/"):
        base = base[len("master/"):]
    cands = [base]
    m = re.search(r"_(?:iosbundled|bundled)$", base)
    if m:
        cands.append(base[: m.start()])
    for cand in cands:
        if cand not in _SCHEMA_JSON_CACHE:
            obj = None
            js = os.path.join(
                INTERMEDIATE_DIR,
                ("master_schema/%s_schema.json" % cand).replace("/", os.sep))
            if os.path.isfile(js):
                try:
                    with open(js, "r", encoding="utf-8-sig") as f:
                        loaded = json.load(f)
                    if isinstance(loaded, dict):
                        obj = loaded
                except (OSError, ValueError):
                    obj = None
            _SCHEMA_JSON_CACHE[cand] = obj
        obj = _SCHEMA_JSON_CACHE[cand]
        if obj is not None:
            return obj
    return None


def schema_for(logical_name):
    obj = _schema_json(logical_name)
    if not obj:
        return None
    return [e.get("columnName") for e in obj.get("valueSchema", [])
            if isinstance(e, dict)]


def _key_names_for(logical_name):
    obj = _schema_json(logical_name)
    if not obj:
        return None
    ks = obj.get("keySchema")
    names = [e.get("columnName") for e in ks if isinstance(e, dict)] \
        if isinstance(ks, list) else None
    return names or None


_VALUES_SCENARIO = [
    "command",
    "movie_sequence_section",
    "movie_sequence_wait",
    "movie_sequence_skip_enable",
    "text_character_id",
    "text_body",
    "text_voice_path",
    "text_voice_immediately",
    "text_balloon_position",
    "character_active_id",
    "character_active_only_id",
    "character_inactive_id",
    "character_in_id",
    "character_in_position",
    "character_in_face",
    "character_in_reverse",
    "character_out_id",
    "character_out_kind",
    "character_out_all_kind",
    "character_face_id",
    "character_face_face",
    "character_animation_id",
    "character_animation_kind",
    "screen_fade_in_color",
    "screen_fade_in_time",
    "screen_fade_out_color",
    "screen_fade_out_time",
    "screen_shake_time",
    "screen_shake_size",
    "screen_color_effect_preset",
    "screen_color_effect_time",
    "screen_color_effect_custom_matrix",
    "screen_color_effect_custom_time",
    "screen_color_effect_disable_time",
    "background_path",
    "bgm_channel",
    "bgm_id",
    "bgm_stop_channel",
    "bgm_fade_in_channel",
    "bgm_fade_in_id",
    "bgm_fade_in_time",
    "bgm_fade_out_channel",
    "bgm_fade_out_time",
]
_VALUES_GACHA_ODDS = [
    "character_id",
    "rarity",
    "weight",
    "odds_up",
    "is_limited",
    "is_exchangeable",
    "to_use_as_trial_reading_forced",
]
_VALUES_EX_BOOST_ODDS = ["weight"] + [
    name
    for i in range(1, 11)
    for name in ("lot_kind%d_kind" % i, "lot_kind%d_value" % i)
]


def _values_header_for(logical_name, ncols=None):
    base = logical_name
    if base.endswith(".orderedmap"):
        base = base[:-len(".orderedmap")]
    if base.startswith("master/"):
        base = base[len("master/"):]
    base = re.sub(r"_(?:iosbundled|bundled)$", "", base)
    if base.startswith("story/") and base.endswith("/scenario"):
        names = _VALUES_SCENARIO
    elif base.startswith("gacha_odds/"):
        names = _VALUES_GACHA_ODDS
    elif base.startswith("ex_boost/odds/"):
        names = _VALUES_EX_BOOST_ODDS
    else:
        return None
    if ncols is None:
        return list(names)
    if len(names) < ncols:
        print("警告：%s Values 列名 %d 个 < 数据 %d 列，表头回退 cN"
              % (logical_name, len(names), ncols))
        return None
    return list(names[:ncols])


MASTER_CHAINS_B64 = "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"
CHAIN_BY_CLASS = {}
CHAIN_BY_PATH = {}
CHAIN_FAMILIES = []
try:
    _cj = json.loads(zlib.decompress(base64.b64decode(MASTER_CHAINS_B64)).decode("utf-8"))
    CHAIN_BY_CLASS.update(_cj["class_chains"])
    CHAIN_BY_PATH.update(_cj["path_chain"])
    CHAIN_FAMILIES.extend(sorted(_cj["family"].items(), key=lambda kv: -len(kv[0])))
    del _cj
except Exception as _e:
    print("警告：内置 master 路由表加载失败：%s" % _e)

for _i, (_pref, _clss) in enumerate(CHAIN_FAMILIES):
    if _pref == "master/ex_boost/odds/lots_combination/":
        CHAIN_FAMILIES[_i] = ("master/ex_boost/odds/", _clss)
        break


def chain_for(logical_name):
    base = logical_name
    for suf in (".orderedmap", ".csv"):
        if base.endswith(suf):
            base = base[:-len(suf)]
            break
    ch = CHAIN_BY_PATH.get(base)
    if ch:
        return [ch]
    if base.startswith("master/story/") and base.endswith("/scenario"):
        ch = CHAIN_BY_CLASS.get("ScenarioCommandTable")
        if ch:
            return [ch]
    for pref, clss in CHAIN_FAMILIES:
        if base.startswith(pref):
            return [CHAIN_BY_CLASS[c] for c in clss]
    return []


def classify_logical(path):
    if path.endswith(".amf3.deflate"):
        return "data_deflate"
    if path.endswith(".orderedmap"):
        return "orderedmap"
    if path.endswith(".amf3"):
        return "amf3"
    if path.endswith(".png"):
        return "png"
    if path.endswith(".mp3"):
        return "mp3"
    if path.endswith(".deflate"):
        return "text_deflate"
    return "plain"


def menu2_name(path):
    if classify_logical(path) in ("data_deflate", "text_deflate"):
        return path[:-len(".deflate")]
    return path


def menu3_name(path):
    kind = classify_logical(path)
    if kind == "data_deflate":
        return path[:-len(".amf3.deflate")] + ".json"
    if kind == "amf3":
        return path[:-len(".amf3")] + ".json"
    if kind == "orderedmap":
        return path[:-len(".orderedmap")] + ".csv"
    return menu2_name(path)


def safe_write(dst_abs, data):
    os.makedirs(os.path.dirname(dst_abs), exist_ok=True)
    tmp = dst_abs + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, dst_abs)


def _id3_synchsafe(n):
    return bytes(((n >> 21) & 0x7F, (n >> 14) & 0x7F, (n >> 7) & 0x7F, n & 0x7F))


def _id3_decode_raw(raw):
    try:
        return raw.decode("cp932")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _id3_tit2_utf16(text):
    return b"\x01\xff\xfe" + text.encode("utf-16-le") + b"\x00\x00"


def id3_fix_bytes(data):
    sz = len(data)
    has_v2 = sz >= 10 and data[:3] == b"ID3" and data[3] == 3 and not data[5] & 0x40
    tsize = 0
    if has_v2:
        tsize = _mp3_unsynchsafe(int.from_bytes(data[6:10], "big"))
        if tsize <= 0 or 10 + tsize > sz:
            has_v2 = False
    frames = []
    tit2 = None
    had_tool = False
    if has_v2:
        pos, end = 10, 10 + tsize
        while pos + 10 <= end:
            fid = data[pos:pos + 4]
            if not (0x41 <= fid[0] <= 0x5A):
                break
            fsz = int.from_bytes(data[pos + 4:pos + 8], "big")
            if fsz <= 0 or pos + 10 + fsz > end:
                return None
            body = data[pos + 10:pos + 10 + fsz]
            pos += 10 + fsz
            if fid in (b"TENC", b"TSSE", b"COMM"):
                had_tool = True
                continue
            if fid == b"TIT2" and body:
                tit2 = (body[0], body[1:])
            frames.append((fid, body))
    audio_end = sz
    has_v1 = False
    v1_title = None
    if sz >= 128 and data[sz - 128:sz - 125] == b"TAG":
        has_v1 = True
        audio_end = sz - 128
        v1_title = data[sz - 125:sz - 95].rstrip(b"\x00 ")
    changed = False
    if tit2 is not None:
        enc, raw = tit2
        if enc != 1:
            new_tit2 = _id3_tit2_utf16(_id3_decode_raw(raw.rstrip(b"\x00")))
            frames = [(b"TIT2", new_tit2) if f == b"TIT2" else (f, b)
                      for f, b in frames]
            changed = True
    elif has_v1 and v1_title:
        frames.insert(0, (b"TIT2", _id3_tit2_utf16(_id3_decode_raw(v1_title))))
        changed = True
    if has_v1:
        changed = True
    audio = data[10 + tsize:audio_end] if has_v2 else data[:audio_end]
    if not frames:
        return audio if has_v2 or has_v1 else None
    frames_bin = b"".join(fid + len(fb).to_bytes(4, "big") + b"\x00\x00" + fb
                          for fid, fb in frames)
    if (not changed and not had_tool
            and has_v2 and len(frames_bin) <= tsize):
        return None
    if has_v2 and len(frames_bin) <= tsize:
        tag_total = 10 + tsize
    else:
        tag_total = 10 + len(frames_bin)
        if sz % 2048 == 0:
            total = -(-tag_total // 2048) * 2048
            tag_total = total - len(audio)
    new_data = (b"ID3\x03\x00\x00" + _id3_synchsafe(tag_total - 10)
                + frames_bin + b"\x00" * (tag_total - 10 - len(frames_bin))
                + audio)
    return new_data


def _resolve_dst(dst_rel):
    if os.path.isabs(dst_rel):
        return dst_rel
    return os.path.join(BASE_DIR, dst_rel.replace("/", os.sep))


def task_menu2(args):
    src_rel, dst_rel, kind = args
    src = _resolve_dst(src_rel)
    dst = _resolve_dst(dst_rel)
    if kind == "png":
        if dst_rel == src_rel:
            with open(src, "r+b") as f:
                f.write(b"\x89PNG")
        else:
            with open(src, "rb") as f:
                data = f.read()
            safe_write(dst, b"\x89PNG" + data[4:])
        return dst_rel
    with open(src, "rb") as f:
        data = f.read()
    if kind == "inflate":
        out = raw_inflate(data)
    elif kind == "mp3":
        out = mp3_decode(data)
        fixed = id3_fix_bytes(out)
        if fixed is not None:
            out = fixed
    else:
        out = data
    if dst_rel != src_rel:
        safe_write(dst, out)
        if kind == "inflate" and src_rel.startswith("intermediate/"):
            try:
                os.remove(src)
            except OSError:
                pass
    else:
        with open(src, "r+b") as f:
            f.write(out)
            f.truncate(len(out))
    return dst_rel


def task_menu6(args):
    src_rel, hname = args
    src = _resolve_dst(src_rel)
    with open(src, "rb") as f:
        data = f.read()
    kind, task_kind, ext = classify_content(data)
    folder = kind.split("_")[0]
    dst_abs = os.path.join(UNMAPPED_DIR, folder, hname + ext)
    if task_kind == "png":
        out = b"\x89PNG" + data[4:]
    elif task_kind == "mp3":
        out = mp3_decode(data)
        fixed = id3_fix_bytes(out)
        if fixed is not None:
            out = fixed
    elif task_kind == "inflate":
        out = raw_inflate(data)
    elif task_kind == "amf3_json":
        obj = amf3_decode(data)
        out = json.dumps(obj, ensure_ascii=False, indent=1, default=str).encode("utf-8")
    elif task_kind == "inflate_amf3":
        obj = amf3_decode(raw_inflate(data))
        out = json.dumps(obj, ensure_ascii=False, indent=1, default=str).encode("utf-8")
    elif task_kind == "om_csv":
        records = om_parse_generic(data)
        ncols = 0
        parsed = []
        has_sub = False
        for r in records:
            parsed.append((r["key"], r["sub_key"], r["cells"]))
            if r["sub_key"] is not None:
                has_sub = True
            if len(r["cells"]) > ncols:
                ncols = len(r["cells"])
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow((["key", "sub_key"] if has_sub else ["key"]) +
                   ["c%d" % i for i in range(ncols)])
        for key, sub, cells in parsed:
            w.writerow(([key, sub if sub is not None else ""] if has_sub else [key]) +
                       list(cells) + [""] * (ncols - len(cells)))
        out = buf.getvalue().encode("utf-8")
    else:
        out = data
    safe_write(dst_abs, out)
    return folder


def task_amf3_to_json(args):
    src_rel, dst_rel = args
    src = os.path.join(BASE_DIR, src_rel.replace("/", os.sep))
    dst = os.path.join(BASE_DIR, dst_rel.replace("/", os.sep))
    with open(src, "rb") as f:
        obj = amf3_decode(f.read())
    txt = json.dumps(obj, ensure_ascii=False, indent=1, default=str)
    safe_write(dst, txt.encode("utf-8"))
    return src_rel


def task_om_to_csv(args):
    src_rel, dst_rel = args
    src = os.path.join(BASE_DIR, src_rel.replace("/", os.sep))
    dst = os.path.join(BASE_DIR, dst_rel.replace("/", os.sep))
    logical_name = src_rel[len("intermediate/"):] if src_rel.startswith("intermediate/") else src_rel
    cands = chain_for(logical_name)
    if not cands:
        raise OMError("无路由链: %s" % logical_name)
    with open(src, "rb") as f:
        data = f.read()
    last_err = None
    records = None
    for ch in cands:
        try:
            records = om_parse(data, ch)
            break
        except OMError as e:
            last_err = e
    if records is None:
        raise OMError("%s: %s" % (logical_name, last_err))
    schema = schema_for(logical_name)
    ncols = 0
    parsed = []
    for r in records:
        flat = r["cells"]
        parsed.append((r["key"], r["sub_key"], flat))
        if len(flat) > ncols:
            ncols = len(flat)
    has_sub = any(s is not None for _, s, _ in parsed)
    key_names = _key_names_for(logical_name)
    k1 = key_names[0] if key_names else "key"
    k2 = "/".join(key_names[1:]) if key_names and len(key_names) > 1 else "sub_key"
    if not parsed:
        pass
    elif schema and len(schema) != ncols:
        print("警告：%s schema %d 列 != 数据 %d 列，表头回退 cN"
              % (logical_name, len(schema), ncols))
        schema = None
    values_header = None
    if schema is None:
        values_header = _values_header_for(
            logical_name, None if not parsed else ncols)
    if schema:
        header = ([k1, k2] if has_sub else [k1]) + schema
    elif values_header:
        header = ([k1, k2] if has_sub else [k1]) + values_header
    else:
        header = ([k1, k2] if has_sub else [k1]) + \
                 ["c%d" % i for i in range(ncols)]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(header)
    for key, sub, cells in parsed:
        pad = cells + [""] * (ncols - len(cells))
        w.writerow(([key, sub if sub is not None else ""] if has_sub else [key]) + pad)
    safe_write(dst, buf.getvalue().encode("utf-8-sig"))
    return src_rel


def task_json_to_amf3(args):
    src_rel, dst_rel = args
    src = os.path.join(BASE_DIR, src_rel.replace("/", os.sep))
    dst = os.path.join(BASE_DIR, dst_rel.replace("/", os.sep))
    with open(src, "r", encoding="utf-8") as f:
        obj = json.load(f)
    safe_write(dst, amf3_encode(obj))
    return src_rel


def task_csv_to_om(args):
    src_rel, dst_rel = args
    src = os.path.join(BASE_DIR, src_rel.replace("/", os.sep))
    dst = os.path.join(BASE_DIR, dst_rel.replace("/", os.sep))
    logical_name = src_rel[len("intermediate/"):] if src_rel.startswith("intermediate/") else src_rel
    cands = chain_for(logical_name)
    if not cands:
        raise OMError("无路由链: %s" % logical_name)
    n_layers = len(cands[0].split(":")[0])
    with open(src, "r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.reader(f))
    if not rows:
        raise ValueError("empty csv")
    header = rows[0]
    body = rows[1:]
    kn = _key_names_for(logical_name)
    if kn:
        n_keys = 1 + (1 if len(kn) > 1 else 0)
    else:
        n_keys = 2 if (len(header) > 1 and header[1] == "sub_key") else 1
    has_sub = n_keys > 1 and n_layers > 1
    ki = 0
    si = 1 if has_sub else -1
    grouped = {}
    for r in body:
        key = r[ki]
        sub = r[si] if si >= 0 else None
        cells = r[n_keys:]
        grouped.setdefault(key, {}).setdefault(sub, []).append(cells)
    safe_write(dst, om_build(grouped, n_layers))
    return src_rel


def chunkify(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _batch_run(fn, items):
    out = []
    for t in items:
        try:
            out.append(fn(t))
        except Exception as e:
            tid = t[0] if isinstance(t, (list, tuple)) and t else t
            print("\n错误：%s %s" % (tid, e))
    return out


def make_batch(fn):
    return partial(_batch_run, fn)


def run_parallel(tasks, fn, label, chunk=48, results=None):
    total = len(tasks)
    if total == 0:
        print("%s：无任务" % label)
        return set()
    prog = Progress(total, label)
    ok = set()
    workers = min(os.cpu_count() or 4, 32)
    batches = list(chunkify(tasks, max(1, min(chunk, max(1, total // max(1, workers) // 4)))))
    with ProcessPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(fn, b) for b in batches]
        size_of = dict(zip(futs, (len(b) for b in batches)))
        for fut in as_completed(futs):
            try:
                r = fut.result()
                if isinstance(r, (list, tuple, set)):
                    ok.update(r)
                    if results is not None:
                        results.extend(r)
                elif r is not None:
                    ok.add(r)
                    if results is not None:
                        results.append(r)
            except Exception as e:
                print("\n错误：%s" % e)
            prog.step(size_of[fut])
    prog.finish()
    return ok


def iter_intermediate():
    out = []
    if not os.path.isdir(INTERMEDIATE_DIR):
        return out
    for dp, dn, fn in os.walk(INTERMEDIATE_DIR):
        for name in fn:
            if name.endswith(".tmp"):
                continue
            rel = os.path.relpath(os.path.join(dp, name), INTERMEDIATE_DIR)
            out.append(normalize_path(rel))
    return out


def menu1(rec):
    ensure_hash_map(rec)
    paths = []
    seen = set()
    for p in read_path_list(CODE_PATH_TXT) + read_path_list(ASSET_PATH_TXT):
        if p not in seen:
            seen.add(p)
            paths.append(p)
    todo = []
    states = rec["file_states"]
    for p in paths:
        if states.get(p, 0) >= 1:
            continue
        todo.append(p)
    prog = Progress(len(todo), "[菜单1 还原]")
    restored = missing = 0

    def copy_one(p):
        src_rel = pick_source(rec["hash_map"], p)
        if src_rel is None:
            return None
        dst_abs = os.path.join(INTERMEDIATE_DIR, p.replace("/", os.sep))
        src_abs = os.path.join(BASE_DIR, src_rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(dst_abs), exist_ok=True)
        shutil.copyfile(src_abs, dst_abs)
        return p

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(32, (os.cpu_count() or 4) * 4)) as tex:
        for res in tex.map(copy_one, todo):
            if res is None:
                missing += 1
            else:
                states[res] = max(states.get(res, 0), 1)
                restored += 1
            prog.step()
    prog.finish()
    save_record(rec)
    print("还原 %d，缺失 %d，跳过(已完成) %d" % (restored, missing, len(paths) - len(todo)))


def menu2(rec):
    states = rec["file_states"]
    tasks = []
    for rel in iter_intermediate():
        logical = rel
        if logical not in states and logical.endswith(".deflate"):
            cand = logical[:-len(".deflate")]
            if cand in states:
                logical = cand
        st = states.get(logical, 0)
        if st >= 2:
            continue
        kind = classify_logical(rel)
        src_rel = "intermediate/" + rel
        if kind in ("data_deflate", "text_deflate"):
            tasks.append((src_rel, "intermediate/" + menu2_name(rel), "inflate"))
        elif kind == "png":
            tasks.append((src_rel, src_rel, "png"))
        elif kind == "mp3":
            tasks.append((src_rel, src_rel, "mp3"))
        else:
            states[logical] = max(st, 2)
            continue
    ok = run_parallel(tasks, make_batch(task_menu2), "[菜单2 解密至游戏格式]")
    for t in tasks:
        if t[1] not in ok:
            continue
        name = t[1][len("intermediate/"):]
        logical = name
        if logical not in states and logical.endswith(".amf3"):
            cand = logical + ".deflate"
            if cand in states:
                logical = cand
        states[logical] = max(states.get(logical, 0), 2)
        if classify_logical(logical) in ("png", "mp3", "text_deflate", "plain"):
            states[logical] = 3
        src_logical = t[0][len("intermediate/"):]
        if src_logical.endswith(".deflate") and src_logical != logical:
            states[src_logical] = max(states.get(src_logical, 0), 3)
    save_record(rec)
    print("处理 %d 个文件" % len(tasks))


def _physical_to_logical(rel, states):
    if rel in states:
        return rel
    if rel.endswith(".amf3"):
        cand = rel + ".deflate"
        if cand in states:
            return cand
        cand = rel[:-len(".amf3")] + ".orderedmap"
        if cand in states:
            return cand
    return rel if rel in states else None


def menu3(rec):
    states = rec["file_states"]
    amf_tasks = []
    om_tasks = []
    for rel in iter_intermediate():
        logical = _physical_to_logical(rel, states) or rel
        st = states.get(logical, 0)
        if st >= 3:
            continue
        if rel.endswith(".amf3"):
            amf_tasks.append(("intermediate/" + rel,
                              "intermediate/" + rel[:-len(".amf3")] + ".json"))
        elif rel.endswith(".orderedmap"):
            om_tasks.append(("intermediate/" + rel,
                             "intermediate/" + rel[:-len(".orderedmap")] + ".csv"))
    amf_ok = run_parallel(amf_tasks, make_batch(task_amf3_to_json), "[菜单3 amf3→json]", chunk=16)
    om_ok = run_parallel(om_tasks, make_batch(task_om_to_csv), "[菜单3 orderedmap→csv]", chunk=64)
    ok_set = amf_ok | om_ok
    for t in amf_tasks + om_tasks:
        logical = _physical_to_logical(t[0][len("intermediate/"):], states) or \
                  t[0][len("intermediate/"):]
        if t[0] not in ok_set:
            continue
        states[logical] = 3
        try:
            os.remove(os.path.join(BASE_DIR, t[0].replace("/", os.sep)))
        except OSError:
            pass
    for logical, st in list(states.items()):
        if st == 2 and classify_logical(logical) in ("text_deflate", "plain"):
            states[logical] = 3
    save_record(rec)


ENC_DATA_EXT = ".amf3.deflate"


_COLIDX_CACHE = {}


def _col_index_info(header):
    key = tuple(header)
    info = _COLIDX_CACHE.get(key)
    if info is None:
        exact = {}
        prefix = {}
        suffix = {}
        for i, h in enumerate(key):
            if not h:
                continue
            exact.setdefault(h, []).append(i)
            j = h.find(".")
            while j != -1:
                prefix.setdefault(h[:j], []).append(i)
                j = h.find(".", j + 1)
            k = h.find(".values.")
            while k != -1:
                suffix.setdefault(h[k + 8:], []).append(i)
                k = h.find(".values.", k + 1)
        info = (exact, prefix, suffix)
        _COLIDX_CACHE[key] = info
    return info


def _cols_named(header, *names):
    exact, prefix, suffix = _col_index_info(header)
    out = set()
    for name in names:
        out.update(exact.get(name, ()))
        out.update(prefix.get(name, ()))
        out.update(suffix.get(name, ()))
    return sorted(out)


def _col_named(header, *names):
    for c in _cols_named(header, *names):
        return c
    return -1


_ANIM_FIELD_KINDS = {
    "shadow_animation_path": "animlayout",
    "extra_character_back_animation_path": "animlayout",
    "extra_character_fore_animation_path": "animlayout",
    "damage_check_back_animation_path": "animlayout",
    "damage_check_fore_animation_path": "animlayout",
    "hit_count_check_back_animation_path": "animlayout",
    "hit_count_check_fore_animation_path": "animlayout",
    "outhole_animation_path": "animlayout",
}

_GACHA_CHAR_ODDS_COLS = ("character_odds_rarity_3", "character_odds_rarity_4",
                         "character_odds_rarity_5")
_GACHA_EQUIP_ODDS_COLS = ("equipment_odds_rarity_3", "equipment_odds_rarity_4",
                          "equipment_odds_rarity_5")

_VOICE_NUMBERED_PREFIXES = (
    "battle/win_",
    "battle/matched_skill_",
    "battle/battle_start_",
    "battle/skill_",
    "battle/power_flip_",
    "battle/outhole_",
    "battle/exchange_power_flip_",
)

_VOICE_SINGLE_KEYS = (
    "battle/matched_skill_ready",
    "battle/skill_ready",
)


class PathSplicer:
    def __init__(self, rec):
        self.rec = rec
        self.hash_map = rec["hash_map"]
        self.out = set()
        self.candidate_count = 0
        self._master_names = None
        self._probed = set()

    def exists(self, logical):
        return get_hashed_rel(logical, cached=False) in self.hash_map

    def add(self, logical, verify=False):
        self.candidate_count += 1
        if not verify:
            self.out.add(normalize_path(logical))
            return
        n = normalize_path(logical)
        if n in self._probed:
            return
        self._probed.add(n)
        if not self.exists(logical):
            return
        self.out.add(n)

    @staticmethod
    def cell(row, idx):
        if 0 <= idx < len(row):
            v = row[idx].strip()
            if v != "" and v != "(None)":
                return v
        return None


def derive_sprite_sheet(path, gated=True):
    if gated:
        if not (path.startswith("character") or path.startswith("battle")):
            return None
        if path.startswith("battle/common"):
            return None
    segs = path.split("/")
    if path.startswith("character/"):
        last = "special_sprite_sheet" if segs[-1] == "special" else "sprite_sheet"
        return "/".join(segs[:-1] + [last])
    if path.startswith("ability_node/"):
        return "ability_node/sprite_sheet"
    if path.startswith("scene/"):
        return "/".join(segs[:2] + ["sprite_sheet"])
    if path.startswith("battle/common/layer0"):
        return "battle/common/layer0"
    if path.startswith("battle/common/layer1"):
        return "battle/common/layer1"
    if path.startswith("town/particle/"):
        return "/".join(segs[:-1] + ["sprite_sheet"])
    last_dir = segs[-2]
    return "/".join(segs[:-2] + [last_dir, last_dir])


def emit_animlayout(splicer, p, gated=True, verify=False):
    splicer.add(p + ".parts" + ENC_DATA_EXT, verify=verify)
    splicer.add(p + ".frame" + ENC_DATA_EXT, verify=True)
    splicer.add(p + ".timeline" + ENC_DATA_EXT, verify=verify)
    s = derive_sprite_sheet(p, gated=gated)
    if s:
        splicer.add(s + ".png", verify=verify)
        splicer.add(s + ".atlas" + ENC_DATA_EXT, verify=verify)


def emit_dash_panel(splicer, directory):
    for deg in (0, 45, 90, 135, 180, 225, 270, 315):
        emit_animlayout(splicer, "%s/fixed_%d" % (directory, deg))
    emit_animlayout(splicer, directory + "/smart")


def emit_movie(splicer, p):
    splicer.add(p + ".movie" + ENC_DATA_EXT)
    splicer.add(p + ".timeline" + ENC_DATA_EXT)
    segs = p.split("/")
    sp = "/".join(segs[:-1] + ["sprite_sheet"])
    splicer.add(sp + ".png")
    splicer.add(sp + ".atlas" + ENC_DATA_EXT)


_BATTLE_ACT_COLS = {
    "master/battle/assist/assist_multiball": "action.path",
    "master/battle/boss/conductor": "enemy_action2,enemy_action3,enemy_action4,enemy_action7,enemy_action8,weapon_action1,weapon_action2,weapon_action3,weapon_action4,weapon_action5,weapon_action6",
    "master/battle/boss/fire_sphere": "phase2_enemy_action_skill1,phase2_enemy_action_solo_attack1,phase2_enemy_action_solo_attack2,phase2_enemy_action_solo_attack3,phase2_enemy_action_solo_attack4,phase2_enemy_action_summon_bits1,phase2_enemy_action_summon_bits2,phase2_enemy_action_summon_bits3,phase3_enemy_action_awakening1,phase3_enemy_action_skill1,phase3_enemy_action_skill2,phase3_enemy_action_skill3,phase3_enemy_action_solo_attack1,phase3_enemy_action_solo_attack2,phase3_enemy_action_solo_attack3,phase3_enemy_action_solo_attack4,phase3_enemy_action_solo_attack5,phase3_enemy_action_solo_attack6,phase3_enemy_action_stun,phase3_enemy_action_stun2,phase3_enemy_action_stun3,phase3_enemy_action_summon_bits1,phase3_enemy_action_summon_bits2,phase3_enemy_action_summon_bits3,phase3_enemy_action_summon_bits4,phase3_enemy_action_summon_bits5,phase3_enemy_action_summon_bits6,phase3_enemy_action_summon_m_bits1,phase3_enemy_action_summon_m_bits2,phase3_enemy_action_summon_m_bits3,phase3_enemy_action_summon_m_bits4",
    "master/battle/boss/fire_sphere_phase1_crystal": "phase1_enemy_action_attack_a1,phase1_enemy_action_attack_a2,phase1_enemy_action_attack_b1,phase1_enemy_action_attack_b2,phase1_enemy_action_attack_c1,phase1_enemy_action_attack_c2,phase1_enemy_action_attack_d1,phase1_enemy_action_attack_d2,phase1_enemy_action_skill_a,phase1_enemy_action_skill_b,phase1_enemy_action_skill_c,phase1_enemy_action_skill_d",
    "master/battle/boss/fire_sphere_phase4_micronucleus": "phase4_enemy_action_attack_a1,phase4_enemy_action_attack_a2,phase4_enemy_action_attack_a3,phase4_enemy_action_attack_b1,phase4_enemy_action_attack_b2,phase4_enemy_action_attack_b3,phase4_enemy_action_attack_c1,phase4_enemy_action_attack_c2,phase4_enemy_action_attack_c3,phase4_enemy_action_attack_d1,phase4_enemy_action_attack_d2,phase4_enemy_action_attack_d3,phase4_enemy_action_entering,phase4_enemy_action_skill_a,phase4_enemy_action_skill_b,phase4_enemy_action_skill_c,phase4_enemy_action_skill_d",
    "master/battle/boss/funnel/general_funnel": "cutin001,enemy_action101,enemy_action102,enemy_action103,enemy_action104,enemy_action105,enemy_action106,enemy_action107,enemy_action108,enemy_action109,enemy_action110,enemy_action111,enemy_action112,enemy_action113,enemy_action114,enemy_action115,enemy_action116,enemy_action117,enemy_action118,enemy_action119,enemy_action120,enemy_action121,enemy_action122,enemy_action123,enemy_action124,enemy_action125,enemy_action126,enemy_action127,enemy_action128,enemy_action129,enemy_action130,enemy_action131,enemy_action132,enemy_action133,enemy_action134,enemy_action135,enemy_action136,enemy_action137,enemy_action138,enemy_action139,enemy_action140",
    "master/battle/boss/general_boss": "enemy_action01,enemy_action02,enemy_action03,enemy_action04,enemy_action05,enemy_action06,enemy_action07,enemy_action08,enemy_action09,enemy_action10,enemy_action11,enemy_action12,enemy_action13,enemy_action14,enemy_action15,enemy_action16,enemy_action17,enemy_action18,enemy_action19,enemy_action20,enemy_action21,enemy_action22,enemy_action23,enemy_action24,enemy_action25,enemy_action26,enemy_action27,enemy_action28,enemy_action29,enemy_action30,enemy_action31,enemy_action32,enemy_action33,enemy_action34,enemy_action35,enemy_action36,enemy_action37,enemy_action38,enemy_action39,enemy_action40,enemy_action41,enemy_action42,enemy_action43,enemy_action44,enemy_action45,enemy_action46,enemy_action47,enemy_action48,enemy_action49,enemy_action50,pre_action.path",
    "master/battle/boss/general_enemy_watch": "action_content.content",
    "master/battle/boss/holy_sphere": "phase1_crystal_enemy_action_attack_x1,phase1_crystal_enemy_action_attack_y1,phase1_crystal_enemy_action_attack_z1,phase1_crystal_enemy_action_skill_x1,phase1_crystal_enemy_action_skill_y1,phase1_crystal_enemy_action_skill_z1,phase1_enemy_action_phase1_x_attack1,phase1_enemy_action_phase1_x_attack3,phase1_enemy_action_phase1_x_funnel1,phase1_enemy_action_phase1_x_funnel2,phase1_enemy_action_phase1_x_skill1,phase1_enemy_action_phase1_y_attack1,phase1_enemy_action_phase1_y_attack2,phase1_enemy_action_phase1_y_attack3,phase1_enemy_action_phase1_y_funnel1,phase1_enemy_action_phase1_y_skill1,phase1_enemy_action_phase1_z_attack1,phase1_enemy_action_phase1_z_attack3,phase1_enemy_action_phase1_z_attack4,phase1_enemy_action_phase1_z_attack5,phase1_enemy_action_phase1_z_attack6,phase1_enemy_action_phase1_z_funnel1,phase1_enemy_action_phase1_z_funnel2,phase1_enemy_action_phase1_z_funnel3,phase1_enemy_action_phase1_z_funnel4,phase1_enemy_action_phase1_z_skill1,phase2_enemy_action_phase2_attack1,phase2_enemy_action_phase2_attack2,phase2_enemy_action_phase2_attack3,phase2_enemy_action_phase2_attack4,phase2_enemy_action_phase2_attack5,phase2_enemy_action_phase2_attack6,phase2_enemy_action_phase2_funnel1,phase2_enemy_action_phase2_funnel2,phase2_enemy_action_phase2_funnel3,phase2_enemy_action_phase2_funnel4,phase2_enemy_action_phase2_funnel5,phase2_enemy_action_phase2_skill1,phase4_enemy_action_phase4_attack1,phase4_enemy_action_phase4_attack2,phase4_enemy_action_phase4_attack3,phase4_enemy_action_phase4_attack4,phase4_enemy_action_phase4_attack5,phase4_enemy_action_phase4_funnel0,phase4_enemy_action_phase4_funnel1,phase4_enemy_action_phase4_funnel2,phase4_enemy_action_phase4_funnel3,phase4_enemy_action_phase4_skill1,phase4_enemy_action_phase4_skill2",
    "master/battle/boss/kraken": "kraken_enemy_action101,kraken_enemy_action102,kraken_enemy_action201,tentacle_enemy_action101,tentacle_enemy_action201",
    "master/battle/boss/orochi": "enemy_action101",
    "master/battle/boss/orochi_ex": "phase2_attack1.action_paths,phase2_attack2.action_paths,phase2_attack3.action_paths,phase2_normal1_action_paths,phase2_normal2_action_paths,phase2_normal3_action_paths,phase4_attack1.action_paths",
    "master/battle/boss/orochi_ex_head": "phase1_attack_e.action_paths,phase1_group1_a_attack1.action_paths,phase1_group1_a_attack2.action_paths,phase1_group1_a_attack3.action_paths,phase1_group1_b_attack1.action_paths,phase1_group1_b_attack2.action_paths,phase1_group1_b_attack3.action_paths,phase1_group1_c_attack1.action_paths,phase1_group1_c_attack2.action_paths,phase1_group1_c_attack3.action_paths,phase1_group1_d_attack1.action_paths,phase1_group1_d_attack2.action_paths,phase1_group1_d_attack3.action_paths,phase1_trial1.action_paths,phase1_trial2.action_paths",
    "master/battle/boss/thunder_sphere": "phase1_enemy_action_gravity_off1,phase1_enemy_action_gravity_on1,phase1_enemy_action_gravity_shift1,phase1_enemy_action_skill1,phase1_enemy_action_skill2,phase1_enemy_action_solo_attack1,phase1_enemy_action_solo_attack2,phase1_enemy_action_solo_attack3,phase1_enemy_action_solo_attack4,phase1_enemy_action_solo_attack5,phase1_enemy_action_solo_attack6,phase1_enemy_action_summon_bits1,phase1_enemy_action_summon_bits2,phase3_enemy_action_gravity_on1,phase3_enemy_action_gravity_shift1,phase3_enemy_action_link_attack_a1,phase3_enemy_action_link_attack_b1,phase3_enemy_action_link_attack_b2,phase3_enemy_action_skill1,phase3_enemy_action_skill2,phase3_enemy_action_solo_attack1,phase3_enemy_action_solo_attack2,phase3_enemy_action_solo_attack3,phase3_enemy_action_solo_attack4",
    "master/battle/boss/thunder_sphere_micronucleus": "phase2_enemy_action_move_attack1_1,phase2_enemy_action_move_attack1_2,phase2_enemy_action_move_attack2_1,phase2_enemy_action_move_attack2_2,phase2_enemy_action_skill,phase2_enemy_action_skill1,phase2_enemy_action_skill2,phase2_enemy_action_solo_attack1,phase2_enemy_action_solo_attack1_1,phase2_enemy_action_solo_attack1_2,phase2_enemy_action_solo_attack2,phase2_enemy_action_solo_attack2_1,phase2_enemy_action_solo_attack2_2,phase2_enemy_action_solo_attack3,phase2_enemy_action_solo_attack4,phase2_enemy_action_summon_bits1,phase2_enemy_action_summon_bits2",
    "master/battle/boss/thunder_sphere_phase3_crystal": "phase3_enemy_action_attack1,phase3_enemy_action_attack2,phase3_enemy_action_buff",
    "master/battle/boss/thunder_sphere_phase4_crystal": "phase4_enemy_action_awakening3,phase4_enemy_action_link_buff,phase4_enemy_action_link_debuff,phase4_enemy_action_link_skill,phase4_enemy_action_skill1,phase4_enemy_action_solo_attack1,phase4_enemy_action_solo_attack2,phase4_enemy_action_solo_attack3,phase4_enemy_action_solo_attack4",
    "master/battle/boss/touyakiren_ceo": "enemy_action1,enemy_action2,enemy_action3,enemy_action_back_routine1_attack_pod_attack1,enemy_action_back_routine1_attack_pod_attack2,enemy_action_back_routine1_attack_pod_skill1,enemy_action_back_routine1_funnel_attack1,enemy_action_back_routine1_funnel_attack2,enemy_action_back_routine1_funnel_skill1,enemy_action_back_routine1_support_attack1_1,enemy_action_back_routine1_support_attack2,enemy_action_back_routine1_support_remove,enemy_action_back_routine1_support_skill1,enemy_action_back_routine1_wave_attack1,enemy_action_back_routine1_wave_attack2,enemy_action_back_routine1_wave_skill1,enemy_action_back_routine2_super_amplified_discharge_attack_pod,enemy_action_back_routine2_super_amplified_discharge_funnel,enemy_action_back_routine2_super_amplified_discharge_support,enemy_action_back_routine2_super_amplified_discharge_wave,enemy_action_fore_routine1_cannon_attack1,enemy_action_fore_routine1_cannon_attack2,enemy_action_fore_routine1_cannon_attack3,enemy_action_fore_routine1_cannon_skill1,enemy_action_fore_routine1_gatling_attack1,enemy_action_fore_routine1_gatling_attack2,enemy_action_fore_routine1_gatling_attack3,enemy_action_fore_routine1_gatling_skill1,enemy_action_fore_routine1_laser_attack1,enemy_action_fore_routine1_laser_attack2,enemy_action_fore_routine1_laser_attack3,enemy_action_fore_routine1_laser_skill1,enemy_action_fore_routine2_super_amplified_discharge_cannon1,enemy_action_fore_routine2_super_amplified_discharge_cannon2,enemy_action_fore_routine2_super_amplified_discharge_cannon3,enemy_action_fore_routine2_super_amplified_discharge_cannon4,enemy_action_fore_routine2_super_amplified_discharge_cannon5,enemy_action_fore_routine2_super_amplified_discharge_gatling1,enemy_action_fore_routine2_super_amplified_discharge_gatling2,enemy_action_fore_routine2_super_amplified_discharge_gatling3,enemy_action_fore_routine2_super_amplified_discharge_gatling4,enemy_action_fore_routine2_super_amplified_discharge_gatling5,enemy_action_fore_routine2_super_amplified_discharge_laser_l,enemy_action_fore_routine2_super_amplified_discharge_laser_r",
    "master/battle/boss/water_sphere": "phase1_crystal_enemy_action_attack_x1,phase1_crystal_enemy_action_attack_y1,phase1_crystal_enemy_action_attack_z1,phase1_crystal_enemy_action_skill_x1,phase1_crystal_enemy_action_skill_y1,phase1_crystal_enemy_action_skill_z1,phase1_enemy_action_attack_x1,phase1_enemy_action_attack_x2,phase1_enemy_action_attack_y1,phase1_enemy_action_attack_z1,phase1_enemy_action_funnel_x1,phase1_enemy_action_funnel_y1,phase1_enemy_action_funnel_y2,phase1_enemy_action_funnel_y3,phase1_enemy_action_funnel_z1,phase1_enemy_action_funnel_z2,phase1_enemy_action_funnel_z3,phase1_enemy_action_skill_x1,phase1_enemy_action_skill_y1,phase1_enemy_action_skill_z1,phase2_enemy_action_attack1,phase2_enemy_action_funnel1,phase2_enemy_action_funnel2,phase2_enemy_action_funnel3,phase2_enemy_action_gravity1,phase2_enemy_action_gravity3,phase2_enemy_action_skill1,phase2_enemy_action_target1,phase2_enemy_action_target2,phase2_enemy_action_target3,phase2_enemy_action_target4,phase2_enemy_action_target5,phase4_enemy_action_attack_x1,phase4_enemy_action_attack_x21,phase4_enemy_action_funnel0,phase4_enemy_action_funnel_x1,phase4_enemy_action_funnel_x2,phase4_enemy_action_funnel_x3,phase4_enemy_action_skill1,phase4_enemy_action_skill2,phase4_enemy_action_target_x1,phase4_enemy_action_tornado_x1,phase4_enemy_action_tornado_x2",
    "master/battle/boss/water_sphere_micronucleus": "phase3_micronucleus_enemy_action_attack1,phase3_micronucleus_enemy_action_attack2,phase3_micronucleus_enemy_action_attack3,phase3_micronucleus_enemy_action_link_attack1,phase3_micronucleus_enemy_action_link_attack2,phase3_micronucleus_enemy_action_link_attack3,phase3_micronucleus_enemy_action_link_attack4,phase3_micronucleus_enemy_action_link_attack5,phase3_micronucleus_enemy_action_link_skill1,phase3_micronucleus_enemy_action_skill1",
    "master/battle/boss/wind_sphere": "phase1_enemy_action_invincible_disable,phase1_enemy_action_skill_x1,phase1_enemy_action_skill_y1,phase1_enemy_action_solo_attack_x1,phase1_enemy_action_solo_attack_x2,phase1_enemy_action_solo_attack_x3,phase1_enemy_action_solo_attack_x4,phase1_enemy_action_solo_attack_y1,phase1_enemy_action_solo_attack_y2,phase1_enemy_action_solo_attack_y3,phase1_enemy_action_solo_attack_y4,phase1_enemy_action_solo_attack_y5,phase1_enemy_action_solo_attack_y6,phase1_enemy_action_summon_bits_x1,phase1_enemy_action_summon_bits_y1,phase1_enemy_action_summon_bits_y2,phase2_crystal1.enemy_action_attack1,phase2_crystal1.enemy_action_attack2,phase2_crystal1.enemy_action_attack3,phase2_crystal1.enemy_action_buff,phase2_crystal1.enemy_action_dead,phase2_crystal1.enemy_action_skill1,phase2_crystal2.enemy_action_attack1,phase2_crystal2.enemy_action_attack2,phase2_crystal2.enemy_action_attack3,phase2_crystal2.enemy_action_buff,phase2_crystal2.enemy_action_dead,phase2_crystal2.enemy_action_skill1,phase2_crystal3.enemy_action_attack1,phase2_crystal3.enemy_action_attack2,phase2_crystal3.enemy_action_attack3,phase2_crystal3.enemy_action_buff,phase2_crystal3.enemy_action_dead,phase2_crystal3.enemy_action_skill1,phase2_enemy_action_awakening2,phase2_enemy_action_initial,phase2_enemy_action_skill_y1,phase2_enemy_action_solo_attack_x1,phase2_enemy_action_solo_attack_x2,phase2_enemy_action_solo_attack_x3,phase2_enemy_action_solo_attack_x4,phase2_enemy_action_summonbits_x1,phase3_crystal1.enemy_action_attack1,phase3_crystal1.enemy_action_attack2,phase3_crystal1.enemy_action_attack3,phase3_crystal1.enemy_action_buff,phase3_crystal1.enemy_action_dead,phase3_crystal1.enemy_action_skill1,phase3_enemy_action_initial,phase4_enemy_action_attack1,phase4_enemy_action_attack2,phase4_enemy_action_attack3,phase4_enemy_action_field_effect,phase4_enemy_action_funnel1,phase4_enemy_action_funnel2,phase4_enemy_action_funnel3,phase4_enemy_action_initial,phase4_enemy_action_skill1,phase4_enemy_action_skill2",
    "master/battle/boss/wind_sphere_micronucleus": "enemy_action_attack1,enemy_action_attack2,enemy_action_attack3,enemy_action_attack4,enemy_action_field_effect,enemy_action_link_attack1,enemy_action_link_attack2,enemy_action_link_attack3,enemy_action_link_skill1,enemy_action_skill1",
    "master/battle/item/executable_instant_item": "program_path",
    "master/battle/yakumono/breakable_block": "enemy_action101",
    "master/battle/zako/general_zako": "enemy_action101,enemy_action102,enemy_action103,enemy_action104",
}


def rule_enemy_source_fields(splicer):
    fc = _FileCache(splicer)
    for key in _iter_master_names(splicer):
        if not key.startswith("master/battle/"):
            continue
        data = fc.read_orderedmap_rows(key)
        if not data:
            continue
        header, rows = data
        tl = _col_named(header, "marker_timeline_path")
        anim_cols = [c
                     for f in _ANIM_FIELD_KINDS
                     for c in _cols_named(header, f)]
        act_names = _BATTLE_ACT_COLS.get(key)
        if act_names is None:
            mb = re.sub(r"_(?:iosbundled|bundled)$", "", key)
            act_names = _BATTLE_ACT_COLS.get(mb)
        act_cols = sorted(_cols_named(header, *act_names.split(","))) if act_names else []
        pa_cols = _cols_named(header, "pre_action")
        for row in rows:
            if tl >= 0:
                v = splicer.cell(row, tl)
                if v:
                    emit_animlayout(splicer, v)
            for c in anim_cols:
                v = splicer.cell(row, c)
                if v:
                    emit_animlayout(splicer, v)
            for c in act_cols:
                v = splicer.cell(row, c)
                if not v:
                    continue
                for p in (s.strip() for s in v.split(",")):
                    if p and p != "(None)" and "/" in p \
                            and re.match(r"^[A-Za-z0-9_/$]+$", p):
                        splicer.add(p + ".action.dsl" + ENC_DATA_EXT)
            for c in pa_cols:
                v = splicer.cell(row, c)
                if not v:
                    continue
                for p in (s.strip() for s in v.split(",")):
                    if p and p != "(None)" and "/" in p \
                            and re.match(r"^[A-Za-z0-9_/$]+$", p):
                        splicer.add(p + ".action.dsl" + ENC_DATA_EXT)


def rule_zone_dash_panel(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/battle/zone", "master/battle/zone_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ci = _col_named(header, "dash_panel_directory")
        for row in rows:
            v = splicer.cell(row, ci)
            if v:
                emit_dash_panel(splicer, v)


def rule_sound_keys(splicer):
    fc = _FileCache(splicer)
    for key in _iter_master_names(splicer):
        base = key[len("master/"):] if key.startswith("master/") else key
        first = base.split("/")[0]
        if first not in ("asset",):
            continue
        name = base.split("/")[-1]
        is_voice = name.startswith("voice_asset")
        if not (name.startswith("bgm_asset") or name.startswith("sound_effect_asset")
                or is_voice):
            continue
        data = fc.read_orderedmap_full(key)
        if not data:
            continue
        _, _, keys = data
        for v in keys:
            v = v.strip()
            if v and v != "(None)":
                if is_voice:
                    splicer.add(v + ".mp3", verify=True)
                else:
                    splicer.add(v + ".mp3")


def rule_voices(splicer):
    fc = _FileCache(splicer)
    ch = fc.read_orderedmap_rows("master/character/character")
    sids = []
    if ch:
        header, rows = ch
        si = _col_named(header, "string_id")
        for row in rows:
            v = splicer.cell(row, si)
            if v:
                sids.append(v)
    for sid in sids:
        base = "character/%s/voice/" % sid
        for prefix in _VOICE_NUMBERED_PREFIXES:
            for i in range(512):
                cand = base + prefix + str(i) + ".mp3"
                if not splicer.exists(cand):
                    break
                splicer.add(cand, verify=True)
        for key in _VOICE_SINGLE_KEYS:
            cand = base + key + ".mp3"
            splicer.add(cand, verify=True)
    sp = fc.read_orderedmap_full("master/character/character_speech")
    if sp:
        header, rows, keys = sp
        vi = _col_named(header, "voice_path")
        cid2sid = {}
        if ch:
            hh, rr = ch
            ci_sid = _col_named(hh, "string_id")
            data_full = fc.read_orderedmap_full("master/character/character")
            if data_full:
                _, _, ckeys = data_full
                for i, row in enumerate(rr):
                    sid = splicer.cell(row, ci_sid)
                    if sid and i < len(ckeys):
                        cid2sid[ckeys[i]] = sid
        for i, row in enumerate(rows):
            v = splicer.cell(row, vi)
            if not v:
                continue
            cid = keys[i] if i < len(keys) else None
            sid = cid2sid.get(cid)
            if not sid:
                continue
            cand = "character/%s/voice/%s.mp3" % (sid, v)
            splicer.add(cand, verify=True)


def rule_town_content(splicer):
    fc = _FileCache(splicer)
    data = fc.read_orderedmap_rows("master/town/town_content")
    if not data:
        return
    header, rows = data
    cb = _col_named(header, "background_image")
    cbl = _col_named(header, "background_blured_image")
    cm = _col_named(header, "mask_image")
    cp = _col_named(header, "particle")
    cbg = _col_named(header, "bgm")
    for row in rows:
        for c in (cb, cbl, cm):
            v = splicer.cell(row, c)
            if v:
                splicer.add(v + ".png")
        v = splicer.cell(row, cp)
        if v:
            emit_animlayout(splicer, v, gated=False)
        v = splicer.cell(row, cbg)
        if v:
            splicer.add(v + ".mp3")


def rule_feature_announcement(splicer):
    fc = _FileCache(splicer)
    data = fc.read_orderedmap_rows("master/feature_banner/feature_announcement")
    if not data:
        return
    header, rows = data
    ci = _col_named(header, "image_path")
    for row in rows:
        v = splicer.cell(row, ci)
        if v:
            splicer.add(v + ".png")


def rule_degree(splicer):
    fc = _FileCache(splicer)
    data = fc.read_orderedmap_rows("master/degree/degree")
    if not data:
        return
    header, rows = data
    ci = _col_named(header, "degree_image")
    cbase = _col_named(header, "icon_base_image")
    for row in rows:
        for c in (ci, cbase):
            if c < 0:
                continue
            v = splicer.cell(row, c)
            if v:
                splicer.add(v + ".png")


_AVAIL_TIME_SUFFIXES = ("_always", "_usual", "_fever", "_back", "_middle", "_fore")

_TERRAIN_KIND_MAP = {
    "BLOCK": "block",
    "BREAKABLE_BLOCK": "breakable_block",
    "BREAKABLE_DECORATION": "breakable_decoration",
    "DECORATION": "decoration",
    "YUREMONO": "yuremono",
    "DIRECT_INSTANT_ITEM": None,
    "SKILL_INVOKER": None,
    "TALKY_YAKUMONO": None,
}

_STORY_TABLES = (
    "master/quest/main_quest",
    "master/quest/ex_quest",
    "master/quest/character_quest",
    "master/quest/event/advent_event_quest",
    "master/quest/event/challenge_dungeon_event_quest",
    "master/quest/event/expert_single_event_quest",
    "master/quest/event/hard_multi_event_quest",
    "master/quest/event/ranking_event_single_quest",
    "master/quest/event/story_event_single_quest",
    "master/quest/event/tower_dungeon_event_quest",
    "master/quest/event/world_story_event_quest",
    "master/quest/practice/practice_quest",
    "master/tutorial/tutorial_quest",
    "master/tutorial/tutorial_quest_iosbundled",
    "master/tutorial/triggered_tutorial",
    "master/battle/zone_action",
    "master/battle/zone_action_iosbundled",
)

_EVENT_BG_TABLES = (
    "master/quest/event/expert_single_event",
    "master/quest/event/expert_single_event_quest_folder",
    "master/quest/event/ranking_event",
    "master/quest/event/hard_multi_event",
    "master/quest/event/world_story_event",
    "master/quest/event/carnival_event",
    "master/quest/event/carnival_event_quest_folder",
    "master/quest/event/raid_event",
    "master/quest/event/rush_event",
    "master/quest/event/rush_event_quest_folder",
    "master/quest/event/solo_time_attack_event",
    "master/quest/event/score_attack_event",
    "master/quest/event/advent_event",
)


_CHAR_UI_EVO_IMAGES = (
    "skill_cutin",
    "cutin_skill_chain",
    "thumb_party_unison",
    "thumb_party_main",
    "battle_member_status",
    "thumb_level_up",
    "battle_control_board",
    "full_shot_1440_1920",
    "full_shot_illustration_setting",
)
_CHAR_FACE_IMAGES = (
    "square", "square_132_132", "square_round_136_136", "square_round_95_95",
)

_BATTLE_VOICE_PREFIXES = (
    "win_", "matched_skill_", "battle_start_", "skill_", "power_flip_",
    "outhole_", "exchange_power_flip_", "normal_attack_",
)
_BATTLE_VOICE_SINGLE = ("skill_ready", "matched_skill_ready")


def _remove_available_time(name):
    for suf in _AVAIL_TIME_SUFFIXES:
        if name.endswith(suf):
            return name[: -len(suf)]
    return name


def _terrain_anim_path(field_path, kind):
    p = field_path.lower()
    p = _remove_available_time(p)
    p = p.replace("@", "/yakumono/%s/" % kind)
    return "battle/field_object/" + p


class _FileCache:
    _json_cache = {}
    _table_cache = {}
    _json_once = set()
    _table_once = set()

    def __init__(self, splicer):
        self._json_cache = _FileCache._json_cache
        self._table_cache = _FileCache._table_cache

    @classmethod
    def reset(cls):
        cls._json_cache.clear()
        cls._table_cache.clear()
        cls._json_once.clear()
        cls._table_once.clear()

    def read_decoded(self, logical):
        if logical in self._json_cache:
            return self._json_cache[logical]
        result = None
        jp = os.path.join(INTERMEDIATE_DIR, logical.replace("/", os.sep) + ".json")
        try:
            with open(jp, "r", encoding="utf-8-sig") as f:
                result = json.load(f)
        except (json.JSONDecodeError, OSError):
            result = None
        if logical in self._json_once:
            self._json_cache[logical] = result
        else:
            self._json_once.add(logical)
        return result

    def read_text(self, logical):
        tp = os.path.join(INTERMEDIATE_DIR, logical.replace("/", os.sep))
        try:
            with open(tp, "r", encoding="utf-8-sig") as f:
                return f.read()
        except OSError:
            return None

    def read_orderedmap_full(self, master_key):
        if master_key in self._table_cache:
            return self._table_cache[master_key]
        result = None
        csv_rel = menu3_name(master_key + ".orderedmap")
        csv_path = os.path.join(INTERMEDIATE_DIR, csv_rel.replace("/", os.sep))
        try:
            with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
                rows = list(csv.reader(f))
            if rows:
                header = rows[0]
                n_keys = self._key_column_count(master_key, header)
                keys = [r[0] if r else "" for r in rows[1:]]
                parsed = [r[n_keys:] + [""] * (len(header) - n_keys - (len(r) - n_keys))
                          for r in rows[1:]]
                result = (header[n_keys:], parsed, keys)
        except (OSError, csv.Error):
            result = None
        if master_key in self._table_once:
            self._table_cache[master_key] = result
        else:
            self._table_once.add(master_key)
        return result

    def read_orderedmap_rows(self, master_key):
        result = self.read_orderedmap_full(master_key)
        if result is not None:
            return result[0], result[1]
        return None

    def _key_column_count(self, master_key, header):
        kn = _key_names_for(master_key)
        if kn:
            return 1 + (1 if len(kn) > 1 else 0)
        return 2 if (len(header) > 1 and header[1] == "sub_key") else 1


def _iter_master_names(splicer):
    if splicer._master_names is None:
        names = set()
        for p in splicer.rec["file_states"]:
            if p.startswith("master/") and p.endswith(".orderedmap"):
                names.add(p[: -len(".orderedmap")])
        splicer._master_names = sorted(names)
    return splicer._master_names


def _register_master_cells(splicer, fc, mk, colspec):
    names = []
    for cols in colspec.values():
        names.extend(cols.split(","))
    data = fc.read_orderedmap_rows(mk)
    if not data:
        return
    header, rows = data
    idx = {}
    for n in names:
        c = _col_named(header, n)
        if c >= 0:
            idx[n] = c
    if not idx:
        return
    suffix_of = {}
    for suffix, cols in colspec.items():
        for n in cols.split(","):
            suffix_of[n] = suffix
    for row in rows:
        for n, c in idx.items():
            if c >= len(row):
                continue
            v = row[c].strip()
            if not v or v == "(None)" or "/" not in v or v.startswith("master/"):
                continue
            for p in (s.strip() for s in v.split(",")):
                if p and p != "(None)":
                    splicer.add(p + suffix_of[n])


_ABILITY_ACTION_COLS = {
    "master/ability/ability":
        {".action.dsl" + ENC_DATA_EXT: "trigger.values.instant_content.values.action_path"},
    "master/ability/leader_ability":
        {".action.dsl" + ENC_DATA_EXT: "trigger.values.instant_content.values.action_path"},
}


def rule_ability_action_paths(splicer):
    fc = _FileCache(splicer)
    for mk, colspec in _ABILITY_ACTION_COLS.items():
        _register_master_cells(splicer, fc, mk, colspec)


_ACTIVE_MISSION_COLS = {
    "master/active_mission/active_mission_event":
        {".png": "event_background_image,home_banner_image,list_banner_image,logo_image"},
    "master/active_mission/real_incentive_mission_real_reward":
        {".png": "image"},
}


def rule_active_mission_assets(splicer):
    fc = _FileCache(splicer)
    for mk, colspec in _ACTIVE_MISSION_COLS.items():
        _register_master_cells(splicer, fc, mk, colspec)


_ASSIST_YAKUMONO_SKILL_COLS = {
    "master/battle/assist/assist_yakumono":
        {".png": "invoke_skill.skill_cutin_image",
         ".mp3": "invoke_skill.skill_voice_paths"},
}


def rule_assist_yakumono_skill_assets(splicer):
    fc = _FileCache(splicer)
    for mk, colspec in _ASSIST_YAKUMONO_SKILL_COLS.items():
        _register_master_cells(splicer, fc, mk, colspec)


_CAMPAIGN_COLS = {
    "master/campaign/multi_special_exchange/multi_special_exchange_campaign":
        {".png": "header_background_image,home_banner_image,id1_header_background_image,id2_header_background_image,id3_header_background_image"},
    "master/campaign/special_exchange/special_exchange_campaign":
        {".png": "header_background_image", ".html.deflate": "how_to_play.rich_text"},
    "master/campaign/start_dash_exchange/start_dash_exchange_campaign":
        {".png": "header_background_image"},
    "master/campaign/treasure_vault_exchange/treasure_vault_exchange_campaign":
        {".png": "header_background_image", ".html.deflate": "how_to_play.rich_text"},
}


def rule_campaign_assets(splicer):
    fc = _FileCache(splicer)
    for mk, colspec in _CAMPAIGN_COLS.items():
        _register_master_cells(splicer, fc, mk, colspec)


def rule_character_election_images(splicer):
    fc = _FileCache(splicer)
    _register_master_cells(splicer, fc, "master/character_election/character_election",
                           {".png": "header_background_image"})


_COLLECT_ITEM_EVENT_COLS = {
    "master/reward/event/collect_item_event":
        {".png": "event_background_image,event_list_header_banner_image,home_banner_image,shop_background_image,shop_list_banner_image",
         ".html.deflate": "how_to_play.rich_text"},
}


def rule_collect_item_event_assets(splicer):
    fc = _FileCache(splicer)
    for mk, colspec in _COLLECT_ITEM_EVENT_COLS.items():
        _register_master_cells(splicer, fc, mk, colspec)


def rule_encyclopedia_world_assets(splicer):
    fc = _FileCache(splicer)
    _register_master_cells(splicer, fc, "master/encyclopedia/encyclopedia",
                           {".png": "kind.values.world_banner,kind.values.world_header_background"})


def rule_equipment_enhancement_shop_images(splicer):
    fc = _FileCache(splicer)
    _register_master_cells(splicer, fc, "master/equipment_enhancement/equipment_enhancement_shop_category",
                           {".png": "banner_image,header_background_image"})


_EVENT_UI_COLS = {
    "master/quest/event/advent_event":
        {".png": "header_kind.header_background_path,header_mini_banner_path,list_banner_path,logo_image,main_quest_guide.icon,main_quest_guide.icon_event_lock",
         ".mp3": "bgm"},
    "master/quest/boss_battle/boss_battle_multi_pickup_event":
        {".png": "boss_battle_top_background_image", ".html.deflate": "rich_text"},
    "master/quest/boss_battle/boss_battle_multi_pickup_event_schedule":
        {".png": "background_image"},
    "master/quest/event/carnival_event":
        {".png": "header_background_image,list_banner_path,logo_image", ".mp3": "bgm"},
    "master/quest/event/challenge_dungeon_event":
        {".png": "header_background_image,list_banner_path"},
    "master/quest/event/daily_exp_mana_event":
        {".png": "header_background_image,list_banner_path"},
    "master/quest/event/daily_week_event":
        {".png": "header_background_image,list_banner_path"},
    "master/quest/event/event_folder":
        {".png": "header_background_image,list_banner_path"},
    "master/quest/event/event_shop_select_item_campaign":
        {".png": "header_background_image"},
    "master/quest/event/expert_single_event":
        {".png": "folder_logo_image,list_banner_path,logo_image", ".mp3": "bgm"},
    "master/quest/event/expert_single_event_campaign":
        {".png": "folder_logo_image,logo_image"},
    "master/quest/event/hard_multi_event":
        {".png": "header_mini_banner_path,list_banner_path,logo_image,unlock_logo_image", ".mp3": "bgm"},
    "master/quest/event/raid_event":
        {".png": "boss_thumbnail_image,header_background_image,header_mini_banner_path,list_banner_path", ".mp3": "bgm"},
    "master/quest/event/ranking_event":
        {".png": "background_blur_image,header_mini_banner_path,list_banner_path,logo_image,result_dialog_background_image", ".mp3": "bgm"},
    "master/quest/event/rush_event":
        {".png": "header_background_image,header_mini_banner_path,list_banner_path,logo_image", ".mp3": "bgm"},
    "master/quest/event/score_attack_event":
        {".png": "header_background_image,list_banner_path,logo_image,quest_result_logo_image", ".mp3": "bgm"},
    "master/quest/event/solo_time_attack_event":
        {".png": "list_banner_path,logo_image,quest_result_logo_image", ".mp3": "bgm"},
    "master/quest/event/story_event":
        {".png": "header_background_image,list_banner_path"},
    "master/quest/event/tower_dungeon_event":
        {".png": "header_background_image,list_banner_path,quest_list_background_image,reward_panel_background_image", ".mp3": "bgm"},
    "master/quest/event/world_story_event":
        {".png": "header_mini_banner_path,list_banner_path,logo_image,mode_select_logo_image", ".mp3": "bgm"},
}


def rule_event_ui_assets(splicer):
    fc = _FileCache(splicer)
    for mk, colspec in _EVENT_UI_COLS.items():
        _register_master_cells(splicer, fc, mk, colspec)


_PAYMENT_COLS = {
    "master/payment/android_payment":
        {".png": "display_kind.image_path", ".html.deflate": "display_kind.rich_text"},
    "master/payment/ios_payment":
        {".png": "display_kind.image_path", ".html.deflate": "display_kind.rich_text"},
}


def rule_payment_display_assets(splicer):
    fc = _FileCache(splicer)
    for mk, colspec in _PAYMENT_COLS.items():
        _register_master_cells(splicer, fc, mk, colspec)


_QUEST_UI_COLS = {
    "master/quest/boss_battle_quest": {".png": "thumbnail_image"},
    "master/quest/character_quest": {".png": "thumbnail_image"},
    "master/quest/event/advent_event_quest":
        {".png": "kind.values.battle_start_cutin_image_path,thumbnail_image"},
    "master/quest/event/carnival_event_quest": {".png": "thumbnail_image"},
    "master/quest/event/carnival_event_quest_folder": {".png": "thumbnail_image"},
    "master/quest/event/challenge_dungeon_event_quest": {".png": "thumbnail_image"},
    "master/quest/event/daily_exp_mana_event_quest": {".png": "thumbnail_image"},
    "master/quest/event/daily_week_event_quest": {".png": "thumbnail_image"},
    "master/quest/event/expert_single_event_quest": {".png": "thumbnail_image"},
    "master/quest/event/expert_single_event_quest_folder":
        {".png": "boss_logo_image,thumbnail_image"},
    "master/quest/event/hard_multi_event_quest":
        {".png": "kind.values.battle_cutin_boss_image,thumbnail_image"},
    "master/quest/event/raid_event_quest": {".png": "thumbnail_image"},
    "master/quest/event/raid_event_quest_folder": {".png": "thumbnail_image"},
    "master/quest/event/ranking_event_single_quest": {".png": "thumbnail_image"},
    "master/quest/event/rush_event_quest": {".png": "thumbnail_image"},
    "master/quest/event/rush_event_quest_folder": {".png": "thumbnail_image"},
    "master/quest/event/score_attack_event_quest": {".png": "thumbnail_image"},
    "master/quest/event/score_attack_event_quest_folder": {".png": "thumbnail_image"},
    "master/quest/event/solo_time_attack_event_quest": {".png": "thumbnail_image"},
    "master/quest/event/story_event_single_quest": {".png": "thumbnail_image"},
    "master/quest/event/tower_dungeon_event_quest": {".png": "thumbnail_image"},
    "master/quest/event/world_story_event_boss_battle_quest": {".png": "thumbnail_image"},
    "master/quest/event/world_story_event_quest": {".png": "thumbnail_image"},
    "master/quest/ex_chapter": {".mp3": "bgm"},
    "master/quest/ex_quest":
        {".png": "thumbnail_image", ".mp3": "kind.values.battle_play_win.voice_path"},
    "master/quest/main_chapter": {".mp3": "bgm"},
    "master/quest/main_quest":
        {".png": "thumbnail_image", ".mp3": "kind.values.battle_play_win.voice_path"},
    "master/quest/practice/practice_quest": {".png": "thumbnail_image"},
    "master/quest/practice/practice_quest_folder": {".png": "thumbnail_image"},
    "master/skill_preview/skill_preview_quest": {".png": "thumbnail_image"},
    "master/tutorial/tutorial_quest_iosbundled":
        {".png": "kind.values.battle_feature.title_image,thumbnail_image"},
}


def rule_quest_ui_assets(splicer):
    fc = _FileCache(splicer)
    for mk, colspec in _QUEST_UI_COLS.items():
        _register_master_cells(splicer, fc, mk, colspec)


_SHOP_THUMB_COLS = {
    "master/shop/boss_coin_shop": {".png": "thumbnail_id"},
    "master/shop/boss_coin_shop_category": {".png": "banner_image,header_background_image"},
    "master/shop/event_item_shop": {".png": "thumbnail_id"},
    "master/shop/star_grain_shop": {".png": "thumbnail_id"},
}


def rule_shop_thumbnails(splicer):
    fc = _FileCache(splicer)
    for mk, colspec in _SHOP_THUMB_COLS.items():
        _register_master_cells(splicer, fc, mk, colspec)


_SKILL_ICON_COLS = {
    "master/skill/action_skill": {".png": "icon_id"},
    "master/skill/action_skill_iosbundled": {".png": "icon_id"},
}


def rule_skill_icons(splicer):
    fc = _FileCache(splicer)
    for mk, colspec in _SKILL_ICON_COLS.items():
        _register_master_cells(splicer, fc, mk, colspec)


_SKILL_PROGRAM_COLS = {
    "master/skill/action_skill": {".action.dsl" + ENC_DATA_EXT: "program_path"},
    "master/skill/action_skill_iosbundled": {".action.dsl" + ENC_DATA_EXT: "program_path"},
    "master/skill/switched_action_skill": {".action.dsl" + ENC_DATA_EXT: "program_path"},
    "master/skill/power_flip_action":
        {".action.dsl" + ENC_DATA_EXT: "power_flip_action1,power_flip_action2,power_flip_action3"},
    "master/skill/power_flip_action_iosbundled":
        {".action.dsl" + ENC_DATA_EXT: "power_flip_action1,power_flip_action2,power_flip_action3"},
}


def rule_skill_program_actions(splicer):
    fc = _FileCache(splicer)
    for mk, colspec in _SKILL_PROGRAM_COLS.items():
        _register_master_cells(splicer, fc, mk, colspec)


_TIPS_COLS = {
    "master/tips/tips": {".png": "asset_path"},
    "master/tips/tutorial_tips_iosbundled": {".png": "asset_path"},
}


def rule_tips_images(splicer):
    fc = _FileCache(splicer)
    for mk, colspec in _TIPS_COLS.items():
        _register_master_cells(splicer, fc, mk, colspec)


_TOWN_BGM_COLS = {
    "master/town/town_bgm": {".mp3": "bgm"},
    "master/town/town_bgm_set_list": {".png": "header_image,icon"},
}


def rule_town_bgm_assets(splicer):
    fc = _FileCache(splicer)
    for mk, colspec in _TOWN_BGM_COLS.items():
        _register_master_cells(splicer, fc, mk, colspec)


def rule_unique_condition_icon(splicer):
    fc = _FileCache(splicer)
    _register_master_cells(splicer, fc, "master/character/unique_condition",
                           {".png": "icon_image"})


def rule_story_columns(splicer):
    fc = _FileCache(splicer)
    for mk in _STORY_TABLES:
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        mcol = _col_named(header, "story_movie_path")
        ucol = _col_named(header, "story_movie_ui_scale_path")
        scol = _col_named(header, "story_scenario_path",
                          "action.values.scenario_path")
        rcol = _col_named(header, "action.values.replay_log_path")
        for row in rows:
            for c in (mcol, ucol):
                if c < 0:
                    continue
                v = splicer.cell(row, c)
                if v:
                    for part in v.split(","):
                        p = part.strip()
                        if p and p != "(None)" and p.startswith("story/"):
                            emit_movie(splicer, p)
            for c in (scol, rcol):
                if c < 0:
                    continue
                v = splicer.cell(row, c)
                if v:
                    for part in v.split(","):
                        p = part.strip()
                        if not p or p == "(None)":
                            continue
                        if p.startswith("story/"):
                            splicer.add("master/" + p + ".orderedmap")
                        elif p.startswith("battle/log/"):
                            splicer.add(p + ".battle" + ENC_DATA_EXT)
                            splicer.add(p + ".ball" + ENC_DATA_EXT)


def rule_field_columns(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/battle/field", "master/battle/field_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        cols = range(10)
        for row in rows:
            for c in cols:
                v = splicer.cell(row, c)
                if v:
                    emit_animlayout(splicer, v)


def rule_event_backgrounds(splicer):
    fc = _FileCache(splicer)
    for mk in _EVENT_BG_TABLES:
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ci = _col_named(header, "background_animation")
        gate = False
        if ci < 0 and mk == "master/quest/event/advent_event":
            ci = _col_named(header, "header_kind.header_background_path")
            gate = True
        if ci < 0:
            continue
        for row in rows:
            v = splicer.cell(row, ci)
            if not v or not v.startswith("quest/event/"):
                continue
            if gate and not any(splicer.exists(v + s) for s in (
                    ".png", ".parts" + ENC_DATA_EXT, ".frame" + ENC_DATA_EXT,
                    ".timeline" + ENC_DATA_EXT)):
                continue
            emit_animlayout(splicer, v, gated=False)


def rule_stage_node_backgrounds(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/quest/main_chapter", "master/quest/ex_chapter"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ci = _col_named(header, "stage_node_background")
        if ci < 0:
            continue
        for row in rows:
            v = splicer.cell(row, ci)
            if v:
                emit_animlayout(splicer, v, gated=False)


def rule_enemy_element_columns(splicer):
    fc = _FileCache(splicer)
    variant_cols = ("element.character_animation_path_red",
                    "element.character_animation_path_blue",
                    "element.character_animation_path_yellow",
                    "element.character_animation_path_green",
                    "element.character_animation_path_white",
                    "element.character_animation_path_black")
    for mk in ("master/battle/zako/general_zako",
               "master/battle/zako/general_zako_iosbundled",
               "master/battle/boss/funnel/general_funnel",
               "master/battle/boss/funnel/general_funnel_iosbundled",
               "master/battle/boss/general_boss",
               "master/battle/boss/general_boss_iosbundled",
               "master/battle/yakumono/breakable_block"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ki = _col_named(header, "element")
        pi = _col_named(header, "element.character_animation_path")
        cols = [_col_named(header, n) for n in variant_cols]
        for row in rows:
            kind = splicer.cell(row, ki)
            if kind == "0":
                for c in cols:
                    if c >= 0:
                        v = splicer.cell(row, c)
                        if v:
                            emit_animlayout(splicer, v)
            else:
                if pi >= 0:
                    v = splicer.cell(row, pi)
                    if v:
                        emit_animlayout(splicer, v)


def _collect_funnel_refs(node, out):
    if isinstance(node, list) and len(node) == 2 \
            and node[0] in ("Funnel", "Zako", "StandardFunnel") and isinstance(node[1], str):
        out.add(node[1])
        return
    if isinstance(node, list):
        for x in node:
            _collect_funnel_refs(x, out)
    elif isinstance(node, dict):
        for v in node.values():
            _collect_funnel_refs(v, out)


def _esdl_collect_paths(fc, base):
    obj = fc.read_decoded(base + ".esdl")
    if not isinstance(obj, dict):
        return [], [], set()
    abp = obj.get("bH")
    if not isinstance(abp, str):
        return [], [], set()
    actions = set()
    anims = []
    funnels = set()

    def add_action(fp):
        if isinstance(fp, str) and fp:
            actions.add(abp + fp)

    def walk_quantum(q):
        if isinstance(q, list) and len(q) >= 2 and q[0] in ("T1", "T2"):
            if q[0] == "T1" and len(q) > 1:
                items = q[1] if isinstance(q[1], list) else [q[1]]
                for it in items:
                    if isinstance(it, dict):
                        add_action(it.get("b"))
                        walk_quantum(it.get("value"))
            elif q[0] == "T2" and len(q) > 2:
                items = q[1] if isinstance(q[1], list) else [q[1]]
                for it in items:
                    if isinstance(it, dict):
                        walk_quantum(it.get("value"))
                walk_quantum(q[2])
        elif isinstance(q, dict):
            add_action(q.get("b"))
            walk_quantum(q.get("value"))

    _collect_funnel_refs(obj, funnels)

    v = obj.get("ar")
    if isinstance(v, str) and v:
        anims.append(("timeline", v))
    for k in ("as", "at"):
        v = obj.get(k)
        if isinstance(v, str) and v:
            anims.append(("animlayout", v))
    for k in ("bn", "bm", "bl", "bk"):
        v = obj.get(k)
        if isinstance(v, str) and v:
            anims.append(("animlayout", v))
    v = obj.get("bx")
    if isinstance(v, list) and len(v) > 1 and isinstance(v[1], dict):
        pre = v[1].get("pre_action_path")
        if isinstance(pre, list):
            for p in pre:
                add_action(p)
    v = obj.get("bo")
    if isinstance(v, list):
        for x in v:
            if isinstance(x, str) and x:
                funnels.add(x)

    for form in obj.get("au") or []:
        if not isinstance(form, dict):
            continue
        for st in form.get("g") or []:
            if not isinstance(st, dict):
                continue
            for a in st.get("i") or []:
                if isinstance(a, dict):
                    add_action(a.get("b"))
            for qa in st.get("xi") or []:
                walk_quantum(qa)
        for k in ("m", "i", "k"):
            for item in form.get(k) or []:
                if isinstance(item, dict):
                    add_action(item.get("b"))
        for w in form.get("h") or []:
            if not isinstance(w, dict):
                continue
            c = w.get("i")
            if isinstance(c, list) and len(c) > 1 and c[0] == "T3" \
                    and isinstance(c[1], list):
                for p in c[1]:
                    if isinstance(p, str):
                        add_action(p)
    return sorted(actions), anims, funnels


def rule_esdl_action_dsl(splicer):
    fc = _FileCache(splicer)
    dsl_ext = ".action.dsl" + ENC_DATA_EXT
    sf_key2paths = {}
    data = fc.read_orderedmap_full("master/battle/boss/funnel/standard_funnel")
    if data:
        header, rows, keys = data
        ci = 1
        for i, row in enumerate(rows):
            p = splicer.cell(row, ci)
            if p:
                sf_key2paths.setdefault(keys[i], []).append(p)
    multiball_actions = []
    for mk in ("master/battle/multiball/multiball",
               "master/battle/multiball/multiball_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        cols = [i for i, h in enumerate(header) if h == "action"]
        for row in rows:
            for c in cols:
                v = splicer.cell(row, c)
                if v:
                    multiball_actions.append(v)

    esdl_visited = set()
    dsl_visited = set()
    dsl_queue = deque()

    def add_dsl(path):
        if "/" not in path:
            return
        splicer.add(path + dsl_ext)
        if path not in dsl_visited:
            dsl_queue.append(path)

    def expand_esdl(base):
        if base in esdl_visited:
            return
        esdl_visited.add(base)
        actions, anims, funnels = _esdl_collect_paths(fc, base)
        for p in actions:
            add_dsl(p)
        for kind, v in anims:
            if kind == "timeline":
                splicer.add(v + ".timeline" + ENC_DATA_EXT)
            else:
                emit_animlayout(splicer, v)
        for fname in funnels:
            for sub in sf_key2paths.get(fname, ()):
                splicer.add(sub + ".esdl" + ENC_DATA_EXT)
                expand_esdl(sub)

    def process_dsl(base):
        if base in dsl_visited:
            return
        dsl_visited.add(base)
        obj = fc.read_decoded(base + ".action.dsl")
        if obj is None:
            return
        cmds = []
        effects = []
        funnels = set()
        _collect_dsl_refs(obj, cmds, effects, funnels)
        for path, spec in effects:
            _emit_dsl_effect(splicer, path, spec)
        for name, params in cmds:
            slots = _ACTION_DSL_NESTED_SLOTS.get(name)
            if slots:
                for s in slots:
                    if s < len(params) and isinstance(params[s], str) and params[s]:
                        add_dsl(params[s])
                if name == "CreateBombMultiball" and len(params) > 1 \
                        and isinstance(params[1], str) and params[1]:
                    emit_animlayout(splicer, params[1])
            if name == "CreateFixedAttack":
                if len(params) > 2 and params[2] == ["Generic"]:
                    emit_animlayout(splicer, "battle/effect/hit/fixed_damage/fixed")
            elif name == "CreateRatioAttack":
                emit_animlayout(splicer, "battle/effect/hit/ratio_damage/quotient")
            elif name == "ChangeFieldAssets":
                for v in params[3:16]:
                    if isinstance(v, list) and len(v) >= 2 and v[0] == "Some" \
                            and isinstance(v[1], str) and v[1]:
                        if v[1].endswith("/dash_panel"):
                            emit_dash_panel(splicer, v[1])
                        else:
                            emit_animlayout(splicer, v[1])
        for fname in funnels:
            for sub in sf_key2paths.get(fname, ()):
                splicer.add(sub + ".esdl" + ENC_DATA_EXT)
                expand_esdl(sub)

    for mk in ("master/battle/boss/standard_boss",
               "master/battle/boss/funnel/standard_funnel"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ci = _col_named(header, "path")
        for row in rows:
            v = splicer.cell(row, ci)
            if v:
                splicer.add(v + ".esdl" + ENC_DATA_EXT)
                expand_esdl(v)
    for p in sorted(q for q in splicer.rec["file_states"] if q.endswith(".esdl" + ENC_DATA_EXT)):
        expand_esdl(p[: -len(".esdl" + ENC_DATA_EXT)])
    for p in sorted(q for q in splicer.rec["file_states"] if q.endswith(dsl_ext)):
        base = p[: -len(dsl_ext)]
        if base not in dsl_visited:
            dsl_queue.append(base)
    for v in multiball_actions:
        add_dsl(v)
    while dsl_queue:
        process_dsl(dsl_queue.popleft())


_ADSL_ELEMENTS = ("red", "blue", "yellow", "green", "white", "black", "colorless")

_ACTION_DSL_NESTED_SLOTS = {
    "CreateBombMultiball": (5,),
    "CreateTornado": (6,),
    "CreateTargetAttack": (4,),
}


def _dsl_effect_path_variant(path, suffix):
    name = path.rsplit("/", 1)[-1]
    return path + "/" + name + "_" + suffix + "/" + name + "_" + suffix


def _collect_dsl_refs(node, cmds, effects, funnels):
    if isinstance(node, list):
        if len(node) >= 2 and node[0] == "Command" \
                and isinstance(node[1], list) and node[1] and isinstance(node[1][0], str):
            cmds.append((node[1][0], node[1][1:]))
        elif node and node[0] in ("SpecifyEffectDirectly", "ResolveByElement"):
            if len(node) >= 2 and isinstance(node[1], str):
                if node[0] == "SpecifyEffectDirectly":
                    effects.append((node[1], None))
                else:
                    try:
                        effects.append((node[1], int(node[2]) if len(node) > 2 else 255))
                    except (ValueError, TypeError):
                        effects.append((node[1], 255))
            return
        elif len(node) == 2 and node[0] in ("Funnel", "Zako", "StandardFunnel") \
                and isinstance(node[1], str):
            funnels.add(node[1])
            return
        for x in node:
            _collect_dsl_refs(x, cmds, effects, funnels)
    elif isinstance(node, dict):
        for v in node.values():
            _collect_dsl_refs(v, cmds, effects, funnels)


def _emit_dsl_effect(splicer, path, spec):
    if spec is None:
        emit_animlayout(splicer, path)
    elif 1 <= spec <= 7:
        emit_animlayout(splicer, _dsl_effect_path_variant(path, _ADSL_ELEMENTS[spec - 1]))
    elif spec == 255:
        for suffix in _ADSL_ELEMENTS:
            emit_animlayout(splicer, _dsl_effect_path_variant(path, suffix))


def rule_terrain_field_objects(splicer):
    fc = _FileCache(splicer)
    terrains = set()
    for mk in ("master/battle/field_data", "master/battle/field_data_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ci = 1
        for row in rows:
            v = splicer.cell(row, ci)
            if v:
                terrains.add(v)
                splicer.add(v + ENC_DATA_EXT)
    for p in splicer.rec["file_states"]:
        if p.startswith("battle/terrain/") and p.endswith(ENC_DATA_EXT):
            terrains.add(p[: -len(ENC_DATA_EXT)])
    for t in sorted(terrains):
        obj = fc.read_decoded(t)
        if not isinstance(obj, dict):
            continue
        for layer in obj.get("layers") or []:
            if not isinstance(layer, dict):
                continue
            for o in layer.get("objects") or []:
                ttype = o.get("type") if isinstance(o, dict) else None
                if not ttype or "#" not in ttype:
                    continue
                head, _, rest = ttype.partition("#")
                kind = _TERRAIN_KIND_MAP.get(head)
                if kind:
                    emit_animlayout(splicer, _terrain_anim_path(rest, kind))
                elif head == "DASH_PANEL_FIXED":
                    pass
                elif head == "DIRECT_INSTANT_ITEM":
                    pass
                elif head == "SKILL_INVOKER":
                    pass
                elif head == "TALKY_YAKUMONO":
                    pass


_SCENARIO_SOURCE_TABLES = (
    ("master/tutorial/triggered_tutorial", "contents_kind", ("4",),
     "contents_kind.values.story_scenario_path"),
    ("master/battle/zone_action", "action", ("9",),
     "action.values.scenario_path"),
    ("master/quest/main_quest", "kind", ("0",),
     "kind.values.story_scenario_path"),
    ("master/quest/ex_quest", "kind", ("0",),
     "kind.values.story_scenario_path"),
    ("master/quest/practice/practice_quest", "kind", ("0",),
     "kind.values.story_scenario_path"),
    ("master/quest/character_quest", "kind", ("0",),
     "kind.values.story_scenario_path"),
    ("master/quest/event/story_event_single_quest", "kind", ("0",),
     "kind.values.story_scenario_path"),
    ("master/quest/event/ranking_event_single_quest", "kind", ("0",),
     "kind.values.story_scenario_path"),
    ("master/quest/event/advent_event_quest", "kind", ("0",),
     "kind.values.story_scenario_path"),
    ("master/quest/event/challenge_dungeon_event_quest", "kind", ("0",),
     "kind.values.story_scenario_path"),
    ("master/quest/event/world_story_event_quest", "kind", ("0",),
     "kind.values.story_scenario_path"),
    ("master/tutorial/tutorial_quest", "kind", ("1",),
     "kind.values.story_scenario_path"),
)


def rule_scenario_contents(splicer):
    fc = _FileCache(splicer)
    scen_paths = set()
    for mk, kind_col, kinds, scen_col in _SCENARIO_SOURCE_TABLES:
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ki = _col_named(header, kind_col)
        si = _col_named(header, scen_col)
        if ki < 0 or si < 0:
            continue
        for row in rows:
            if splicer.cell(row, ki) in kinds:
                sv = splicer.cell(row, si)
                if sv:
                    scen_paths.add(sv)
    for sp in sorted(scen_paths):
        data = fc.read_orderedmap_rows("master/" + sp)
        if not data:
            continue
        header, rows = data
        ti = _col_named(header, "command")
        vi = _col_named(header, "text_voice_path")
        bi = _col_named(header, "background_path")
        for row in rows:
            t = splicer.cell(row, ti)
            if not t:
                continue
            if t == "0":
                v = splicer.cell(row, vi)
                if v:
                    splicer.add(v + ".mp3")
            elif t == "21":
                b = splicer.cell(row, bi)
                if b:
                    splicer.add(b + ".png", verify=True)


def rule_gacha_table_paths(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/gacha/gacha", "master/gacha/tutorial_gacha"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        bcol = _col_named(header, "banner_image")
        ncol = _col_named(header, "note")
        fcol = _col_named(header, "feature_image")
        ci = _col_named(header, "odds_rarity_string_id")
        ct = _col_named(header, "tutorial_odds_rarity_string_id")
        cp = _col_named(header, "prize_kind")
        gcol = _col_named(header, "bgm")
        cchar = _cols_named(header, *_GACHA_CHAR_ODDS_COLS)
        cequip = _cols_named(header, *_GACHA_EQUIP_ODDS_COLS)
        for row in rows:
            v = splicer.cell(row, bcol)
            if v:
                splicer.add(v + ".png")
            v = splicer.cell(row, fcol)
            if v:
                splicer.add(v + ".png")
            v = splicer.cell(row, ncol)
            if v and v != "(None)":
                splicer.add(v + ".html.deflate")
            for c in (ci, ct):
                v = splicer.cell(row, c)
                if v:
                    splicer.add("master/gacha_odds/%s.orderedmap" % v)
            if cp >= 0:
                kind = splicer.cell(row, cp)
                cells = cchar if kind == "0" else \
                    cequip if kind == "1" else ()
                for c in cells:
                    v = splicer.cell(row, c)
                    if v:
                        splicer.add("master/gacha_odds/%s.orderedmap" % v)
            v = splicer.cell(row, gcol)
            if v:
                splicer.add(v + ".mp3")
    data = fc.read_orderedmap_rows("master/gacha/gacha_feature_content")
    if data:
        header, rows = data
        ki = _col_named(header, "asset_kind")
        ii = _col_named(header, "image")
        mi = _col_named(header, "movie")
        for row in rows:
            kind = splicer.cell(row, ki)
            if kind == "0":
                v = splicer.cell(row, mi)
                if v:
                    emit_movie(splicer, v)
            elif kind == "1":
                v = splicer.cell(row, ii)
                if v:
                    splicer.add(v + ".png")
    data = fc.read_orderedmap_rows("master/gacha/gacha_campaign")
    if data:
        header, rows = data
        si = _col_named(header, "share.image")
        for row in rows:
            v = splicer.cell(row, si)
            if v:
                splicer.add(v + ".png")
    data = fc.read_orderedmap_rows("master/ex_boost/ex_boost")
    if data:
        header, rows = data
        ci = _col_named(header, "lots_combination_odds_file_path")
        for row in rows:
            v = splicer.cell(row, ci)
            if v:
                splicer.add("master/ex_boost/odds/lots_combination/%s.orderedmap" % v)
                splicer.add("master/ex_boost/odds/ability/%s_a.orderedmap" % v)
                splicer.add("master/ex_boost/odds/ability/%s_b.orderedmap" % v)


def rule_gacha_movie_ids(splicer):
    fc = _FileCache(splicer)
    data = fc.read_orderedmap_rows("master/gacha/gacha")
    if data:
        header, rows = data
        cols = [17,
                18]
        for row in rows:
            for c in cols:
                v = splicer.cell(row, c)
                if v and v != "(None)":
                    splicer.add("gacha/%s.gacha%s" % (v, ENC_DATA_EXT))
    data = fc.read_orderedmap_rows("master/gacha/tutorial_gacha")
    if data:
        header, rows = data
        ci = _col_named(header, "movie_id")
        for row in rows:
            v = splicer.cell(row, ci)
            if v and v != "(None)":
                splicer.add("gacha/%s.gacha%s" % (v, ENC_DATA_EXT))


def rule_banner_table_paths(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/feature_banner/feature_banner",
               "master/feature_banner/feature_banner_secondary",
               "master/feature_banner/feature_banner_misc"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ci = _col_named(header, "home_banner_path")
        if ci < 0:
            continue
        for row in rows:
            v = splicer.cell(row, ci)
            if not v:
                continue
            for part in v.split(","):
                p = part.strip()
                if p and p != "(None)":
                    splicer.add(p + ".png")
    data = fc.read_orderedmap_rows("master/banner/banner_image")
    if data:
        header, rows = data
        cols = [_col_named(header, "home_banner_path"),
                _col_named(header, "list_banner_path"),
                _col_named(header, "header_mini_banner_path")]
        for row in rows:
            for c in cols:
                if c < 0:
                    continue
                v = splicer.cell(row, c)
                if v:
                    for part in v.split(","):
                        p = part.strip()
                        if p and p != "(None)":
                            splicer.add(p + ".png")


def rule_video_dialog_contents(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/tutorial/video_dialog_contents",
               "master/tutorial/video_dialog_contents_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ki = _col_named(header, "kind")
        pi = _col_named(header, "kind.path")
        for row in rows:
            kind = splicer.cell(row, ki)
            v = splicer.cell(row, pi)
            if not v:
                continue
            if kind == "1":
                emit_movie(splicer, v)
            else:
                splicer.add(v + ".png")


def rule_skill_preview_battle_logs(splicer):
    fc = _FileCache(splicer)
    data = fc.read_orderedmap_rows("master/gacha/gacha_skill_preview")
    if data:
        header, rows = data
        ci = _col_named(header, "log")
        for row in rows:
            v = splicer.cell(row, ci)
            if v:
                splicer.add(v + ".battle" + ENC_DATA_EXT)
    data = fc.read_orderedmap_rows("master/skill_preview/skill_preview_character")
    if data:
        header, rows = data
        for c in _cols_named(header, "log"):
            for row in rows:
                v = splicer.cell(row, c)
                if v:
                    splicer.add(v + ".battle" + ENC_DATA_EXT)

def rule_login_bonus_images(splicer):
    fc = _FileCache(splicer)
    data = fc.read_orderedmap_rows("master/bonus/login_bonus")
    if not data:
        return
    header, rows = data
    bcol = _col_named(header, "background_image")
    icol = _col_named(header, "image_asset_path")
    vcol = _col_named(header, "voice.path")
    for row in rows:
        for c in (bcol, icol):
            if c < 0:
                continue
            v = splicer.cell(row, c)
            if v:
                splicer.add(v + ".png")
        v = splicer.cell(row, vcol)
        if v:
            splicer.add(v + ".mp3")


def rule_player_history_images(splicer):
    fc = _FileCache(splicer)
    data = fc.read_orderedmap_rows("master/player_history/player_history_card_background")
    if data:
        header, rows = data
        cols = [_col_named(header, "frame_image_path"),
                _col_named(header, "thumbnail_image_path")]
        for row in rows:
            for c in cols:
                if c < 0:
                    continue
                v = splicer.cell(row, c)
                if v:
                    splicer.add(v + ".png")
    data = fc.read_orderedmap_rows("master/player_history/player_history_challenge_single_boss")
    if data:
        header, rows = data
        c = _col_named(header, "thumbnail_image_path")
        if c >= 0:
            for row in rows:
                v = splicer.cell(row, c)
                if v:
                    splicer.add(v + ".png")


def rule_boss_battle_stage_node_images(splicer):
    fc = _FileCache(splicer)
    data = fc.read_orderedmap_rows("master/quest/boss_battle_stage_node")
    if not data:
        return
    header, rows = data
    icol = _col_named(header, "image")
    hcol = _col_named(header, "header_background_image")
    gcol = _col_named(header, "bgm")
    for row in rows:
        for c in (icol, hcol):
            if c < 0:
                continue
            v = splicer.cell(row, c)
            if v:
                splicer.add(v + ".png")
        v = splicer.cell(row, gcol)
        if v:
            splicer.add(v + ".mp3")


def rule_floor_thumbnails(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/battle/floor", "master/battle/floor_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ci = _col_named(header, "battle_thumbnail_image")
        if ci < 0:
            continue
        for row in rows:
            v = splicer.cell(row, ci)
            if v:
                splicer.add(v + ".png")


def _emit_character_pixelart(splicer, prefix):
    emit_animlayout(splicer, "character/%s/pixelart/pixelart" % prefix, verify=True)
    emit_animlayout(splicer, "character/%s/pixelart/special" % prefix, verify=True)


def rule_character_ui_paths(splicer):
    fc = _FileCache(splicer)
    char_keys = []
    for mk in ("master/character/character", "master/character/character_iosbundled"):
        data = fc.read_orderedmap_full(mk)
        if not data:
            continue
        header, rows, keys = data
        si = 0
        me = _col_named(header, "max_evolution_level")
        for i, row in enumerate(rows):
            sid = splicer.cell(row, si)
            if not sid:
                continue
            max_evo = 1
            if me >= 0:
                v = splicer.cell(row, me)
                if v:
                    try:
                        max_evo = int(v)
                    except ValueError:
                        pass
            char_keys.append((sid, max_evo))
    extra_ids = set()
    for mk in ("master/story/story_character",
               "master/story/story_character_iosbundled"):
        data = fc.read_orderedmap_full(mk)
        if not data:
            continue
        header, rows, keys = data
        bcol = _col_named(header, "base_image_path")
        fcol = _col_named(header, "face_image_path")
        for i, row in enumerate(rows):
            if keys[i]:
                char_keys.append((keys[i], 1))
            for c in (bcol, fcol):
                if c < 0 or c >= len(row):
                    continue
                v = row[c].strip()
                if v and v != "(None)":
                    for p in (s.strip() for s in v.split(",")):
                        if p and p != "(None)" and "/" in p:
                            splicer.add(p + ".png")
            for v in row:
                v = v.strip() if isinstance(v, str) else ""
                if not v.startswith("character/"):
                    continue
                segs = v.split("/")
                if len(segs) >= 3 and segs[1]:
                    extra_ids.add(segs[1])
    for sid in sorted(extra_ids):
        char_keys.append((sid, 1))
    for sid, max_evo in char_keys:
        evos = (0,) if max_evo < 1 else (0, 1)
        _emit_character_pixelart(splicer, sid)
        for evo in evos:
            for name in _CHAR_UI_EVO_IMAGES:
                if name == "skill_cutin":
                    splicer.add("character/%s/ui/%s_%d.atf.deflate" % (sid, name, evo), verify=True)
                else:
                    splicer.add("character/%s/ui/%s_%d.png" % (sid, name, evo), verify=True)
            for name in _CHAR_FACE_IMAGES:
                splicer.add("character/%s/ui/%s_%d.png" % (sid, name, evo), verify=True)
        splicer.add("character/%s/ui/episode_banner_0.png" % sid, verify=True)
        base = "character/%s/ui/illustration_setting_sprite_sheet" % sid
        splicer.add(base + ".png", verify=True)
        splicer.add(base + ".atlas" + ENC_DATA_EXT, verify=True)
        splicer.add("character/%s/battle/character_detail_skill_preview.battle%s" % (sid, ENC_DATA_EXT), verify=True)
        splicer.add("character/%s/battle/character_info_skill_preview.battle%s" % (sid, ENC_DATA_EXT), verify=True)


def rule_battle_voice_lists(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/character/character", "master/character/character_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        si = 0
        for row in rows:
            sid = splicer.cell(row, si)
            if not sid:
                continue
            base = "character/%s/voice/battle/" % sid
            for prefix in _BATTLE_VOICE_PREFIXES:
                for i in range(512):
                    cand = base + prefix + str(i) + ".mp3"
                    if not splicer.exists(cand):
                        break
                    splicer.add(cand, verify=True)
            for key in _BATTLE_VOICE_SINGLE:
                cand = base + key + ".mp3"
                splicer.add(cand, verify=True)


def rule_flipper_skin(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/equipment_enhancement/equipment_flipper_skin/flipper_skin",
               "master/equipment_enhancement/equipment_flipper_skin/flipper_skin_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        c1 = _col_named(header, "flipper_animation_path")
        c2 = _col_named(header, "flipper_additional_animation_path")
        for row in rows:
            for c in (c1, c2):
                if c < 0:
                    continue
                v = splicer.cell(row, c)
                if v:
                    emit_animlayout(splicer, v)


def rule_atlas_subimages(splicer):
    fc = _FileCache(splicer)
    for p in sorted(q for q in splicer.rec["file_states"] if q.endswith(".atlas" + ENC_DATA_EXT)):
        obj = fc.read_decoded(p[: -len(ENC_DATA_EXT)])
        if not isinstance(obj, list):
            continue
        for entry in obj:
            if isinstance(entry, dict):
                n = entry.get("n")
                if isinstance(n, str) and n:
                    splicer.add(n + ".png", verify=True)


def rule_parts_images(splicer):
    fc = _FileCache(splicer)
    for p in sorted(q for q in splicer.rec["file_states"] if q.endswith(".parts" + ENC_DATA_EXT)):
        obj = fc.read_decoded(p[: -len(ENC_DATA_EXT)])
        if not isinstance(obj, dict):
            continue
        imgs = obj.get("i")
        if not isinstance(imgs, list):
            continue
        for it in imgs:
            if isinstance(it, dict):
                v = it.get("p")
                if isinstance(v, str) and v:
                    splicer.add(v + ".png", verify=True)


def rule_ex_boost_odds_kinds(splicer):
    fc = _FileCache(splicer)
    for mk in _iter_master_names(splicer):
        if not mk.startswith("master/ex_boost/odds/lots_combination/"):
            continue
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        _, rows = data
        for row in rows:
            cells = list(row)
            i = 1
            while i + 1 < len(cells):
                v0 = cells[i].strip() if i < len(cells) else ""
                v1 = cells[i + 1].strip() if i + 1 < len(cells) else ""
                i += 2
                if not v1 or v1 == "(None)":
                    continue
                if v0 == "0":
                    splicer.add("master/ex_boost/odds/status/%s.orderedmap" % v1)
                elif v0 == "1":
                    splicer.add("master/ex_boost/odds/ability/%s.orderedmap" % v1)


def rule_assist_cutin_voices(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/battle/assist/assist_cutin",
               "master/battle/assist/assist_cutin_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ci = _col_named(header, "joining_voice_paths")
        if ci < 0:
            continue
        for row in rows:
            v = splicer.cell(row, ci)
            if not v:
                continue
            for p in (s.strip() for s in v.split(",")):
                if p and p != "(None)":
                    splicer.add(p + ".mp3")


def rule_multiball_pixelart(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/battle/multiball/multiball",
               "master/battle/multiball/multiball_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ci = _col_named(header, "image_prefix")
        if ci < 0:
            continue
        for row in rows:
            v = splicer.cell(row, ci)
            if v:
                emit_animlayout(splicer, "character/%s/pixelart/pixelart" % v)


def rule_help_pages(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/help/help", "master/help/help_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        _, rows = data
        for row in rows:
            for v in row:
                for part in (s.strip() for s in v.split(",")):
                    if part.startswith("rich_text/"):
                        splicer.add(part + ".html.deflate")


def rule_rich_text_images(splicer):
    fc = _FileCache(splicer)
    for rel in sorted(splicer.rec["file_states"]):
        if not (rel.startswith("rich_text/") and rel.endswith(".html.deflate")):
            continue
        html = fc.read_text(rel[:-len(".deflate")])
        if not html:
            continue
        for src in re.findall(r'src="([^"]+)"', html):
            if src.startswith("file://"):
                splicer.add(src[len("file://"):].split(".")[0] + ".png")


def rule_orb_images(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/item/equipment", "master/item/equipment_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ki = _col_named(header, "kind")
        fi = _col_named(header, "kind.values.orb_full_size_image")
        ti = _col_named(header, "kind.values.orb_thumbnail_image")
        for row in rows:
            if splicer.cell(row, ki) != "1":
                continue
            full = splicer.cell(row, fi)
            thumb = splicer.cell(row, ti)
            if full:
                splicer.add(full + ".png")
                splicer.add(full + "_small.png")
            if thumb:
                splicer.add(thumb + ".png")


def rule_timeline_sounds(splicer):
    fc = _FileCache(splicer)
    ext = ".timeline" + ENC_DATA_EXT
    for p in sorted(q for q in splicer.rec["file_states"] if q.endswith(ext)):
        obj = fc.read_decoded(p[:-len(ENC_DATA_EXT)])
        if not isinstance(obj, dict):
            continue
        for s in obj.get("sounds") or []:
            if isinstance(s, dict):
                v = s.get("path")
                if isinstance(v, str) and v:
                    splicer.add(v + ".mp3")


def rule_assist_multiball_voices(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/battle/assist/assist_multiball",
               "master/battle/assist/assist_multiball_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ci = _col_named(header, "skill_voice_paths")
        icol = _col_named(header, "skill_cutin_image_path")
        for row in rows:
            v = splicer.cell(row, icol)
            if v:
                splicer.add(v + ".png")
            v = splicer.cell(row, ci)
            if not v:
                continue
            for part in (s.strip() for s in v.split(",")):
                if not part or part == "(None)":
                    continue
                splicer.add(part + ".mp3")


def rule_feature_guide_dialog(splicer):
    fc = _FileCache(splicer)
    data = fc.read_orderedmap_rows("master/feature_banner/feature_guide_dialog")
    if not data:
        return
    header, rows = data
    ci = _col_named(header, "image")
    if ci < 0:
        return
    for row in rows:
        v = splicer.cell(row, ci)
        if v and v.startswith("dynamic/"):
            splicer.add(v + ".png")


_BOSS_FAMILY_TABLES = (
    "master/battle/boss/general_boss",
    "master/battle/boss/funnel/general_funnel",
    "master/battle/zako/general_zako",
    "master/battle/boss/conductor",
    "master/battle/boss/orochi",
    "master/battle/boss/orochi_ex",
    "master/battle/boss/kraken",
    "master/battle/boss/funnel/tentacle",
    "master/battle/boss/touyakiren_ceo",
    "master/battle/boss/wind_sphere",
    "master/battle/boss/water_sphere",
    "master/battle/boss/thunder_sphere",
    "master/battle/boss/holy_sphere",
    "master/battle/boss/fire_sphere",
)

_ABILITY_DAMAGE_ELEMENTS = ("red", "blue", "yellow", "green", "white", "black")
_ABILITY_DAMAGE_KINDS = ("hit", "player", "shot")


def rule_instant_ability_effects(splicer):
    for e in _ABILITY_DAMAGE_ELEMENTS:
        for k in _ABILITY_DAMAGE_KINDS:
            emit_animlayout(
                splicer,
                "battle/effect/ability_damage/ability_damage_%s/ability_damage_%s_%s" % (e, k, e))


def rule_instant_item_animations(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/battle/item/executable_instant_item",
               "master/battle/item/obtainable_instant_item",
               "master/battle/item/executable_instant_item_iosbundled",
               "master/battle/item/obtainable_instant_item_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ci = _col_named(header, "animation_path")
        pc = _col_named(header, "program_path")
        for row in rows:
            v = splicer.cell(row, ci)
            if v:
                emit_animlayout(splicer, v)
            v = splicer.cell(row, pc)
            if v:
                splicer.add(v + ".action.dsl" + ENC_DATA_EXT)


def rule_zone_animation_columns(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/battle/zone", "master/battle/zone_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        cols = [35,
                37]
        for row in rows:
            for c in cols:
                v = splicer.cell(row, c)
                if v:
                    emit_animlayout(splicer, v)


def rule_talky_yakumono_animations(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/battle/yakumono/talky_yakumono",
               "master/battle/yakumono/talky_yakumono_iosbundled",
               "master/battle/assist/assist_yakumono",
               "master/battle/assist/assist_yakumono_iosbundled",
               "master/battle/yakumono/skill_invoker",
               "master/battle/yakumono/skill_invoker_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ci = 1 if mk.startswith("master/battle/assist/assist_yakumono") else 0
        for row in rows:
            v = splicer.cell(row, ci)
            if v:
                emit_animlayout(splicer, v)


def rule_degree_string_id_icons(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/degree/degree",):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        ci = _col_named(header, "string_id")
        if ci < 0:
            continue
        for row in rows:
            v = splicer.cell(row, ci)
            if v:
                splicer.add("dynamic/degree/%s.png" % v)


def rule_thumbnail_numbered_frames(splicer):
    for p in list(splicer.out):
        if not p.startswith("quest/thumbnail/") or not p.endswith(".png"):
            continue
        d, name = p.rsplit("/", 1)
        name = name[: -len(".png")]
        bases = []
        m = re.match(r"^(.+?)_(\d+)$", name)
        if m and m.group(2).isdigit():
            bases.append(m.group(1))
        if name.isdigit():
            bases.append("")
        for base in bases:
            for n in range(1, 16):
                for tail in ("%02d" % n, str(n)):
                    cand = "%s/%s%s.png" % (d, base + "_" if base else "", tail)
                    splicer.add(cand, verify=True)


def rule_boss_funnel_family(splicer):
    fc = _FileCache(splicer)
    tables = list(_BOSS_FAMILY_TABLES)
    for mk in _iter_master_names(splicer):
        if not mk.startswith("master/battle/"):
            continue
        if any(mk == t or mk.startswith(t + "_") for t in _BOSS_FAMILY_TABLES):
            tables.append(mk)
    for mk in tables:
        data = fc.read_orderedmap_full(mk)
        if not data:
            continue
        header, rows, keys = data
        bases = set()
        for row in rows:
            for v in row:
                v = v.strip()
                if not v.startswith(("battle/boss/", "battle/funnel/")):
                    continue
                bases.add(v)
                if v.endswith("_marker"):
                    bases.add(v[: -len("_marker")])
                elif v.endswith("_shadow"):
                    bases.add(v[: -len("_shadow")])
        for b in sorted(bases):
            emit_animlayout(splicer, b)


def rule_asset_keys(splicer):
    fc = _FileCache(splicer)
    for mk in ("master/asset/bgm_asset", "master/asset/bgm_asset_bundled",
               "master/asset/bgm_asset_iosbundled",
               "master/asset/sound_effect_asset", "master/asset/sound_effect_asset_bundled",
               "master/asset/sound_effect_asset_iosbundled",
               "master/asset/voice_asset", "master/asset/voice_asset_bundled",
               "master/asset/voice_asset_iosbundled"):
        data = fc.read_orderedmap_full(mk)
        if not data:
            continue
        header, rows, keys = data
        for k in keys:
            k = k.strip()
            if k:
                splicer.add(k + ".mp3")
    for mk in ("master/generated/trimmed_image",
               "master/generated/trimmed_image_iosbundled"):
        data = fc.read_orderedmap_full(mk)
        if not data:
            continue
        header, rows, keys = data
        for k in keys:
            k = k.strip()
            if k:
                splicer.add(k + ".png")
    for mk in ("master/string/ui_string", "master/string/ui_string_bundled",
               "master/string/ui_string_iosbundled"):
        data = fc.read_orderedmap_rows(mk)
        if not data:
            continue
        header, rows = data
        si = _col_named(header, "string")
        for row in rows:
            v = splicer.cell(row, si)
            if v and v.startswith("dynamic/"):
                splicer.add(v + ".png")


def rule_master_schema(splicer):
    for mk in _iter_master_names(splicer):
        table = mk[len("master/"):]
        splicer.add("master_schema/" + table + "_schema" + ENC_DATA_EXT, verify=True)


def rule_box_gacha_background(splicer):
    fc = _FileCache(splicer)
    data = fc.read_orderedmap_rows("master/box_gacha/box_gacha")
    if data:
        header, rows = data
        ci = _col_named(header, "background_animation")
        gcol = _col_named(header, "change_bgm")
        for row in rows:
            v = splicer.cell(row, ci)
            if v:
                emit_animlayout(splicer, v, gated=False)
            v = splicer.cell(row, gcol)
            if v:
                splicer.add(v + ".mp3")
    _register_master_cells(splicer, fc, "master/box_gacha/box",
                           {".png": "empty_thumbnail,locked_thumbnail,logo_image,thumbnail"})


def rule_field_object_layouts(splicer):
    known = set(splicer.out)
    known.update(splicer.rec["file_states"])
    anim_suf = (".parts" + ENC_DATA_EXT, ".frame" + ENC_DATA_EXT, ".timeline" + ENC_DATA_EXT)
    img_suf = (".png", ".atlas" + ENC_DATA_EXT)
    all_suf = anim_suf + img_suf

    dirs = defaultdict(set)
    for p in known:
        if not p.startswith("battle/field_object/"):
            continue
        d, fn = p.rsplit("/", 1)
        if d.count("/") < 3:
            continue
        dirs[d].add(fn)

    for d, fns in sorted(dirs.items()):
        kind = d.rsplit("/", 1)[-1]
        area = d.rsplit("/", 2)[-2]

        for s in img_suf:
            splicer.add("%s/%s%s" % (d, kind, s), verify=True)
        for s in all_suf:
            splicer.add("%s/%s%s" % (d, kind, s), verify=True)
            splicer.add("%s/%s_%s%s" % (d, area, kind, s), verify=True)
        for fn in sorted(fns):
            stem = fn
            for s in all_suf:
                if stem.endswith(s):
                    stem = stem[:-len(s)]
                    break
            m = re.search(r"_zone(\d+)$", stem)
            if not m:
                continue
            zbase = stem[: m.start()]
            for n in range(1, 13):
                for s in all_suf:
                    splicer.add("%s/%s_zone%d%s" % (d, zbase, n, s), verify=True)


def rule_npc_character(splicer):
    fc = _FileCache(splicer)
    data = fc.read_orderedmap_rows("master/encyclopedia/encyclopedia")
    if not data:
        return
    header, rows = data
    ci = _col_named(header, "npc_character_id")
    if ci < 0:
        return
    faces = ("square", "square_132_132", "square_round_136_136",
             "square_round_95_95", "battle_member_status")
    for row in rows:
        v = splicer.cell(row, ci)
        if not v:
            continue
        for face in faces:
            splicer.add("character/%s/ui/%s_0.png" % (v, face), verify=True)
        pa = "character/%s/pixelart/pixelart" % v
        for s in (".parts" + ENC_DATA_EXT, ".frame" + ENC_DATA_EXT, ".timeline" + ENC_DATA_EXT):
            splicer.add(pa + s, verify=True)
        splicer.add("character/%s/pixelart/sprite_sheet.png" % v, verify=True)
        splicer.add("character/%s/pixelart/sprite_sheet.atlas" % v + ENC_DATA_EXT, verify=True)


def rule_field_object_siblings(splicer):
    known = set(splicer.out)
    known.update(splicer.rec["file_states"])
    all_suf = (".parts" + ENC_DATA_EXT, ".frame" + ENC_DATA_EXT, ".timeline" + ENC_DATA_EXT,
               ".png", ".atlas" + ENC_DATA_EXT)
    areas = set()
    for p in known:
        seg = p.split("/")
        if len(seg) >= 5 and seg[0] == "battle" and seg[1] == "field" \
                and not p.startswith("battle/field_object/"):
            areas.add((seg[2], seg[3]))

    for world, area in sorted(areas):
        base = "battle/field_object/%s/%s" % (world, area)
        for kind, name in (("gate", "%s_gate" % area),
                           ("transit_pod", "%s_transit_pod" % area),
                           ("fever_gauge", "%s_fever_gauge" % area)):
            for s in all_suf:
                splicer.add("%s/%s/%s%s" % (base, kind, name, s), verify=True)
        for s in (".png", ".atlas" + ENC_DATA_EXT):
            for kind in ("gate", "transit_pod", "outhole", "fever_gauge", "rotation_panel"):
                splicer.add("%s/%s/%s%s" % (base, kind, kind, s), verify=True)
        for zn in range(1, 13):
            for s in (".parts" + ENC_DATA_EXT, ".frame" + ENC_DATA_EXT, ".timeline" + ENC_DATA_EXT):
                splicer.add("%s/outhole/%s_outhole_zone%d%s" % (base, area, zn, s), verify=True)
                splicer.add("%s/outhole/outhole_zone%d%s" % (base, zn, s), verify=True)


def rule_atlas_gen_layouts(splicer):
    fc = _FileCache(splicer)
    known = set(splicer.out)
    known.update(splicer.rec["file_states"])
    sufs = (".parts" + ENC_DATA_EXT, ".frame" + ENC_DATA_EXT, ".timeline" + ENC_DATA_EXT,
            ".movie" + ENC_DATA_EXT, ".ui" + ENC_DATA_EXT)
    for p in sorted(q for q in splicer.rec["file_states"] if q.endswith(".atlas" + ENC_DATA_EXT)):
        obj = fc.read_decoded(p[: -len(ENC_DATA_EXT)])
        if not isinstance(obj, list):
            continue
        seen = set()
        for e in obj:
            if not isinstance(e, dict):
                continue
            n = e.get("n")
            if not isinstance(n, str) or "/.gen/" not in n:
                continue
            d, rest = n.split("/.gen/", 1)
            anim = rest.split("/")[0]
            key = d + "/" + anim
            if key in seen or key in known:
                continue
            seen.add(key)
            for s in sufs:
                c = key + s
                splicer.add(c, verify=True)


def rule_anim_layout_sheets(splicer):
    known = set(splicer.out)
    known.update(splicer.rec["file_states"])
    anim_suf = (".parts" + ENC_DATA_EXT, ".timeline" + ENC_DATA_EXT, ".frame" + ENC_DATA_EXT)
    stems = set()
    for p in known:
        for s in anim_suf:
            if p.endswith(s):
                stems.add(p[:-len(s)])
                break
    for st in sorted(stems):
        for s in anim_suf:
            splicer.add(st + s, verify=True)
        sheet = derive_sprite_sheet(st)
        if sheet:
            splicer.add(sheet + ".png", verify=True)
            splicer.add(sheet + ".atlas" + ENC_DATA_EXT, verify=True)


_MENU4_RULES = (
    rule_enemy_source_fields,
    rule_zone_dash_panel,
    rule_sound_keys,
    rule_voices,
    rule_town_content,
    rule_feature_announcement,
    rule_degree,
    rule_ability_action_paths,
    rule_active_mission_assets,
    rule_assist_yakumono_skill_assets,
    rule_campaign_assets,
    rule_character_election_images,
    rule_collect_item_event_assets,
    rule_encyclopedia_world_assets,
    rule_equipment_enhancement_shop_images,
    rule_event_ui_assets,
    rule_payment_display_assets,
    rule_quest_ui_assets,
    rule_shop_thumbnails,
    rule_skill_icons,
    rule_skill_program_actions,
    rule_tips_images,
    rule_town_bgm_assets,
    rule_unique_condition_icon,
    rule_story_columns,
    rule_field_columns,
    rule_event_backgrounds,
    rule_stage_node_backgrounds,
    rule_enemy_element_columns,
    rule_esdl_action_dsl,
    rule_terrain_field_objects,
    rule_scenario_contents,
    rule_gacha_table_paths,
    rule_gacha_movie_ids,
    rule_banner_table_paths,
    rule_video_dialog_contents,
    rule_skill_preview_battle_logs,
    rule_login_bonus_images,
    rule_player_history_images,
    rule_boss_battle_stage_node_images,
    rule_floor_thumbnails,
    rule_character_ui_paths,
    rule_battle_voice_lists,
    rule_boss_funnel_family,
    rule_instant_ability_effects,
    rule_instant_item_animations,
    rule_zone_animation_columns,
    rule_talky_yakumono_animations,
    rule_degree_string_id_icons,
    rule_asset_keys,
    rule_master_schema,
    rule_thumbnail_numbered_frames,
    rule_flipper_skin,
    rule_atlas_subimages,
    rule_parts_images,
    rule_ex_boost_odds_kinds,
    rule_assist_cutin_voices,
    rule_multiball_pixelart,
    rule_help_pages,
    rule_rich_text_images,
    rule_orb_images,
    rule_timeline_sounds,
    rule_assist_multiball_voices,
    rule_feature_guide_dialog,
    rule_npc_character,
    rule_box_gacha_background,
    rule_atlas_gen_layouts,
    rule_field_object_layouts,
    rule_field_object_siblings,
    rule_anim_layout_sheets,
)


def menu4_collect_dynamic_paths(rec):
    _FileCache.reset()
    _SCHEMA_JSON_CACHE.clear()
    HASHED_PATH_CACHE.clear()
    splicer = PathSplicer(rec)
    t0 = time.time()
    total = len(_MENU4_RULES)

    def _dwidth(s):
        return sum(2 if ord(c) > 0x2E7F else 1 for c in s)

    prev_w = 0
    for i, rule in enumerate(_MENU4_RULES, 1):
        rule(splicer)
        line = "\r[菜单4 %d/%d] %s | 已拼接路径 %d | 候选 %d | 用时 %.1fs" % (
            i, total, rule.__name__, len(splicer.out), splicer.candidate_count,
            time.time() - t0)
        w = _dwidth(line)
        if prev_w > w:
            line += " " * (prev_w - w)
        prev_w = max(prev_w, w)
        sys.stdout.write(line)
        sys.stdout.flush()
    sys.stdout.write("\n")
    return sorted(splicer.out), splicer.candidate_count


def menu4(rec):
    t0 = time.time()
    ensure_hash_map(rec)
    new_paths, candidate_count = menu4_collect_dynamic_paths(rec)
    merged = sorted(set(normalize_path(p) for p in new_paths if p))
    added = append_unique_lines(ASSET_PATH_TXT, merged)
    print("路径拼接：候选 %d，输出 %d，本轮新增 %d，耗时 %.1fs"
          % (candidate_count, len(merged), added, time.time() - t0))


def menu5(rec):
    prev_total = len(read_path_list(ASSET_PATH_TXT))
    for rnd in range(1, 21):
        print("===== 第 %d 轮 =====" % rnd)
        menu1(rec)
        menu2(rec)
        menu3(rec)
        menu4(rec)
        cur_total = len(read_path_list(ASSET_PATH_TXT))
        if cur_total == prev_total:
            print("AssetPath 无新增，已收敛。")
            break
        prev_total = cur_total


def classify_content(data):
    if data[:8] == b"\x89png\r\n\x1a\n":
        return "png", "png", ".png"
    if data[:3] == b"ID3" or (len(data) > 2 and data[0] == 0x7F):
        return "mp3", "mp3", ".mp3"
    if len(data) > 6 and data[:2] == b"\x78\xda":
        try:
            blob = zlib.decompress(data)
            _om_parse_index(blob)
            try:
                om_parse_generic(data)
                return "orderedmap", "om_csv", ".csv"
            except Exception:
                return "orderedmap", "copy", ".orderedmap"
        except Exception:
            pass
    if len(data) > 8:
        n = struct.unpack_from("<i", data, 0)[0]
        if 0 < n < len(data) and data[4:6] == b"\x78\xda":
            try:
                blob = zlib.decompress(data[4:4 + n])
                _om_parse_index(blob)
                try:
                    om_parse_generic(data)
                    return "orderedmap_nested", "om_csv", ".csv"
                except Exception:
                    return "orderedmap_nested", "copy", ".orderedmap"
            except Exception:
                pass
    amf3 = False
    try:
        out = raw_inflate(data)
        if out and out[0] in (0x06, 0x09, 0x0A, 0x0C):
            amf3 = True
        elif out[:5] == b"<?xml" or b"<" in out[:32]:
            return "xml", "inflate", ".xml"
        else:
            if not out:
                return "deflate", "inflate", ".bin"
            _k, t2, e2 = classify_content(out)
            if t2 == "inflate":
                return "deflate", "inflate", ".bin"
            if t2 == "amf3_json":
                return "deflate", "inflate_amf3", ".json"
            return "deflate", t2, e2
    except Exception:
        pass
    if not amf3 and data and data[0] in (0x06, 0x09, 0x0A, 0x0C):
        try:
            amf3_decode(data)
            amf3 = True
        except Exception:
            pass
    if amf3:
        if data and data[0] in (0x06, 0x09, 0x0A, 0x0C):
            return "amf3", "amf3_json", ".json"
        return "amf3", "inflate_amf3", ".json"
    return "raw", "copy", ".bin"


def menu6(rec):
    ensure_hash_map(rec)
    known_hashes = set()
    for p in read_path_list(CODE_PATH_TXT) + read_path_list(ASSET_PATH_TXT):
        known_hashes.add(get_hashed_rel(p))
    old_paths = read_path_list(OLD_PATH_TXT)
    for p in old_paths:
        known_hashes.add(get_hashed_rel(p))
    unmapped = []
    for key, rels in rec["hash_map"].items():
        if len(key) == 41 and key[2] == "/" and key not in known_hashes:
            unmapped.extend(rels)
    print("无路径文件：%d 个" % len(unmapped))
    tasks = []
    for rel in unmapped:
        hname = "_".join(rel.split("/")[-2:])
        tasks.append((rel, hname))
    if old_paths:
        odir = os.path.join(UNMAPPED_DIR, "intermediate")
        for p in old_paths:
            src_rel = pick_source(rec["hash_map"], p)
            if src_rel:
                dst = os.path.join(odir, p.replace("/", os.sep))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(os.path.join(BASE_DIR, src_rel.replace("/", os.sep)), dst)
        print("OldPath 还原 %d 条至 Unmapped/intermediate" % len(old_paths))
    got = []
    run_parallel(tasks, make_batch(task_menu6), "[菜单6 内容解密→可读态]", results=got)
    counts = {}
    for folder in got:
        counts[folder] = counts.get(folder, 0) + 1
    print("按格式输出：" + ", ".join("%s=%d" % kv for kv in sorted(counts.items())))


def enc_step1(rec):
    tasks_j, tasks_c = [], []
    for rel in iter_intermediate():
        if rel.endswith(".json"):
            tasks_j.append(("intermediate/" + rel,
                            "intermediate/" + rel[:-len(".json")] + ".amf3"))
        elif rel.endswith(".csv"):
            tasks_c.append(("intermediate/" + rel,
                            "intermediate/" + rel[:-len(".csv")] + ".orderedmap"))
    ok_j = run_parallel(tasks_j, make_batch(task_json_to_amf3), "[加密1 json→amf3]", chunk=32)
    ok_c = run_parallel(tasks_c, make_batch(task_csv_to_om), "[加密1 csv→orderedmap]", chunk=64)
    ok_set = ok_j | ok_c
    for t in tasks_j + tasks_c:
        if t[0] not in ok_set:
            continue
        try:
            os.remove(os.path.join(BASE_DIR, t[0].replace("/", os.sep)))
        except OSError:
            pass
        logical = t[0][len("intermediate/"):]
        logical = re.sub(r"\.(json|csv)$",
                         lambda m: ".amf3.deflate" if m.group(1) == "json" else ".orderedmap",
                         logical)
        rec["file_states"][normalize_path(logical)] = 2
    save_record(rec)
    print("加密1 完成")


def enc_step2(rec):
    states = rec["file_states"]
    tasks = []
    for logical, st in list(states.items()):
        if st < 2:
            continue
        kind = classify_logical(logical)
        cur = menu2_name(logical)
        cur_abs = os.path.join(INTERMEDIATE_DIR, cur.replace("/", os.sep))
        if not os.path.isfile(cur_abs):
            continue
        if kind == "data_deflate":
            tasks.append(("intermediate/" + cur, "intermediate/" + logical, "inflate"))
        elif kind == "text_deflate":
            tasks.append(("intermediate/" + cur, "intermediate/" + logical, "inflate"))
        elif kind == "png":
            tasks.append(("intermediate/" + cur, "intermediate/" + cur, "png_enc"))
        elif kind == "mp3":
            tasks.append(("intermediate/" + cur, "intermediate/" + cur, "mp3_enc"))
    run_parallel(tasks, make_batch(task_menu2_enc), "[加密2 重加密]")
    for logical in list(states.keys()):
        if states.get(logical, 0) >= 2:
            states[logical] = 1
    save_record(rec)
    print("加密2 完成：%d 个" % len(tasks))


def task_menu2_enc(args):
    src_rel, dst_rel, kind = args
    src = os.path.join(BASE_DIR, src_rel.replace("/", os.sep))
    dst = os.path.join(BASE_DIR, dst_rel.replace("/", os.sep))
    with open(src, "rb") as f:
        data = f.read()
    if kind == "inflate":
        out = raw_deflate(data)
    elif kind == "png_enc":
        with open(src, "r+b") as f:
            f.write(b"\x89png")
        return dst_rel
    elif kind == "mp3_enc":
        out = mp3_encode(data)
    else:
        out = data
    if dst_rel != src_rel:
        safe_write(dst, out)
        try:
            os.remove(src)
        except OSError:
            pass
    else:
        safe_write(src, out)
    return dst_rel


def enc_step3(rec):
    ensure_hash_map(rec)
    moved = failed = 0
    for rel in iter_intermediate():
        src_abs = os.path.join(INTERMEDIATE_DIR, rel.replace("/", os.sep))
        src_rel_full = "intermediate/" + rel
        cands = rec["hash_map"].get(get_hashed_rel(rel))
        if not cands:
            failed += 1
            continue
        target_rel = cands[0]
        dst_abs = os.path.join(ENCRYPTED_DIR, target_rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(dst_abs), exist_ok=True)
        shutil.move(src_abs, dst_abs)
        moved += 1
        rec["file_states"].pop(rel, None)
    save_record(rec)
    print("加密3：移动 %d 个至 Encrypted，未匹配 %d 个" % (moved, failed))


def check_codepath():
    if not os.path.isfile(CODE_PATH_TXT):
        print("缺少 CodePath.txt")
        return False
    return True


def main():
    if not check_codepath():
        sys.exit(1)
    rec = load_record()
    mode = MODE_DECRYPT
    while True:
        mode_name = "解密" if mode == MODE_DECRYPT else "加密"
        print("\n=== WorldFlipper 数据包工具 [%s模式] ===" % mode_name)
        if mode == MODE_DECRYPT:
            print("1. 路径还原")
            print("2. 解密至游戏格式（png，mp3，deflate）")
            print("3. 解密至可读格式（amf3>json，orderedmap>csv）")
            print("4. 路径拼接>AssetPath.txt")
            print("5. 循环运行1-4")
            print("6. Unmapped处理")
        else:
            print("1. 可读格式加密（json>amf3，csv>orderedmap）")
            print("2. 游戏格式加密（png，mp3，deflate）")
            print("3. 路径加密至Encrypted")
        print("s. 切换模式")
        choice = input("> ").strip().lower()
        try:
            if choice == "s":
                mode = MODE_ENCRYPT if mode == MODE_DECRYPT else MODE_DECRYPT
            elif choice == "1":
                if mode == MODE_DECRYPT:
                    menu1(rec)
                else:
                    enc_step1(rec)
            elif choice == "2":
                if mode == MODE_DECRYPT:
                    menu2(rec)
                else:
                    enc_step2(rec)
            elif choice == "3":
                if mode == MODE_DECRYPT:
                    menu3(rec)
                else:
                    enc_step3(rec)
            elif choice == "4":
                if mode == MODE_DECRYPT:
                    menu4(rec)
                else:
                    print("加密模式下无此步骤")
            elif choice == "5":
                if mode == MODE_DECRYPT:
                    menu5(rec)
                else:
                    enc_step1(rec)
                    enc_step2(rec)
                    enc_step3(rec)
            elif choice == "6":
                if mode == MODE_DECRYPT:
                    menu6(rec)
                else:
                    print("加密模式下无此步骤")
            else:
                print("无效输入")
        except KeyboardInterrupt:
            print("\n中断（进度已持久化）")
        except Exception as e:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
