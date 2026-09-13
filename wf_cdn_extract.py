import json
import os
import re
import shutil
import sys
import zipfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(ROOT, "extract_config.json")

DIR_RE = re.compile(r"^archive-(.+)-(full|diff)$")
FULL_RE = re.compile(r"^(?:asset|pinball)-(\d+\.\d+\.\d+)-(\d+)-([0-9a-f]+)\.zip$")
DIFF_RE = re.compile(r"^(?:asset|pinball)-(\d+\.\d+\.\d+)-(\d+\.\d+\.\d+)-(\d+)-([0-9a-f]+)\.zip$")

PLATFORM_GROUPS = {
    "android": ["android", "common", "medium"],
    "ios": ["ios", "common", "medium"],
}
VARIANT_GROUPS = ["android_medium", "android_small"]


def load_config():
    cfg = {"platform": "android", "include_android_variants": False}
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                cfg.update(saved)
        except Exception as e:
            print("[警告] 读取 extract_config.json 失败，使用默认配置: %s" % e)
    if cfg.get("platform") not in PLATFORM_GROUPS:
        cfg["platform"] = "android"
    cfg["include_android_variants"] = bool(cfg.get("include_android_variants"))
    return cfg


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print("[警告] 写入 extract_config.json 失败: %s" % e)


def vkey(version):
    return tuple(int(x) for x in version.split("."))


def scan():
    groups = {}
    for entry in sorted(os.listdir(ROOT)):
        fullpath = os.path.join(ROOT, entry)
        if not os.path.isdir(fullpath):
            continue
        m = DIR_RE.match(entry)
        if not m:
            continue
        group, kind = m.group(1), m.group(2)
        bucket = groups.setdefault(group, {})
        store = bucket.setdefault(kind, {})
        for name in sorted(os.listdir(fullpath)):
            p = os.path.join(fullpath, name)
            if not os.path.isfile(p):
                continue
            if kind == "full":
                fm = FULL_RE.match(name)
                if fm:
                    store.setdefault(fm.group(1), []).append((int(fm.group(2)), p))
            else:
                dm = DIFF_RE.match(name)
                if dm:
                    store.setdefault((dm.group(1), dm.group(2)), []).append((int(dm.group(3)), p))
    for bucket in groups.values():
        for kind in ("full", "diff"):
            for k in bucket.get(kind, {}):
                bucket[kind][k].sort()
    return groups


def build_chain(group, bucket):
    errors = []
    fulls = bucket.get("full", {})
    diffs = bucket.get("diff", {})
    if not fulls:
        return None, [], None, ["缺 full 目录（游戏逻辑会报 'Asset initial version not found'）"], []
    full_vers = sorted(fulls.keys(), key=vkey)
    if len(full_vers) != 1:
        errors.append("full 版本不唯一: %s（需人工确认，不做猜测）" % full_vers)
        return None, [], None, errors, []
    start = full_vers[0]

    edges = {}
    for (a, b), files in diffs.items():
        if a in edges:
            errors.append("diff 链分叉: %s -> %s 与 %s -> %s" % (a, edges[a][0], a, b))
        else:
            edges[a] = (b, [p for _, p in files])

    chain = []
    used = set()
    cur = start
    while cur in edges:
        nxt, files = edges[cur]
        chain.append((nxt, files))
        used.add((cur, nxt))
        cur = nxt
    if not chain:
        errors.append("diff 链为空：没有任何包以 full 版本 %s 为起点" % start)
    outside = [(a, b) for (a, b) in diffs if (a, b) not in used]
    return start, chain, cur, errors, outside


class Stats:
    def __init__(self):
        self.zips = 0
        self.written = 0
        self.skipped_dirs = 0
        self.skipped_removed_csv = 0
        self.deleted_existing = 0

    def merge(self, other):
        self.zips += other.zips
        self.written += other.written
        self.skipped_dirs += other.skipped_dirs
        self.skipped_removed_csv += other.skipped_removed_csv
        self.deleted_existing += other.deleted_existing


def safe_join(dest_root, entry_name):
    if entry_name.startswith("/") or entry_name.startswith("\\"):
        return None
    if re.match(r"^[A-Za-z]:", entry_name):
        return None
    parts = entry_name.split("/")
    for p in parts:
        if p in ("", ".") or p == "..":
            return None
    return os.path.join(dest_root, *parts)


def extract_zip(zip_path, dest_root, stats, log=lambda msg: None):
    stats.zips += 1
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            name = info.filename
            if name.endswith("/"):
                stats.skipped_dirs += 1
                continue
            if name == ".removed.csv":
                stats.skipped_removed_csv += 1
                continue
            target = safe_join(dest_root, name)
            if target is None:
                log("[拒绝] 不安全条目路径: %s (%s)" % (name, os.path.basename(zip_path)))
                continue
            if os.path.exists(target):
                if os.path.isdir(target):
                    shutil.rmtree(target)
                else:
                    os.remove(target)
                stats.deleted_existing += 1
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f:
                f.write(z.read(info))
            stats.written += 1


def _write_info_file(final_version):
    data = {
        "version": final_version,
        "assetRecoveryInfo": [],
        "totalSize": 0,
        "assetSizeKind": "fulfill",
        "baseUrl": "",
        "latestModifiedTimeOfArchive": "",
    }
    total = 0
    dl = os.path.join(ROOT, "download")
    for root, dirs, files in os.walk(dl):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    data["totalSize"] = total
    with open(os.path.join(ROOT, "info.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print("info.json 已生成: version=%s / totalSize=%d" % (final_version, total))


def action_extract_full_chain(groups, cfg):
    platform = cfg["platform"]
    active = list(PLATFORM_GROUPS[platform])
    if cfg["include_android_variants"] and platform == "android":
        active += VARIANT_GROUPS
    dest_root = os.path.join(ROOT, "download")
    print("\n平台: %s，目录组: %s" % (platform, " + ".join(active)))
    print("输出目录: %s" % dest_root)
    total = Stats()
    chain_ends = []
    for group in active:
        bucket = groups.get(group)
        if not bucket:
            print("\n[%s] 无此目录组，跳过" % group)
            continue
        start, chain, end, errors, outside = build_chain(group, bucket)
        if errors:
            print("\n[%s] 版本链异常，跳过该组（零猜测准则）:" % group)
            for e in errors:
                print("  - %s" % e)
            continue
        pkgs = [(p, start) for p in [p for _, p in bucket["full"][start]]]
        pkgs += [(p, to) for to, files in chain for p in files]
        print("\n[%s] 链: %s -> %s，共 %d 包" % (group, start, end, len(pkgs)))
        if outside:
            print("  [警告] %d 个链外版本对不参与解压（本地缺中间版本包，链在 %s 处断开）: %s"
                  % (len(outside), end, outside[:5]))
        st = Stats()
        for p, ver in pkgs:
            extract_zip(p, dest_root, st)
            print("  %s  已写 %d" % (os.path.basename(p), st.written))
        print("[%s] 小计: 包 %d / 文件 %d / .removed.csv 跳过 %d / 覆盖已存在 %d"
              % (group, st.zips, st.written, st.skipped_removed_csv, st.deleted_existing))
        total.merge(st)
        chain_ends.append(end)
    print("\n=== 菜单1 汇总 ===")
    print("zip 包: %d / 落盘文件: %d / 跳过目录条目: %d / .removed.csv 跳过: %d / 覆盖已存在: %d"
          % (total.zips, total.written, total.skipped_dirs, total.skipped_removed_csv, total.deleted_existing))
    if chain_ends:
        _write_info_file(max(chain_ends, key=vkey))
    else:
        print("[警告] 没有成功处理的目录组，跳过 info.json 生成")


def _parse_removed_csv(data):
    paths = []
    for line in data.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("rowid"):
            continue
        parts = line.split(",")
        if len(parts) >= 2 and parts[1].strip():
            paths.append(parts[1].strip())
    return paths


def _write_entry(z, info, dest_root):
    target = safe_join(dest_root, info.filename)
    if target is None:
        print("  [拒绝] 不安全条目路径: %s (%s)" % (info.filename, z.filename))
        return False
    if os.path.exists(target):
        os.remove(target)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as f:
        f.write(z.read(info))
    return True


def action_extract_history(groups, cfg):
    dest_base = os.path.join(ROOT, "History")
    diff_groups = [g for g in sorted(groups) if "diff" in groups[g] and groups[g]["diff"]]
    if not diff_groups:
        print("未找到任何 diff 目录")
        return
    print("\n真实差异导出（CRC32 内容比对，仅修改差异落盘，新增不导出），输出目录: %s" % dest_base)
    state = {}
    baseline_index = {}
    g_new = g_mod = g_same = g_del = g_base = 0
    for group in diff_groups:
        bucket = groups[group]
        diffs = bucket.get("diff", {})
        fulls = bucket.get("full", {})
        start = None
        if len(fulls) == 1:
            start = sorted(fulls.keys(), key=vkey)[0]
        elif len(fulls) > 1:
            print("\n[%s] full 版本不唯一: %s（需人工确认，不做猜测），跳过该组" % (group, sorted(fulls.keys(), key=vkey)))
        if start is None:
            if len(fulls) <= 1:
                print("\n[%s] 缺 full 目录（无基线无法判定修改差异），跳过该组" % group)
            continue
        baseline_dest = os.path.join(dest_base, start)
        baseline_n = 0
        for _, p in fulls[start]:
            with zipfile.ZipFile(p) as z:
                for info in z.infolist():
                    name = info.filename
                    if name.endswith("/") or name == ".removed.csv":
                        continue
                    state[name] = info.CRC
                    baseline_index[name] = (p, info)
                    baseline_n += 1
        pairs = sorted(diffs.keys(), key=lambda ab: (vkey(ab[1]), vkey(ab[0])))
        print("\n[%s] 基线 %s（+ %d 文件，懒导出），diff 版本对 %d 个" % (group, start, baseline_n, len(pairs)))
        for (a, to) in pairs:
            st_new = st_mod = st_same = st_del = st_base = 0
            dest_root = os.path.join(dest_base, to)
            for _, p in diffs[(a, to)]:
                with zipfile.ZipFile(p) as z:
                    for info in z.infolist():
                        name = info.filename
                        if name.endswith("/"):
                            continue
                        if name == ".removed.csv":
                            for rp in _parse_removed_csv(z.read(info).decode("utf-8-sig", "replace")):
                                if rp in state:
                                    del state[rp]
                                    st_del += 1
                                baseline_index.pop(rp, None)
                            continue
                        crc = info.CRC
                        if name not in state:
                            state[name] = crc
                            st_new += 1
                            continue
                        if state[name] == crc:
                            st_same += 1
                            continue
                        if _write_entry(z, info, dest_root):
                            state[name] = crc
                            st_mod += 1
                            if name in baseline_index:
                                bz_path, bz_info = baseline_index.pop(name)
                                with zipfile.ZipFile(bz_path) as bz:
                                    if _write_entry(bz, bz_info, baseline_dest):
                                        st_base += 1
            print("  %s: 新增(不导出) %d / 修改导出 %d / 基线旧内容导出 %d / 未变化跳过 %d / 删除(仅状态) %d"
                  % (to, st_new, st_mod, st_base, st_same, st_del))
            g_new += st_new
            g_mod += st_mod
            g_base += st_base
            g_same += st_same
            g_del += st_del
    print("\n=== 菜单2 汇总 ===")
    print("新增(不导出): %d / 修改导出: %d / 基线旧内容导出: %d / 未变化跳过: %d / 删除(仅状态): %d"
          % (g_new, g_mod, g_base, g_same, g_del))


def print_scan_report(groups):
    print("=== CDN 扫描结果 ===")
    any_diff_end = None
    for group in sorted(groups):
        bucket = groups[group]
        line = "[%s]" % group
        fulls = bucket.get("full", {})
        diffs = bucket.get("diff", {})
        if fulls:
            line += " full版本: %s（%d 分片）" % (
                "/".join(sorted(fulls, key=vkey)), sum(len(v) for v in fulls.values()))
        if diffs:
            pairs = sorted(diffs.keys(), key=lambda ab: (vkey(ab[1]), vkey(ab[0])))
            line += " diff: %s -> %s（%d 版本对 / %d 包）" % (
                pairs[0][0], pairs[-1][1], len(pairs), sum(len(v) for v in diffs.values()))
            if any_diff_end is None or vkey(pairs[-1][1]) > vkey(any_diff_end):
                any_diff_end = pairs[-1][1]
        print(line)
    if any_diff_end:
        print("目标版本（diff 链尾最大值）: %s" % any_diff_end)
    print()


def main():
    if not any(DIR_RE.match(e) for e in os.listdir(ROOT) if os.path.isdir(os.path.join(ROOT, e))):
        print("[错误] 当前目录(%s)下没有 archive-*-full / archive-*-diff 目录。" % ROOT)
        print("本脚本必须放在 CDN 目录内运行。")
        input("按回车退出...")
        return
    cfg = load_config()
    while True:
        groups = scan()
        print_scan_report(groups)
        print("当前平台: %s（菜单3 切换）" % cfg["platform"])
        print("--------------------------------------------------")
        print("1. 按游戏逻辑解压（full + 完整 diff 链 -> download/ + info.json）")
        print("2. 真实差异导出（仅修改差异 + full 基线懒导出 -> History/<版本>/）")
        print("3. 切换平台（android / ios）")
        print("0. 退出")
        choice = input("请选择: ").strip()
        if choice == "1":
            action_extract_full_chain(groups, cfg)
        elif choice == "2":
            action_extract_history(groups, cfg)
        elif choice == "3":
            cfg["platform"] = "ios" if cfg["platform"] == "android" else "android"
            save_config(cfg)
            print("平台已切换为: %s" % cfg["platform"])
        elif choice == "0":
            break
        else:
            print("无效选择")
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n已中断")
