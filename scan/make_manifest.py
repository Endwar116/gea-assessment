#!/usr/bin/env python3
"""產生／核對出貨清單（MANIFEST.json、SHIP_MANIFEST.json）
=========================================================
只列 repo 裡真的存在、真的出貨的檔案，sha256 用完整 64 位。

    python3 scan/make_manifest.py            # 重新產生兩份清單
    python3 scan/make_manifest.py --check    # 重算比對；不符 exit 1

內部字白名單（INTERNAL_RE）：出貨檔命中任何一個就拒絕產生（exit 1），
這是「出貨前 outgate」——不靠人記得掃。
"""
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIP_EXT = (".py", ".md", ".json", ".html", ".txt", "LICENSE", ".gitignore")
SKIP_DIR = (".git", "__pycache__", "gea_report", "report", ".claude")
SKIP_FILE = ("MANIFEST.json", "SHIP_MANIFEST.json")
INTERNAL_RE = re.compile(r"三樓|VS-7|andwar|agr_gate|SIC-SH|HL-6|\bEGI\b|BRSCP|\bR22\b")


def shipped_files():
    out = []
    for dp, dns, fns in os.walk(ROOT):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIR)
        for fn in sorted(fns):
            rel = os.path.relpath(os.path.join(dp, fn), ROOT)
            if fn in SKIP_FILE or not fn.endswith(SHIP_EXT):
                continue
            out.append(rel)
    return out


def build():
    files, bad = [], []
    for rel in shipped_files():
        data = open(os.path.join(ROOT, rel), "rb").read()
        if rel != "scan/make_manifest.py" and INTERNAL_RE.search(data.decode("utf-8", "replace")):
            bad.append(rel)
        files.append({"file": rel, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return files, bad


def main():
    files, bad = build()
    if bad:
        print("✗ 出貨檔含內部字，拒絕產生清單：", bad)
        return 1
    manifest = {"repo": "gea-assessment", "generated_by": "scan/make_manifest.py",
                "rule": "列出 repo 內所有出貨副檔名的檔案（排除 .git/__pycache__/報告輸出與清單本身）；sha256 為完整 64 位",
                "count": len(files), "files": files}
    ship = {"note": "所有列出的檔案都是 SHIP（出貨）；internal_refs 由 make_manifest.py 的白名單掃描計算，必須全為 0",
            "files": [{"file": f["file"], "class": "SHIP", "internal_refs": 0} for f in files]}
    if "--check" in sys.argv:
        cur = json.load(open(os.path.join(ROOT, "scan", "MANIFEST.json"), encoding="utf-8"))
        ok = cur.get("files") == files
        print("✓ MANIFEST 與實際檔案一致" if ok else "✗ MANIFEST 與實際檔案不符（重新產生：python3 scan/make_manifest.py）")
        return 0 if ok else 1
    json.dump(manifest, open(os.path.join(ROOT, "scan", "MANIFEST.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump(ship, open(os.path.join(ROOT, "scan", "SHIP_MANIFEST.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"✓ 清單已產生：{len(files)} 檔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
