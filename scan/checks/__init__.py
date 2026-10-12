"""
GEA S 掃描檢測模組庫 v0.5 — 內容導向、fail-closed（stdlib only，純地端）
=====================================================================
評分模型（60/40 兩層）不變：
  · 前 60 分＝基礎門檻（gate，pass/fail）：「有沒有做這件事」
  · 後 40 分＝品質深化（quality，0-100）：「做得多好」；gate fail → 品質 0
  · 空系統 → 趨近 0

v0.5 的根本改變：**看內容和行為，不看檔名。**
  · 一個叫 audit_log.jsonl 的空檔不是紀錄；一個叫 gate_guard.py 的空檔不是攔截。
  · 有雜湊鏈的紀錄，鏈會被重算；改一個字元就會被抓到。
  · 金鑰掃描讀完整檔、含 .pem/.key/無副檔名，標 TEST_ONLY 的另列揭露。
  · hook 不只看有沒有設定，還看引用的腳本在不在；加 --probe 會真的餵一筆危險指令看它擋不擋。

每個 domain check(root, agent=False, probe=False) → dict:
  {id, label, tier, tracks, gate:{passed, ev}, quality:{score, ev}, risk}
ev 字串必須是確定性的（同一輸入同一輸出），不可含時間戳或暫存路徑。
"""
import hashlib
import json
import math
import os
import re
import subprocess
import sys

MAX_READ = 1_000_000          # 單檔最多讀 1 MB
MAX_LINES = 2000              # jsonl 最多解析行數
_INVENTORY = None
_JSONLOGS = {}                # root -> [(relpath, records)]

TEXT_EXT = (".env", ".txt", ".md", ".json", ".jsonl", ".yaml", ".yml", ".py", ".js", ".ts",
            ".sh", ".cfg", ".ini", ".toml", ".pem", ".key", ".crt", ".conf", ".properties", ".xml", ".html")
BINARY_EXT = (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar", ".pyc", ".sqlite", ".db",
              ".woff", ".woff2", ".ttf", ".ico", ".mp4", ".mp3", ".so", ".dylib", ".exe", ".bin")


# ─────────────────────────── 共用：檔案清單與讀取 ───────────────────────────
def build_inventory(root, max_files=40000, skip=(".git", "node_modules", "__pycache__", ".TRASH"),
                    dir_sample_cap=200):
    """單一目錄檔數超過 dir_sample_cap 視為資料目錄，只抽樣前 cap 個。
    目錄與檔名都排序，確保同一輸入產生同一清單（確定性輸出）。"""
    global _INVENTORY, _JSONLOGS
    inv, n = [], 0
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in skip)
        batch = sorted(fns)
        if len(batch) > dir_sample_cap:
            batch = batch[:dir_sample_cap]
        for fn in batch:
            inv.append(os.path.join(dp, fn))
            n += 1
            if n >= max_files:
                _INVENTORY = (root, inv); _JSONLOGS.pop(root, None); return len(inv)
    _INVENTORY = (root, inv)
    _JSONLOGS.pop(root, None)
    return len(inv)


def _inventory(root):
    global _INVENTORY
    if _INVENTORY is None or _INVENTORY[0] != root:
        build_inventory(root)
    return _INVENTORY[1]


def _files(root, exts=None, name_re=None, limit=40000, no_ext=False):
    out = []
    for p in _inventory(root):
        low = p.lower()
        base = os.path.basename(p)
        if exts and not low.endswith(exts):
            if not (no_ext and "." not in base):
                continue
        if name_re and not re.search(name_re, base, re.I):
            continue
        out.append(p)
        if len(out) >= limit:
            break
    return out


def _rel(root, p):
    return os.path.relpath(p, root).replace(os.sep, "/")


def _read(p, limit=MAX_READ):
    """讀文字檔（最多 limit bytes）；二進位或讀不到回 None。"""
    try:
        with open(p, "rb") as f:
            raw = f.read(limit)
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace")


def _nonblank_lines(txt):
    return [l for l in (txt or "").splitlines() if l.strip()]


def _json_obj(p):
    txt = _read(p)
    if txt is None:
        return None
    try:
        return json.loads(txt)
    except ValueError:
        return None


def _json_lines(p, max_lines=MAX_LINES):
    """解析 jsonl：回傳 (records, n_lines, n_bad)。只收 dict 型紀錄。"""
    txt = _read(p)
    if txt is None:
        return [], 0, 0
    recs, n, bad = [], 0, 0
    for line in txt.splitlines():
        if not line.strip():
            continue
        n += 1
        if n > max_lines:
            break
        try:
            o = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if isinstance(o, dict):
            recs.append(o)
        else:
            bad += 1
    return recs, n, bad


def _json_logs(root):
    """所有「內容真的是 JSON 紀錄」的 .jsonl/.ndjson（不看檔名）。快取。"""
    if root in _JSONLOGS:
        return _JSONLOGS[root]
    out = []
    for p in _files(root, exts=(".jsonl", ".ndjson"))[:200]:
        recs, n, bad = _json_lines(p)
        if recs:
            out.append((_rel(root, p), recs))
    _JSONLOGS[root] = out
    return out


def _G(passed, ev):  return {"passed": bool(passed), "ev": ev}
def _Q(score, ev):   return {"score": max(0, min(100, int(score))), "ev": ev}


# ─────────────────────────── 雜湊鏈重算 ───────────────────────────
_HASH_KEYS = ("hash", "current_event_hash", "event_hash", "entry_hash")
_PREV_KEYS = ("prev_hash", "previous_event_hash", "previous_hash", "parent_hash")


def _chain_keys(rec):
    hk = next((k for k in _HASH_KEYS if k in rec), None)
    pk = next((k for k in _PREV_KEYS if k in rec), None)
    return hk, pk


def _digests(body):
    """常見正規化方式的 sha256 候選：sorted keys × (compact|default 分隔) × (ascii|utf8) × (有無 sha256: 前綴)。"""
    out = set()
    for ascii_ in (False, True):
        for seps in ((",", ":"), None):
            try:
                txt = json.dumps(body, ensure_ascii=ascii_, sort_keys=True, separators=seps)
            except (TypeError, ValueError):
                continue
            h = hashlib.sha256(txt.encode("utf-8")).hexdigest()
            out.add(h); out.add("sha256:" + h)
    return out


def verify_chain(recs):
    """重算一條雜湊鏈。
    回傳 {chained, linked, recomputed, broken_at, n}
      chained    紀錄有 hash＋prev_hash 類欄位
      linked     每筆 prev_hash 等於前一筆的 hash
      recomputed 每筆 hash 都能用某種正規化重算出來
      broken_at  第一個失敗的行號（1-based），沒有則 None
    支援 SIC-JS ledger 信封 {seq, prev_hash, packet, hash} 與一般 {…, prev_hash, hash}。"""
    if not recs:
        return {"chained": False, "linked": False, "recomputed": False, "broken_at": None, "n": 0}
    hk, pk = _chain_keys(recs[0])
    if not hk or not pk:
        return {"chained": False, "linked": False, "recomputed": False, "broken_at": None, "n": len(recs)}
    linked = recomputed = True
    broken = None
    for i, r in enumerate(recs):
        if hk not in r or pk not in r:
            linked = recomputed = False; broken = broken or i + 1; break
        if i > 0 and r[pk] != recs[i - 1][hk]:
            linked = False; broken = broken or i + 1
        if {"seq", "prev_hash", "packet", "hash"} <= set(r.keys()):
            body = {"seq": r["seq"], "prev_hash": r["prev_hash"], "packet": r["packet"]}
        else:
            body = {k: v for k, v in r.items() if k != hk}
        if r[hk] not in _digests(body):
            recomputed = False; broken = broken or i + 1
    return {"chained": True, "linked": linked, "recomputed": recomputed, "broken_at": broken, "n": len(recs)}


# ─────────────────────────── 領域 1：動作紀錄 ───────────────────────────
def dom_logging(root, agent=False, probe=False):
    logs = _json_logs(root)
    gate = _G(bool(logs), f"JSON 紀錄檔（內容判定）：{len(logs)} 個" if logs else "找不到任何內容為 JSON 紀錄的檔案 ✗")
    full = link = broken = none = 0
    scores, broken_where = [], []
    for rel, recs in logs[:25]:
        c = verify_chain(recs)
        if not c["chained"]:
            none += 1; scores.append(0)
        elif c["broken_at"]:
            broken += 1; scores.append(0); broken_where.append(f"{rel}:{c['broken_at']}")
        elif c["recomputed"]:
            full += 1; scores.append(100)
        else:
            link += 1; scores.append(50)      # 連結連續但雜湊算法未知
    qs = (sum(scores) / len(scores)) if scores else 0
    ev = (f"鏈驗證：{full} 全重算／{link} 僅連結／{broken} 鏈斷／{none} 無鏈（抽樣 {len(scores)}）" if logs else "—")
    if broken_where:
        ev += f"　✗ 疑似竄改：{broken_where[:3]}"
    return {"id": "logging", "label": "動作紀錄", "tier": "基本", "tracks": ["通用"],
            "gate": gate, "quality": _Q(qs, ev), "risk": "無紀錄＝出事無法回溯；無防竄＝紀錄可被改而不留痕"}


# ─────────────────────────── 領域 2：金鑰隔離 ───────────────────────────
_SECRET_PATS = [
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("openai", re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_\-]{20,}")),
    ("google", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("aws", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")),
    ("github", re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("slack", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-/+=]{16,})")),
]
_PLACEHOLDER = re.compile(r"(?i)(<|>|\$\{|\$[A-Z_]|your[_-]|xxx|example|changeme|todo|placeholder|\*\*\*|dummy)")
_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")
_TEST_MARK = re.compile(r"(?i)test[_-]?only|testonly")


def _entropy(s):
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in freq.values())


def _scan_secret_text(txt):
    kinds = []
    for name, pat in _SECRET_PATS:
        for m in pat.finditer(txt):
            if name == "assignment" and _PLACEHOLDER.search(m.group(0)):
                continue
            kinds.append(name); break
    return kinds


def dom_secrets(root, agent=False, probe=False):
    real, test, warn = [], [], []
    cands = _files(root, exts=TEXT_EXT + (".env",), no_ext=True)
    for p in cands:
        base = os.path.basename(p)
        if base.lower().endswith(BINARY_EXT) or (base.startswith(".env") is False and "." not in base and os.path.getsize(p) > MAX_READ):
            continue
        txt = _read(p)
        if txt is None:
            continue
        rel = _rel(root, p)
        kinds = _scan_secret_text(txt)
        if kinds:
            if _TEST_MARK.search(rel) or _TEST_MARK.search(txt[:20000]):
                test.append(f"{rel}[{kinds[0]}]")
            else:
                real.append(f"{rel}[{kinds[0]}]")
            continue
        if base.lower().endswith((".env", ".toml", ".cfg", ".ini", ".yaml", ".yml", ".properties")) or base.startswith(".env"):
            for m in _ENTROPY_RE.finditer(txt):
                s = m.group(0)
                if (re.search(r"[a-z]", s) and re.search(r"[A-Z]", s) and re.search(r"[0-9]", s)
                        and _entropy(s) >= 4.6):
                    warn.append(rel); break
    real.sort(); test.sort(); warn.sort()
    ev = "無明文憑證外露 ✓" if not real else f"命中 {len(real)} 檔（{real[:3]}）✗"
    if test:
        ev += f"　｜　測試金鑰 {len(test)}（標 TEST_ONLY，已揭露、不算洩漏）：{test[:3]}"
    if warn:
        ev += f"　｜　高熵字串待人工確認 {len(warn)}：{warn[:3]}"
    gate = _G(not real, ev)
    managed = False
    for p in _files(root, exts=(".gitignore",)):
        if re.search(r"\.env|\.pem|\.key|secret|credential", _read(p, 50000) or "", re.I):
            managed = True; break
    if not managed:
        for p in _files(root, exts=(".json", ".txt", ".cfg", ".yaml", ".yml"), name_re=r"exclusion|sensitive|secret|ignore"):
            if _nonblank_lines(_read(p, 50000)) and (_json_obj(p) or not p.endswith(".json")):
                managed = True; break
    qs = (80 if managed else 20) - min(30, 10 * len(warn))
    q = _Q(qs, ("有敏感檔管理設定（.gitignore／exclusion 有實際內容）" if managed else "無敏感檔管理設定（僅靠剛好沒洩）")
           + (f"；高熵警示 {len(warn)}" if warn else ""))
    return {"id": "secrets", "label": "金鑰隔離", "tier": "基本", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "憑證外露＝他人冒用你的付費/資料"}


# ─────────────────────────── 領域 3：危險操作攔截 ───────────────────────────
_BLOCK_EVIDENCE = re.compile(r"sys\.exit\(\s*[1-9]|\bexit\s+[1-9]|\breturn\s+[1-9]\b|deny|block|reject|forbid|拒絕|攔截|rm\s+-rf|PreToolUse|dangerous|危險")
_TOOLS = ("Bash", "Write", "Edit")


def _matcher_covers(matcher, tool):
    if matcher in (None, "", "*"):
        return True
    try:
        return re.fullmatch(matcher, tool) is not None
    except re.error:
        return tool in matcher


def _proj_dir(settings_path, root):
    """settings.json 所屬的專案目錄（.claude 的上一層），不是 .claude 目錄就用 root。"""
    d = os.path.dirname(settings_path)
    return os.path.dirname(d) if os.path.basename(d) == ".claude" else root


def _resolve_hook_script(command, root, settings_path):
    """從 hook command 找出被呼叫的腳本路徑；回傳 (path or None, exists, executable_ok)。"""
    proj = _proj_dir(settings_path, root)
    toks = command.replace('"', " ").replace("'", " ").split()
    for i, t in enumerate(toks):
        if not (t.endswith((".py", ".sh", ".js", ".rb")) or "/" in t):
            continue
        cand = t.replace("$CLAUDE_PROJECT_DIR", proj).replace("${CLAUDE_PROJECT_DIR}", proj)
        for base in (None, root, proj):
            path = cand if base is None else os.path.join(base, cand)
            if os.path.isfile(path):
                direct = (i == 0)
                return path, True, (os.access(path, os.X_OK) if direct else True)
        return cand, False, False
    return None, False, False


def _hooks(root):
    """解析所有 settings.json 的 PreToolUse hooks → [(matcher, command, script, exists, exec_ok, proj_dir)]"""
    out = []
    for p in _files(root, exts=("settings.json", "settings.local.json")):
        o = _json_obj(p)
        if not isinstance(o, dict):
            continue
        for ent in (o.get("hooks") or {}).get("PreToolUse", []) or []:
            if not isinstance(ent, dict):
                continue
            for h in ent.get("hooks", []) or []:
                cmd = (h or {}).get("command")
                if not cmd:
                    continue
                script, exists, xok = _resolve_hook_script(cmd, root, p)
                out.append((ent.get("matcher"), cmd, script, exists, xok, _proj_dir(p, root)))
    return out


def _probe_hook(command, root, settings_root):
    """餵一筆 rm -rf / 的 PreToolUse 事件給 hook；回傳 'blocked' | 'allowed' | 'error:…'"""
    payload = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                          "tool_input": {"command": "rm -rf /"}, "cwd": root})
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/"),
           "CLAUDE_PROJECT_DIR": settings_root, "LANG": "C.UTF-8"}
    try:
        r = subprocess.run(command, shell=True, input=payload, capture_output=True, text=True,
                           cwd=root, env=env, timeout=10)
    except Exception as e:  # timeout 等
        return f"error:{type(e).__name__}"
    if re.search(r"No such file|can't open file|not found|No module named", (r.stderr or "")):
        return "error:script"          # 跑不起來不算擋下
    if r.returncode == 2:
        return "blocked"
    try:
        o = json.loads(r.stdout.strip() or "{}")
        hso = o.get("hookSpecificOutput", {}) if isinstance(o, dict) else {}
        if (o.get("decision") == "block" or hso.get("permissionDecision") == "deny"):
            return "blocked"
    except ValueError:
        pass
    return "allowed"


def dom_guardrail(root, agent=False, probe=False):
    tracks = ["通用"] + (["agent"] if agent else [])
    scripts = []
    for p in _files(root, exts=(".py", ".sh"), name_re=r"gate|guard|intercept|攔截|firewall|hook"):
        txt = _read(p, 200000)
        if txt and _nonblank_lines(txt) and _BLOCK_EVIDENCE.search(txt):
            scripts.append(_rel(root, p))
    scripts.sort()
    hooks = _hooks(root) if agent else []
    hooks_ok = [h for h in hooks if h[3]]
    hooks_bad = [h for h in hooks if not h[3]]
    coverage = [t for t in _TOOLS if any(_matcher_covers(h[0], t) for h in hooks_ok)]
    parts = []
    if hooks_ok:
        parts.append(f"PreToolUse hook {len(hooks_ok)} 條（腳本存在），涵蓋 {coverage or '無'}")
    if hooks_bad:
        parts.append(f"⚠ {len(hooks_bad)} 條 hook 引用的腳本不存在：{sorted(_rel(root, h[2]) if h[2] and h[2].startswith(root) else str(h[2]) for h in hooks_bad)[:2]}")
    if scripts:
        parts.append(f"攔截腳本（有實際內容）{len(scripts)}：{scripts[:2]}")
    gate = _G(bool(scripts) or bool(hooks_ok), "；".join(parts) if parts else "無危險操作攔截（沒有有內容的攔截腳本，也沒有引用到存在腳本的 hook）✗")

    qs = 0
    if hooks_ok:
        qs = 30 + 10 * len(coverage) + (20 if all(h[4] for h in hooks_ok) else 0)
    qs += min(50, 25 * len(scripts)) if not hooks_ok else min(20, 10 * len(scripts))
    probe_ev = ""
    if hooks_ok:
        if probe:
            results = []
            for m, cmd, script, _, _, proj in hooks_ok:
                if _matcher_covers(m, "Bash"):
                    results.append(_probe_hook(cmd, root, proj))
            if "blocked" in results:
                qs += 20; probe_ev = "；實測擋下 rm -rf / ✓"
            elif results and all(r == "allowed" for r in results):
                qs = min(qs, 50); probe_ev = "；⚠ 實測：hook 沒擋 rm -rf /"
            elif results:
                probe_ev = f"；實測無結果（{sorted(set(results))}）"
            else:
                probe_ev = "；無涵蓋 Bash 的 hook 可實測"
        else:
            qs = min(qs, 80); probe_ev = "；未實測（加 --probe 會真的餵一筆危險指令）"
    q = _Q(qs, f"hook 可用={bool(hooks_ok)}；涵蓋 {len(coverage)}/3；有內容的攔截腳本 {len(scripts)}{probe_ev}")
    return {"id": "guardrail", "label": "危險操作攔截", "tier": "基本", "tracks": tracks,
            "gate": gate, "quality": q, "risk": "一次誤操作＝不可逆損失（刪除/誤發/誤付款）"}


# ─────────────────────────── 領域 4：完成需核准 ───────────────────────────
_VERDICT_TOKEN = re.compile(r"\b(VALID|INVALID|APPROVED|REJECTED|PASS|FAIL|verdict)\b|核准|駁回|通過|不通過|判定")
_REF_RE = re.compile(r"(?:file://|/)?([\w\-./一-鿿]+\.(?:jsonl|json|md|py|html|txt|sh|log)(?![\w]))|sha256:[0-9a-f]{64}")
_SIC_STATUS = {"pending", "in_progress", "completed", "dismissed", "archived"}


def _refs_resolve(txt, base_dir, root):
    """文中的證據引用至少一個找得到（相對檔案所在目錄或 root），或是 sha256 錨。"""
    for m in _REF_RE.finditer(txt):
        if m.group(0).startswith("sha256:"):
            return True
        rel = m.group(1)
        if not rel:
            continue
        for b in (base_dir, root):
            cand = os.path.normpath(os.path.join(b, rel.lstrip("/")))
            if os.path.exists(cand) and cand != base_dir:
                return True
        if os.path.exists(m.group(0)):
            return True
    return False


def sicjs_packet_check(pkt):
    """SIC-JS packet 結構檢查（非官方 validator）：completed 必須有證據、核准、非本人驗證者。
    回傳 (status, ok, reason)。"""
    if not isinstance(pkt, dict) or "sic_version" not in pkt or not isinstance(pkt.get("task"), dict):
        return None, False, "not a packet"
    st = pkt["task"].get("status")
    if st not in _SIC_STATUS:
        return st, False, f"status 不在白名單：{st!r}"
    if st != "completed":
        return st, True, "non-completed"
    a = pkt.get("assurance") or {}
    me = (pkt.get("entity") or {}).get("identity_ref")
    if not a.get("evidence_refs"):
        return st, False, "completed 無 evidence_refs"
    if not a.get("approval_refs"):
        return st, False, "completed 無 approval_refs"
    if not a.get("verifier_refs"):
        return st, False, "completed 無 verifier_refs"
    if a.get("verification_status") != "verified":
        return st, False, "completed 但 verification_status≠verified"
    if me and (me in a.get("verifier_refs", []) or me in a.get("approval_refs", [])):
        return st, False, "completed 由本人核准／驗證（自我認證）"
    return st, True, "evidenced"


def _sicjs_packets(root):
    """找出目錄裡的 SIC-JS packet：獨立 .json 與 ledger 信封裡的 packet。"""
    out = []
    for p in _files(root, exts=(".json",))[:400]:
        o = _json_obj(p)
        if isinstance(o, dict) and "sic_version" in o and isinstance(o.get("task"), dict):
            out.append((_rel(root, p), o))
    for rel, recs in _json_logs(root):
        for i, r in enumerate(recs):
            pk = r.get("packet") if isinstance(r.get("packet"), dict) else (r if "sic_version" in r else None)
            if pk and isinstance(pk.get("task"), dict):
                out.append((f"{rel}:{i + 1}", pk))
    return out


def dom_closure(root, agent=False, probe=False):
    evidenced, claimed = [], []
    for p in _files(root, exts=(".md", ".json", ".jsonl", ".txt"), name_re=r"verdict|governance|closure|結案|approval|核准"):
        txt = _read(p, 200000)
        if not txt or not _nonblank_lines(txt):
            continue
        rel = _rel(root, p)
        if _VERDICT_TOKEN.search(txt) and _refs_resolve(txt, os.path.dirname(p), root):
            evidenced.append(rel)
        else:
            claimed.append(rel)
    packets = _sicjs_packets(root)
    completed_ok, completed_bad = [], []
    for rel, pkt in packets:
        st, ok, why = sicjs_packet_check(pkt)
        if st == "completed":
            (completed_ok if ok else completed_bad).append(f"{rel}（{why}）")
    evidenced.sort(); claimed.sort()
    n_art = len(evidenced) + len(claimed) + len(completed_ok) + len(completed_bad)
    parts = []
    if evidenced: parts.append(f"有判定＋可找到證據的結案檔 {len(evidenced)}：{evidenced[:2]}")
    if claimed: parts.append(f"⚠ 只有宣稱、無判定或證據找不到 {len(claimed)}：{claimed[:2]}")
    if packets: parts.append(f"SIC-JS 封包 {len(packets)}（completed 合格 {len(completed_ok)}／不合格 {len(completed_bad)}）")
    if completed_bad: parts.append(f"⚠ 不合格 completed：{completed_bad[:2]}")
    gate = _G(bool(evidenced) or bool(packets), "；".join(parts) if parts else "無結案治理跡象（AI 可能自宣完成）✗")
    if n_art:
        qs = 100 * (len(evidenced) + len(completed_ok)) / n_art
    else:
        qs = 0
    if packets and not (evidenced or claimed or completed_ok or completed_bad):
        qs = 60   # 有治理封包但還沒有結案案例
    q = _Q(qs, f"結案工件 {n_art}，其中有證據 {len(evidenced) + len(completed_ok)}（結構檢查，非官方 validator）")
    return {"id": "closure", "label": "完成需核准", "tier": "基本", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "AI 自己說做完＝報喜不報憂，爛攤子累積"}


# ─────────────────────────── 領域 5：中斷可復原 ───────────────────────────
def _valid_doc(p):
    """json：非空 dict/list；md/txt：至少 3 行有內容。"""
    if p.endswith(".json"):
        o = _json_obj(p)
        return bool(o) and isinstance(o, (dict, list))
    return len(_nonblank_lines(_read(p, 200000))) >= 3


def dom_continuity(root, agent=False, probe=False):
    tracks = ["通用"] + (["agent"] if agent else [])
    sig, verifiable = [], 0
    for p in _files(root, exts=(".json", ".md"), name_re=r"handoff|接手|state.?current|slt|acv|continuity|checkpoint|wake|醒來"):
        if not _valid_doc(p):
            continue
        sig.append(_rel(root, p))
        if p.endswith(".json"):
            o = _json_obj(p)
            if isinstance(o, dict) and ("sic_version" in o and isinstance(o.get("task"), dict) and isinstance(o.get("state"), dict)
                                        or re.search(r"slt", os.path.basename(p), re.I) and o):
                verifiable += 1
    sig.sort()
    gate = _G(bool(sig), f"交接/狀態快照（有內容）：{len(sig)} 個" if sig else "無中斷復原機制（沒有有內容的交接檔）✗")
    q = _Q((60 if verifiable else 25) + min(15, len(sig) * 5), f"可驗證交接包 {verifiable}；快照 {len(sig)}")
    return {"id": "continuity", "label": "中斷可復原", "tier": "可持續", "tracks": tracks,
            "gate": gate, "quality": q, "risk": "每次中斷從零開始，知識一直蒸發"}


# ─────────────────────────── 領域 6：檔案規則 ───────────────────────────
def dom_filerules(root, agent=False, probe=False):
    sig = [_rel(root, p) for p in _files(root, exts=(".md", ".json", ".txt", ".yaml", ".yml"),
                                         name_re=r"rule|規則|convention|config|policy|governance|CLAUDE\.md|README")
           if _valid_doc(p) or (p.endswith((".yaml", ".yml", ".txt")) and _nonblank_lines(_read(p, 100000)))]
    sig.sort()
    gate = _G(bool(sig), f"檔案/操作規則（有內容）：{len(sig)} 份" if sig else "無明文檔案規則 ✗")
    gen = [p for p in _files(root, exts=(".py",), name_re=r"gen_view|rebuild|sync|generate|make_")
           if re.search(r"\bdef \w+|open\(", _read(p, 100000) or "")]
    excl = [p for p in _files(root, exts=(".json",), name_re=r"exclusion|_config") if _valid_doc(p)]
    single_truth = bool(gen or excl)
    q = _Q(70 if single_truth else 30, f"單一真源/生成視圖機制={single_truth}（生成腳本 {len(gen)}，設定 {len(excl)}）")
    return {"id": "filerules", "label": "檔案規則", "tier": "基本", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "沒有規則＝各做各的，遲早結構崩壞"}


# ─────────────────────────── 領域 7：事件可查 ───────────────────────────
def dom_eventquery(root, agent=False, probe=False):
    dbs = []
    for p in _files(root, exts=(".sqlite", ".sqlite3", ".db")):
        try:
            with open(p, "rb") as f:
                if f.read(16) == b"SQLite format 3\x00":
                    dbs.append(_rel(root, p))
        except OSError:
            pass
    logs = _json_logs(root)
    gate = _G(bool(dbs or logs), "有可查詢的事件來源" if (dbs or logs) else "無事件來源 ✗")
    q = _Q(100 if dbs else (40 if logs else 0),
           f"結構化事件庫 {len(dbs)} 個（秒查）" if dbs else f"{len(logs)} 個 jsonl 需逐檔 grep（成本高）")
    return {"id": "eventquery", "label": "事件可查", "tier": "可稽核", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "稽核成本高到沒人做"}


# ─────────────────────────── 領域 8：引用完整 ───────────────────────────
_ABS_REF = re.compile(r"(/[\w\-./一-鿿]+\.(?:jsonl|json|md|py|html|txt)(?![\w]))")
_MD_LINK = re.compile(r"\[[^\]]*\]\(([^)\s#]+)(?:#[^)]*)?\)")
_TICK_REF = re.compile(r"`([\w\-./一-鿿]+/[\w\-./一-鿿]+\.(?:jsonl|json|md|py|html|txt|sh))`")


def dom_integrity(root, agent=False, probe=False):
    """絕對路徑引用與 Markdown 相對連結算「引用」，斷了扣分。
    反引號裡的路徑只算「提及」（文件常常在討論別的 repo 的檔案），找不到只列出、不扣分。"""
    known = set(_inventory(root))
    total = broken = mention_missing = 0
    broken_list, mention_list = [], []

    def _exists_rel(d, t):
        return os.path.exists(os.path.normpath(os.path.join(d, t))) or os.path.exists(os.path.normpath(os.path.join(root, t)))

    for p in _files(root, exts=(".md",), limit=400):
        txt = _read(p, 300000)
        if txt is None:
            continue
        d, rel = os.path.dirname(p), _rel(root, p)
        for m in _ABS_REF.finditer(txt):
            g = m.group(1)
            if g.startswith(root):
                total += 1
                if g not in known:
                    broken += 1; broken_list.append(f"{rel}→{g}")
        seen = set()
        for m in _MD_LINK.finditer(txt):
            t = m.group(1)
            if t in seen or re.match(r"(?i)^(https?:|mailto:|data:|tel:|#)", t) or t.startswith("/"):
                continue
            seen.add(t)
            total += 1
            if not _exists_rel(d, t):
                broken += 1; broken_list.append(f"{rel}→{t}")
        for m in _TICK_REF.finditer(txt):
            t = m.group(1)
            if t not in seen and not _exists_rel(d, t):
                seen.add(t); mention_missing += 1; mention_list.append(f"{rel}→{t}")
        if total >= 1500:
            break
    docs = _files(root, exts=(".md",))
    gate = _G(bool(docs), f"文件 {len(docs)} 份" if docs else "無文件 ✗")
    rate = (broken / total) if total else 0
    ev = (f"抽樣 {total} 引用（絕對路徑＋Markdown 連結），斷鏈 {rate * 100:.0f}%" + (f"：{sorted(broken_list)[:3]}" if broken_list else "")) if total else "無可驗證的引用"
    if mention_missing:
        ev += f"；反引號提及但找不到 {mention_missing}（不扣分）：{sorted(mention_list)[:2]}"
    q = _Q(int(100 * (1 - min(1, rate * 3))) if total else 50, ev)
    return {"id": "integrity", "label": "引用完整", "tier": "可持續", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "文件互指卻找不到＝知識地圖失真"}


# ─────────────────────────── 領域 9：事故教訓迴圈 ───────────────────────────
def dom_incident(root, agent=False, probe=False):
    found, folded = [], False
    for p in _files(root, exts=(".jsonl", ".md"), name_re=r"incident|lesson|postmortem|erratum|事故|教訓|勘誤"):
        if p.endswith(".jsonl"):
            recs, _, _ = _json_lines(p)
            ok = bool(recs)
        else:
            ok = len(_nonblank_lines(_read(p, 200000))) >= 3
        if ok:
            found.append(_rel(root, p))
            if re.search(r"lesson|教訓", os.path.basename(p), re.I):
                folded = True
    found.sort()
    gate = _G(bool(found), f"事故/教訓紀錄（有內容）：{len(found)} 份" if found else "無事故教訓迴圈 ✗")
    q = _Q((60 if folded else 20) + min(40, len(found) * 15), f"教訓帳={folded}；紀錄 {len(found)}")
    return {"id": "incident", "label": "事故教訓迴圈", "tier": "可稽核", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "沒有教訓迴圈＝同一個坑一直跌"}


# ─────────────────────────── 領域 10：視圖不過期 ───────────────────────────
def dom_staleness(root, agent=False, probe=False):
    """視圖是否比真源舊。真源證據二擇一：同名 .md/.json 配對，或 html 頭部有「生成視圖/generated/真源」註記"""
    stale = checked = annotated = 0
    for v in _files(root, exts=(".html",), limit=800):
        base = os.path.splitext(v)[0]
        paired = False
        for src in (base + ".md", base + ".json", base + ".jsonl"):
            if os.path.exists(src):
                paired = True
                checked += 1
                if os.path.getmtime(src) - os.path.getmtime(v) > 86400:
                    stale += 1
                break
        if not paired:
            head = _read(v, 1500) or ""
            if re.search(r"生成視圖|真源|auto-?generated|generated by", head, re.I):
                annotated += 1
    evidenced = checked + annotated
    htmls = _files(root, exts=(".html",), limit=1)
    gate = _G(evidenced > 0 or not htmls,
              f"{checked} 對同名配對＋{annotated} 個生成註記" if evidenced else ("無 html 視圖（不適用）" if not htmls else "有 html 但無真源證據（無配對亦無生成註記）"))
    qs = int(100 * (1 - stale / checked)) if checked else (80 if annotated else (50 if not htmls else 0))
    q = _Q(qs, f"{stale}/{checked} 對過期>1天；註記視圖 {annotated} 個" if checked else f"全靠生成註記（{annotated} 個）")
    return {"id": "staleness", "label": "視圖不過期", "tier": "可持續", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "主管看著過期資訊做決策"}


DOMAINS = {
    "logging": dom_logging, "secrets": dom_secrets, "guardrail": dom_guardrail,
    "closure": dom_closure, "continuity": dom_continuity, "filerules": dom_filerules,
    "eventquery": dom_eventquery, "integrity": dom_integrity, "incident": dom_incident,
    "staleness": dom_staleness,
}
