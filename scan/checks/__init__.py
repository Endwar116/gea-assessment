"""
AI 自檢模組庫 v0.3 — 60/40 兩層評分（stdlib only，純地端）
============================================================
委託方 2026-07 裁定的評分模型：
  · 前 60 分＝**基礎門檻**（gate，pass/fail 二分，相對寬鬆）：「有沒有做這件事」
  · 後 40 分＝**品質深化**（quality，0-100 連續）：「這件事做得多好」＝前 60 的細部版
  · 鐵律：品質 gated on 基礎——某領域基礎 fail，該領域品質自動 0（連 log 都沒有，談什麼防竄）
  · 空系統（全 gate fail）→ 趨近 0 分

每個 domain check(root, agent) → dict:
  {id, label, tier, tracks, gate:{passed, ev}, quality:{score, ev}, risk}
"""
import os
import re
import json

_INVENTORY = None


def build_inventory(root, max_files=40000, skip=(".git", "node_modules", "__pycache__", ".TRASH"),
                    dir_sample_cap=200):
    """v0.4 效能：單一目錄檔數超過 dir_sample_cap 視為資料/索引目錄（均質生成物），
    只抽樣前 cap 個——體檢是抽證據不是全讀；大幅削外接卷/大 repo 的 IO。"""
    global _INVENTORY
    inv = []
    n = 0
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in skip]
        batch = fns if len(fns) <= dir_sample_cap else fns[:dir_sample_cap]
        for fn in batch:
            inv.append(os.path.join(dp, fn))
            n += 1
            if n >= max_files:
                _INVENTORY = (root, inv); return len(inv)
    _INVENTORY = (root, inv)
    return len(inv)


def _files(root, exts=None, name_re=None, limit=40000):
    global _INVENTORY
    if _INVENTORY is None or _INVENTORY[0] != root:
        build_inventory(root)
    out = []
    for p in _INVENTORY[1]:
        if exts and not p.lower().endswith(exts):
            continue
        if name_re and not re.search(name_re, os.path.basename(p), re.I):
            continue
        out.append(p)
        if len(out) >= limit:
            break
    return out


def _G(passed, ev):  return {"passed": bool(passed), "ev": ev}
def _Q(score, ev):   return {"score": max(0, min(100, int(score))), "ev": ev}


def dom_logging(root, agent=False):
    logs = _files(root, exts=(".jsonl",), name_re=r"log|state|event|delivery|audit|history")
    gate = _G(bool(logs), f"AI 動作紀錄檔：{len(logs)} 個" if logs else "找不到任何紀錄檔 ✗")
    hashed = 0
    for p in logs[:25]:
        try:
            if re.search(r'"(prev_hash|current_event_hash|previous_event_hash|hash)"', open(p, encoding="utf-8", errors="replace").readline()):
                hashed += 1
        except OSError:
            pass
    q = _Q(min(100, hashed * 25) if logs else 0,
           f"{hashed}/{min(len(logs),25)} 抽樣有防竄雜湊欄位" if logs else "—")
    return {"id": "logging", "label": "動作紀錄", "tier": "基本", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "無紀錄＝出事無法回溯；無防竄＝紀錄可被改而不留痕"}


def dom_secrets(root, agent=False):
    pat = re.compile(r"(?i)(sk-[a-z0-9]{20,}|AIza[0-9A-Za-z_\-]{30,}|api[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY)")
    hits = []
    for p in _files(root, exts=(".env", ".txt", ".md", ".json", ".yaml", ".yml", ".py", ".js", ".ts", ".sh", ".cfg", ".ini")):
        try:
            if pat.search(open(p, encoding="utf-8", errors="replace").read(8000)):
                hits.append(os.path.relpath(p, root))
        except OSError:
            pass
    gate = _G(not hits, "無明文憑證外露 ✓" if not hits else f"命中 {len(hits)} 檔（{hits[:3]}）✗")
    excl = _files(root, exts=(".json", ".txt", ".cfg", ".gitignore"), name_re=r"exclusion|ignore|sensitive|secret")
    q = _Q(80 if excl else 20, f"有系統化敏感檔管理設定（{len(excl)}）" if excl else "無敏感檔管理設定（僅靠剛好沒洩）")
    return {"id": "secrets", "label": "金鑰隔離", "tier": "基本", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "憑證外露＝他人冒用你的付費/資料"}


def dom_guardrail(root, agent=False):
    tracks = ["通用"] + (["agent"] if agent else [])
    sig = [os.path.basename(p) for p in _files(root, exts=(".py", ".sh"), name_re=r"gate|guard|intercept|攔截|firewall")]
    hook = False
    if agent:
        for p in _files(root, exts=("settings.json",)):
            try:
                if "PreToolUse" in json.dumps(json.load(open(p, encoding="utf-8")).get("hooks", {})):
                    hook = True
            except Exception:
                pass
    gate = _G(bool(sig) or hook, f"攔截機制：{(['PreToolUse hook'] if hook else [])+sig[:2]}" if (sig or hook) else "無危險操作攔截 ✗")
    qs = (50 if hook else 0) + min(50, len(sig) * 25)
    q = _Q(qs, f"hook上線={hook}；攔截腳本 {len(sig)} 支")
    return {"id": "guardrail", "label": "危險操作攔截", "tier": "基本", "tracks": tracks,
            "gate": gate, "quality": q, "risk": "一次誤操作＝不可逆損失（刪除/誤發/誤付款）"}


def dom_closure(root, agent=False):
    sig = [os.path.basename(p) for p in _files(root, exts=(".py", ".md", ".jsonl"), name_re=r"brscp|verdict|governance|closure|結案")]
    gate = _G(bool(sig), f"結案治理跡象：{sig[:2]}" if sig else "無（AI 可能自宣完成）✗")
    q = _Q(min(100, len(sig) * 30), f"結案相關工件 {len(sig)} 個")
    return {"id": "closure", "label": "完成需核准", "tier": "基本", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "AI 自己說做完＝報喜不報憂，爛攤子累積"}


def dom_continuity(root, agent=False):
    tracks = ["通用"] + (["agent"] if agent else [])
    sig = [os.path.basename(p) for p in _files(root, exts=(".json", ".md"), name_re=r"handoff|接手|state.?current|slt|acv|continuity|checkpoint")]
    gate = _G(bool(sig), f"交接/狀態快照：{len(sig)} 個" if sig else "無中斷復原機制 ✗")
    verifiable = bool(_files(root, exts=(".json",), name_re=r"slt.*封包|slt.*packet|slt_"))
    q = _Q((60 if verifiable else 25) + min(15, len(sig) * 5), f"可驗證交接包={verifiable}；快照 {len(sig)}")
    return {"id": "continuity", "label": "中斷可復原", "tier": "可持續", "tracks": tracks,
            "gate": gate, "quality": q, "risk": "每次中斷從零開始，知識一直蒸發"}


def dom_filerules(root, agent=False):
    sig = [os.path.basename(p) for p in _files(root, exts=(".md", ".json", ".txt"), name_re=r"rule|規則|convention|config|policy|governance")]
    gate = _G(bool(sig), f"檔案/操作規則：{len(sig)} 份" if sig else "無明文檔案規則 ✗")
    single_truth = bool(_files(root, exts=(".py",), name_re=r"gen_view|rebuild|sync")) or \
                   bool(_files(root, exts=(".json",), name_re=r"exclusion|_config"))
    q = _Q(70 if single_truth else 30, f"單一真源/生成視圖機制={single_truth}")
    return {"id": "filerules", "label": "檔案規則", "tier": "基本", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "沒有規則＝各做各的，遲早結構崩壞"}


def dom_eventquery(root, agent=False):
    dbs = _files(root, exts=(".sqlite", ".db"), name_re=r"event|log|audit|history")
    logs = _files(root, exts=(".jsonl",), name_re=r"log|event")
    gate = _G(bool(dbs or logs), "有可查詢的事件來源" if (dbs or logs) else "無事件來源 ✗")
    q = _Q(100 if dbs else (40 if logs else 0),
           f"結構化事件庫 {len(dbs)} 個（秒查）" if dbs else f"{len(logs)} 個 jsonl 需逐檔 grep（成本高）")
    return {"id": "eventquery", "label": "事件可查", "tier": "可稽核", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "稽核成本高到沒人做"}


def dom_integrity(root, agent=False):
    # 效能（v0.3）：預建 inventory 路徑集合，引用命中改 O(1)，避免外接卷逐條 os.path.exists 的 IO 瓶頸
    global _INVENTORY
    if _INVENTORY is None or _INVENTORY[0] != root:
        build_inventory(root)
    known = set(_INVENTORY[1])
    ref = re.compile(r"(/[\w\-./一-鿿]+\.(md|py|json|jsonl|html|txt))")
    total = broken = 0
    for p in _files(root, exts=(".md",), limit=400):
        try:
            txt = open(p, encoding="utf-8", errors="replace").read(30000)
        except OSError:
            continue
        for m in ref.finditer(txt):
            g = m.group(1)
            if g.startswith("/"):
                total += 1
                # 只驗 inventory 涵蓋範圍內的路徑（root 底下）；範圍外不計（避免誤判外部引用）
                if g.startswith(root) and g not in known:
                    broken += 1
        if total >= 1500:
            break
    docs = _files(root, exts=(".md",))
    gate = _G(bool(docs), f"文件 {len(docs)} 份" if docs else "無文件 ✗")
    rate = (broken / total) if total else 0
    q = _Q(int(100 * (1 - min(1, rate * 3))) if total else 50,
           f"抽樣 {total} 引用，斷鏈 {rate*100:.0f}%" if total else "無絕對路徑引用可驗")
    return {"id": "integrity", "label": "引用完整", "tier": "可持續", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "文件互指卻找不到＝知識地圖失真"}


def dom_incident(root, agent=False):
    found = [os.path.relpath(p, root) for p in _files(root, exts=(".jsonl", ".md"), name_re=r"incident|lesson|egi|postmortem|事故|教訓|勘誤")]
    gate = _G(bool(found), f"事故/教訓紀錄：{len(found)} 份" if found else "無事故教訓迴圈 ✗")
    folded = any("lesson" in f.lower() or "教訓" in f for f in found)
    q = _Q((60 if folded else 20) + min(40, len(found) * 15), f"教訓帳={folded}；紀錄 {len(found)}")
    return {"id": "incident", "label": "事故教訓迴圈", "tier": "可稽核", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "沒有教訓迴圈＝同一個坑一直跌"}


def dom_staleness(root, agent=False):
    """視圖是否比真源舊（檢核表 2-4；v0.3 重寫時丟失、v0.4 紅隊找回）
    真源證據二擇一：同名 .md/.json 配對，或 html 頭部有「生成視圖/generated/真源」註記"""
    stale = checked = annotated = 0
    htmls = _files(root, exts=(".html",), limit=800)
    for v in htmls:
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
            try:
                head = open(v, encoding="utf-8", errors="replace").read(1500)
                if re.search(r"生成視圖|真源|auto-?generated|generated by", head, re.I):
                    annotated += 1
            except OSError:
                pass
    evidenced = checked + annotated
    gate = _G(evidenced > 0 or not htmls,
              f"{checked} 對同名配對＋{annotated} 個生成註記" if evidenced else "有 html 但無真源證據（無配對亦無生成註記）")
    qs = int(100 * (1 - stale / checked)) if checked else (80 if annotated else 0)
    q = _Q(qs, f"{stale}/{checked} 對過期>1天；註記視圖 {annotated} 個" if checked else f"全靠生成註記（{annotated} 個）")
    return {"id": "staleness", "label": "視圖不過期", "tier": "可持續", "tracks": ["通用"],
            "gate": gate, "quality": q, "risk": "主管看著過期資訊做決策"}


DOMAINS = {
    "logging": dom_logging, "secrets": dom_secrets, "guardrail": dom_guardrail,
    "closure": dom_closure, "continuity": dom_continuity, "filerules": dom_filerules,
    "eventquery": dom_eventquery, "integrity": dom_integrity, "incident": dom_incident,
    "staleness": dom_staleness,
}
