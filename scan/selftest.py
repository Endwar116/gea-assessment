#!/usr/bin/env python3
"""
自測（selftest）v0.5 — fail-closed：證明評分引擎抓得到問題，任何人 clone 下來一鍵驗證
=================================================================================
原則：
  · 每次跑用獨立的暫存輸出目錄，帶 run_id 並比對，絕不讀殘留的 score.json
  · 子程序離開碼不對（引擎錯誤 exit 2）＝該案例 FAIL
  · 「名字對、內容空」的目錄必須拿低分（防灌分）
  · 雜湊鏈改一個字元必須被抓到
  · 元測試：故意弄壞引擎，selftest 必須 FAIL（否則 selftest 自己就是裝飾品）

用法：python3 selftest.py [--no-meta]     exit 0=全過、1=有 fail
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
FAILS = []


def run(target, profile="basic", agent=False, probe=False, min_score=None, expect_rc=0):
    """跑一次 selfcheck；回傳 (rc, score 或 None)。rc 不符預期、run_id 不符都記 FAIL。"""
    out = tempfile.mkdtemp(prefix="selfcheck_out_")
    rid = uuid.uuid4().hex[:12]
    cmd = [sys.executable, "-B", os.path.join(HERE, "selfcheck.py"), target, "--profile", profile, "--out", out, "--run-id", rid]
    if agent:
        cmd.append("--agent")
    if probe:
        cmd.append("--probe")
    if min_score is not None:
        cmd += ["--min-score", str(min_score)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != expect_rc:
        FAILS.append(f"離開碼 {p.returncode}≠{expect_rc}：{' '.join(cmd[2:])}\n{p.stdout[-800:]}{p.stderr[-800:]}")
        return p.returncode, None
    if p.returncode == 2:
        return p.returncode, None
    sp = os.path.join(out, "score.json")
    if not os.path.exists(sp):
        FAILS.append(f"沒有 score.json：{target}"); return p.returncode, None
    res = json.load(open(sp, encoding="utf-8"))
    if res.get("run_id") != rid:
        FAILS.append(f"run_id 不符（讀到殘留輸出？）：{target}"); return p.returncode, None
    return p.returncode, res


def check(name, cond, detail=""):
    print(f"  {'✅' if cond else '❌'} {name}{('：' + detail) if detail else ''}")
    if not cond:
        FAILS.append(name)
    return cond


def dom(res, did):
    return next(c for c in res["checks"] if c["id"] == did)


def chained_log(path, n=5, tamper_line=None):
    """一條真的雜湊鏈：hash = sha256(compact sorted JSON of record-without-hash)"""
    prev, lines = "GENESIS", []
    for i in range(1, n + 1):
        body = {"seq": i, "action": f"step-{i}", "prev_hash": prev}
        h = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        body["hash"] = h
        lines.append(json.dumps(body))
        prev = h
    if tamper_line:
        lines[tamper_line - 1] = lines[tamper_line - 1].replace(f"step-{tamper_line}", f"step-{tamper_line}X")
    open(path, "w").write("\n".join(lines) + "\n")


HOOK_BLOCK = """#!/usr/bin/env python3
import json, sys
d = json.load(sys.stdin)
cmd = d.get("tool_input", {}).get("command", "")
if "rm -rf" in cmd:
    print("blocked dangerous command", file=sys.stderr); sys.exit(2)
sys.exit(0)
"""
HOOK_ALLOW = "#!/usr/bin/env python3\nimport sys\n# guard placeholder: deny nothing yet\nsys.exit(0)\n"


def w(d, rel, content):
    p = os.path.join(d, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(content)
    return p


def build_good(base, name="good", hook=HOOK_BLOCK):
    g = os.path.join(base, name); os.makedirs(g)
    chained_log(os.path.join(g, "audit_log.jsonl"))
    w(g, "gate_guard.py", hook)
    w(g, ".claude/settings.json", json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Bash|Write|Edit", "hooks": [{"type": "command", "command": "python3 \"$CLAUDE_PROJECT_DIR/gate_guard.py\""}]}]}}))
    w(g, "governance_verdict.md", "# 結案\nverdict: APPROVED\n證據 evidence: audit_log.jsonl（鏈驗證通過）\n")
    w(g, "handoff_state.json", json.dumps({"task": "demo", "pending": ["next step"]}))
    w(g, "rules_convention.md", "# 規則\n1. 寫入前驗證\n2. 不自宣完成\n3. 紀錄要有雜湊鏈\n")
    w(g, "exclusion_config.json", json.dumps({"exclude": [".env", "*.pem"]}))
    w(g, ".gitignore", ".env\n*.pem\n")
    return g


def build_fixtures(base):
    f = {}
    f["empty"] = os.path.join(base, "empty"); os.makedirs(f["empty"])
    f["mid"] = os.path.join(base, "mid"); os.makedirs(f["mid"])
    w(f["mid"], "app_log.jsonl", '{"action":"x","data":1}\n')
    f["good"] = build_good(base)
    # B2 防灌分：檔名全對、內容全空（hook 引用不存在的腳本）
    ne = os.path.join(base, "named_empty"); os.makedirs(ne)
    for rel in ("audit_log.jsonl", "gate_guard.py", "governance_verdict.md", "handoff_state.json", "rules_convention.md", "exclusion_config.json"):
        w(ne, rel, "")
    w(ne, ".claude/settings.json", json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "python3 missing_guard.py"}]}]}}))
    f["named_empty"] = ne
    # B3 竄改：good 的鏈改一個字元
    t = build_good(base, "tampered")
    chained_log(os.path.join(t, "audit_log.jsonl"), tamper_line=3)
    f["tampered"] = t
    # B6 金鑰：真外露 vs TEST_ONLY
    s = os.path.join(base, "secrets_real"); os.makedirs(s)
    w(s, "app_log.jsonl", '{"action":"x"}\n')
    w(s, "config.toml", 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n')
    w(s, "keys/service.pem", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n-----END PRIVATE KEY-----\n")
    w(s, "deploy", "export OPENAI_KEY=sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")   # 無副檔名
    f["secrets_real"] = s
    st = os.path.join(base, "secrets_test"); os.makedirs(st)
    w(st, "app_log.jsonl", '{"action":"x"}\n')
    w(st, "fixtures/TEST_ONLY_ed25519_private.pem", "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA\n-----END PRIVATE KEY-----\n")
    f["secrets_test"] = st
    # B7 相對連結
    l = os.path.join(base, "links"); os.makedirs(l)
    w(l, "app_log.jsonl", '{"action":"x"}\n')
    w(l, "docs/a.md", "see [b](b.md) and [c](missing.md) and `docs/b.md` and `other/repo.md`\n")
    w(l, "docs/b.md", "# b\n")
    f["links"] = l
    # B4 hook 沒擋
    f["hook_allow"] = build_good(base, "hook_allow", hook=HOOK_ALLOW)
    return f


def meta_test():
    """把 scan/ 複製到暫存，故意把 dom_logging 弄壞，跑那份 selftest（--no-meta）→ 必須 FAIL。"""
    tmp = tempfile.mkdtemp(prefix="selfcheck_meta_")
    try:
        dst = os.path.join(tmp, "scan")
        shutil.copytree(HERE, dst, ignore=shutil.ignore_patterns("__pycache__", "report", "gea_report"))
        cp = os.path.join(dst, "checks", "__init__.py")
        src = open(cp, encoding="utf-8").read()
        broken = src.replace("def dom_logging(root, agent=False, probe=False):\n",
                             "def dom_logging(root, agent=False, probe=False):\n    raise RuntimeError('engine deliberately broken')\n", 1)
        assert broken != src, "patch failed"
        open(cp, "w", encoding="utf-8").write(broken)
        p = subprocess.run([sys.executable, "-B", os.path.join(dst, "selftest.py"), "--no-meta"], capture_output=True, text=True)
        return p.returncode != 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    no_meta = "--no-meta" in sys.argv
    base = tempfile.mkdtemp(prefix="selfcheck_ft_")
    try:
        f = build_fixtures(base)
        print("── 分數範圍 ──")
        _, r = run(f["empty"]);           r and check("空系統≈1", r["overall_score"] <= 5, f"{r['overall_score']}")
        _, r = run(f["mid"]);             r and check("只有無防竄 log（60/40 分離）", 15 <= r["overall_score"] <= 45, f"{r['overall_score']}")
        _, good = run(f["good"]);         good and check("治理完整≥65", good["overall_score"] >= 65, f"{good['overall_score']}")
        good and check("治理完整案基礎門檻全過", all(c["gate"]["passed"] for c in good["checks"]))
        _, r = run(f["named_empty"]);     r and check("B2 名字對、內容空 ≤30（防灌分）", r["overall_score"] <= 30, f"{r['overall_score']}")
        print("── 內容判定 ──")
        good and check("B3 真雜湊鏈全重算＝100", dom(good, "logging")["quality"]["score"] == 100, dom(good, "logging")["quality"]["ev"])
        _, r = run(f["tampered"]);        r and check("B3 竄改一字元→鏈斷、品質 0", dom(r, "logging")["quality"]["score"] == 0 and "鏈斷" in dom(r, "logging")["quality"]["ev"], dom(r, "logging")["quality"]["ev"])
        r and good and check("B3 竄改版總分低於完整版", r["overall_score"] < good["overall_score"], f"{r['overall_score']} < {good['overall_score']}")
        _, r = run(f["secrets_real"]);    r and check("B6 .toml/.pem/無副檔名的憑證都抓到→gate fail", not dom(r, "secrets")["gate"]["passed"] and "命中 3" in dom(r, "secrets")["gate"]["ev"], dom(r, "secrets")["gate"]["ev"])
        _, r = run(f["secrets_test"]);    r and check("B6 TEST_ONLY 私鑰：揭露但不算洩漏", dom(r, "secrets")["gate"]["passed"] and "測試金鑰 1" in dom(r, "secrets")["gate"]["ev"], dom(r, "secrets")["gate"]["ev"])
        _, r = run(f["links"], "sustained"); r and check("B7 相對連結斷鏈被抓到、反引號提及只列不扣", "斷鏈 50%" in dom(r, "integrity")["quality"]["ev"] and "提及但找不到 1" in dom(r, "integrity")["quality"]["ev"], dom(r, "integrity")["quality"]["ev"])
        print("── hook／攔截 ──")
        _, r = run(f["named_empty"], agent=True); r and check("B4 hook 引用的腳本不存在→不給分", not dom(r, "guardrail")["gate"]["passed"], dom(r, "guardrail")["gate"]["ev"])
        _, r = run(f["good"], agent=True); r and check("B4 hook 設定＋腳本存在（未實測）≤80", dom(r, "guardrail")["gate"]["passed"] and dom(r, "guardrail")["quality"]["score"] <= 80, dom(r, "guardrail")["quality"]["ev"])
        _, r = run(f["good"], agent=True, probe=True); r and check("B4 --probe 實測擋下 rm -rf /→品質 100", dom(r, "guardrail")["quality"]["score"] == 100 and "實測擋下" in dom(r, "guardrail")["quality"]["ev"], dom(r, "guardrail")["quality"]["ev"])
        _, r = run(f["hook_allow"], agent=True, probe=True); r and check("B4 --probe hook 沒擋→品質≤50 並警示", dom(r, "guardrail")["quality"]["score"] <= 50 and "沒擋" in dom(r, "guardrail")["quality"]["ev"], dom(r, "guardrail")["quality"]["ev"])
        print("── 介面 ──")
        rc, _ = run(f["mid"], min_score=90, expect_rc=3); check("B8 低於 --min-score→exit 3", rc == 3)
        rc, _ = run(os.path.join(base, "nope"), expect_rc=2); check("B8 目錄不存在→exit 2", rc == 2)
        _, a = run(f["good"]); _, b = run(f["good"])
        if a and b:
            for k in ("run_id", "generated"):
                a.pop(k); b.pop(k)
            check("B9 同一輸入兩次輸出相同（排除 run_id/時間戳）", a == b)
            check("B9 score.json 帶 schema_version", a.get("schema_version", "").startswith("gea-scan-score/"))
        if not no_meta:
            print("── 元測試 ──")
            check("B1 引擎故意弄壞時 selftest 必須 FAIL", meta_test())
    finally:
        shutil.rmtree(base, ignore_errors=True)
    n_fail = len(FAILS)
    print(f"\n  {'✓ 引擎正常（全部通過）' if not n_fail else f'✗ {n_fail} 項失敗'}")
    for x in FAILS:
        print("   -", x.splitlines()[0])
    sys.exit(0 if not n_fail else 1)


if __name__ == "__main__":
    main()
