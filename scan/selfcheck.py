#!/usr/bin/env python3
"""
GEA S 掃描 — 地端 60/40 兩層評分引擎 v0.5（stdlib only，零外傳）
===================================================================
對自己的 AI 系統目錄跑 → 分數＋風險清單。資料完全不出門。不代言任何法規；僅供自我檢視。

評分模型：
  · 前 60 分＝基礎門檻（每領域 gate 過＝拿滿該領域的基礎分；寬鬆二分）
  · 後 40 分＝品質深化（每領域 quality 0-100 × 該領域品質分；且 gate fail→品質 0）
  · 空系統（全 gate fail）≈ 0 分

用法：python3 selfcheck.py <目錄> [--profile basic|sustained|auditable] [--agent] [--probe]
                            [--out 報告目錄] [--min-score N] [--mapping]
離開碼：0＝完成且達門檻　3＝低於 --min-score　2＝引擎錯誤／用法錯誤（fail-closed：出錯就不給分）
"""
import argparse
import html
import json
import os
import sys
import uuid
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True
from checks import DOMAINS  # noqa: E402

VERSION = "0.5"
SCHEMA = "gea-scan-score/1"
EXIT_OK, EXIT_ERROR, EXIT_BELOW = 0, 2, 3


def load_profile(name):
    return json.load(open(os.path.join(HERE, "profiles", f"{name}.json"), encoding="utf-8"))


def grade(s):
    return "🟢綠" if s >= 75 else ("🟡黃" if s >= 45 else "🔴紅")


def _e(v):
    """C1：所有進 HTML 的字串都跳脫。ev／target 會帶被掃目錄的檔名與路徑，被掃對象不可信。"""
    return html.escape(str(v), quote=True)


def _write_card(out, out_dir):
    """由 score.json 生成給老闆看的報告卡 HTML（自足、可離線開；C1：輸入全跳脫＋CSP 封死腳本與外連）"""
    g = out["overall_score"]
    color = "#16A34A" if g >= 75 else ("#D97706" if g >= 45 else "#DC2626")
    rows_gate = "".join(
        f'<tr><td>{"✅" if r["gate"]["passed"] else "❌"}</td><td>{_e(r["label"])}</td>'
        f'<td>{_e(r["gate"]["ev"])}</td><td>{"" if r["gate"]["passed"] else "⚠ " + _e(r["risk"])}</td></tr>'
        for r in out["checks"])
    rows_q = "".join(
        f'<tr><td>{_e(r["quality"]["score"]) if r["gate"]["passed"] else "—"}</td><td>{_e(r["label"])}</td>'
        f'<td>{_e(r["quality"]["ev"]) if r["gate"]["passed"] else "基礎未過，不計"}</td></tr>'
        for r in out["checks"])
    page = f"""<!DOCTYPE html><html lang="zh-TW"><head><meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>GEA S 掃描報告卡</title>
<style>body{{font-family:'Noto Sans TC',sans-serif;background:#F3F4F6;margin:0;padding:0 0 40px;color:#1F2937}}
.hero{{background:#111827;color:#fff;padding:24px 30px}}.hero h1{{margin:0;font-size:22px}}
.score{{font-size:56px;font-weight:900;color:{color}}}.sub{{color:#64748B;font-size:13px}}
.wrap{{max-width:820px;margin:20px auto;padding:0 18px}}
.card{{background:#fff;border:1px solid #E5E7EB;padding:16px 20px;margin-bottom:14px;box-shadow:0 1px 6px rgba(0,0,0,.05)}}
table{{width:100%;border-collapse:collapse;font-size:13px}}td,th{{padding:6px 8px;border-bottom:1px solid #eee;text-align:left;vertical-align:top}}
.dis{{font-size:11px;color:#94A3B8;margin-top:8px}}</style></head>
<body><header class="hero"><h1>🛡️ GEA S 掃描報告卡</h1>
<div class="sub">{_e(out["profile_label"])}{"（agent軌）" if out["agent_track"] else ""}｜{_e(out["generated"])}｜對象：{_e(out["target"])}｜run {_e(out["run_id"])}</div></header>
<main class="wrap">
<div class="card" style="text-align:center"><div class="score">{_e(g)}<span style="font-size:24px">/100</span></div>
<div class="sub">門檻分＝基礎 {_e(out["base_60"])}/60 ＋ 品質 {_e(out["depth_40"])}/40　｜　成熟度光譜 {_e(out["spectrum_score"])}/100
{"<br><b style='color:#DC2626'>⚠ 未偵測到運作中的 AI 系統</b>" if not out.get("system_present", True) else ""}</div></div>
<div class="card"><b>① 基礎門檻（有沒有做這幾件事）</b>
<table><tr><th></th><th>項目</th><th>現況</th><th>風險</th></tr>{rows_gate}</table></div>
<div class="card"><b>② 品質深化（做得多好）</b>
<table><tr><th>分</th><th>項目</th><th>說明</th></tr>{rows_q}</table></div>
<div class="card dis">{_e(out["disclaimer"])}</div>
</main></body></html>"""
    open(os.path.join(out_dir, "report_card.html"), "w", encoding="utf-8").write(page)


def assess(root, profile, agent=False, probe=False):
    """跑所有領域並聚合。任何領域丟例外 → 直接 raise（不給分、不吞錯）。"""
    prof = load_profile(profile)
    doms = [d for d in prof["domains"] if d in DOMAINS]
    n = len(doms)
    gate_each, qual_each = 60.0 / n, 40.0 / n
    results, gate_got, qual_got = [], 0.0, 0.0
    for did in doms:
        r = DOMAINS[did](root, agent=agent, probe=probe)
        gp = gate_each if r["gate"]["passed"] else 0.0
        qp = (qual_each * r["quality"]["score"] / 100.0) if r["gate"]["passed"] else 0.0
        r["_gate_pts"], r["_qual_pts"], r["_dom_total"] = round(gp, 1), round(qp, 1), round(gp + qp, 1)
        gate_got += gp
        qual_got += qp
        results.append(r)
    base, depth = round(gate_got), round(qual_got)

    def _passed(did):
        return next((r["gate"]["passed"] for r in results if r["id"] == did), False)
    # 系統存在性錨：連紀錄/規則/攔截都沒有＝非運作中 AI 系統，反向指標(secrets)不該撐分
    system_present = _passed("logging") or _passed("filerules") or (agent and _passed("guardrail"))
    overall = (base + depth) if system_present else round((base + depth) * 0.1)
    spectrum = round(sum((60 if r["gate"]["passed"] else 0) + 0.4 * (r["quality"]["score"] if r["gate"]["passed"] else 0)
                         for r in results) / n) if n else 0
    if not system_present:
        spectrum = round(spectrum * 0.1)
    return {"schema_version": SCHEMA, "tool": "gea-scan", "version": VERSION,
            "target": root, "profile": prof["profile"], "profile_label": prof["label"],
            "agent_track": agent, "probe": probe,
            "overall_score": overall, "overall_grade": grade(overall),
            "base_60": base, "depth_40": depth, "system_present": system_present,
            "spectrum_score": spectrum, "checks": results,
            "disclaimer": "本工具僅供自我檢視，不構成任何法律/法規/標準之符合性聲明；結果代表基本門檻檢查，非安全無虞保證。"}


def main():
    ap = argparse.ArgumentParser(description="GEA S 掃描（產物層自動檢查）")
    ap.add_argument("target")
    ap.add_argument("--profile", default="basic", choices=["basic", "sustained", "auditable"])
    ap.add_argument("--agent", action="store_true", help="agent 型部署：解析 .claude/settings.json 的 PreToolUse hooks")
    ap.add_argument("--probe", action="store_true",
                    help="實測 hook：餵一筆 rm -rf / 的 PreToolUse 事件給你的 hook（會執行目標目錄裡的 hook 腳本，預設關閉）")
    ap.add_argument("--mapping", action="store_true", help="報告尾附 ISO42001/NIST/OWASP 參考對照")
    ap.add_argument("--out", default="./gea_report", help="報告輸出目錄（預設 ./gea_report/，不寫回工具目錄）")
    ap.add_argument("--min-score", type=int, default=None, help="低於此門檻分 exit 3（接 CI 用）")
    ap.add_argument("--run-id", default=None, help="本次執行識別（預設自動產生；selftest 用來比對輸出）")
    a = ap.parse_args()
    root = os.path.abspath(a.target)
    if not os.path.isdir(root):
        print(f"✗ 目錄不存在：{root}")
        return EXIT_ERROR

    try:
        out = assess(root, a.profile, agent=a.agent, probe=a.probe)
    except Exception as e:  # fail-closed：引擎出錯就不出報告
        print(f"✗ 引擎錯誤（不出報告）：{type(e).__name__}: {e}")
        return EXIT_ERROR
    out["run_id"] = a.run_id or uuid.uuid4().hex[:12]
    out["generated"] = datetime.now(timezone(timedelta(hours=8))).isoformat()[:19]
    out_dir = os.path.abspath(a.out)
    os.makedirs(out_dir, exist_ok=True)
    json.dump(out, open(os.path.join(out_dir, "score.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    _write_card(out, out_dir)

    n = len(out["checks"])
    print("=" * 64)
    print(f"  GEA S 掃描報告　{out['profile_label']}{'（agent軌）' if a.agent else ''}{'（--probe 實測）' if a.probe else ''}")
    print(f"  對象：{root}")
    print("=" * 64)
    if not out["system_present"]:
        print("\n  ⚠ 未偵測到運作中的 AI 系統（無紀錄/規則/攔截）——分數已大幅折抵。\n")
    print(f"\n  【門檻分】{out['overall_score']}/100　{out['overall_grade']}　＝　基礎門檻 {out['base_60']}/60　＋　品質深化 {out['depth_40']}/40")
    print(f"  【成熟度光譜】{out['spectrum_score']}/100（原加權模型：整體程度，較平滑；門檻分較嚴，缺基礎即崩）\n")
    print("  ── 基礎門檻（有沒有做這件事）──")
    for r in out["checks"]:
        print(f"  {'✅' if r['gate']['passed'] else '❌'} {r['label']:8s}（{r['_gate_pts']}/{round(60 / n, 1)}）{r['gate']['ev']}")
        if not r["gate"]["passed"]:
            print(f"        ⚠ {r['risk']}")
    print("\n  ── 品質深化（做得多好；基礎沒過則不計）──")
    for r in out["checks"]:
        if r["gate"]["passed"]:
            print(f"  {grade(r['quality']['score'])} {r['label']:8s}（{r['_qual_pts']}/{round(40 / n, 1)}）{r['quality']['ev']}")
        else:
            print(f"  ⊘ {r['label']:8s} 基礎未過，品質不計")
    print("\n" + "=" * 64)
    print(f"  機讀報告：{os.path.join(out_dir, 'score.json')}　｜　紅黃/❌項＝你的風險點，建議優先處理")
    print("  " + out["disclaimer"])
    print("=" * 64)
    if a.mapping:
        try:
            mp = json.load(open(os.path.join(HERE, "mappings", "framework_mapping.json"), encoding="utf-8"))
            byid = {m["domain"]: m for m in mp["mappings"]}
            print("\n  ── 國際框架參考對照（非合規認證，僅供理解檢查點來源）──")
            for r in out["checks"]:
                m = byid.get(r["id"])
                if m:
                    print(f"  · {r['label']:8s} ISO42001:{m['ISO42001'][:22]} | NIST:{m['NIST_AI_RMF'][:16]} | {m['OWASP_LLM'][:14]}")
            print("  " + mp["_disclaimer"])
        except Exception as e:
            print(f"  （對照表讀取失敗：{e}）")
    if a.min_score is not None and out["overall_score"] < a.min_score:
        print(f"\n  ✗ 門檻分 {out['overall_score']} 低於 --min-score {a.min_score}（exit 3）")
        return EXIT_BELOW
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
