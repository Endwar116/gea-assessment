#!/usr/bin/env python3
"""
AI 系統自檢工具 — 地端 60/40 兩層評分引擎 v0.3（stdlib only，零外傳）
===================================================================
給中小企業：git clone → 對自己的 AI 系統目錄跑 → 分數＋風險清單。資料完全不出門。
不代言任何法規；僅供自我檢視。

評分模型（委託方 2026-07 裁定）：
  · 前 60 分＝基礎門檻（每領域 gate 過＝拿滿該領域的基礎分；寬鬆二分）
  · 後 40 分＝品質深化（每領域 quality 0-100 × 該領域品質分；且 gate fail→品質 0）
  · 空系統（全 gate fail）≈ 0 分

用法：python3 selfcheck.py <目錄> [--profile basic|sustained|auditable] [--agent] [--out 報告目錄]
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from checks import DOMAINS


def load_profile(name):
    return json.load(open(os.path.join(HERE, "profiles", f"{name}.json"), encoding="utf-8"))


def grade(s):
    return "🟢綠" if s >= 75 else ("🟡黃" if s >= 45 else "🔴紅")


def _write_card(out, out_dir):
    """由 score.json 生成給老闆看的報告卡 HTML（自足、可離線開）"""
    g = out["overall_score"]
    color = "#16A34A" if g >= 75 else ("#D97706" if g >= 45 else "#DC2626")
    rows_gate = "".join(
        f'<tr><td>{"✅" if r["gate"]["passed"] else "❌"}</td><td>{r["label"]}</td>'
        f'<td>{r["gate"]["ev"]}</td><td>{"" if r["gate"]["passed"] else "⚠ "+r["risk"]}</td></tr>'
        for r in out["checks"])
    rows_q = "".join(
        f'<tr><td>{r["quality"]["score"] if r["gate"]["passed"] else "—"}</td><td>{r["label"]}</td>'
        f'<td>{r["quality"]["ev"] if r["gate"]["passed"] else "基礎未過，不計"}</td></tr>'
        for r in out["checks"])
    html = f"""<!DOCTYPE html><html lang="zh-TW"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>AI 系統自檢報告卡</title>
<style>body{{font-family:'Noto Sans TC',sans-serif;background:#F3F4F6;margin:0;padding:0 0 40px;color:#1F2937}}
.hero{{background:#111827;color:#fff;padding:24px 30px}}.hero h1{{margin:0;font-size:22px}}
.score{{font-size:56px;font-weight:900;color:{color}}}.sub{{color:#64748B;font-size:13px}}
.wrap{{max-width:820px;margin:20px auto;padding:0 18px}}
.card{{background:#fff;border:1px solid #E5E7EB;padding:16px 20px;margin-bottom:14px;box-shadow:0 1px 6px rgba(0,0,0,.05)}}
table{{width:100%;border-collapse:collapse;font-size:13px}}td,th{{padding:6px 8px;border-bottom:1px solid #eee;text-align:left;vertical-align:top}}
.dis{{font-size:11px;color:#94A3B8;margin-top:8px}}</style></head>
<body><header class="hero"><h1>🛡️ AI 系統自檢報告卡</h1>
<div class="sub">{out["profile_label"]}{"（agent軌）" if out["agent_track"] else ""}｜{out["generated"]}｜對象：{out["target"]}</div></header>
<main class="wrap">
<div class="card" style="text-align:center"><div class="score">{g}<span style="font-size:24px">/100</span></div>
<div class="sub">門檻分＝基礎 {out["base_60"]}/60 ＋ 品質 {out["depth_40"]}/40　｜　成熟度光譜 {out["spectrum_score"]}/100
{"<br><b style='color:#DC2626'>⚠ 未偵測到運作中的 AI 系統</b>" if not out.get("system_present",True) else ""}</div></div>
<div class="card"><b>① 基礎門檻（有沒有做這幾件事）</b>
<table><tr><th></th><th>項目</th><th>現況</th><th>風險</th></tr>{rows_gate}</table></div>
<div class="card"><b>② 品質深化（做得多好）</b>
<table><tr><th>分</th><th>項目</th><th>說明</th></tr>{rows_q}</table></div>
<div class="card dis">{out["disclaimer"]}</div>
</main></body></html>"""
    open(os.path.join(out_dir, "report_card.html"), "w", encoding="utf-8").write(html)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--profile", default="basic", choices=["basic", "sustained", "auditable"])
    ap.add_argument("--agent", action="store_true")
    ap.add_argument("--mapping", action="store_true", help="報告尾附 ISO42001/NIST/OWASP 參考對照")
    ap.add_argument("--out", default="./gea_report", help="報告輸出目錄（預設 ./gea_report/，不寫回工具目錄）")
    a = ap.parse_args()
    root = os.path.abspath(a.target)
    if not os.path.isdir(root):
        print(f"✗ 目錄不存在：{root}"); sys.exit(1)

    prof = load_profile(a.profile)
    doms = [d for d in prof["domains"] if d in DOMAINS]
    n = len(doms)
    gate_each = 60.0 / n     # 每領域的基礎分額
    qual_each = 40.0 / n     # 每領域的品質分額

    results, gate_got, qual_got = [], 0.0, 0.0
    for did in doms:
        try:
            r = DOMAINS[did](root, agent=a.agent)
        except Exception as e:
            r = {"id": did, "label": did, "tier": "?", "tracks": ["通用"],
                 "gate": {"passed": False, "ev": f"出錯：{e}"}, "quality": {"score": 0, "ev": "—"}, "risk": "—"}
        gp = gate_each if r["gate"]["passed"] else 0.0
        qp = (qual_each * r["quality"]["score"] / 100.0) if r["gate"]["passed"] else 0.0  # 品質 gated on 基礎
        r["_gate_pts"] = round(gp, 1)
        r["_qual_pts"] = round(qp, 1)
        r["_dom_total"] = round(gp + qp, 1)
        gate_got += gp
        qual_got += qp
        results.append(r)

    base = round(gate_got)
    depth = round(qual_got)
    overall_raw = base + depth

    # 系統存在性錨（v0.3）：連 log/規則/hook 都沒有＝非運作中 AI 系統，反向指標(secrets)不該撐分
    def _passed(did): return next((r["gate"]["passed"] for r in results if r["id"] == did), False)
    system_present = _passed("logging") or _passed("filerules") or (a.agent and _passed("guardrail"))
    overall = overall_raw if system_present else round(overall_raw * 0.1)

    # 第二視角＝原加權連續模型（保留，搭配並列）：每領域融合分(gate 6:quality 4)等權平均→成熟度光譜
    spectrum = round(sum((60 if r["gate"]["passed"] else 0) + 0.4 * (r["quality"]["score"] if r["gate"]["passed"] else 0)
                         for r in results) / n) if n else 0
    if not system_present:
        spectrum = round(spectrum * 0.1)
    ts = datetime.now(timezone(timedelta(hours=8))).isoformat()[:19]
    out = {"tool": "gea-scan", "version": "0.4", "generated": ts, "target": root,
           "profile": prof["profile"], "profile_label": prof["label"], "agent_track": a.agent,
           "overall_score": overall, "overall_grade": grade(overall),
           "base_60": base, "depth_40": depth, "system_present": system_present,
           "spectrum_score": spectrum, "checks": results,
           "disclaimer": "本工具僅供自我檢視，不構成任何法律/法規/標準之符合性聲明；結果代表基本門檻檢查，非安全無虞保證。"}
    out_dir = os.path.abspath(a.out)
    os.makedirs(out_dir, exist_ok=True)
    json.dump(out, open(os.path.join(out_dir, "score.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    _write_card(out, out_dir)

    print("=" * 64)
    print(f"  AI 系統自檢報告　{prof['label']}{'（agent軌）' if a.agent else ''}")
    print(f"  對象：{root}")
    print("=" * 64)
    if not system_present:
        print("\n  ⚠ 未偵測到運作中的 AI 系統（無紀錄/規則/攔截）——分數已大幅折抵。\n")
    print(f"\n  【門檻分】{overall}/100　{grade(overall)}　＝　基礎門檻 {base}/60　＋　品質深化 {depth}/40")
    print(f"  【成熟度光譜】{spectrum}/100（原加權模型：整體程度，較平滑；門檻分較嚴，缺基礎即崩）\n")
    print("  ── 基礎門檻（有沒有做這件事）──")
    for r in results:
        mark = "✅" if r["gate"]["passed"] else "❌"
        print(f"  {mark} {r['label']:8s}（{r['_gate_pts']}/{round(60/n,1)}）{r['gate']['ev']}")
        if not r["gate"]["passed"]:
            print(f"        ⚠ {r['risk']}")
    print("\n  ── 品質深化（做得多好；基礎沒過則不計）──")
    for r in results:
        if r["gate"]["passed"]:
            print(f"  {grade(r['quality']['score'])} {r['label']:8s}（{r['_qual_pts']}/{round(40/n,1)}）{r['quality']['ev']}")
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
            for r in results:
                m = byid.get(r["id"])
                if m:
                    print(f"  · {r['label']:8s} ISO42001:{m['ISO42001'][:22]} | NIST:{m['NIST_AI_RMF'][:16]} | {m['OWASP_LLM'][:14]}")
            print("  " + mp["_disclaimer"])
        except Exception as e:
            print(f"  （對照表讀取失敗：{e}）")


if __name__ == "__main__":
    main()
