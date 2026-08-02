#!/usr/bin/env python3
"""
自測（selftest）— 證明評分引擎算得對，任何人 clone 下來一鍵驗證
================================================================
用固定的黃金測資（不碰真實系統）跑三個已知案例，斷言分數在預期範圍。
引擎被改壞→測試 fail。這是「工具自己也吃自己的藥」（可稽核）。

用法：python3 selftest.py     exit 0=全過、1=有 fail
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def run(target, profile="basic", agent=False):
    cmd = [sys.executable, os.path.join(HERE, "selfcheck.py"), target, "--profile", profile]
    if agent:
        cmd.append("--agent")
    subprocess.run(cmd, capture_output=True, text=True)
    return json.load(open(os.path.join(HERE, "report", "score.json"), encoding="utf-8"))


def build_fixtures(base):
    # A. 空系統：什麼都沒有 → 應 ≈1（系統存在性錨）
    empty = os.path.join(base, "empty"); os.makedirs(empty)

    # B. 只有無防竄 log → 基礎有、品質差；應 15-40（60/40 分離）
    mid = os.path.join(base, "mid"); os.makedirs(mid)
    open(os.path.join(mid, "app_log.jsonl"), "w").write('{"action":"x","data":1}\n')

    # C. 治理完整：log(含hash)+規則+閘門+結案+交接 → 應 ≥65
    good = os.path.join(base, "good"); os.makedirs(good)
    open(os.path.join(good, "audit_log.jsonl"), "w").write('{"action":"x","prev_hash":"abc","hash":"def"}\n')
    open(os.path.join(good, "gate_guard.py"), "w").write("# guardrail\n")
    open(os.path.join(good, "governance_verdict.md"), "w").write("# closure\n")
    open(os.path.join(good, "handoff_state.json"), "w").write("{}\n")
    open(os.path.join(good, "rules_convention.md"), "w").write("# filerules\n")
    open(os.path.join(good, "exclusion_config.json"), "w").write("{}\n")
    return empty, mid, good


def main():
    base = tempfile.mkdtemp(prefix="selfcheck_ft_")
    try:
        empty, mid, good = build_fixtures(base)
        cases = [
            ("空系統≈1", run(empty, "basic"), lambda s: s <= 5),
            ("只有無防竄log(60/40分離)", run(mid, "basic"), lambda s: 15 <= s <= 45),
            ("治理完整≥65", run(good, "basic"), lambda s: s >= 65),
        ]
        ok = 0
        for name, res, pred in cases:
            s = res["overall_score"]
            hit = pred(s)
            ok += hit
            print(f"  {'✅' if hit else '❌'} {name}：實際 {s} 分"
                  f"（基礎{res['base_60']}/品質{res['depth_40']}/光譜{res['spectrum_score']}）")
        # 額外斷言：good 的基礎門檻應全過（gate 分離正確）
        good_res = run(good, "basic")
        gates = [c["gate"]["passed"] for c in good_res["checks"]]
        gate_ok = all(gates)
        print(f"  {'✅' if gate_ok else '❌'} 治理完整案基礎門檻全過：{sum(gates)}/{len(gates)}")
        ok += gate_ok
        total = len(cases) + 1
        print(f"\n  {ok}/{total} 通過" + ("　✓ 引擎正常" if ok == total else "　✗ 引擎異常"))
        sys.exit(0 if ok == total else 1)
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()
