# GEA 自我審計報告｜GEA PMP Self-Audit Report

> 日期 Date：2026-10-13｜審計方法 Method：`pmp/2026-10-13_GEA出貨審計PMP_gea-release-manufacturing-pmp.md` v1.0
> 對象 Target：分支 `claude/gea-b-engine`（含 `claude/gea-a-public-surface`），基底 `main@0f1de8b`
> 審計者 Auditor：GEA 維護者（Claude Code 雲端 session）
> **性質：自審。** 寫程式的和審程式的是同一個 agent。依 PMP G11 與 GEA 自己的指標 5.2，
> 這份報告只能宣稱「自審全過」，**不能宣稱「獨立驗證過」**；獨立驗證待委託方或第三方重跑本報告附的指令。
> **Nature: self-audit.** The code author and the auditor are the same agent. This report claims
> "all gates passed on self-audit" and nothing more; independent verification means someone else re-runs the commands below.

---

## English summary

Audited the two branches (public-surface cleanup A1–A7, content-based engine B1–B11) with the GEA Release Manufacturing PMP.
All 12 gates pass on fresh runs. Fifteen findings: ten carried over from the optimisation plan and fixed, five new ones found
while auditing (an extension-regex ordering bug that mis-resolved `.jsonl` as `.json`; a hook-probe path bug that counted
"python3: file not found" as "blocked"; secret false positives on a real tree, all placeholders; back-ticked paths penalised
as broken links; a manifest listing files that do not exist). Dogfood: a directory of correctly named empty files drops
from 76 to 1; a real hash-chained agent home rises from 2 to 65 with both chains recomputed; a one-character tamper that
the old engine did not notice (78 → 78) now zeroes the logging quality (90 → 82); a `TEST_ONLY` private key that the old
engine reported as "no exposed credentials" is now disclosed. Remaining limitations and non-claims are listed at the end.

---

## 1. 發現表｜Findings

| # | 嚴重度 | 檔案 | 問題 | 證據 | 處置 |
|---|---|---|---|---|---|
| F1 | 🔴 | `scan/checks/__init__.py`（v0.3） | 靠檔名給分：檔名全對、內容全空的目錄拿高分 | 舊引擎對 selftest 的 `named_empty` 測資：**76**（本次重跑） | 偵測層重做（B2–B7）；新引擎：**1** |
| F2 | 🔴 | 同上 | 假陰性：有雜湊鏈、寫入前驗證的真日誌被判「非運作中 AI 系統」 | 舊引擎掃 `IMCC/雲端德`：**2**；新引擎：**65**，鏈驗證「2 全重算」 | B3 |
| F3 | 🔴 | 同上 | 假陰性：`.pem` 私鑰不掃，報「無明文憑證外露 ✓」 | 舊引擎只讀 `.env .txt .md .json …` 前 8000 字 | B6；新引擎掃 SIC-JS 包揭露 1 把 TEST_ONLY 私鑰 |
| F4 | 🔴 | `scan/TECH_DOSSIER.md`、`gea_assess.py` | 公開 repo 含自標 INTERNAL 文件與內部代號 | `grep` 命中 13 處 | A1：移除文件、改寫 3 處；outgate 現在 0 命中 |
| F5 | 🟡 | `scan/selftest.py`（v0.3） | fail-open：不查離開碼、讀殘留 `score.json` | 舊引擎對 `tampered` 測資仍 **78**（竄改無感） | B1：fail-closed＋元測試；新引擎 tampered **82 < 90**，logging 品質 0 |
| F6 | 🟡 | `scan/report/*`、`__pycache__` | 跑過的報告 commit 進 repo | `git ls-files` | A2：`--out`＋`.gitignore` |
| F7 | 🟡 | `scan/selfcheck.py` | 恆 exit 0，無法接 CI | 讀碼 | B8：0／2／3 |
| F8 | 🟡 | `gea_assess.py` | Q 問卷 2 分不需證據 | 讀碼 `grade()` | B10：無證據以 1 計並標宣稱 |
| F9 | ⚪ | README、docstring、mapping、scan/README | 20 vs 24 指標；9 vs 10 領域；DEMO 23/24；MIT vs Apache；`cd ai-selfcheck` | grep | A3–A5 |
| F10 | ⚪ | `gea_assess.py` | `--answers` 非法值直接崩潰 | 讀碼 `int(a)` | B11：驗證＋exit 2 |
| F11 | 🟡 **新** | `scan/checks/__init__.py` | 副檔名正規表示式 `(md\|py\|json\|jsonl…)` 順序錯：`x.jsonl` 被配成 `x.json`，證據引用與絕對路徑都會誤判為斷鏈。**v0.3 的 integrity 也有同一個 bug** | selftest `good` 的 closure 在修前判「證據找不到」 | 改為最長優先＋`(?![\w])` |
| F12 | 🟡 **新** | 同上 `_probe_hook` | hook 實測的專案目錄從腳本路徑往上兩層算，算錯；`python3` 找不到檔案 exit 2，被當成「擋下」 | selftest `hook_allow` 在修前顯示「實測擋下 ✓」 | 專案目錄改從 settings 路徑算；stderr 有「No such file／can't open file」算 error，不算擋下 |
| F13 | 🟡 **新** | 同上 `dom_secrets` | 對真實目錄假陽性：IMCC 全樹 18 命中，逐條人工判讀**全是佔位值**（`my_secret_key_for_testing`、`sk-12345678901234567890`、`sk-proj-xxxx…`） | 本報告 §3 | 佔位過濾擴大兩次並套用到所有樣式；最終 IMCC 真外露 **0**、測試金鑰 1 |
| F14 | ⚪ **新** | 同上 `dom_integrity` | 反引號裡的路徑算斷鏈，討論別的 repo 的文件被扣到 0 | `雲端德` 的 integrity 品質一度 0（斷鏈 82%） | 反引號提及只列不扣 |
| F15 | ⚪ **新** | `scan/MANIFEST.json` | 列了兩份不在 repo 的 `R14_*.md`；sha256 只有 16 位 | 讀檔 | A7：`make_manifest.py` 重產，`--check` 可比對 |
| F16 | ⚪ **新** | 本報告初稿 | §5.4 把內部字白名單原文貼進報告，`make_manifest.py` 的 outgate 拒絕產生清單 | `✗ 出貨檔含內部字，拒絕產生清單：['audits/…']` | 改為引用白名單所在位置，不列原文。這同時證明 outgate 真的會擋 |

## 2. 審計閘結果｜Gate results

| 閘 | 結果 | 證據（本報告 §5 原文） |
|---|---|---|
| G0 身分與版本 | ✅ | `selfcheck.VERSION=0.5`、`gea_assess.VERSION=0.2.0`、CHANGELOG 最新段、README 表格一致；`schema_version: gea-scan-score/1` |
| G1 公開面 | ✅ | 內部字 grep 0 行；`make_manifest.py` outgate 通過；PUBLISH_AUDIT 舊段原文保留、勘誤追加 |
| G2 內容不是檔名 | ✅ | selftest B2：named_empty **1**（≤30） |
| G3 fail-closed | ✅ | selftest 查離開碼、`run_id` 比對、元測試「引擎弄壞→selftest FAIL」通過；目錄不存在 exit 2 |
| G4 假陰性 | ✅ | 雲端德：logging 過、2 鏈全重算；SIC-JS 包：TEST_ONLY 私鑰列出；竄改一字元：`audit_log.jsonl:3` 被標出 |
| G5 假陽性 | ✅（有條件） | IMCC 全樹 18→6→0，逐條判讀皆佔位；**但佔位過濾是在本次審計中才補的，之前兩版都有假陽性**（F13） |
| G6 行為實測 | ✅ | `--probe` 預設關、文件寫明會執行目標的 hook；擋下→100；沒擋→≤50；跑不起來不算擋下（F12 修後） |
| G7 宣稱≠驗證 | ✅ | Q self-test「全 2 無證據→50、24 題標宣稱」；S 的 closure 要 token＋可解析引用；packet completed 三要件＋非本人 |
| G8 介面與 CI | ✅ | exit 0/2/3；同一真實目錄兩次 `score.json` 相同（排除 run_id/generated）：True |
| G9 文件一致 | ✅ | README 範例分數改為 42.9（DEMO 實得）；`scan/README` 10 領域列名補 staleness；指令可直接執行 |
| G10 清單 | ✅ | `make_manifest.py --check`：一致（17 檔） |
| G11 非宣稱 | ✅ | 見 §4 |

## 3. 狗糧｜Dogfood（同一引擎，真實目錄）

| 對象 | 舊引擎 v0.3 | 新引擎 v0.5 | 判讀 |
|---|---|---|---|
| 空目錄 | 1 | 1 | 維持 |
| 檔名全對、內容全空（selftest B2） | **76** | **1** | 灌分被擋 |
| 治理完整測資（真鏈＋真 hook＋有證據的結案） | 78 | 90 | — |
| 同上，鏈改一字元 | **78（無感）** | **82**，logging 品質 0，標 `audit_log.jsonl:3` | 竄改可見 |
| `IMCC/雲端德`（auditable＋agent） | **2**，判「非運作中」 | **65**，logging 過、2 鏈全重算 | 假陰性消失。扣分項是真的：沒有 hook、沒有事故教訓帳、沒有 .gitignore |
| `protocols/SIC-JS_4.1_FR-002`（auditable） | secrets「無明文憑證外露 ✓」 | 34；揭露 `fixtures/keys/TEST_ONLY_ed25519_private.pem` | 漏報消失。4 個「不合格 completed」是該包自帶的負面測資（`fixtures/fail/`），引擎如實列出，不是誤判 |
| `gea-assessment` 自己（auditable＋agent） | 2 | 24 | 如實：工具 repo 沒有日誌、hook、結案檔。`selftest.py` 裡的 PEM 字串被列為測試金鑰（正確，內容含 TEST_ONLY） |
| `IMCC` 全樹（auditable＋agent，3.7 秒） | — | 83；secrets 命中 18→6→**0**（逐條人工判讀皆為佔位值），測試金鑰 1 | 見 F13 |

## 4. 剩餘限制與非宣稱｜Limitations and non-claims

1. **這是自審，不是獨立驗證。** 寫碼者＝審計者。要稱為「審計過的版本」，需要另一個人／agent 重跑 §5 的指令並簽字。
2. SIC-JS packet 的 `completed` 檢查是結構檢查，**不是官方 validator**。接官方 validator 是計畫 C2，要等 SIC-JS 4.2 WP7。
3. `--probe` 只餵一種危險指令（`rm -rf /`）給 Bash hook；擋得住它不代表擋得住別的。
4. 雜湊鏈重算只認 8 種常見正規化（sorted keys × compact/預設分隔 × ascii/utf8 × 有無 `sha256:` 前綴）；別的算法只能拿「僅連結」50 分。
5. 熵值警示只對設定類副檔名做，而且只是警示；佔位過濾可能把真的、但長得像佔位的金鑰放過（例如真金鑰剛好含 `test`）。
6. Q 問卷的證據欄是受測方自己填的文字；GEA 只強制「宣稱要有錨」，**不驗證那個錨是真的**。
7. 分數不是安全保證。全綠只代表這 10 個領域的已知失效型態有蓋子。
8. 本次審計中引擎被修了四次（F11–F14）才過閘。這表示 selftest 的測資在修前有漏洞；現在的測資覆蓋了這四個案例，但不保證沒有第五個。

## 5. 新鮮輸出｜Fresh outputs（原文）

### 5.1 `python3 scan/selftest.py`

```
── 分數範圍 ──
  ✅ 空系統≈1：1
  ✅ 只有無防竄 log（60/40 分離）：26
  ✅ 治理完整≥65：90
  ✅ 治理完整案基礎門檻全過
  ✅ B2 名字對、內容空 ≤30（防灌分）：1
── 內容判定 ──
  ✅ B3 真雜湊鏈全重算＝100：鏈驗證：1 全重算／0 僅連結／0 鏈斷／0 無鏈（抽樣 1）
  ✅ B3 竄改一字元→鏈斷、品質 0：鏈驗證：0 全重算／0 僅連結／1 鏈斷／0 無鏈（抽樣 1）　✗ 疑似竄改：['audit_log.jsonl:3']
  ✅ B3 竄改版總分低於完整版：82 < 90
  ✅ B6 .toml/.pem/無副檔名的憑證都抓到→gate fail：命中 3 檔（['config.toml[aws]', 'deploy[openai]', 'keys/service.pem[private_key]']）✗
  ✅ B6 TEST_ONLY 私鑰：揭露但不算洩漏：無明文憑證外露 ✓　｜　測試金鑰 1（標 TEST_ONLY，已揭露、不算洩漏）：['fixtures/TEST_ONLY_ed25519_private.pem[private_key]']
  ✅ B7 相對連結斷鏈被抓到、反引號提及只列不扣：抽樣 2 引用（絕對路徑＋Markdown 連結），斷鏈 50%：['docs/a.md→missing.md']；反引號提及但找不到 1（不扣分）：['docs/a.md→other/repo.md']
── hook／攔截 ──
  ✅ B4 hook 引用的腳本不存在→不給分：⚠ 1 條 hook 引用的腳本不存在：['missing_guard.py']
  ✅ B4 hook 設定＋腳本存在（未實測）≤80：hook 可用=True；涵蓋 3/3；有內容的攔截腳本 1；未實測（加 --probe 會真的餵一筆危險指令）
  ✅ B4 --probe 實測擋下 rm -rf /→品質 100：hook 可用=True；涵蓋 3/3；有內容的攔截腳本 1；實測擋下 rm -rf / ✓
  ✅ B4 --probe hook 沒擋→品質≤50 並警示：hook 可用=True；涵蓋 3/3；有內容的攔截腳本 1；⚠ 實測：hook 沒擋 rm -rf /
── 介面 ──
  ✅ B8 低於 --min-score→exit 3
  ✅ B8 目錄不存在→exit 2
  ✅ B9 同一輸入兩次輸出相同（排除 run_id/時間戳）
  ✅ B9 score.json 帶 schema_version
── 元測試 ──
  ✅ B1 引擎故意弄壞時 selftest 必須 FAIL

  ✓ 引擎正常（全部通過）
```

### 5.2 `python3 gea_assess.py --self-test`

```
=== GEA 自我測試 ===
  PASS  全部程式層防住＋有證據 → 100（實得 100.0）
  PASS  全部宣稱 2 分但無證據 → 以 1 計＝50，24 題標宣稱（實得 50.0）
  PASS  作答檔驗證：6 種非法輸入全部被擋（實得 6）
  PASS  作答檔驗證：合法輸入正規化正確
  PASS  全無防護 → 0（實得 0.0）
  PASS  全部只有規則沒有閘 → 50（實得 50.0）
  PASS  全未作答 → 0 分＋作答率 0（分母紀律）
  PASS  權重：治理與安全 82 > 其他 18，總和 100
  PASS  24 個指標基本訊息完整（what/why/evidence/how/fix）

✅ 自我測試全過
```

### 5.3 `python3 scan/make_manifest.py --check`

```
✓ MANIFEST 與實際檔案一致
```

### 5.4 內部字 grep（白名單原文見 `scan/make_manifest.py` 的 `INTERNAL_RE`；本報告不列出，見 F16）

```
(無輸出 / no output)
```

### 5.5 `python3 scan/selfcheck.py IMCC/雲端德 --profile auditable --agent`

```
================================================================
  GEA S 掃描報告　級三 可稽核（agent軌）
  對象：/home/user/IMCC/雲端德
================================================================

  【門檻分】65/100　🟡黃　＝　基礎門檻 48/60　＋　品質深化 17/40
  【成熟度光譜】65/100（原加權模型：整體程度，較平滑；門檻分較嚴，缺基礎即崩）

  ── 基礎門檻（有沒有做這件事）──
  ✅ 動作紀錄    （6.0/6.0）JSON 紀錄檔（內容判定）：2 個
  ✅ 金鑰隔離    （6.0/6.0）無明文憑證外露 ✓
  ❌ 危險操作攔截  （0.0/6.0）無危險操作攔截（沒有有內容的攔截腳本，也沒有引用到存在腳本的 hook）✗
        ⚠ 一次誤操作＝不可逆損失（刪除/誤發/誤付款）
  ✅ 完成需核准   （6.0/6.0）SIC-JS 封包 8（completed 合格 0／不合格 0）
  ✅ 檔案規則    （6.0/6.0）檔案/操作規則（有內容）：1 份
  ✅ 中斷可復原   （6.0/6.0）交接/狀態快照（有內容）：2 個
  ✅ 視圖不過期   （6.0/6.0）無 html 視圖（不適用）
  ✅ 引用完整    （6.0/6.0）文件 4 份
  ✅ 事件可查    （6.0/6.0）有可查詢的事件來源
  ❌ 事故教訓迴圈  （0.0/6.0）無事故教訓迴圈 ✗
        ⚠ 沒有教訓迴圈＝同一個坑一直跌

  ── 品質深化（做得多好；基礎沒過則不計）──
  🟢綠 動作紀錄    （4.0/4.0）鏈驗證：2 全重算／0 僅連結／0 鏈斷／0 無鏈（抽樣 2）
  🔴紅 金鑰隔離    （0.8/4.0）無敏感檔管理設定（僅靠剛好沒洩）
  ⊘ 危險操作攔截   基礎未過，品質不計
  🟡黃 完成需核准   （2.4/4.0）結案工件 0，其中有證據 0（結構檢查，非官方 validator）
  🔴紅 檔案規則    （1.2/4.0）單一真源/生成視圖機制=False（生成腳本 0，設定 0）
  🟡黃 中斷可復原   （2.8/4.0）可驗證交接包 1；快照 2
  🟡黃 視圖不過期   （2.0/4.0）全靠生成註記（0 個）
  🟡黃 引用完整    （2.0/4.0）無可驗證的引用；反引號提及但找不到 9（不扣分）：['proposals/2026-10-13_GEA優化規劃_gea-optimization-plan.md→.claude/settings.json', 'proposals/2026-10-13_GEA優化規劃_gea-optimization-plan.md→scan/README.md']
  🔴紅 事件可查    （1.6/4.0）2 個 jsonl 需逐檔 grep（成本高）
  ⊘ 事故教訓迴圈   基礎未過，品質不計

================================================================
  機讀報告：<out>/score.json　｜　紅黃/❌項＝你的風險點，建議優先處理
  本工具僅供自我檢視，不構成任何法律/法規/標準之符合性聲明；結果代表基本門檻檢查，非安全無虞保證。
================================================================
```

### 5.6 舊引擎（`main@0f1de8b` 的 `scan/`）對同一組測資與目錄

```
OLD named_empty basic: 76
OLD good basic: 78
OLD tampered basic: 78
OLD home auditable+agent: 2
```

---

獨立驗證方式：clone 分支，依序跑 §5.1–5.3，再對你自己的目錄跑 §5.5 的指令並逐條判讀命中。
To verify independently: clone the branch, run §5.1–5.3, then run §5.5 against your own directory and judge every hit by hand.
