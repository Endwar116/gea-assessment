# VS-7 中小企業 AI 自檢系統 — 完整技術資料檔（TECH DOSSIER）

> 版本 v0.3｜2026-07-10｜作者 （ 三樓）｜狀態：核心引擎完成、可 demo、待 v0.4 出貨打磨
> 本檔＝單一入口：讀完這一份就掌握整個系統的設計、規格、程式、驗證、複現、路線。
> 完整性驗證：`MANIFEST.json`（9 檔 sha256）；程式語法自檢 PASS。

---

## 0. 一句話定義

一個**免費、開源、純地端、零依賴（Python 標準庫）**的 AI／Agent 系統體檢工具：對一個目錄跑，用「證據導向」評出系統有沒有達到**安全、可持續、可稽核**的基本門檻，輸出分數＋風險清單＋報告卡。**引流工具**（測出痛點→高階顧問轉化），**不代言任何法規**。

---

## 1. 設計脈絡與定位（委託方裁定）

| 面向 | 定案 | 出處 |
|------|------|------|
| 資安痛點 | 純地端、資料零外傳、無伺服器（stdlib） | 2026-07-10 委託方 |
| 商業角色 | Lead magnet：免費 repo → 痛點顯現 → 顧問轉化 | 同上 |
| 法規立場 | 對照 ISO 42001/NIST/OWASP 僅參考，明示非合規認證 | 同上 |
| 評分模型 | 60/40 兩層＋原加權模型並列（成熟度光譜） | 2026-07-10 委託方兩次裁定 |
| 空系統 | 應趨近 1 分（系統存在性錨） | 2026-07-10 委託方 |
| 開發分工 |  全包到 demo；商業層派 | 2026-07-10 委託方 |

**核心洞察**：本工具的檢測邏輯＝ 多 agent 環境為了治理自己而實戰做出的工具（logger／閘門／帳本／掃描器／三件套…），翻譯成企業看得懂的體檢即成品。每個檢測項都對應一個真實踩過的坑。

---

## 2. 系統架構

```
ai-selfcheck/（純 Python 標準庫，git clone 即跑）
├── selfcheck.py            入口：選層級→跑9領域→60/40聚合→報告(終端+score.json+report_card.html)
├── checks/__init__.py      10 個檢測領域（各回 gate+quality）＋共用 inventory 快取
├── profiles/               嚴謹度分層（領域清單）
│   ├── basic.json          級一 基本可控（5 領域）
│   ├── sustained.json      級二 可持續（7 領域）
│   └── auditable.json      級三 可稽核（9 領域）
├── mappings/
│   └── framework_mapping.json   9領域×ISO42001/NIST AI RMF/OWASP LLM 參考對照
├── report/                 產出（跑後生成）：score.json + report_card.html
├── README.md               企業下載使用說明
├── MANIFEST.json           檔案 sha256 清單（完整性驗證）
└── TECH_DOSSIER.md         ← 本檔
```

資料流：`目錄 → build_inventory(一次遍歷) → 9領域各讀快取判定 → 每領域{gate,quality} → 60/40聚合+光譜 → score.json → report_card.html`

---

## 3. 評分模型完整規格（v0.3）

### 3.1 兩層＋雙視角

- **門檻分（主，60/40）**
  - 前 60 分＝**基礎門檻**：n 個領域，每領域 gate 通過＝拿 `60/n`；二分、寬鬆（「有沒有做」）
  - 後 40 分＝**品質深化**：每領域 quality(0-100) × `40/n`；連續（「做得多好」）
  - **gated 鐵律**：gate fail → 該領域品質分自動 0（連 log 都沒有，談什麼防竄）
- **成熟度光譜（副，原加權模型保留）**：每領域融合分 `(gate?60:0)+0.4×quality` 等權平均；較平滑，看整體程度。與門檻分並列輸出。
- **系統存在性錨**：`logging.gate OR filerules.gate OR (agent AND guardrail.gate)`＝False → 判定「非運作中 AI 系統」，總分與光譜 ×0.1（空系統→≈1）。修掉「反向指標（沒洩漏≠有管理）撐分」問題。

### 3.2 分級
`≥75 綠｜45-74 黃｜<45 紅`

---

## 4. 十個檢測領域規格（v0.3 起含「視圖不過期」staleness，共 10 項與 score.json 輸出一致）

| 領域 | 基礎門檻（gate，60池） | 品質深化（quality，40池） | 對應檢核表 | 轉譯自 /andwar |
|------|----------------------|--------------------------|-----------|---------------|
| logging 動作紀錄 | 有 log/state/event jsonl | 抽樣有防竄 hash 欄位比例 | 1-1,3-1 | vs_sic_log／四樓 verify_hash_chain |
| secrets 金鑰隔離 | 無明文憑證外露 | 有系統化敏感檔管理設定 | 1-4 | agr_gate 敏感樣式+exclusion_config |
| guardrail 危險操作攔截 | 有 gate/guard 腳本 or hook | hook上線+多類涵蓋 | 1-3 | agr_gate／PreToolUse |
| closure 完成需核准 | 有 verdict/governance 跡象 | 結案工件數 | 1-2 | BRSCP／PTGR C4 |
| continuity 中斷可復原 | 有 handoff/state/slt/acv | 可驗證交接包(slt)+快照數 | 2-2 | 三件套／SLT validate |
| filerules 檔案規則 | 有 rule/convention/config | 單一真源/生成視圖機制 | 2-3 | gen_views／R16 |
| eventquery 事件可查 | 有 log or db | 有結構化事件庫(sqlite)秒查 | 3-3 | andwar_eventdb |
| integrity 引用完整 | 有文件 | 抽樣引用斷鏈率（O(1)集合命中） | 2-3 | path_scanner／orphan_scan |
| incident 事故教訓迴圈 | 有 incident/lesson 紀錄 | 有教訓帳+折入 | 3-5 | EGI 事故帳／lessons |

每領域附 `risk`（沒有會怎樣）供報告顯示。agent 軌加分：guardrail/continuity 額外查 hook/可驗證封包。

---

## 5. 檢核表（規則種子，人工版）

15 題三門檻（基本可控／可持續／可稽核），每題附「怎麼驗證（要看得到證據）」＋「沒有會怎樣」。
完整表：`計畫/中小企業AI導入檢核表_v0.1.md`（房）。此表＝檢測模組的規則來源。

---

## 6. 國際框架參考映射

`mappings/framework_mapping.json`：9 領域各對應 ISO/IEC 42001、NIST AI RMF、OWASP LLM Top 10 條目。
**每處明示**：僅供理解檢查點來源，非合規認證；正式判定須授權機構。`--mapping` 選項在報告尾顯示。

---

## 7. 驗證紀錄（R14 紅隊，證據導向）

| 對象 | 門檻分 | 結論 |
|------|--------|------|
| 空目錄 | **1** | 系統存在性錨觸發，反向指標不撐分 ✓ |
| 中間目錄（只有無hash的log） | **26** | 基礎✅品質✗，60/40 分離清楚 ✓ |
| 我們自己系統（auditable+agent） | **88 綠** | 9 基礎全過60/60+品質28/40 ✓ |

四預測全驗證（空1/我88/中26/gated）。效能：CPU 極快（0.44s），walltime 瓶頸=外接卷 IO（本地 SSD 快）。
完整報告：`R14_預測.md`、`R14_預測_v0.3評分模型.md`。

---

## 8. 版本演進

- v0.1：檢核表（人工）＋產品章程
- v0.2：評分引擎＋9 模組＋加權連續分（紅隊抓修 N/A 膨脹）
- **v0.3（現）**：60/40 兩層＋系統存在性錨＋成熟度光譜並列＋框架映射＋報告卡 HTML＋README＋MANIFEST
- v0.4（待）：遍歷加速、出貨前 outgate 清內部路徑/代號、landing 頁、自媒體素材、商業轉化（）

---

## 9. 複現指南（從零）

1. `python3 selfcheck.py <目錄> --profile basic`（最小）
2. 加 `--agent` 測 agent 型；加 `--mapping` 看框架對照
3. 看 `report/report_card.html`（給主管）與 `report/score.json`（機讀）
4. 驗完整性：比對 `MANIFEST.json` 的 sha256
5. 改規則：編 `checks/__init__.py` 領域函式（回 gate+quality）＋ `profiles/*.json` 加領域

---

## 10. 已知限制（誠實）

1. 效能：大目錄外接卷 os.walk IO 瓶頸（v0.4 早停/平行）
2. integrity 對「單一房」偏嚴（跨區引用會斷）——已限 root 內判定
3. 出貨前必跑 outgate 白名單掃，清掉 repo 內  內部路徑/人名/代號
4. secrets 為特徵掃描，非萬能（混淆/編碼憑證可能漏）

---

## 附：相關檔案地圖

| 類 | 路徑 |
|----|------|
| repo 本體 | `三樓//待送包/ai-selfcheck/` |
| 產品章程 | `三樓//計畫/VS-7_中小企業AI自檢系統_產品章程_v0.1.md` |
| 檢核表 | `三樓//計畫/中小企業AI導入檢核表_v0.1.md` |
| 任務追蹤 | `三樓//DB/tasks.jsonl`（VS-7）｜登記 `_INDEX.md`（D39-D43） |
| 事件查詢 | `python3 三樓//tools/andwar_eventdb.py find VS-7` |
