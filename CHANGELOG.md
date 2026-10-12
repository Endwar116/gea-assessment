# CHANGELOG

## 2026-10-13 — S 掃描 v0.5、Q 問卷 v0.2.0（計畫 B：偵測層改為內容導向、fail-closed）

根因：舊引擎靠「檔名」給分。6 個檔名正確、內容為空的檔案可以拿 78 分；
一個有雜湊鏈、寫入前驗證的真日誌因為檔名不含 `log` 只拿 2 分；
`.pem` 私鑰被報成「無明文憑證外露 ✓」。這一版整個偵測層重做。

| ID | 變更 | 驗收（都在 `scan/selftest.py`） |
|---|---|---|
| B1 | selftest fail-closed：查離開碼、獨立暫存輸出、`run_id` 比對、元測試（引擎弄壞時 selftest 必 FAIL） | 元測試通過 |
| B2 | 防灌分測資：檔名全對、內容全空 | 1 分（舊版 78） |
| B3 | logging 看內容：任何 `.jsonl` 都解析；辨認鏈欄位並**重算**（支援 SIC-JS ledger 信封與一般 `hash`/`prev_hash`）；品質分＝已驗證鏈比例 | 真鏈 100；改一字元→鏈斷、品質 0 |
| B4 | guardrail 看設定和行為：解析 `.claude/settings.json` PreToolUse，查 matcher 涵蓋 Bash/Write/Edit、腳本存在與可執行；`--probe` 餵一筆 `rm -rf /` 看 hook 擋不擋 | 腳本不存在→不給分；實測擋下→100；沒擋→≤50 並警示 |
| B5 | closure 看證據：verdict 檔要有判定 token＋找得到的證據引用；SIC-JS packet 做結構檢查（completed 須有證據、核准、非本人驗證者） | 空 verdict 不給分 |
| B6 | secrets 讀完整檔（≤1 MB）；掃 `.pem`/`.key`/`.toml`/`.env*`/無副檔名；加 AWS、GitHub、Slack 樣式與熵值警示；標 `TEST_ONLY` 的另列「測試金鑰」 | 三種藏法都抓到；TEST_ONLY 揭露不算洩漏 |
| B7 | integrity 也查 Markdown 相對連結；反引號提及只列不扣 | 斷鏈被抓到 |
| B8 | 離開碼：0 達門檻、3 低於 `--min-score`、2 引擎錯誤 | 可接 CI |
| B9 | `score.json` 加 `schema_version`／`run_id`；同一輸入同一輸出（排除 run_id/時間戳） | 跑兩次 diff 為空 |
| B10 | Q 問卷加證據欄：每題可附 `evidence`；2 分沒證據以 1 計並標「宣稱」 | self-test |
| B11 | `--answers` 驗證輸入；非法值給清楚訊息並 exit 2 | self-test |

狗糧（同一引擎掃真實目錄，數字見 `audits/`）：
空目錄 1｜名字對內容空 1（舊 78）｜一個有雜湊鏈日誌的 agent 家目錄 63（舊 2，且不再被判「非運作中系統」）｜含 TEST_ONLY 私鑰的協定包：揭露 1 把測試金鑰（舊：漏報）。

## 2026-10-13 — v0.4（計畫 A：清公開面）

- 移除自標 INTERNAL 的 `scan/TECH_DOSSIER.md`、已 commit 的報告輸出與 `__pycache__`；加 `.gitignore`
- 清掉內部代號與不公開的規格引用
- `scan/selfcheck.py --out`（預設 `./gea_report/`），不寫回工具目錄
- 數字對齊：24 指標、10 領域；DEMO 答滿 24/24；對照表補 staleness
- 授權統一 Apache-2.0；修正 `cd` 路徑
- `PUBLISH_AUDIT.md` 依 no-backfill 追加勘誤
- `scan/make_manifest.py`：完整 sha256 清單、只列實際出貨檔、內部字 outgate、`--check`

## 2026-08-02 — v0.1.0 / S 掃描 v0.3

首次公開。
