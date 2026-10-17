# urlscan.io Collector v1：獨立資料工程支線

基底：PR #18 的 `61b7e8da5b0a997c1f8f2f2dca10a68ec839ffd8`。
本輪位於 `research/urlscan-readonly-v1`，不修改 Assignment 03 的 75 個 frozen files，
也不重新訓練或呼叫正式 test。此模組僅使用 Python 3.12 標準函式庫。

## 不受人工複核進度影響的工作

| 項目 | 本版狀態 | 輸出／界線 |
|---|---|---|
| URLScan read-only API client | 已實作 | GET Search、Result、DOM、Screenshot；沒有 POST submission |
| Search-first 與身分核對 | 已實作 | 搜尋最近回傳的 10 筆；核對完整 task URL、UUID、public visibility、時間；只選最新 exact match |
| Request budget／retry | 已實作 | 單執行緒、預設 12 秒間隔、3 次有界嘗試；429/5xx/transport failure 退避、尊重 Retry-After 及 reset headers；超過 60 秒延後 |
| Evidence acquisition | 已實作 | JSON、DOM 文字、PNG；SHA-256、掃描時間與下載時間、最終 URL、HTTP 狀態、來源提示 |
| Missing modality／attrition | 已實作 | COMPLETE/PARTIAL/NONE 與獨立 flags；所有記錄仍需審查；不能據此宣稱 label 正確 |
| Resume／integrity | 已實作 | 輸入 fingerprint、逐筆 checkpoint、檔案 hash；復跑可重試不完整項目 |
| AI 初判獨立匯入 | 已實作並匯入本次附件 | 656 annotations；287 暫判 0、96 暫判 1、273 uncertain；真人新增 0 |
| 人工 CSV 匯入保護 | 已補強 | 拒絕已明示 AI 的 reviewer ID/type；無法以程式驗證偽裝的人名或真正獨立性 |
| GitHub Actions smoke | 已設定 | ubuntu-24.04／Python 3.12；僅 existing example.com public scan；實際成敗以 Actions run 為準 |
| 歷史樣本批次補證 | 執行入口已完成，尚未執行 | 輸入原私有 packets，先小批量；本 XLSX 沒有完整 URL，不從 hostname 猜 URL |
| 相似度引擎 | 待後續實作 | 本版僅保存 exact SHA-256；TLSH／MinHash／pHash、近似群組與門檻仍未完成 |
| 完整歷史／campaign novelty | 仍受舊缺口限制 | 保留 history v6 partial 狀態；unknown campaign 不能轉成 unseen |

## 最新架構與研究依賴

1. **Frozen benchmark**：既有 URL baseline、DOM／URL+DOM、formal test，保持鎖定。
2. **Historical development audit**：保留 PR #18 的 656 個原因追查項目與 history v6 排除索引。
3. **Evidence acquisition**：原 packet URL → exact public search → JSON/DOM/PNG → checksum、時間、缺失報表。
4. **Coordinator annotations**：AI 初判只協助安排補證；不得向仍在獨立盲審的人員展示 AI 答案。
5. **Human evidence gate**：兩位真正獨立的人員、來源家族及時間證據、衝突時第三人裁決。新 urlscan snapshot 是新 evidence item，不能覆蓋原 HTML 或虛構原 capture time。
6. **Dataset vNext**：只有複核、完整 overlap receipt 與 group-aware isolation 都成立才可納入新資料；本版所有 acquired records 的 `eligible_for_training=false`。
7. **Research experiments**：依序頁面複雜度 → 正常登入誤報 → 融合新增錯誤 → 對抗性／開放環境驗證。Attention Fusion、模態 dropout、few-shot、PCAP、Anti-Cloaking 多視角實驗保留為後續工作。

上述 656 筆來自舊 development，不是 656 筆新訓練資料。AI 的信心不是校準機率。
已核對全部 review IDs 與表內 SHA-256 對應既有 queue；本輪沒有原 HTML bytes，沒有重新對 656 份 snapshot 計算 hash。
原表的 `publisher_date` 不是 capture time，AI 審閱日期也不是 capture time。

## 執行

從 repository root 執行。API key 從環境或既有 GitHub Secret `URLSCAN_API_KEY` 取得，
不要寫入命令參數、檔案、log 或 repository。公開 smoke 不必新增 Secret。

```bash
python -m unittest discover -s research/urlscan_v1 -p 'test_*.py' -v
python -m research.urlscan_v1.collector --smoke --request-limit 15 --output /private/urlscan-smoke-001
```

雲端 `.github/workflows/urlscan-readonly.yml` 在本支線同 repository 的 PR 變更觸發 offline tests，
成功後執行 live smoke。也支援 workflow_dispatch（GitHub 通常要求 workflow 已存在於 default branch 才能手動啟動）。
Smoke 必須取得 Result、DOM、有效 PNG envelope 及非空 HTTP requests 才 exit 0。
查無合適 scan、限流、附件缺失都會如實報告，不把「程式跑完」等同「資料完整」。
PNG 驗證檢查 signature、chunk bounds／CRC／IHDR／IDAT／IEND，沒有完整解壓或影像語意驗證。
HTTP gzip／deflate 及無 encoding header 的 gzip DOM object 會有界解壓，
分別記錄傳輸 bytes 的 hash 與可讀內容 hash；兩者不可混用來判定原 snapshot 相同。

批次原始輸入使用既有私有 `packets_blinded.jsonl`，每列須有 `review_id`、`sample_id`、
`html_sha256`、完整 `url` 與 `scope=historical_development_audit`；本版拒絕不在既有 queue 的 ID。
URL 來源信任已核對的原 packet；公用 queue 沒有 raw URL，不能單靠它驗證 URL 身分。
可指定已知 `scan_uuid`，仍會核對 result 中的 task URL／UUID／public visibility。

```bash
python -m research.urlscan_v1.collector --input /private/packets_blinded.jsonl --limit 5 --request-limit 30 --output /private/urlscan-batch-001
python -m research.urlscan_v1.collector --input /private/packets_blinded.jsonl --limit 5 --request-limit 30 --output /private/urlscan-batch-001 --resume
python -m research.urlscan_v1.collector --input /private/packets_blinded.jsonl --limit 5 --request-limit 30 --output /private/urlscan-batch-001 --resume --retry-incomplete
python -m research.urlscan_v1.ai_review --workbook /private/review_B_AI_completed.xlsx --output /private/ai-import-001
```

同一 run 的有效輸入（含 limit 後的順序）不可變動；增大批次使用新 output。
預設 resume 重用已保存的成功與失敗紀錄；`--retry-incomplete` 才重試未完整項目。
每次 invocation 有自己的 request budget；原 quota window 與實際限制仍以 provider 為準。
此版不分頁、不遍歷歷史、不聲稱「搜尋不到即沒有歷史 scan」。
每個使用者原始 URL 會傳給 urlscan 搜尋 API，但不提交新的掃描，也不直接造訪該目標。

## 輸出與保存

- `run.json`：輸入與 policy identity。
- `private/<candidate hash>/record.json`：URL、UUID、原始／新 snapshot 關係、時間、錯誤與品質 flags。
- `private/.../result.json`、`dom.html.txt`、`screenshot.png`：不可信原始證據，只供受控離線分析。
- `public/dataset_attrition_report.json`：總量、取得數、未嘗試數、缺失／失敗原因、人審／訓練新增數。
- `public/artifact_hashes.json`：只含 candidate hash、檔案 hash／bytes 與完整性狀態。

雲端 smoke 僅上傳 `public/`，原始 evidence 在 runner 清理。**這個 smoke 不提供長期 raw evidence 保存**。
正式 batch 需在受控執行環境保存 `private/`；公開 repo 的大量雲端批次尚需接上私有儲存或加密 artifact。
AI annotations 與填寫表格也不推送公開 GitHub；public summary 可以保留。

完整性與內容可用性分開：即使 HTTP 403 或錯誤頁三份檔案齊全，也只代表取得完整，
會保留 `access_blocked` 等 flags，仍是 `REVIEW_REQUIRED`。HTTP metadata 不是 HAR 或 PCAP。
Result 404 是未完成／不可用，attachment 404 是缺件，410 是已刪除；都不是目標 benign/phishing 判定。
Provider verdict 不會作為 label、模型輸入或獨立人工證據。`task.source` 只提示來源，
同一 PhishTank/OpenPhish feed 的轉載不能當成兩個獨立來源家族。

## 下一批不需等人工定案的工程

1. 將原私有 packets 與 AI annotations 依 review ID/hash 連接，先排 273 uncertain 的補證需求；盲審表維持獨立。
2. 在私有／加密儲存就緒後，按固定小批次配額執行，逐批保留 attrition，不因取得失敗刪掉樣本。
3. 以實際 DOM／Screenshot 建立 canonicalization 與 exact/fuzzy 候選索引，先使用合成 fixture 驗證程式。
4. 人工標籤與 pairwise same-template 判讀可用後，才在獨立 development 校準相似度門檻。

本版不實作自動 label inheritance、相似樣本自動刪除、正式訓練或新的 holdout 評估。

API 依據（2026-10-17 檢查）：
- https://urlscan.io/docs/api/ — Result/DOM/Screenshot、404/410、rate limit headers。
- https://urlscan.io/docs/search/ — `task.url.keyword`、query escaping、最近結果優先；index 為 lowercase，所以仍需本地精確核對。
