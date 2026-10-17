# urlscan.io Collector v1：獨立資料工程支線

基底：PR #18 的 `61b7e8da5b0a997c1f8f2f2dca10a68ec839ffd8`。
本輪位於 `research/urlscan-readonly-v1`，不修改 Assignment 03 的 75 個 frozen files，
也不重新訓練或呼叫正式 test。Collector 核心使用 Python 3.12 標準函式庫；加密與相似度模組使用 `requirements.txt` 的固定依賴。

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
| 歷史樣本批次補證 | 已接回原 packets、產生私有 Secret 輸入與 5 筆批次 | 273 uncertain 中 271 筆可搜尋；2 筆 userinfo URL 留待處理；首批已執行但 0/5 命中；正在補查及推進下一批 |
| 相似度候選索引 | 已實作 tags SHA-256、MinHash64、pHash64、dHash64 | 已索引 656 歷史 DOM；視覺模組待新證據；TLSH 為未安裝的選用套件；無標籤繼承 |
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
已接回原 packets 並對 656 份原 HTML bytes 全部重新計算 SHA-256，與既有 queue 全部一致。
原表的 `publisher_date` 不是 capture time，AI 審閱日期也不是 capture time。

## 執行

從 repository root 執行。API key 從環境或既有 GitHub Secret `URLSCAN_API_KEY` 取得，
不要寫入命令參數、檔案、log 或 repository。公開 smoke 不必新增 Secret。

```bash
python -m pip install -r research/urlscan_v1/requirements.txt
python -m unittest discover -s research/urlscan_v1 -p 'test_*.py' -v
python -m research.urlscan_v1.collector --smoke --request-limit 15 --output /private/urlscan-smoke-001
```

雲端 `.github/workflows/urlscan-readonly.yml` 在本支線同 repository 的 PR 變更觸發 offline tests，
成功後執行加密保存的 live smoke。也支援 workflow_dispatch（GitHub 通常要求 workflow 已存在於 default branch 才能手動啟動）。
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

雲端 smoke 與歷史 batch 僅上傳 `evidence.enc` 和彙總資料，原始 evidence 在 runner 清理。
加密 artifact 保留 30 天，需下載至持久私有儲存；GitHub Actions artifact 不是永久保存。
本地交接包保存解密私鑰；公開 repo 與 runner 都不持有證據解密私鑰。
AI annotations 與填寫表格也不推送公開 GitHub；public summary 可以保留。

完整性與內容可用性分開：即使 HTTP 403 或錯誤頁三份檔案齊全，也只代表取得完整，
會保留 `access_blocked` 等 flags，仍是 `REVIEW_REQUIRED`。HTTP metadata 不是 HAR 或 PCAP。
Result 404 是未完成／不可用，attachment 404 是缺件，410 是已刪除；都不是目標 benign/phishing 判定。
Provider verdict 不會作為 label、模型輸入或獨立人工證據。`task.source` 只提示來源，
同一 PhishTank/OpenPhish feed 的轉載不能當成兩個獨立來源家族。

## 本輪批次、加密與索引

- `batch_plan.py` 逐筆核對 queue、packet、AI annotation 和原 snapshot bytes。271 筆可搜尋 uncertain 按固定 seed 排序，每批優先不同 hostname（不是 registered-domain 分組，也不是統計隨機抽樣），不丟棄重複主機。共 55 批，最後一批 1 筆。2 筆含 userinfo 的 URL 保留 blocked receipt，不擅自改寫 URL。
- 完整候選清單由 `URLSCAN_CANDIDATES_GZIP_B64_01` 與 `URLSCAN_CANDIDATES_GZIP_B64_02` 兩個 Secrets 讀取，repository 不包含候選明文或候選密文。私有 JSONL 壓縮再 Base64，沒有 AI 理由或真人投票。本輪 48,668 ASCII bytes 拆為 32,000 與 16,668 bytes；每段保守限制 32,000 bytes，不再貼近官方 48 KB 上限。舊單一 Secret 在實際介面被拒收，因此撤回先前「可直接上傳」的說明。Base64／gzip 本身不是加密，保護由 GitHub Secrets 提供；不可將字串放入 repository。
- 設定 v2 明確指定段數與完整字串長度。依序拼接後仍核對原本的 compressed/plaintext SHA-256，再驗證完整 pool，最後按 offset/limit 選取批次。缺段、超長、截斷、順序錯誤與內容竄改都會在 API 請求前拒絕。舊的單一 Secret 不會當作缺段 fallback。讀取器最多支援 8 段，目前 workflow 明確注入 2 段；未來擴充須同步改 workflow/config。
- `config/cloud_batch.json` 綁定 compressed/plaintext SHA-256 與收件公鑰 fingerprint。初始批次 offset=0、limit=5、最多 25 次 API requests；目前診斷批次見文末、間隔至少 12 秒。完整 pool 先驗證才切片，失敗樣本留在 attrition report。
- `secure_store.py` 使用 RSA-3072 OAEP-SHA256 包裝一次性 AES-256-GCM key；每個 archive 有隨機 key/nonce，header 作為 AAD。先驗證 GCM tag 再解 ZIP；拒絕路徑越界、symlink、重複成員和不安全覆寫。最大未壓縮 archive 512 MB；大量資料應維持小批次，避免超出上限。
- `encrypted_batch.py` 在 API 請求前驗證公鑰/config/Secret 輸入；下載後建立相似度索引，整包加密才移到 upload 路徑。索引失敗時仍嘗試保留已抓取的加密證據。取消、runner crash 或超時仍可能使尚未封裝的資料遺失，不能宣稱任何失敗都可續跑。
- `.github/workflows/urlscan-encrypted-batch.yml` 僅同 repository 受控研究分支的 PR（workflow/config 改變時）或手動觸發；不是排程，也不會一次跑完 55 批。缺 Secret 時在任何 API 請求前失敗，設定後必須重新執行包含本次分段修正的新 run，不能重跑舊 SHA 的 run。分支 workflow 尚不在 default branch 時，使用本次 PR 更新所產生的新 run 的 **Re-run all jobs**。
- 小批次確認後才更新 offset，先逐批下載／驗證加密 artifact，再推進下一批。原 Collector 支援本地 resume；cloud wrapper 每次建立新 evidence run，不會跨 runner 自動 resume，也不會把再次搜尋到的較新 scan 當原 scan。

```bash
python -m research.urlscan_v1.batch_plan --packets /private/packets_blinded.jsonl --annotations /private/ai_annotations.jsonl --output /private/batch-plan
python -m research.urlscan_v1.similarity --packets /private/packets_blinded.jsonl --output /private/history-index
python -m research.urlscan_v1.encrypted_batch --work /private/run-001 --publish /private/encrypted-output
python -m research.urlscan_v1.secure_store decrypt --input /private/evidence.enc --private-key /private/evidence-private-key.pem --output /private/restored
python -m research.urlscan_v1.similarity --packets /private/packets_blinded.jsonl --run /private/restored/capture --output /private/combined-index
```

`encrypted_batch` 的 API key 與兩段候選 Secrets 均由環境注入，不放在命令列。證據解密私鑰只供下載後本地恢復，**不要設成 GitHub Secret**；CI 不需要它。加密只保護儲存與上傳，下載／解析期間 runner 仍會接觸明文，不能視為不可信網頁的執行沙箱。

### 相似度定義與限制

`similarity.py` v1 使用 HTMLParser 的起訖標籤序列（保留順序、忽略文字／屬性）產生 canonical SHA-256；5-token shingles 與固定 seed 的 64 個 MinHash 估計 Jaccard。這不是 browser 修復後的 DOM tree，可能將錯誤頁或共用 layout 歸為同結構。SHA 相同也不表示相同 campaign 或 label。

PNG 經完整解碼、白底透明合成、等比例 letterbox 至 256×256，再產生 pHash／dHash。pHash 用 32×32 DCT 的左上 8×8、排除 DC 中位數、DC bit 固定 0（63 個有效位）；不得直接套用其他實作的距離門檻。極低對比影像保留索引但不做視覺近鄰檢索，該品質門檻不是 phishing 門檻。

每筆每模態最多選 top-5，取聯集為候選 pairs；這只是人工工作量控制，**不是相似度判定門檻**。不做傳遞閉包、不自動合併、不刪除、不分配 split groups、不繼承標籤。缺失模態保留 null，不補成 0。TLSH 套件未安裝時明示不可用，不假造 TLSH 結果。pairwise 版本上限 5,000 evidence items，放大前需分片或 ANN。

歷史實跑：656 DOM、0 Visual、2,647 pairs；32 個 canonical exact groups 涉及 125 筆。這是純標籤序列相同，不是經人驗證的 template duplicates。個別 pairs 與索引放私有交接包，repository 只保留彙總。正式標籤、pairwise same-template 標註及相似度門檻仍待獨立 development 人工驗證。

API 依據（2026-10-17 檢查）：
- https://urlscan.io/docs/api/ — Result/DOM/Screenshot、404/410、rate limit headers。
- https://urlscan.io/docs/search/ — `task.url.keyword`、query escaping、最近結果優先；index 為 lowercase，所以仍需本地精確核對。

加密與 Secrets 依據（2026-10-17）：
- https://cryptography.io/en/stable/hazmat/primitives/aead/
- https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/
- https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets

## 2026-10-17 未命中診斷與下一批

已下載並解密 run `38994129840` attempt 2 的 artifact `12086296762`：
首批 5 筆均為 API 回傳 0 筆，非本地 URL／visibility／時間過濾掉結果。
原查詢為 `task.url.keyword`、size=10，沒有顯式日期條件；帳號可見歷史仍可能受方案限制。
首批沒有 query 或 fragment，正規化沒有改變 URL；其中 1 筆有大小寫路徑。
不能由 0 筆推論網站死亡、從未被掃描或標籤。

新增 opt-in `search_diagnostics`：原始 task URL → 有差異才查 normalized task URL →
page URL → task hostname，每項最多最近 10 筆、加 public filter、共用請求與限流上限。
每次保留回傳數、has_more（若供應商提供）、精確符合數與拒收原因。
同 hostname、不同 path/scheme/query/fragment 的結果只供診斷，不能取代原 URL 證據；
任何成功候選在 Result 下載後仍重新驗證 task URL/UUID/visibility/time。
沒有搜尋全文歷史、放寬標籤、轉成 POST 掃描或自動跨批次執行。

本次配置 offset=0、limit=10：重查原首批 5 筆，再處理原排程第 2 批 5 筆。
request_limit=70 包含重試，間隔至少 12 秒；遇限流或預算耗盡停止，未處理數另記。
原 Secrets、排序與金鑰不變。完成後須查看命中／失敗與保存產物，再決定 offset=10 的批次。

搜尋欄位依官方文件：https://urlscan.io/docs/search/
`task.url.keyword` 是原提交 URL；`page.url.keyword` 是跳轉後 URL；domain 搜尋不是頁面等價證明。
