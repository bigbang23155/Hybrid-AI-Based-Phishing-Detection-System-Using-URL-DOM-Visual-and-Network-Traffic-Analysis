# Assignment 02 口頭簡報（2–3 分鐘）

這次把 Assignment 01 的 URL 清理流程延伸成可重現的 baseline 實驗。原本抽樣其實已使用固定
seed 的 random sampling，不是直接取前 2,000 筆；我保留此作法。18 個 features 現在定位為
initial baseline，透過 registry 保證訓練與預測的欄位及順序一致，也可指定任意經驗證的子集合。

切分方面，我改用 Public Suffix List-aware 的 eTLD+1 或正規化 IP 作為 group。同一 domain 不會
跨 train、validation、test。test seed 固定為 2025；development 內用五個預先指定 seeds 重複
train/validation，模型與 ablation 共用切分，再以 validation F1 平均值選參數。比較 Logistic
Regression 與受限制的 Decision Tree，並固定 phishing=1、threshold=0.5。

偏差是目前最重要的限制。Tranco 程式會人工建立 `https://domain/`，phishing feeds 則保留完整
path/query。因此 HTTPS、path/query 長度等可能學到來源，而不是 phishing。本次要求 baseline
及移除 `uses_https` 的 sensitivity analysis，但這不能消除 source-label confounding。

目前 checkout 沒有正式 raw/processed dataset，所以我沒有捏造 accuracy、F1 或圖表。程式已可
輸出 audit、五次 validation 的 mean±SD、test metrics、兩類 importance、permutation importance、
defanged errors、split manifest 與 fitted pipelines。補入原始檔後，以 README 的兩個指令準備資料
並執行一次即可產生正式結果。下一步是取得並校驗封存資料、執行鎖定流程，再蒐集來源重疊且包含
完整 URL 的 benign data；之後才擴展至 DOM、visual 與 network 模組。

後續我也檢視了 PhiUSIIL audit 的既有結論：其 134,850 筆 legitimate 全是 HTTPS root URL，
所以仍無法解決 legitimate root 與 phishing full-path/query 的偏差。IDE 中提到的 audit ZIP 並未
掛載到目前環境，因此沒有把它冒充成已重新驗證的 Dataset v2。

我實作並實際執行 observed legitimate URL collector：以 2026-09-26 下載並凍結的 Tranco list
為 sampling frame，seed 20250926 從 rank 1,001–100,000 抽 1,200 domains，每個 domain 最多三筆，
並限制 public IP、same-domain、robots、redirect、timeout 及敏感 query token。環境的 outbound
proxy 幾乎全面拒絕網站存取，最後只有 1 個 domain、3 筆 observed URLs，另有 2,398 次失敗。
Suitability gate 要求至少 2,000 URLs、300 domain groups 與 20% inner pages，因此正式判定為
**unsuitable**；沒有建立 Dataset v2，也沒有開啟 test set 或製造模型結果。下一步只需在允許
public web retrieval 的環境重跑相同 frozen-list 指令，或提供有授權的 original full-URL benign corpus。

ISCX-URL2016 `All.csv` 據使用者檢查只有 79 個預先計算 features 與 class，沒有原始 URL 或
domain ID，因此不能重算本研究 features 或做 domain-disjoint split，也沒有拿來建立 Dataset v2。
目前已準備完整 Windows project export 與 PowerShell scripts：先跑固定 10-domain diagnostic，
連線足夠才允許以既定 1,200-domain 設定收集，且新輸出不會覆寫原本失敗 pilot。
