# Assignment 03：development 錯誤與偏差審查

**決策：保留原本六個主比較條件，完成最終評估規格凍結。** 沒有發現資料配對、特徵重建或模型重現的阻斷性錯誤；但存在明顯的頁面複雜度依賴及來源／時間組成限制。此決策只支持繼續同一歷史來源的內部 benchmark，不是部署或開放環境能力認證。

## 核對範圍與證據

- 4,203 個 development URL/DOM 特徵紀錄重新擷取成功；兩份完整特徵檔的 SHA-256 與原實驗一致。
- 六個 baseline 模型只使用原 train 3,461 筆、seed 4941401 重建；模型序列化檔 SHA-256 全部與原實驗相同。4,452 個 validation probabilities 的最大差異為 0。
- 雲端 [Actions 37898355594](https://github.com/bigbang23155/Hybrid-AI-Based-Phishing-Detection-System-Using-URL-DOM-Visual-and-Network-Traffic-Analysis/actions/runs/37898355594) 執行 commit `edb641f424d7c6ca42bd45bc5e8b16be55abb9f4`，164 tests 通過（37.08 s）。
- 獨立核驗 240 個可由 ledger 重建的切片、292 筆跨模型／對照的修正及新增錯誤紀錄、960 次置換的彙總，以及 RF 混合模型密碼欄位差異區間。292 是比較紀錄數，不是不同樣本數。語言／月份／密碼切片混淆數也與原實驗逐項一致。本機與雲端核驗 JSON 相同。
- Test feature rows、test predictions 均為 0；原本 55 筆失敗保留。原資料、特徵、參數、seed、threshold 與 split 未修改。

## 1. 混合模型修正了什麼，也新增了什麼

| 模型／對照 | 修正 FP | 修正 FN | 新增 FP | 新增 FN |
| --- | ---: | ---: | ---: | ---: |
| RF / url_only | 29 | 34 | 7 | 11 |
| RF / dom_only | 25 | 21 | 9 | 12 |
| GBDT / url_only | 31 | 20 | 8 | 12 |
| GBDT / dom_only | 34 | 18 | 7 | 14 |

RF 混合對 URL-only 修正 63 筆，同時新增 18 筆錯誤（7 FP／11 FN），其中 6 筆含 password input。對 DOM-only 新增 21 筆錯誤（9 FP／12 FN），其中 8 筆含 password input。增益並非每個樣本都改善，必須保留逐筆比較。

`paired_changes.jsonl.gz` 保留每筆變化及原／混合分數；`confidence_cases.json` 依分數與 ID 固定列出各混合模型最高信心的 10 FP／10 FN，共 40 個模型－案例紀錄。它是可重現的檢視佇列，未宣稱已人工判定頁面意圖或修正來源 label。

## 2. 密碼欄位差異：不能直接解釋成密碼欄位造成錯誤

RF 混合模型中，含 password input 的 145 筆 F1 為 87.12%，未含的 597 筆為 92.47%；原始差異為 −5.35 個百分點。以 556 個完整 final groups 進行 2,000 次 bootstrap，present − absent 的 F1 95% 描述性區間為 **−15.53 至 +1.69 個百分點**，涵蓋 0。這不證明兩組相等，也不足以確立穩定的密碼欄位懲罰。

| RF 混合指標 | 未含 password | 含 password | 含 − 未含 |
| --- | ---: | ---: | ---: |
| 原始 FPR | 6.15% | 11.67% | +5.52 百分點 |
| 複雜度標準化 FPR | 7.82% | 8.27% | +0.45 百分點 |
| 原始 FNR | 8.33% | 16.47% | +8.14 百分點 |
| 複雜度標準化 FNR | 9.17% | 11.24% | +2.07 百分點 |

標準化使用 train 定義的 tag_count 四層，將兩組套用相同的 pooled validation class weights；每層、每個 password 組及相關類別至少 5 筆。此主條件保留全部 369 benign 與 373 phishing。差距縮小與組成差異的解釋相符，但只有粗略複雜度調整，未排除其他混雜，也沒有對調整後差異建立新的確認性檢定。

## 3. 頁面複雜度與分類錯誤有強烈關聯

分層界線只由 train 計算：tag_count = 106、475、1083，validation 不參與選界線。

| Validation tag_count | Benign / phishing | RF 混合 FPR | RF 混合 recall |
| --- | ---: | ---: | ---: |
| <106 | 30 / 153 | 26.67%（8/30） | 98.69%（151/153） |
| 106–474 | 69 / 100 | 13.04%（9/69） | 90.00%（90/100） |
| 475–1082 | 128 / 88 | 5.47%（7/128） | 79.55%（70/88） |
| ≥1083 | 142 / 32 | 1.41%（2/142） | 75.00%（24/32） |

簡單頁面組的 phishing 比例為 83.61%，最複雜組為 18.39%。正常的簡單頁面較容易誤報；複雜的 phishing 頁面較容易漏報。這是後續外部評估的重要風險：高 F1 的切片也可能有高 FPR，不能只用 F1 說該類頁面「處理得很好」。各層樣本數不同，以上為觀察關聯。

## 4. 模型是否真的使用 complexity 特徵

固定模型、不重訓，對既定群組作 30 次聯合置換。以下為 validation F1 的平均下降（百分點）；within 條件保留 password presence × English/other-or-missing × source-shard 的分層。

| 置換群組 | RF 全域 | RF within | GBDT 全域 | GBDT within |
| --- | ---: | ---: | ---: | ---: |
| all_url | 19.13 | 16.97 | 20.92 | 18.95 |
| all_dom | 26.05 | 21.63 | 23.27 | 19.24 |
| complexity | 7.21 | 5.72 | 3.39 | 2.64 |
| credential | 1.39 | 0.96 | 0.02 | -0.02 |

complexity 為明確固定的 9 個 tag/resource/script/iframe 欄位，credential 為 8 個 form/input/action 欄位，詳細名稱見 review config。RF 的 complexity 群組置換造成平均 F1 下降 7.21 個百分點，within 仍下降 5.72；支持這組模型輸入具有實際預測作用，並非只有資料平均值不同。

此診斷不能單獨證明惡意捷徑或因果偏差，也不能證明抗攻擊能力。跨群組關係可能被置換打破，生成不真實的特徵組合；特徵相關性亦影響重要性分配。30 次 shuffle 的標準差／分位範圍只表示置換變異，不是人口信賴區間。各 block 的下降量不能相加。

## 5. 來源、時間與語言限制

- 六個 shard 的 RF 混合 F1 約 89.19%–93.98%，但它們只是同一 published corpus 的檔案分片，不能視為六個獨立外部來源。
- Validation 有多個月份只有 phishing；例如 2025-01 為 60 phishing／0 benign。這些月份的 FPR 無法估計，不是 0%。月份組成差異使單月 F1 不能直接當成時間漂移趨勢。
- 英文與其他語言的類別比例不同；小語言切片保留分母與 undefined 指標，不能以高分推論跨語言泛化。
- 來源 labels 沿用 publisher；本輪沒有人工重新 adjudicate，也沒有取得新的 browser rendering、redirect 或 network evidence。

## 決策與後續界線

沒有發現需要重抽資料、換 seed 或修改程式／特徵定義的 correctness blocker。本輪只評估已固定模型的局限，保持六個模型－模態條件不變，不因 validation 觀察進行追分。
最終評估規格固定在 `config/assignment03_final_evaluation_v1.json`，包括資料與來源雜湊、核心程式／依賴、特徵順序、六個模型雜湊、參數、seed 4941401、threshold 0.5、全部指標與成對 group-bootstrap 方法。未合併 train+validation。
本輪完成使用者指定的第 1、2 步。正式 test 執行仍是下一個獨立步驟；未實作可直接解封的 test inference 開關。最終同來源 test 也不能解決外部、時間或零日泛化問題。

## 可重現性與已知限制

原始審查 ZIP SHA-256：`4f3ff304419986e8ede184097824b19cfc4201f6c1b68a398e06fbdbb6d599c6`，artifact 11601054214。
首次 run 37897955600 在 Docker 基底映像資訊記錄步驟失敗，尚未執行 development 擷取或診斷；已修正並保留紀錄，未改審查設定。
獨立核驗可從公開預測重算錯誤與區間，但沒有從公開 artifact 重算每次 permutation prediction（private model/features 未公開），也沒有從原始頁面人工確定每筆錯誤成因。這些限制保留在 verification JSON。
重跑入口：`scripts/verify_development_review.py`；閱讀用 notebook：`notebooks/assignment03_development_review.ipynb`。測試資料保持封存。
