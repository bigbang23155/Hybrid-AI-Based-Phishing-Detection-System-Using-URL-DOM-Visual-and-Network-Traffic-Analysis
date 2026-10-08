# Assignment 03：development-only 特徵與共同建模結果

固定 4,203 筆 development 樣本完成特徵擷取，新增失敗 0；70 次預先指定訓練全部完成。742 筆 test 保持封存，原有 55 筆 oversized 失敗保留，不補抽。

RF 主種子的 URL+DOM validation F1 為 91.28%，相對 URL-only 提升 6.15 個百分點；成對 95% 區間為 +3.71 至 +8.68 個百分點。這是同一歷史來源資料上的 development 證據，尚未建立開放環境、對抗性或零日偵測能力。

## 執行與完整性

- Execution commit：`7153f06cd719d393686e7cc8ceff8591f64b3bf6`。
- [GitHub Actions 37725422890](https://github.com/bigbang23155/Hybrid-AI-Based-Phishing-Detection-System-Using-URL-DOM-Visual-and-Network-Traffic-Analysis/actions/runs/37725422890) 全部成功；本機 158 tests / 39.51 s，雲端 158 tests / 18.36 s。
- 六個來源 shard 的長度及 SHA-256、候選清單 replay、分組清單及定義鎖均通過；逐筆核對 HTML、domain、source ordinal、label、partition 及配對 ID。
- Train：3,461（benign 1,718 / phishing 1,743）；validation：742（369 / 373），涵蓋 556 個 final groups。每一條件使用相同樣本及順序。
- 主比較特徵維度為 URL 18、DOM 23、URL+DOM 41。為 hostname-only 敏感度條件共擷取 URL registry 的 21 個欄位；21+23 的 44 個欄位均為有限值且無缺值，主模型仍只採凍結的 18+23 欄。
- Test feature rows = 0；test predictions = 0。下載的 Parquet 含鄰近 test 列，實體 page 解碼不能宣稱排除所有 test bytes；僅 development HTML scalar 被轉成 Python 並送入特徵擷取。
- 14 個條件 × 5 seeds = 70 fits；只 fit train。threshold 0.5，不調參、不改分組、不選最佳 seed、不校準。
- 保留 4,203 筆 extraction status、140 筆 train/validation 指標列及 51,940 筆 validation 預測。

## 六個主比較條件

預先指定 seed 4941401；百分比以各指標本身為分母。FPR 分母為 369 benign，recall 分母為 373 phishing。95% F1 區間以 556 個完整 final groups 進行 2,000 次成對 bootstrap。

| 模型 | 模態 | F1 | F1 95% 區間 | Recall | FPR | FP / FN |
| --- | --- | ---: | --- | ---: | ---: | ---: |
| RF | URL | 85.13% | 81.56–88.02% | 83.65% | 13.01% | 48 / 61 |
| RF | DOM | 87.99% | 84.34–91.04% | 87.40% | 11.38% | 42 / 47 |
| RF | URL+DOM | 91.28% | 88.02–93.92% | 89.81% | 7.05% | 26 / 38 |
| GBDT | URL | 86.44% | 82.72–89.57% | 86.33% | 13.55% | 50 / 51 |
| GBDT | DOM | 86.59% | 82.65–89.87% | 87.40% | 14.63% | 54 / 47 |
| GBDT | URL+DOM | 90.41% | 86.97–93.26% | 88.47% | 7.32% | 27 / 43 |

RF URL+DOM：accuracy 91.37%、precision 92.80%、ROC-AUC 0.962343、AP 0.964535、Brier 0.0737655；TN/FP/FN/TP = 343/26/38/335。所有完整指標見 `results/assignment03/development_v1/metrics.csv`。

## 成對增益與錯誤互補性

| 模型 | 對照 | ΔF1（百分點） | 95% 區間（百分點） | 修正對照錯誤 | 新增對照原本正確的錯誤 |
| --- | --- | ---: | --- | ---: | ---: |
| RF | URL | +6.15 | +3.71 至 +8.68 | 63 | 18 |
| RF | DOM | +3.29 | +0.92 至 +5.85 | 46 | 21 |
| GBDT | URL | +3.97 | +1.66 至 +6.07 | 51 | 20 |
| GBDT | DOM | +3.82 | +1.46 至 +6.51 | 52 | 21 |

以上區間是預先規劃的描述性比較，未作多重比較校正，不當作確認性顯著性檢定。RF 混合模型的 64 個錯誤分散於 53 個 groups；最高單群 3 筆，前 10 群共 21 筆，不是全由單一大群造成。

## 種子穩定性與訓練差距

| 模型 | 模態 | 主種子 train F1 | 5-seed validation F1 平均 ± 樣本標準差 |
| --- | --- | ---: | ---: |
| RF | URL | 99.37% | 84.96% ± 0.31 百分點 |
| RF | DOM | 99.91% | 87.77% ± 0.60 百分點 |
| RF | URL+DOM | 100.00% | 90.63% ± 0.59 百分點 |
| GBDT | URL | 90.58% | 86.44% ± 0.00 百分點 |
| GBDT | DOM | 91.04% | 86.59% ± 0.00 百分點 |
| GBDT | URL+DOM | 95.51% | 90.39% ± 0.06 百分點 |

標準差不是信賴區間。GBDT 的固定 subsample=1 等設定使部分條件跨種子預測相同，接近零的浮點標準差不表示跨資料集無不確定性。RF train F1 接近 1，validation 明顯較低；不能用 train 分數證明泛化。此次不因觀察結果改參數或重抽 split。

## URL 敏感度條件

均為同一 train/validation 上重新訓練的固定模型，不能解讀成部署時擾動攻擊成功率。以下列出主種子；五個種子的完整結果均保留。

| 模型 | 模態 | URL 條件 | Validation F1 | 相對完整 URL 的 ΔF1（百分點） |
| --- | --- | --- | ---: | ---: |
| RF | URL | no_https | 84.04% | -1.09 |
| RF | URL | hostname_only | 70.59% | -14.54 |
| RF | URL+DOM | no_https | 90.31% | -0.97 |
| RF | URL+DOM | hostname_only | 89.57% | -1.71 |
| GBDT | URL | no_https | 85.29% | -1.15 |
| GBDT | URL | hostname_only | 70.35% | -16.09 |
| GBDT | URL+DOM | no_https | 89.67% | -0.74 |
| GBDT | URL+DOM | hostname_only | 87.17% | -3.25 |

RF hostname-only 的 URL F1 降至 70.59%，加入固定 DOM 後為 89.57%。DOM 在這組限制下仍提供資訊；這不等於已排除內容/來源捷徑，也不等於抵抗惡意改寫。

## 內容與分層特點

- Validation benign 頁的 script_src_count 平均 27.22，phishing 為 7.03；script_count 為 47.25 / 12.58；iframe_count 為 3.89 / 0.65。較複雜頁面在此來源中偏向 benign，須把頁面複雜度與來源組成當成後續外部驗證重點，不能反推「script 多就是安全」。這些是邊際分布，並非 feature importance 或因果解釋。
- RF 混合模型在含 password input 的切片（n=145；60 benign / 85 phishing）F1 87.12%、recall 83.53%、FPR 11.67%；未含者（n=597；309 / 288）F1 92.47%、recall 91.67%、FPR 6.15%。切片的組成不同，屬描述性差異。
- 語言分布不均：英文 n=591（333 / 258），日文 n=68（12 / 56）；不能直接把其 F1 差異視為跨語言泛化能力。小語言及 target 切片常為極小樣本或單一類別。
- validation 的 has_nondefault_port 全為 0。保留該凍結欄位，不利用本次觀察作事後選特徵。
- `development_review.json` 為每個切片新增正負類分母，無 negative 時 FPR 記為 null，無 positive 時 recall 記為 null，n<30 標為小切片。30 僅是事後呈現提醒，不是排除/建模門檻。雲端原始結果仍保留零分母回傳 0 的運算慣例；單類切片的 FPR/recall 解讀請使用這份加註報告。

## 獨立核驗與證據限制

以 scikit-learn 從逐筆預測重算全部 70 組 validation 指標，最大差異 3.33e-16；以實際重複抽樣列（而非 runner 的權重公式）重算六組 F1 區間與四組成對 ΔF1 區間，全部相符。本機與雲端獨立核驗 JSON 完全相同。再核對 70 組 condition/seed 與全套模型參數符合凍結設定。

Train 指標僅為執行證據，未從 private features/models 獨立重算。Fitted model 僅保留 SHA-256、參數及重現資訊，模型檔與原始 HTML/URL/feature vectors 不在公共 artifact；這不是可部署模型發行包。

Python 3.12.15、scikit-learn 1.7.2、NumPy 2.2.6；AMD EPYC 9V45 runner，Docker 限制 2 CPUs / 5 GiB、禁止網路。各筆 extraction 時間及各模型第一個 validation batch / 5 次 warm batch 時間均保留。第一個 validation batch 已在 train prediction 之後，不能稱為程序冷啟動，也不是包含下載/解析的端到端延遲。

Artifact ID：11527856364；原始 ZIP SHA-256：`dbba6dc99b41e7ec417fc98600fc44dcf5385c6ccc38e6a57ceb1e064822f6ac`。
Partition manifest SHA-256：`49e9dc599fe11e243ac6ba18307900ddc854eeabb3cd700eb9f39fbf05f2deb0`。
Definition lock SHA-256：`332503c9473d6976dbea545f0b12fcd915f3af24283c8aa2f092d91e9c0fa039`。

## 下一研究步驟

本階段完成；保留預先指定 RF 主模型與全部六個主比較條件，未因 validation 排名更換協定。先針對英語、credential-entry 與頁面複雜度的 development 錯誤形成版本化假設，再依 `docs/extensions/open_world_robustness.md` 建立獨立時間/來源/活動群及語義保留擾動資料。新研究不得替換這 5,000 筆或回流到既有 test。

目前 RF 混合 FPR 仍為 7.05%（26/369；群組 bootstrap 95% 4.39–9.84%）。歷史平衡樣本的 precision 不能直接轉成真實低盛行率環境的 precision。對抗性訓練、漂移適應與零日偵測尚未實作或驗證；最終 test 也尚未評估。
