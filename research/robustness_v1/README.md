# Assignment 03 之後的獨立補強研究 v1

新增獨立資料工程支線：[urlscan.io Collector v1](../urlscan_v1/README.md)。
可在真人複核未完成時進行 read-only 證據下載與 AI annotation 匯入；不改變以下研究順序及標籤門檻。

這個目錄承接新的研究；Assignment 03 的報告、資料分區、75 個鎖定檔案與正式結果維持原樣。
基底是 PR #17 合併後的 `ff45088e0ca5ff60c15923e15158553219898365`，不是仍停在舊進度的 main。
分支：`research/post-assignment03-robustness-v1`。

## 現在完成到哪裡

- 已實作並執行既有 development 的分層盤點、複核清單及歷史曝光排除清單。
- 已建立 656 筆待複核項目，來源只限原 validation；其中包含 64 筆 RF 混合錯誤、18 筆相對 URL 新增錯誤，以及分層抽出的正確案例。各類重疊，不可相加。
- 已建立樣本量規劃、證據／盲審紀錄檢查及六類演算法的 nested group CV 程式。
- 已建立雲端快照重建與技術交叉檢查；實際執行狀態以 evidence/cloud_receipt.json 為準，檔案不存在即尚未取得雲端結果。
- 真實的新資料訓練、人工標籤修正、融合改良、對抗性訓練及外部驗證均尚未完成。合成資料測試不是研究效果。

此輪沿用「先完成前三項，再執行第四項」的要求。獨立新 holdout 的來源與時間規則必須提前規劃，但不在前三項開發時查看其特徵分布、預測或標籤成效。

## 四個階段與可檢查的交付

| 順序 | 核心問題 | 嘗試及交付 | 進入下一階段的條件 |
|---|---|---|---|
| 1. 頁面複雜度 | 是數量不足、來源組成，還是模型捷徑？ | 新參考樣本＋困難樣本；learning curves；控制 source/time/login；訓練內加權；complexity ablation；多演算法比較 | 已複核的資料版本、完整試驗紀錄、子群分母／區間、限制及採納或不採納決策 |
| 2. 正常登入頁 | password input 是否只代理了頁面類型？ | 分清 login、registration、password reset、付款等情境；在共同複雜度／來源／月份比較 FPR；校準與 threshold 只在訓練內選 | 正常登入子群有足夠獨立樣本；誤報改善與 phishing recall 的代價已核對 |
| 3. 融合新增錯誤 | 哪種證據讓原本正確的預測翻轉？ | 新 development 上比 feature concatenation、校準後機率平均、group OOF stacking；保留 fixes/breaks | 融合輸入完整性、meta-model 無洩漏、逐類錯誤與成本已驗證；固定乾淨模型 |
| 4. 對抗＋開放環境 | 是否抵抗有效擾動並能跨時間／來源／campaign？ | 另立 threat model；train parents 的有效 HTML 變體；未見 operator／family；新的未曝光外部 holdout | 僅在 1–3 結案後執行；失敗／不確定結果也完整保留 |

「完成」不等於一定找到更高分的模型。若區間太寬或改善不可靠，就標成 inconclusive，補資料或保留原模型，不能為了進入下一階段而宣稱已改善。

## 樣本數與資料組成：分開實驗

1. 建立 **reference stream**：以預先固定的抽樣框、domain cap、時間窗和 seed 取得新樣本，保留觀察到的 prevalence、缺失及擷取失敗。
2. 建立 **targeted stream**：補足簡單正常頁、複雜釣魚頁、正常登入頁。其用途是困難樣本研究，不把刻意平衡的比例當成真實網站分布。
3. train 群組採巢狀 12.5%、25%、50%、75%、100% 子集，同一組驗證 fold 比較 learning curves。樣本不足的點保留為不可估計，不能用複製或合成列補足獨立樣本數。
4. 在相同資料量下比較原始組成、train-only class×complexity weighting、source/time/login matched sensitivity、移除 complexity 特徵群。逐一改動後再測組合；保留失敗及沒有進步的結果。
5. 複雜度界線只在每個 training fold 計算。matching、加權、scaling、calibration、threshold 與 feature selection 都不能看 outer fold。沒有共同支持的格子不強行配對。
6. 每個評估子群報告 benign/phishing 數、獨立 group 數、FP/FN 與 paired group bootstrap 區間。區分樣本數不足與實際誤差增加。

`sample_size_plan.json` 的 385 是最保守獨立二項比例 ±5pp 的近似**評估精度**規劃，不是訓練集大小要求，也不是比較兩模型的 power analysis。零誤報下，一側 95% 上界低於 1%／0.1% 約需 299／2,995 個獨立 benign 觀測；有誤報時不能繼續套用此數字。domain 群聚須用 cluster simulation／設計效應重新規劃。正式比較樣本量應使用配對不一致率及 group 結構，不能由舊 test 的小子群結果直接決定。

目前 656 筆是**舊 development 的原因追查清單**，不等於 656 筆新增訓練資料，也不構成新版獨立驗證集。

## 多次標籤交叉複核

- 先核對 URL／HTML 配對、SHA-256、原始資料列、來源版本及時間；擷取失敗不是 benign，空 HTML 不是零向量。
- 對 snapshot 做兩次獨立且對模型輸出及另一位判定不知情的人工審查。每次保留 reviewer、時間、原始證據、判斷理由及標籤。程式不會替真人簽名。
- 證據至少涵蓋兩個實際獨立來源家族，例如帶時間的來源記錄、snapshot 的品牌／表單行為核對、官方身分對應、事件確認。多家服務轉載同一 feed 只算一個家族；兩個模型都說 phishing 不能證明標籤正確。
- 網站不在 blocklist、HTTPS、Tranco 排名都不能單獨證明 benign。現在網站內容也不能直接替過去 snapshot 定案。
- 分歧或 uncertain 進入第三位複核；相反證據需逐項解釋。無法定案就 quarantine，保留原標籤與原因，不以多數決自動翻標。
- 自動標籤檢查、模型 disagreement、異常偵測可排序複核優先度，不直接當 ground truth。要同時抽查正確案例，避免只看錯誤造成 verification bias。
- 抽 10% 已定案樣本做後續盲抽複核，採固定 seed，檢查 raw agreement、Cohen's kappa 及每類分歧率；指標並列，不能把高一致率當成真實正確率。

`review_queue_blinded.jsonl` 是準備清單。`coordinator_key.jsonl` 含標籤與挑選原因，只供協調者，不能一併交給 blind reviewer。兩個檔案在同一研究 repository 中，這是流程上的盲審準備，並非技術存取隔離；正式送審須分開提供。

`prepare_packets` 只解析靜態 HTML，交叉核對兩套 count 實作並記錄 challenge/error/parking/low-text flags。兩套實作共享 HTMLParser，不能說成兩個獨立來源；這些 flags 也不能自動修正標籤。原始快照、URL 僅留在私有工作目錄，不透過公開 CI artifact 散布。source snapshot 的既有取得規則不變，沒有造訪 live phishing site。

`intake review` 檢查記錄格式、snapshot、timezone、有效時間窗、證據來源家族、盲審人員及分歧。它仍信任填入的 reviewer identity、origin family 和理由，**不能用軟體驗證「標籤一定正確」**。出版資料只有日期時，保留不確定性，不捏造精確 capture timestamp 以通過檢查。

## 演算法與公平比較

目前可呼叫的 core candidates：Logistic Regression、RF、Extra Trees、GBDT、HistGradientBoosting、RBF-SVM；每類兩組有界參數，三個記錄種子，URL／DOM／URL+DOM 共用相同樣本與 folds。
XGBoost／LightGBM 為後續有界比較候選，尚未安裝、實作或宣稱比 core 更好。新 library 須另鎖版本與預算。也可用通用 label-noise／outlier 方法協助找案例，但不能自動刪掉「模型不喜歡」的頁面。

`compare.py` 實作第一個 unweighted core 比較：5 outer × 3 inner group folds；inner OOF 選參數，SVM 的 calibration 也顯式使用 training group folds。Scaler 在 pipeline 內；HistGB 關閉內建 row-wise early stopping。Fold 缺類或 group 不足就失敗，不更換 seed 尋找較漂亮結果。

完整預定 core 比較為 270 outer fits＋1,620 inner fits＝1,890 次 estimator fit 呼叫；其中 SVM calibration 還有內部 fits。這是預算，不是已完成次數。所有結果、seed 波動、時間成本一起保留。對多演算法挑選後的 outer CV 結果仍屬探索；獨立成效要由之後新 holdout 驗證。

加權／matching／learning-curve 執行器、paired group bootstrap 彙整、各種融合與 stage promotion 尚待資料複核後按階段實作；`protocol.json` 是這些工作預先固定的方向，不把規劃當成執行完成。
融合時使用 group OOF 預測訓練 meta-model，禁止讓 meta-model 看到 base model 在自己訓練資料上的預測。新的操作 threshold 只由 training calibration 選定。報告 recall at FPR 時要附 FPR 區間與 benign 分母。

## 防止舊資料變成「新 test」

所有舊 5,000 candidates 先放入曝光清單。當前清單能核對 sample、domain、exact HTML、source row、final group；還缺 pilot-only 身分、normalized URL、template／campaign 的完整歷史比對。此缺口明確阻擋新 cohort 的完整 novel 宣稱，不能只檢查 sample ID 就過關。

新版 development 接受帶實際複核紀錄、完整 overlap audit receipt 及 41 個固定特徵的列。新的來源、月份、登入情境、review metadata 都是審查欄位，不是模型輸入。收集來源不同不等於獨立；同 publisher 的不同 shard 不算跨來源驗證。
新外部 holdout 應獨立保存且晚於選模：提前定義時序 cutoff、獨立 source family、campaign／kit 標註及未知情況處理。unknown campaign 不能宣稱 unseen campaign。跨界 component 按預先規則 quarantine，不把未來樣本移回 train。

## 執行方式

從 repository root：

```bash
python -m pip install -r requirements-dom.txt
PYTHONPATH=src:. python -m pytest -q tests research/robustness_v1/test_research.py
PYTHONPATH=src:. python -m research.robustness_v1.intake audit --root . --output /tmp/robustness-intake
```

輸出目錄必須不存在；保留每次執行，不覆寫歷史。

```bash
PYTHONPATH=src:. python -m research.robustness_v1.intake review --input packets.jsonl --output decisions.jsonl
PYTHONPATH=src:. python -m research.robustness_v1.compare --input new_development.jsonl --reviews packets.jsonl --history research/robustness_v1/evidence/history_v6/historical_exposure_registry.jsonl.gz --overlap-audit overlap_receipt.json --output /tmp/research-comparison
```

以上訓練命令目前不能對空白複核清單執行；必須有真實新樣本及證據。所有參數與 input hashes 隨結果保留。

## 目前下一個實際工作

完成原始快照重建的技術查核，準備實際 blind review，並建立新樣本來源 inventory、pilot/template/campaign 曝光比對及分層補樣批次。人工判定及獨立來源證據尚未存在，不會以模型的自動答案冒充完成。
第四階段 `adversarial_training_enabled` 與 `external_evaluation_enabled` 均為 false，且目前沒有啟動它們的工作流程。

方法依據：[group-aware CV](https://scikit-learn.org/1.7/modules/cross_validation.html)、[nested CV](https://scikit-learn.org/stable/auto_examples/model_selection/plot_nested_cross_validation_iris.html)、[permutation importance 限制](https://scikit-learn.org/stable/modules/permutation_importance.html)。工程樣本數、效果門檻及預算是本研究規劃，並非文獻規定的 phishing 通用標準。

## 第二輪：歷史曝光索引補強

已從原 Actions artifact 11382518633 取回 DOM pilot replay index，ZIP 與 CSV
分別通過原紀錄 SHA-256 核對。新增 256 個 pilot ID，合計 5,256 個曝光 ID；
其中 15 筆 pilot HTML 與正式候選相同，因此 ID 不同不代表內容獨立。
`evidence/history_v2/summary.json` 保留輸入雜湊、欄位覆蓋與缺口。
新增索引不是新訓練資料，沒有解封或重跑 test。

```bash
PYTHONPATH=src:. python -m research.robustness_v1.history --root . --archive /path/to/dom_pilot.zip --output /tmp/history-v2
```

compare 已加入歷史 normalized URL／structural template／campaign 的直接排除，
且來源列使用 revision + file + row 比對。缺少 source row 的紀錄仍可依其餘身分排除。
未知 campaign 不提供「未見 campaign」證明。本次索引仍缺 URL baseline、其他 observation
pilot 的完整身分，以及 normalized URL、template、campaign 歷史；不得宣稱查重已全部完成。
新樣本訓練仍需真實複核紀錄及完整 overlap receipt。

本輪另嘗試下載 observation pilot v2 artifact 10922820850，但 GitHub 回傳 404；
無法據此判定刪除、過期或權限原因。Assignment 02 公開 export 已成功重建並驗證，
但其中沒有完整逐筆身分資料，不能代替原始 dataset。詳見 continuation_receipt.json。
目前需要恢復上述原始索引並取得實際人工複核；214 項本機測試通過只代表工程
檢查通過，不代表四項改善已完成，也不代表模型效能提升。

## 第三輪：恢復 A02 保存檔

先前 GitHub artifact 404 的 observation v2 已從保存的完整 delivery 恢復。
ZIP SHA-256 與 repository 原紀錄一致，153 個 manifest 檔案全部核對。
另外取回 4,000 筆歷史 URL baseline；urls.csv 與凍結 dataset hash 一致。
只讀 URL 身分、observation metadata 與舊 DOM，沒有開啟 test_predictions。

`recover_history.py` 輸出合併的 hash-only registry（9,272 筆來源紀錄，不代表
9,272 個獨立 domain 或新樣本）：4,016 筆 normalized URL、9,016 筆 domain、
5,267 筆 HTML、10 筆符合最少 20 tags 的 structural signature。campaign 仍為 0。
索引包含失敗／skipped observation，避免把擷取失敗的已知網址當作未曝光。
來源紀錄可以重疊，不依此估計有效樣本數。

```bash
PYTHONPATH=src:. python -m research.robustness_v1.recover_history --root . --delivery /path/to/assignment02_baseline_and_pilot_v2_complete.zip --output /tmp/history-v3
```

輸出參見 `evidence/history_v3/summary.json`。原始 URL、DOM 與壓縮保存檔不進 Git。
仍缺 Assignment01／其他 URL collection、observation v1，以及正式 cohort／DOM pilot
完整 URL/template/campaign 歷史。未取得獨立人工判讀，因此新資料訓練與後兩階段未啟動。

## 第四輪：URL／template／campaign 查重與真人盲審材料

使用六個固定 shard 重建全部 5,000 筆正式候選的 normalized URL、domain、exact HTML
與 structural signature。`evidence/history_v4` 合併 observation pilot v1，總計 14,288 筆
來源紀錄（9,288 個 unique sample ID）；來源紀錄有意重疊，不代表獨立樣本數。
可比對欄位包含 9,032 筆 normalized URL、10,277 筆 HTML、4,793 筆 structure。

原 `final_group` 與 observation ID 被記錄為 `suspected_campaign_component_id`，供未來
資料隔離。這是 domain/URL/HTML/structure 的保守連通 component；沒有 operator、kit、
事件或獨立 feed 證據，因此 0 筆可標為 confirmed campaign，不能宣稱 unseen campaign。
Assignment 01 的 snapshot bytes 尚未找到，已保留為明確缺口。

656 筆既有 development 原因追查案例已重建為私人快照，技術檢查 656/656 通過。
`review_materials.py` 產生 Reviewer A、Reviewer B 兩份空白盲審表與第三人裁決表。
兩位 reviewer 必須是不同真人且在完成前看不到原標籤、模型結果與對方答案；本程式
不會簽署或代填真人判定。分歧或 uncertain 保留 quarantine。


## 第五／六輪：2026-10-10 歷史資料補齊及真人複核交付

最新索引是 `evidence/history_v6/`，完整 generated registry 與 duplicate groups 另保存在
`history-recovery-v6.zip`；PR 保留程式、coverage、summary 及其檔案雜湊。
解壓交付包到本研究目錄，或依下列指令重建後，才可執行完整 registry integrity test。
乾淨 checkout 的 CI 明確 skip 該檔案核验，不代表雲端已重建歷史索引。
它有 **256,718 筆來源紀錄、248,857 個不同身分 ID**，
包含 domain-only 嘗試紀錄與曾檢視的候選 pool；這不是新樣本數或訓練資料量。

- 重新從 SHA-256 鎖定的 train-000.parquet 重建 DOM pilot；256 個身分及原始 manifest/replay 雜湊均匹配。
  補回 256 個 URL/domain 指紋、242 個合格 structural fingerprints。其餘沒有 signature 不是「沒有 template」。
- 取回 Actions artifact 10901830057，核對 ZIP 雜湊及 31 個 member hashes。
  納入 2,643 個 combined observations、16 個 diagnostic observations、historical evidence URLs，
  以及 1,800 個預先抽定的 candidate domains 和 diagnostic failure domains；保留來源紀錄的重複。
- 找回原始 supplement audit delivery（SHA-256 與原報告一致），
  其 PhiUSIIL ZIP 與 CSV 亦匹配既有雜湊。納入先前已檢視的全部 235,795 個 URL rows，
  僅供曝光排除；142 個不同 normalized URL 身分已在 v5 中。
  原標籤、預計算 features 及 raw URL 均未輸出到此索引。
- 在整份歷史上做 URL、domain、exact HTML、合格 tag-sequence 的 transitive grouping。
  19 / 8,219 / 84 / 237 是各 key **連到兩個以上不同 sample ID 的群組數**，
  不是 duplicated row 數，也不是已确认釣魚 campaign 數。
  相同 normalized URL 已用同一 hash ID 合併者仍保留其多筆來源紀錄。
  `suspected_campaign_component_id` 是保守排除用 proxy，現有 confirmed campaign 仍為 0。
  compare 現在也拒絕與歷史 proxy ID 相同的新資料，並檢查新資料不能拆散同一 proxy。

仍未取得 Assignment01 原 4,000 個 URLs 與較早 local failed collection 原始身分。
URL-only 來源沒有 HTML；近似 template、獨立 campaign/kit/operator 註記也未完成。
因此 v4 的 recoverable-complete 表述不適用於整個研究歷史；v5/v6 明確保留 partial 狀態，
不能簽發 complete novelty 或 unseen-campaign 證明。

`review_intake prepare` 已對既有 656 筆盲審快照驗證所有 HTML hashes，
建立不執行網頁的文字摘錄、兩份獨立 CSV 及必要 evidence 有效時間欄位。
原始 URL/HTML 與填寫表格只在私有交付套件中；公用研究資料夾只保留 summary。
blind attestation 不再預填 true，必須由真人自己確認。

`review_intake import` 可接受部分填寫，拒絕未知/重複 ID、變更 snapshot、同一 reviewer、
未聲明盲審與不完整證據。空白匯入結果是 656 pending、0 reviews，
不會把 AI 文字摘錄當成真人答案。兩次同意但缺少 capture time 的紀錄仍 quarantine；
現有 publisher_date 不是 captured_at，不會編造午夜時間戳。
分歧裁決仍使用 intake.adjudicate 的第三位真人證據流程；本 CSV 匯入不自動解決分歧。

重現指令（不訪問樣本 URL，不訓練、不讀 test predictions）：

```bash
PYTHONPATH=src:. python -m phishing_url.dom_dataset --parquet /private/train-000.parquet --config config/assignment03_dom_pilot.json --output /private/dom-pilot-replay
PYTHONPATH=src:. python -m research.robustness_v1.extend_history --root . --pilot /private/dom-pilot-replay --supplement /private/historical-supplement.zip --output /tmp/history-v5
PYTHONPATH=src:. python -m research.robustness_v1.recover_candidate_pool --root . --delivery /private/assignment02_supplement_audit_36227969493.zip --output /tmp/history-v6
PYTHONPATH=src:. python -m research.robustness_v1.review_intake prepare --source /private/human-review-v1 --output /private/human-review-v2
PYTHONPATH=src:. python -m research.robustness_v1.review_intake import --packets /private/human-review-v2/packets_blinded.jsonl --reviewer-a /private/human-review-v2/reviewer_a/review_form.csv --reviewer-b /private/human-review-v2/reviewer_b/review_form.csv --output /private/review-import
```

PhiUSIIL attribution: Prasad & Chandra (2024), UCI dataset 967, CC BY 4.0,
https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset.
Its inclusion records prior exposure, not source/label approval for training.
