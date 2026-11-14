# PLAN_PIPELINE.md

Rencana khusus **perbaikan pipeline** (kode, eksperimen, pelaporan).
Data baru diatur di `PLAN_DATASET.md`. Baca `AGENT.md` dulu, lalu `IMPLEMENTATION.md`. Aturan di sana tetap berlaku.

Cara kerja untuk agen:
- Satu tugas per sesi kerja. Jangan menggabung dua tugas.
- Sebelum mulai: pastikan keputusan yang dibutuhkan sudah dicentang (bagian 1) dan tugas prasyarat berstatus `done`.
- Setelah selesai: jalankan cek penerimaan, `pytest -q`, perbarui tabel status, laporkan angka asli.
- Lingkungan: `PYTHONPATH=src .venv/Scripts/python.exe scripts/<nama>.py`.
- Jangan commit atau push kecuali diminta.

## 0. Apa yang diperbaiki

| # | Temuan audit | Tugas |
|---|---|---|
| T1 | Recall 0,81 adalah artefak: flow masuk jendela menurut waktu mulai, CICFlowMeter memotong tiap 120 detik, sehingga muncul jendela "weak" yang berlabel carpet tapi tidak berisi trafik serangan | PL-2 |
| T2 | Accuracy (variabel terikat di proposal 3.2) tidak dihitung oleh kode | PL-1 |
| T3 | Tuning tidak memilih apa-apa: semua 8 konfigurasi mendapat parameter yang sama, RF terpilih lebih buruk dari default, `max_features = 1.0` menjadikannya bagging. Ruang cari tidak memuat parameter yang disebut proposal 3.2.4.4 | PL-3 |
| T4 | Ablation tidak sesuai proposal 3.2.2.4: `n_unique_dst` dan entropy tidak pernah dicabut. Set "fitur flow saja" tidak ada, padahal itu pembanding inti rumusan masalah 2 | PL-4 |
| T5 | Permutation importance hanya di fold 0 dan hanya untuk RF | PL-5 |
| T6 | Aturan satu ambang tidak dievaluasi di hold-out, jadi "ML vs aturan" tidak terjawab di data uji | PL-6 |
| T7 | Waktu inferensi hanya mengukur `predict`. Klaim near real-time butuh latensi ujung ke ujung | PL-7 |
| T8 | Kode hanya mengenal satu tangkapan, satu subnet korban, dan serangan UDP port 53 | PL-8, PL-9 |
| T9 | Hold-out v1 kecil dan sudah terbuka | PL-10, PL-12 |
| T10 | Uji robustness MAWI belum ada | PL-13 |
| T11 | Kolom `role` di `metrics.csv` final masih `xgb,primary` | PL-12 (digantikan hasil v2) |
| T12 | Naskah Bab 3 tidak cocok dengan yang dijalankan | PL-16 |

## 1. Keputusan yang harus disetujui manusia dulu

Setelah disetujui, salin ke tabel keputusan dan log perubahan `IMPLEMENTATION.md` dengan nomor D berikutnya (D21 sudah dipakai di branch `experiment` untuk penetapan jendela).

| ID | Pertanyaan | Rekomendasi | Dipakai oleh | Status |
|---|---|---|---|---|
| P1 | Penetapan jendela utama: `start` (proposal 3.2.3.1) atau `spread` (flow dipotong ke semua jendela yang dilaluinya)? | `spread` jadi metode utama, `start` tetap dijalankan sebagai pembanding. Revisi 3.2.3.1 di naskah. Alasan: ini memperbaiki alat ukur, bukan menyetel model. | PL-2 | [ ] |
| P2 | Aturan pilih hasil tuning? | Ambil rata-rata PR-AUC terbaik. Seri hanya jika selisih di bawah satu galat baku (`std / sqrt(5)`), lalu pilih yang paling sederhana. Kalau yang terpilih masih di bawah default, pakai default. | PL-3 | [ ] |
| P3 | Jumlah kombinasi tuning? | 30 per model (kembali ke rencana awal, karena data baru lebih sulit). | PL-3 | [ ] |
| P4 | `max_features = 1.0` boleh untuk RF? | Tidak. Nilai yang boleh: `sqrt`, `log2`, 0.3, 0.5. | PL-3 | [ ] |
| P5 | Ambang keputusan? | Tetap 0,5 sebagai angka utama. Tambahan: satu titik operasi "FPR paling banyak 1 persen" yang ambangnya dipilih dari prediksi CV, dinyatakan sebelum final. | PL-11, PL-12 | [ ] |
| P6 | Jendela weak di data latih (D3) setelah P1? | Tetap dijalankan dua kali. Kalau setelah `spread` jumlah weak di bawah 2 persen jendela carpet, laporkan itu dan pakai satu pengaturan saja (weak ikut dilatih). | PL-2, PL-11 | [ ] |
| P7 | Subclass baru untuk benign sulit? | Ya, `benign_hard`, label 0, ikut dalam stratifikasi fold. | PL-9, PL-10 | [ ] |
| P8 | Susunan hold-out v2? | Seluruh sesi B. Semua data S1 (termasuk hold-out v1) dan sesi A menjadi trainval. | PL-10 | [ ] |
| P9 | Saringan jendela MAWI? | Hanya (subnet, jendela) dengan minimal 20 flow. Angka ini ditetapkan sebelum melihat prediksi. | PL-13 | [ ] |
| P10 | Ablation multi-window 5 dan 30 detik? | Opsional, dikerjakan terakhir jika ada waktu. | PL-15 | [ ] |

## 2. Tabel status dan urutan

Nilai: `todo`, `doing`, `done`, `blocked`.

**Tahap A: tidak butuh data baru.** Hanya memakai trainval S1 dengan validasi silang. Hold-out v1 **tidak disentuh sama sekali** di tahap ini.

| Tugas | Prasyarat | Status | Catatan |
|---|---|---|---|
| PL-1 Accuracy di `evaluate.score` | - | done | accuracy di `score` dan `METRICS`, tes 172/183 |
| PL-2 Penetapan jendela `spread` | P1, P6 | done | D22. Weak 64 ke 1, paket identik, sama dengan branch. `reports/window_assignment.md` |
| PL-3 Perbaikan tuning | P2, P3, P4 | done | 30 setelan, rentang PR-AUC 0,000 sampai 0,003: tak ada yang disetel. `reports/stage_a_findings.md` |
| PL-4 Set ablation sesuai proposal | PL-2 | done | tanpa entropy: FPR RF 0,002 ke 0,029. Fitur flow saja: FPR 0,031. `reports/stage_a_findings.md` |
| PL-5 Importance di semua fold, per kelompok | PL-4 | done | RF bersandar ke `dst_spread`, XGB ke `dst_count`. `reports/stage_a_findings.md` |
| PL-6 Baseline masuk skrip final | PL-1 | done | rehearsal fold 0 lulus. `--final` tidak dijalankan. `reports/stage_a_findings.md` |
| PL-7 Latensi ujung ke ujung | PL-2 | done | hitung paling lama 0,7 s, tunda terburuk 180,7 s. `reports/stage_a_findings.md` |

**Tahap B: butuh sesi A dan B (`PLAN_DATASET.md` DS-8 lulus).**

| Tugas | Prasyarat | Status | Catatan |
|---|---|---|---|
| PL-8 Dukungan banyak tangkapan | DS-1 | todo | |
| PL-9 Pelabelan untuk vektor dan skenario baru | PL-8, P7 | todo | |
| PL-10 Split v2 | PL-9, P8 | todo | |
| PL-11 Jalankan ulang fase 1 sampai 9 | PL-2..PL-7, PL-10 | todo | |
| PL-12 Evaluasi final v2 (satu kali) | PL-11, P5 | todo | |

**Tahap C: data luar dan naskah.**

| Tugas | Prasyarat | Status | Catatan |
|---|---|---|---|
| PL-13 Uji robustness MAWI | PL-12, DS-9, P9 | todo | |
| PL-14 CIC-DDoS2019 (jika K6 = ya) | PL-12, DS-10 | todo | |
| PL-15 Multi-window (jika P10 = ya) | PL-12 | todo | |
| PL-16 Bahan naskah | PL-12, PL-13 | todo | |

## 3. Tahap A

### PL-1 Accuracy di `evaluate.score`

Berkas: `src/carpet/evaluate.py`, `tests/test_evaluate.py`.

Langkah:
1. Di `score()` tambahkan `"accuracy": (tp + tn) / (tp + tn + fp + fn)`.
2. Tambahkan `"accuracy"` ke daftar `METRICS`, di urutan terakhir.
3. Tambah satu tes: confusion matrix 43/1/129/10 memberi accuracy 172/183.

Penerimaan: `pytest -q` hijau. Jangan menjalankan ulang skrip final lama. Accuracy tidak pernah menjadi angka utama (AGENT.md bagian 9).

### PL-2 Penetapan jendela `spread` sebagai metode utama

Latar: di branch `experiment` sudah ada `spread_flows` di `src/carpet/windows.py`, tesnya di `tests/test_windows.py`, dan saklar `config.WINDOW_ASSIGNMENT`. Jendela weak turun dari 64 menjadi 1.

Berkas: `src/carpet/windows.py`, `src/carpet/config.py`, `src/carpet/features.py`, `src/carpet/labeling.py`, `scripts/run_label.py`, `scripts/run_features.py`, `tests/test_windows.py`.

Langkah:
1. Lihat dulu perbedaannya: `git diff main origin/experiment -- src/ scripts/run_label.py scripts/run_features.py tests/test_windows.py`. Baca seluruhnya.
2. Bawa berkas kode itu ke `main` (`git checkout origin/experiment -- <berkas>` per berkas, **bukan** merge seluruh branch: branch itu menghapus `README.md` dan `models/`). Jangan bawa folder `reports/` dari branch.
3. Ubah default `WINDOW_ASSIGNMENT` menjadi `"spread"`. Tata letak folder tetap seperti branch: `start` memakai folder tanpa akhiran (`data/processed`, `reports/experiments`, `reports/tables`, `reports/figures`), `spread` memakai akhiran `_spread`. Dengan begitu tidak ada hasil lama yang dipindah. (Dikerjakan begini, berbeda dari rencana awal yang memindah folder lama.)
4. Semua skrip menulis lewat `config.EXPERIMENTS`, `config.TABLES`, `config.FIGURES`, tidak pernah ke `reports/experiments` secara langsung. Tanpa ini, skrip yang dijalankan di bawah `spread` akan menimpa hasil `start`.
5. Jalankan ulang untuk `spread`: `run_label.py`, `run_split.py`, `run_features.py`.
6. Tulis `reports/window_assignment.md`: tabel jumlah jendela per subclass dan status untuk `start` dan `spread`.

Penerimaan:
- Total paket per sesi sama persis antara `start` dan `spread` (tidak ada paket hilang atau bertambah).
- `start` masih mereproduksi 921 jendela: benign 533, carpet 186 (33 weak), focused 112 (31 weak).
- Jumlah weak di bawah `spread` dicetak. Kalau bukan sekitar 1, berhenti dan lapor.
- `pytest -q` hijau termasuk `test_windows.py`.

Berhenti dan tanya jika: ada flow yang menyentuh lebih dari 4 jendela (`spread_flows` akan gagal dengan pesan itu), atau komposisi fold berubah sehingga satu fold kehilangan sebuah subclass.

Catatan: hold-out v1 ikut dilabeli ulang, itu tidak apa-apa. Yang dilarang adalah melatih, mengevaluasi, atau memplot barisnya.

### PL-3 Perbaikan tuning

Berkas: `src/carpet/config.py` (`TUNE_SPACE`, `TUNE_COMBINATIONS`), `src/carpet/tune.py`, `tests/test_tune.py`, `scripts/run_tune.py`.

Langkah:
1. `TUNE_COMBINATIONS = 30` (P3).
2. `TUNE_SPACE["rf"]`: `n_estimators` [100, 200, 300, 500], `max_depth` [4, 6, 8, 12, 20, None], `min_samples_split` [2, 5, 10], `min_samples_leaf` [1, 2, 3, 5], `max_features` ["sqrt", "log2", 0.3, 0.5], `class_weight` ["balanced", "balanced_subsample"].
3. `TUNE_SPACE["xgb"]`: yang sudah ada, ditambah `gamma` [0, 0.5, 1, 2] dan `reg_lambda` [0.5, 1, 2, 5]. `scale_pos_weight` tetap dihitung dari fold latih, tidak dicari.
4. `tune.pick()` mengikuti P2: `noise = std / sqrt(n_folds)`, bukan `std`.
5. `scripts/run_tune.py`: setelah `pick`, bandingkan dengan default. Kalau rata-rata PR-AUC yang terpilih lebih rendah dari default, simpan parameter default dan tulis `"chosen": "default"` di `chosen_params.json`.
6. Perbarui tes `pick`: kasus seri di dalam satu galat baku memilih yang sederhana; kasus selisih lebih besar memilih yang terbaik.

Penerimaan:
- `chosen_params.json` memuat untuk tiap konfigurasi: parameter terpilih, rata-rata dan std, nilai default, dan apakah yang dipakai hasil cari atau default.
- Tidak ada konfigurasi RF dengan `max_features = 1.0`.
- Dijalankan dua kali dengan seed sama memberi berkas identik.
- Laporkan apakah kedelapan konfigurasi masih mendapat parameter yang sama. Kalau ya, tulis itu apa adanya sebagai temuan.

### PL-4 Set ablation sesuai proposal

Berkas: `src/carpet/config.py` (`FEATURE_SETS`), `scripts/run_ablation.py`.

Tambahkan ke `FEATURE_SETS` (yang lama tetap):

| Nama | Isi | Menjawab |
|---|---|---|
| `flow` | 33 `FLOW_FEATURES` saja | Seberapa jauh fitur flow konvensional tanpa agregat (rumusan masalah 2) |
| `agg_flow_no_dst_count` | `agg_flow` tanpa `n_unique_dst`, `n_src_dst_pairs`, `mean_pkts_per_dst` | Proposal 3.2.2.4, bagian jumlah tujuan |
| `agg_flow_no_dst_count_no_volume` | di atas, juga tanpa `total_pkts`, `total_bytes`, `n_flows`, `max_pkts_per_dst` | Proposal 3.2.2.4 persis: tanpa jumlah tujuan dan volume |
| `agg_flow_no_entropy` | `agg_flow` tanpa `dst_entropy`, `dst_entropy_norm`, `concentration_ratio` | Apakah model bertahan tanpa sinyal utamanya |
| `agg_flow_no_dst_spread` | `agg_flow` tanpa semua fitur di dua baris sebelumnya | Batas bawah: tanpa informasi sebaran tujuan sama sekali |

Kenapa `mean_pkts_per_dst` dan `n_src_dst_pairs` ikut dicabut: yang pertama adalah total dibagi jumlah tujuan, yang kedua pada run sumber tunggal sama dengan jumlah tujuan. Membiarkannya berarti jumlah tujuan masih bisa dihitung balik.

Langkah:
1. Tambah set di atas. Pemeriksaan `FORBIDDEN_FEATURES` di akhir `config.py` harus tetap lulus.
2. `run_ablation.py` menjalankan semua set untuk RF dan XGBoost, kedua pengaturan weak, parameter dari PL-3.
3. Tabel hasil memuat rata-rata dan std tiap metrik, dan selisih terhadap `agg_flow`.

Penerimaan: `reports/tables/ablation.csv` punya satu baris per (set, model, weak). Laporan `reports/phase9_findings.md` ditulis ulang dari angka baru. Kalau `flow` saja menyamai `agg_flow`, tulis itu sebagai temuan, jangan disembunyikan.

### PL-5 Importance di semua fold dan per kelompok

Berkas: `scripts/run_robustness.py` (dan fungsi kecil di `src/carpet/evaluate.py` bila perlu).

Langkah:
1. Permutation importance dihitung di **tiap** fold uji (model dilatih di empat fold lain), untuk RF dan XGBoost, skor PR-AUC, 20 pengulangan, seed dari `config.SEED`. Laporkan rata-rata dan std antar fold.
2. Tambah permutation per kelompok: kolom dalam satu kelompok diacak bersama dengan permutasi baris yang sama.
   - `dst_spread`: `dst_entropy`, `dst_entropy_norm`, `concentration_ratio`
   - `dst_count`: `n_unique_dst`, `n_src_dst_pairs`, `mean_pkts_per_dst`
   - `volume`: `total_pkts`, `total_bytes`, `n_flows`, `max_pkts_per_dst`
   - `source`: `n_unique_src`
   - `protocol`: `udp_ratio`
   - `flow`: 33 fitur flow
3. Daftar kelompok ditulis satu kali di `config.py` (`FEATURE_GROUPS`) dan dipakai juga oleh PL-4 untuk membangun set ablation, supaya tidak ada dua daftar yang bisa berbeda.

Penerimaan: `importance.csv` (per fitur) dan `importance_groups.csv` (per kelompok), keduanya dengan rata-rata dan std antar fold. Tes kecil: gabungan semua kelompok sama persis dengan `agg_flow`, tanpa fitur ganda.

### PL-6 Baseline masuk skrip final

Berkas: `scripts/run_final.py`.

Langkah:
1. Selain RF dan XGBoost, skrip final juga melatih di trainval dan menguji di sisi uji: `SingleFeatureThreshold` pada `dst_entropy_norm`, `SingleFeatureThreshold` pada `n_unique_dst`, dan `AllNegative`.
2. Kolom `role` berisi `main`, `comparison`, `baseline`.
3. Tambah bootstrap atas run di sisi uji (1000 kali, mengambil ulang grup, bukan jendela) untuk recall, precision, FPR, PR-AUC tiap model: kolom `_q025`, `_q50`, `_q975`.
4. Uji hanya dengan `--rehearse`. **Jangan** jalankan `--final`.

Penerimaan: `reports/experiments/phase10_rehearsal/metrics.csv` memuat 5 baris model dengan selang bootstrap. `pytest -q` hijau.

### PL-7 Latensi ujung ke ujung

Berkas: skrip baru `scripts/run_latency.py`.

Ukur pada trainval, 5 kali ulang, ambil median:
1. Waktu menghitung fitur agregat dan ringkasan flow untuk satu jendela (total waktu `pair_counts` + `build_features` + `flow_summary` dibagi jumlah jendela).
2. Waktu `predict` per jendela (RF dan XGBoost).
3. Tulis `reports/tables/latency.csv` dan satu paragraf: tunda deteksi terburuk = panjang jendela (60 s) + timeout flow CICFlowMeter (ambil dari `CAPTURE_NOTES.md`, 120 s untuk S1) + waktu hitung.

Penerimaan: tabel ada, angka berasal dari pengukuran sesi ini. Waktu ekstraksi CICFlowMeter sendiri ditulis "tidak diukur" kecuali manusia memberi angkanya.

## 4. Tahap B

### PL-8 Dukungan banyak tangkapan

Berkas: `src/carpet/config.py`, `src/carpet/io.py`, `scripts/run_ingest.py`, `scripts/run_clean.py`, `tests/test_io.py`.

Rancangan (satu sumber kebenaran):
1. `config.CAPTURES`: kamus `id -> {csvs, attack_log, victim_prefixes, attacker_ips, benign_sources, flow_timeout_s}`. Isi untuk `S1` diambil dari konstanta yang ada sekarang; `A` dan `B` dari `CAPTURE_NOTES.md`.
2. Konstanta tunggal `VICTIM_PREFIX`, `ATTACKER_IP`, `BENIGN_SRC_EXTRA`, `RAW_FLOW_CSVS`, `ATTACK_LOG`, `RAW_ROWS_EXPECTED` dihapus setelah semua pemakainya pindah ke `CAPTURES`. Cari pemakainya dengan grep, jangan ditebak.
3. `io.read_attack_log()` membaca semua log, mengisi kolom v2 yang tidak ada di log S1 dengan nilai tetap (`proto=17`, `dst_port=53`, `spread="uniform"`, `sport_mode="fixed"`, `background="normal"`, `capture="S1"`), lalu menggabung.
4. Gagal dengan pesan jelas jika: `run_id` ganda lintas log, dua run tumpang tindih dalam satu tangkapan, atau nilai faktor di luar daftar `dataset/LOG_SCHEMA.md`.
5. Tabel flow mendapat kolom `capture`. Tambahkan `capture` ke `FORBIDDEN_FEATURES`.
6. Pembersihan "tujuan di luar subnet korban" memakai `victim_prefixes` tangkapan masing-masing.

Penerimaan:
- Dengan hanya S1 terdaftar, fase 1 dan 2 memberi angka yang sama dengan sebelumnya: 9.767.850 baris masuk, 9.758.984 setelah bersih.
- Dengan S1 dan A: jumlah baris per tangkapan dicetak dan cocok dengan jumlah baris CSV.
- Tes: log dengan `run_id` ganda ditolak; log lama tanpa kolom v2 terbaca dengan nilai tetap.

### PL-9 Pelabelan untuk vektor dan skenario baru

Berkas: `src/carpet/labeling.py`, `src/carpet/config.py`, `tests/test_labeling.py`.

Masalah: `is_attacker()` sekarang mengenali sumber palsu hanya untuk UDP port 53, dan `label_windows()` menolak skenario selain `carpet*` dan `focused`.

Langkah:
1. `is_attacker(flows, capture)`: flow penyerang = sumber termasuk `attacker_ips`, **atau** sumber di luar `victim_prefixes` dan di luar `benign_sources`. Syarat port dan protokol tidak dipakai lagi untuk tangkapan baru.
2. Cek regresi untuk S1 dulu: dengan aturan baru, hitung ulang `attacker_flows` S1 dan bandingkan dengan yang lama. Kalau berbeda, pertahankan aturan lama untuk S1 lewat satu bidang di `CAPTURES["S1"]` (`spoof_filter = {"proto": 17, "dst_port": 53}`), dan laporkan selisihnya.
3. `Subclass.BENIGN_HARD = "benign_hard"` (P7). Skenario berawalan `benign-` yang jendelanya penuh di dalam run mendapat subclass ini, label 0, `group = run_id`.
4. Aturan weak tetap: jendela di dalam run serangan dengan nol flow penyerang berstatus `OK_WEAK`. Untuk run `benign-*` tidak ada status weak.
5. Kolom keluaran bertambah: `capture`, dan faktor dari log (`dst`, `spread`, `proto`, `dst_port`, `sport_mode`, `background`, `n_src`, `scenario`) untuk pelaporan. Semuanya masuk `FORBIDDEN_FEATURES`.
6. `check_windows`: tiap run di log (kecuali `TEST`) punya minimal 10 jendela layak pakai; label 1 hanya pada subclass carpet.

Penerimaan:
- S1 saja: 921 jendela dengan status dan subclass identik baris demi baris dengan artefak `start` lama (di bawah `spread`: identik dengan hasil PL-2).
- S1 + A: tabel jumlah jendela per (tangkapan, subclass, status).
- Tes baru: jendela dalam run `benign-wide` berlabel 0 dan bersubclass `benign_hard`; serangan TCP SYN dari sumber acak terhitung sebagai flow penyerang; faktor log tidak ada di `FEATURE_SETS` mana pun.

Berhenti dan tanya jika: ada jendela layak pakai di luar run dengan flow penyerang di atas `UNLOGGED_MIN_FLOWS`.

### PL-10 Split v2

Berkas: `src/carpet/config.py`, `src/carpet/split.py`, `tests/test_split.py`.

Langkah:
1. Catat dulu di log perubahan `IMPLEMENTATION.md`: "hold-out v1 hangus, pindah ke trainval" (K2, P8).
2. Ganti `HOLDOUT_RUNS` dan `HOLDOUT_BENIGN_FRACTION` dengan `HOLDOUT_CAPTURES = ("B",)`. Sebuah jendela masuk hold-out jika dan hanya jika `capture` termasuk di dalamnya. (Kalau K1 = satu sesi: hold-out = run dengan `role = holdout` di `run_plan.csv`, ditambah blok benign yang dipilih dengan seed.)
3. CV tetap `StratifiedGroupKFold` 5 lipatan atas `group`, strata = `subclass` (sekarang empat nilai). Tiap fold harus memuat keempatnya.
4. Perbarui penjaga di `table.trainval()` dan `run_final.py` yang masih merujuk `HOLDOUT_RUNS`.

Penerimaan:
- Tidak ada `group` di lebih dari satu wadah. Tidak ada baris tangkapan B di trainval.
- Cetak komposisi tiap fold dan hold-out per subclass, dan jumlah run carpet, focused, benign sulit di hold-out. Minimal yang diharapkan di hold-out: 10 run carpet, 6 focused, 4 benign sulit.
- Tes: bingkai sintetis dua tangkapan, semua baris tangkapan hold-out mendapat `fold = -1`.

### PL-11 Jalankan ulang fase 1 sampai 9

Urutan skrip, satu per satu, dengan cek penerimaan aslinya di `IMPLEMENTATION.md`:
`run_ingest`, `run_clean`, `run_label`, `run_split`, `run_eda`, `run_features`, `run_baselines`, `run_tune`, `run_ablation`, `run_robustness`.

Aturan:
1. EDA, baseline, tuning, ablation, robustness hanya membaca trainval. Tangkapan B tidak pernah dimuat ke tabel atau gambar.
2. Hasil masuk folder eksperimen baru berakhiran `_v2` (`phase7_baselines_v2`, dan seterusnya). Hasil lama tidak ditimpa.
3. Tulis ulang `reports/eda_findings.md`, `phase7_findings.md`, `phase8_findings.md`, `phase9_findings.md` dari angka baru. Versi lama disalin dulu ke `reports/v1/`.
4. Tambah potongan laporan di robustness, semuanya dari prediksi out-of-fold:
   - recall carpet per `dst` (4, 6, 8, 12, 16, 32, 64, 128), per `spread`, per vektor, per `sport_mode`, per `background`, per tangkapan;
   - FPR per subclass negatif (benign, benign_hard per jenis, focused) dan dekat/jauh dari serangan.
5. Uji label diacak harus tetap jatuh ke ROC-AUC sekitar 0,5.
6. Jika P5 disetujui: dari prediksi out-of-fold, cari ambang terkecil yang memberi FPR paling banyak 1 persen untuk tiap model. Simpan di `reports/experiments/phase9_robustness_v2/operating_point.json`.

Penerimaan: semua laporan fase ditulis ulang; tabel perbandingan "aturan satu ambang vs RF vs XGBoost" untuk set `agg`, `flow`, `agg_flow`; daftar temuan ganjil untuk manusia.

Berhenti dan tanya jika: recall atau F1 rata-rata CV di atas 0,99 (alarm kebocoran sampai terbukti bukan), atau aturan satu ambang masih menyamai model pada data baru (berarti rancangan data di `PLAN_DATASET.md` belum cukup sulit).

### PL-12 Evaluasi final v2, satu kali

Sebelum menjalankan, tulis deklarasi di `IMPLEMENTATION.md` (keputusan baru) dan minta manusia menyetujuinya:
- set fitur (`agg_flow`), pengaturan weak, parameter dari PL-3, seed, ambang 0,5 dan ambang titik operasi dari PL-11 langkah 6;
- peran: RF utama, XGBoost pembanding, tiga baseline;
- daftar potongan laporan yang akan dibuat (di bawah).

Langkah:
1. `run_final.py --rehearse` harus lulus dulu pada fold trainval.
2. `run_final.py --final` dijalankan **satu kali**.
3. Keluaran di `reports/experiments/phase10_final_v2/`: metrik dengan selang bootstrap atas run, confusion matrix, per run, per `dst`, per `spread`, per vektor, per subclass negatif, daftar jendela terlewat dan alarm palsu, gambar ROC, PR, confusion matrix, importance.
4. Model disimpan sebagai `models/final_rf_v2.joblib` dan `models/final_xgb_v2.joblib`. Model v1 tidak ditimpa.
5. Tulis ulang `README.md` bagian hasil dari berkas keluaran. Hasil v1 dipindah ke bagian "hasil awal (S1 saja, hold-out v1)".

Setelah itu **tidak ada** penyetelan ulang. Kalau ada yang salah, lapor ke manusia. Perubahan apa pun pada data, label, fitur, atau parameter sesudah ini berarti hold-out v2 hangus dan harus ditulis begitu.

## 5. Tahap C

### PL-13 Uji robustness MAWI

Berkas: skrip baru `scripts/run_mawi.py`, pembaca kecil di `io.py`.

Langkah:
1. Muat `models/final_rf_v2.joblib` dan `final_xgb_v2.joblib`. Tidak ada `fit` di skrip ini.
2. Flow MAWI melewati pembersihan, penetapan jendela, dan penghitungan fitur yang sama (`clean`, `windows`, `features`). Subnet = /24 tujuan dari tiap flow.
3. Terapkan saringan P9 (minimal 20 flow per jendela-subnet). Cetak jumlah sebelum dan sesudah.
4. Prediksi dengan ambang 0,5 dan ambang titik operasi.
5. Laporkan, per trace dan gabungan:
   - laju alarm = jendela-subnet yang ditandai dibagi semuanya;
   - tabel silang prediksi terhadap label MAWILab (`anomalous`, `other`) dari DS-9;
   - 20 alarm dengan probabilitas tertinggi beserta nilai `n_unique_dst`, `dst_entropy_norm`, `total_pkts`, `udp_ratio`, untuk diperiksa manusia.
6. Bandingkan sebaran tiap fitur MAWI dengan trainval (median dan kuartil). Fitur yang jauh di luar rentang latih ditandai.

Penerimaan: `reports/mawi_findings.md` dan tabel di `reports/experiments/mawi/`. Kalimat kesimpulan hanya boleh berbentuk "laju alarm pada trafik backbone adalah X dari N jendela", bukan "model mendeteksi carpet bombing di MAWI" (proposal 3.2.1.2).

### PL-14 CIC-DDoS2019, hanya jika K6 = ya

1. Pembaca CIC di `io.py` dengan pemetaan kolom dari DS-10, terdaftar sebagai tangkapan `CIC` di `CAPTURES`.
2. Dua eksperimen CV pada trainval, dievaluasi pada fold PNETLab yang sama: (a) latih PNETLab saja, (b) latih PNETLab + CIC rekonstruksi. Jendela CIC hanya pernah ada di sisi latih.
3. Hold-out v2 tidak disentuh. Hasil dilaporkan sebagai eksperimen tambahan dengan batas yang ditulis di `PLAN_DATASET.md` DS-10.

### PL-15 Multi-window, hanya jika P10 = ya

`WINDOW_SECONDS` 5 dan 30 sebagai eksperimen tersendiri (folder berakhiran `_w5`, `_w30`), CV trainval saja, set `agg_flow`, parameter PL-3. Laporkan PR-AUC, recall, dan jumlah jendela. `BOUNDARY_BUFFER_SECONDS` tidak ikut diperkecil.

### PL-16 Bahan naskah (fase 11)

Tulis `reports/thesis_material.md` dari berkas meta dan tabel, tanpa mengetik ulang angka dengan tangan.

1. Ringkasan metode yang benar-benar dijalankan.
2. Daftar revisi Bab 3 yang wajib:

| Subbab | Di proposal | Yang dijalankan |
|---|---|---|
| 3.2.1 | Tiga sumber data | Sesuai hasil K6 dan DS-9 |
| 3.2.3.1 | Flow masuk jendela menurut waktu mulai | Sesuai P1, dengan alasan dan angka weak sebelum dan sesudah |
| 3.2.4.3 | Stratified k-fold, rasio 80:20 | Hold-out per tangkapan, `StratifiedGroupKFold` per sesi, beserta alasannya (jendela bertetangga hampir kembar) |
| 3.2.4.4 | Daftar hyperparameter | Ruang cari PL-3, aturan pilih P2, nilai akhir |
| 3.2.5 | Metrik | Ditambah PR-AUC, selang bootstrap atas run, titik operasi P5 |
| 3.2.6.1 | Victim 192.168.1.0/24, attacker 192.168.1.201 | Topologi dan alamat yang nyata dari `CAPTURE_NOTES.md` |

3. Tabel pemetaan: tiap klaim di proposal ke eksperimen yang mendukung atau membantahnya. Klaim yang tidak diukur ditandai "tidak diukur".
4. Keterbatasan: testbed emulasi, jumlah run, satu alat serangan, timeout flow, MAWI tanpa label carpet, dan (jika ada) batas rekonstruksi CIC.

## 6. Yang tidak dikerjakan

- Tidak menambah model selain RF dan XGBoost, tidak ada deep learning.
- Tidak menambah fitur baru di luar daftar proposal 3.2.3.2 tanpa keputusan manusia.
- Tidak ada SMOTE kecuali CV menunjukkan `class_weight` tidak cukup, dan itu pun hanya di dalam fold latih.
- Tidak menjalankan ulang `run_final.py --final` lama dan tidak mengevaluasi apa pun pada hold-out v1.
- Tidak menyunting berkas hasil lama dengan tangan (termasuk kolom `role` di `phase10_final/metrics.csv`); hasil v2 yang menggantikannya.

## 7. Selesai jika

- [ ] P1 sampai P10 diputuskan dan tercatat di `IMPLEMENTATION.md`.
- [ ] Semua tugas tahap A dan B berstatus `done`, `pytest -q` hijau.
- [ ] Hasil final v2 berasal dari satu kali jalan pada sesi B, dengan selang bootstrap dan baseline di tabel yang sama.
- [ ] Ablation memuat set tanpa jumlah tujuan dan volume (proposal 3.2.2.4) dan set `flow` saja.
- [ ] Laporan MAWI ada.
- [ ] `reports/thesis_material.md` memuat tabel revisi Bab 3 dan pemetaan klaim.
