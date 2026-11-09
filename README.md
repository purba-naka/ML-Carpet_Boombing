# Deteksi DDoS Carpet Bombing dengan Random Forest dan XGBoost

Skripsi: mendeteksi serangan DDoS carpet bombing, yaitu serangan yang menyebar tipis ke banyak host dalam satu subnet /24, memakai machine learning. Unit analisis adalah satu pasangan (subnet tujuan /24, jendela 60 detik). Label biner: 1 = carpet bombing, 0 = benign atau DDoS yang terpusat ke satu host.

Data berasal dari tangkapan sendiri di PNETLab (9,76 juta flow CICFlowMeter, 23 sesi serangan). Random Forest adalah model utama, XGBoost pembanding, sesuai proposal.

Angka di bawah dari metode utama (flow dimasukkan ke jendela menurut waktu mulainya, proposal 3.2.3.1). Eksperimen tambahan ada di branch `experiment`, lihat bagian terakhir.

## Hasil akhir: hold-out, satu kali jalan

Hold-out berisi 183 jendela dari 11 grup: 4 sesi carpet (C9, C10, C11, C12), 2 sesi serangan terpusat (F2, F6), dan 5 blok benign. Model dilatih pada seluruh data latih (648 jendela, 37 grup) dengan parameter hasil tuning di validasi silang, lalu diprediksi satu kali. Hold-out tidak dipakai untuk memilih apa pun, tetapi sudah terbuka, jadi tidak boleh dipakai lagi untuk menyetel.

| | Random Forest (utama) | XGBoost (pembanding) |
|---|---|---|
| Recall | 0,811 (43 dari 53) | 0,811 (43 dari 53) |
| Precision | 0,977 | 0,782 |
| F1 | 0,887 | 0,796 |
| False positive rate | 0,008 (1 dari 130) | 0,092 (12 dari 130) |
| Accuracy | 0,940 | 0,880 |
| PR-AUC | 0,941 | 0,938 |
| ROC-AUC | 0,964 | 0,964 |
| Waktu inferensi | 0,157 ms per jendela | 0,006 ms per jendela |

Confusion matrix (baris = sebenarnya, kolom = prediksi):

| | RF: bukan carpet | RF: carpet | XGB: bukan carpet | XGB: carpet |
|---|---|---|---|---|
| Sebenarnya bukan carpet | 129 | 1 | 118 | 12 |
| Sebenarnya carpet | 10 | 43 | 10 | 43 |

Accuracy dihitung dari confusion matrix. Pada data yang timpang (53 carpet, 130 bukan) accuracy mudah menyesatkan, jadi baca recall, precision, dan FPR.

### Per sesi

| Sesi | Jenis | Jendela | RF terdeteksi | XGBoost terdeteksi |
|---|---|---|---|---|
| C10 | carpet | 14 | 14 | 14 |
| C12 | carpet | 14 | 14 | 14 |
| C11 | carpet | 14 | 8 | 8 |
| C9 | carpet | 11 | 7 | 7 |
| F2 | terpusat | 14 | 0 (benar) | 0 (benar) |
| F6 | terpusat | 14 | 0 (benar) | 12 (alarm palsu) |
| Benign | 5 blok | 102 | 1 alarm palsu | 0 alarm palsu |

### Yang perlu dibaca dengan hati-hati

1. **Semua 10 jendela carpet yang terlewat adalah jendela "weak"** (C11: 6, C9: 4). Pada jendela carpet biasa, recall adalah 43 dari 43. Jendela weak adalah menit di mana serangan sumber tunggal sedang berjalan tetapi tidak ada flow penyerang yang *dimulai* di menit itu: CICFlowMeter memotong flow tiap 120 detik, dan proposal memasukkan flow ke jendela menurut waktu mulainya. Jadi recall 0,81 adalah batas cara pengukuran, bukan kemampuan model. Dari 64 jendela weak di seluruh data, 63 punya flow penyerang yang dimulai di jendela sebelumnya dan masih hidup.
2. **XGBoost salah menandai 12 jendela F6 sebagai carpet.** F6 adalah serangan terpusat (3 tujuan) dari puluhan ribu sumber palsu. XGBoost menganggap banyak sumber sebagai ciri carpet.
3. **Hold-out kecil**: hanya 6 sesi serangan. Satu sesi (F6) menggeser FPR XGBoost dari 0,008 ke 0,092. Anggap angka ini bergeser sekitar itu, bukan titik pasti.
4. **Peran model dikoreksi setelah menjalankan**: fase evaluasi awalnya menyebut XGBoost "utama", bertentangan dengan proposal 3.2.4.1. Angka tidak berubah (hold-out tidak diulang), hanya urutan pelaporannya. Tercatat di `IMPLEMENTATION.md`, log perubahan D20.

## Validasi silang (data latih saja)

5 lipatan yang dikelompokkan per sesi, sehingga satu sesi tidak pernah terbelah antara latih dan uji. Rata-rata 5 lipatan, jendela weak ikut dilatih:

| Fitur | Model | Recall | Precision | FPR | PR-AUC |
|---|---|---|---|---|---|
| 12 agregat | RF | 0,815 | 0,949 | 0,013 | 0,913 |
| 12 agregat | XGBoost | 0,831 | 0,904 | 0,027 | 0,917 |
| 45 (agregat + flow) | RF | 0,860 | 0,908 | 0,026 | 0,951 |
| 45 (agregat + flow) | XGBoost | 0,868 | 0,945 | 0,015 | 0,961 |
| aturan satu ambang pada `dst_entropy_norm` | - | 0,807 | 0,984 | 0,004 | 0,896 |
| aturan satu ambang pada `n_unique_dst` | - | 0,807 | 0,993 | 0,002 | 0,872 |

Simpangan baku antar lipatan 0,035 sampai 0,145, jadi selisih kecil antar baris tidak bisa dibedakan dari derau.

**Temuan jujur: satu aturan dengan satu ambang hampir sama baiknya dengan model.** Di data PNETLab, carpet menyentuh 16 sampai 64 tujuan sedangkan benign tidak pernah melewati 10, sehingga carpet mudah dipisahkan. Model 45 fitur menambah sekitar 0,05 recall di atas aturan itu. Ini batas data, bukan bukti bahwa ML tidak berguna, dan itulah alasan eksperimen carpet yang lebih sempit di branch `experiment`.

## Uji pintasan (ablation)

Fitur yang dicurigai sebagai jalan pintas dicabut satu per satu dari set 45 fitur (RF, jendela weak ikut dilatih):

| Dicabut | Recall | PR-AUC |
|---|---|---|
| tidak ada (45 fitur) | 0,860 | 0,951 |
| `n_unique_src` (jumlah sumber) | 0,860 | 0,951 |
| `udp_ratio` | 0,860 | 0,951 |
| fitur volume (`total_pkts`, `total_bytes`, `n_flows`) | 0,860 | 0,951 |
| semuanya sekaligus (sisa 39) | 0,860 | 0,951 |
| 9 kolom Bwd dan flag TCP **ditambahkan** (72 fitur) | 0,853 | 0,959 |

Mencabut fitur yang dicurigai tidak mengubah apa pun, jadi model tidak memakai jumlah sumber, porsi UDP, atau volume sebagai jalan pintas. Fitur terpenting adalah `dst_entropy_norm` (sekitar setengah dari impurity Random Forest). Menggabungkan fitur agregat dengan fitur flow menaikkan recall dari 0,815 menjadi 0,860 (RF) dan PR-AUC dari 0,913 menjadi 0,951.

Kestabilan: lima seed model menggeser recall paling banyak 0,015. Bootstrap atas sesi (bukan jendela) memberi recall RF 0,863 dengan rentang 95 persen 0,752 sampai 0,957, lebar karena hanya 37 sesi.

Uji label diacak (latih dengan label yang diacak) memberi ROC-AUC 0,49, jadi tidak ada kebocoran label yang terdeteksi.

## Cara kerja

```
CSV flow mentah (dataset/, tidak ada di repo)
  1 ingest     -> data/interim/flows.parquet
  2 clean      -> data/interim/flows_clean.parquet
  3 label      -> data/processed/windows_labeled.parquet   label dari log serangan, bukan dari nilai fitur
  4 split      -> data/processed/split.parquet             hold-out per sesi + 5 lipatan per sesi
  5 EDA        -> reports/eda_findings.md
  6 features   -> 12 fitur agregat + 33 ringkasan flow (mean, std, max)
  7 baseline   -> reports/phase7_findings.md
  8 tuning     -> reports/phase8_findings.md               10 kombinasi acak per model
  9 ablation   -> reports/phase9_findings.md
 10 evaluasi   -> reports/experiments/phase10_final/       satu kali jalan di hold-out
```

Jalankan skrip `scripts/run_*.py` berurutan dengan `PYTHONPATH=src`. Data mentah dan olahan serta PDF proposal tidak ikut di repo (`.gitignore`). `pytest -q` menjalankan 45 tes.

### Model tersimpan

`models/final_rf.joblib` (utama) dan `models/final_xgb.joblib` (pembanding) adalah model hasil fase 10, dilatih pada seluruh data latih. Memuat ulang keduanya memberi confusion matrix hold-out yang sama persis dengan tabel di atas.

```python
import joblib
d = joblib.load("models/final_rf.joblib")
proba = d["model"].predict_proba(df[d["features"]].to_numpy())[:, 1]
```

Isi file adalah dictionary: `model` (pipeline dengan pengisi nilai kosong median di dalamnya), `features` (45 nama kolom, **urutan harus sama**), `params`, `role`, `trained_on`. Fiturnya adalah 12 fitur agregat + 33 ringkasan flow per jendela, jadi input harus berupa tabel fitur per jendela hasil `scripts/run_features.py`, bukan CSV flow mentah. File joblib dapat menjalankan kode saat dimuat: muat hanya file dari repo ini.

Aturan yang dipegang:
- Label hanya dari asal-usul skenario (log serangan), tidak pernah dari ambang fitur.
- Pembagian selalu per sesi, tidak pernah acak per jendela.
- Kelas positif = carpet. Metrik: recall, precision, F1, FPR, PR-AUC, ROC-AUC, bukan accuracy saja.
- Semua konstanta ada di `src/carpet/config.py`. Keputusan dan log perubahan ada di `IMPLEMENTATION.md`.

## Keterbatasan

- Satu penyerang, satu subnet korban, satu hari tangkapan, sebagian besar DNS lewat UDP.
- 22 sesi serangan. Hold-out hanya 6 sesi serangan.
- Carpet di data latih menyentuh 5 sampai 64 tujuan (median 31). Carpet yang lebih sempit dari itu belum pernah dilihat model.
- Benign di testbed selalu mengandung TCP dan serangan tidak, jadi ada risiko model belajar "UDP berarti serangan". Ablation di atas menunjukkan model tidak memakainya, tetapi hanya data di luar testbed yang bisa membuktikannya.
- **Belum dikerjakan dari proposal**: pelatihan memakai CIC-DDoS2019 yang direkonstruksi (3.2.2.4, 3.2.4.2) dan uji ketahanan pada MAWI/MAWILab (3.2.1.2). Saat ini model dilatih dan diuji hanya pada data PNETLab, jadi hasil di atas menjawab "apakah model bekerja di testbed ini", bukan "apakah model bekerja di jaringan lain".
- Perbandingan RF dan XGBoost memakai parameter hasil tuning kecil (10 kombinasi) dan selisihnya berada dalam derau antar lipatan.

## Eksperimen di branch `experiment`

Tidak termasuk hasil di atas dan menyimpang dari proposal, jadi dipisah:
- **Penetapan jendela `spread`**: flow dipotong ke semua jendela yang dilaluinya. Jendela weak turun dari 64 menjadi 1 dan recall validasi silang naik dari 0,860 menjadi 0,992. Namun satu ambang pada `n_unique_dst` kini sama baiknya dengan model, artinya testbed menjadi mudah sekali setelah pengukuran diperbaiki.
- **Probe carpet sempit**: setiap jendela carpet dikurangi menjadi 4 sampai 12 tujuan. Random Forest bertahan (recall 0,99 pada 8 tujuan), XGBoost jatuh (0,13), aturan satu ambang jumlah tujuan gagal total. Ini pengganti murah, bukan serangan nyata.

Laporan lengkapnya ada di `reports/phase9b_window_assignment.md` dan `reports/phase9c_hard_probe.md` pada branch tersebut.
