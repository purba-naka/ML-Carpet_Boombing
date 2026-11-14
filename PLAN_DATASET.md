# PLAN_DATASET.md

Rencana khusus **data**: tangkapan PNETLab baru, MAWI/MAWILab, dan CIC-DDoS2019.
Perbaikan kode ada di `PLAN_PIPELINE.md`. Baca `AGENT.md` dulu, aturan di sana tetap berlaku di sini.

Penanda pelaksana tiap tugas:
- **[MANUSIA]** dikerjakan pemilik skripsi (testbed, unduh data, keputusan).
- **[MODEL]** boleh dikerjakan agen AI. Satu tugas per sesi kerja, jalankan cek penerimaan, laporkan angka asli.

## 0. Kenapa data baru diperlukan

Empat masalah dari audit pipeline yang tidak bisa diperbaiki lewat kode:

| # | Masalah pada data sekarang (S1, 2 Nov 2026) | Akibat |
|---|---|---|
| M1 | Carpet 16/32/64 tujuan, focused 1 sampai 3, benign paling banyak 10 tujuan. Tidak ada kasus di antaranya. | Satu ambang pada `dst_entropy_norm` menyamai model. Nilai tambah ML tidak terbukti. |
| M2 | Semua run carpet (C1..C14) terjadi sebelum semua run focused (F1..F8). Satu hari, satu subnet, satu penyerang, hampir semua DNS/UDP. | Waktu dan protokol bercampur dengan label. Benign selalu punya TCP, serangan tidak. |
| M3 | Hold-out hanya 4 run carpet dan 2 run focused, dan sudah dibuka. | Satu run menggeser FPR dari 0,008 ke 0,092. Tidak bisa dipakai lagi untuk keputusan apa pun. |
| M4 | CIC-DDoS2019 dan MAWI/MAWILab (proposal 3.2.1.1, 3.2.1.2) belum ada. | Rumusan masalah 1 soal generalisasi belum terjawab. |

Target akhir rencana ini: tiga kumpulan data yang siap dibaca pipeline, masing-masing dengan peran yang jelas.

| Kumpulan | Peran | Menutup |
|---|---|---|
| PNETLab sesi A (baru) | tambahan data latih, berisi kasus sulit | M1, M2 |
| PNETLab sesi B (baru, hari lain) | hold-out v2, dibuka satu kali | M3 |
| MAWI/MAWILab | uji alarm palsu pada trafik nyata, tidak pernah dilatih | M4 |
| CIC-DDoS2019 rekonstruksi | opsional, lihat keputusan K6 | M4 |

## 1. Keputusan yang harus disetujui manusia dulu

Agen tidak boleh mengerjakan tugas yang bergantung pada keputusan yang belum dicentang. Setelah disetujui, salin ke tabel keputusan dan log perubahan di `IMPLEMENTATION.md` (nomor D berikutnya yang kosong; D21 sudah dipakai di branch `experiment`).

| ID | Pertanyaan | Rekomendasi | Status |
|---|---|---|---|
| K1 | Berapa sesi tangkapan baru? | Dua sesi di hari berbeda: A untuk latih, B seluruhnya hold-out v2. Kalau hanya sanggup satu sesi: tiap run diberi `role` (train/holdout) di `run_plan.csv` **sebelum** tangkapan, diacak dengan seed, berstrata per skenario. | [ ] |
| K2 | Nasib hold-out lama (C9, C10, C11, C12, F2, F6 dan 5 blok benign)? | Pindah ke data latih. Sudah terbuka, jadi tidak boleh lagi jadi juri. Tulis "hold-out v1 hangus" di log perubahan. | [ ] |
| K3 | Batas definisi carpet vs focused saat merancang run? | Focused = serangan ke 1 sampai 3 host. Carpet = serangan disebar ke 4 host atau lebih dalam satu /24. Ini parameter desain skenario, bukan ambang pelabelan (proposal 3.2.2.4). | [ ] |
| K4 | Skenario benign sulit ikut dicatat sebagai run? | Ya, tiga jenis: `benign-wide`, `benign-flash`, `benign-sweep` (definisi di bagian 3.3). Label 0. | [ ] |
| K5 | Subnet korban kedua? | Ya, `203.0.113.0/24`, dipakai sekitar seperempat run. Membuat kolom `subnet` tidak lagi konstan. | [ ] |
| K6 | CIC-DDoS2019 dikerjakan atau dikeluarkan dari ruang lingkup? | Bicarakan dengan pembimbing. Kalau waktu sempit: keluarkan secara resmi dan tulis di batasan masalah. Kalau dikerjakan: ikuti bagian 6. | [ ] |
| K7 | Trace MAWI mana? | Dua trace 15 menit samplepoint-F dari tanggal berbeda yang punya label MAWILab. Tanggal dipilih dan dicatat sebelum hasil dilihat. | [ ] |

## 2. Tabel status

Nilai: `todo`, `doing`, `done`, `blocked`. Perbarui setelah tiap tugas.

| Tugas | Pelaksana | Status | Catatan |
|---|---|---|---|
| DS-1 Skema log serangan v2 | MODEL | todo | |
| DS-2 Generator `run_plan.csv` | MODEL | todo | |
| DS-3 Siapkan testbed | MANUSIA | todo | |
| DS-4 Uji coba kecil (dry run) | MANUSIA + MODEL | todo | |
| DS-5 Tangkap sesi A | MANUSIA | todo | |
| DS-6 Tangkap sesi B | MANUSIA | todo | |
| DS-7 PCAP ke flow | MANUSIA | todo | |
| DS-8 Validasi tangkapan | MODEL | todo | |
| DS-9 MAWI/MAWILab | MANUSIA + MODEL | todo | |
| DS-10 CIC-DDoS2019 (jika K6 = ya) | MODEL | todo | |

## 3. Rancangan tangkapan PNETLab baru

### 3.1 Aturan umum

1. **Semua trafik serangan tercatat.** Skrip serangan sendiri yang menulis baris log saat mulai dan selesai. Tidak ada serangan manual di luar skrip. (Di S1 ada serangan tak tercatat 09:34 sampai 10:22 yang terpaksa dibuang.)
2. **Urutan run diacak dengan seed.** Carpet, focused, dan benign sulit berselang-seling. Tidak boleh ada blok "semua carpet dulu".
3. **Satu run = 12 menit (720 detik), mulai tepat di detik 0 sebuah menit.** Memberi 12 jendela penuh, di atas batas `MIN_USABLE_WINDOWS_PER_RUN = 10`.
4. **Jeda antar run 4 menit.** Lebih panjang dari timeout flow CICFlowMeter (120 detik) ditambah penyangga batas (60 detik).
5. **Benign latar berjalan terus**, termasuk selama serangan, dan minimal 60 menit benign murni di awal dan di akhir sesi.
6. **Jam semua node disinkronkan** (NTP atau `date -s` dari satu sumber) sebelum mulai. Catat zona waktu mesin yang menjalankan CICFlowMeter.
7. **ID run unik lintas sesi**: awalan sesi, misalnya `A-C01`, `A-F03`, `B-W02`. ID lama (`C1`, `F1`, ...) tidak dipakai ulang.
8. Data mentah baru disimpan di `dataset/sesiA/` dan `dataset/sesiB/` (`pcaps/`, `csv/`, `attack_log.csv`, `run_plan.csv`). Folder `dataset/` yang lama tidak disentuh.

### 3.2 Faktor serangan

| Faktor | Kolom log | Nilai |
|---|---|---|
| Jenis | `scenario` | `carpet-low`, `carpet-mid`, `carpet-stealth`, `focused` |
| Jumlah host tujuan | `dst` | carpet: 4, 6, 8, 12, 16, 32, 64, 128. focused: 1, 2, 3 |
| Sebaran antar tujuan | `spread` | `uniform` (rata), `skewed` (20 persen host menerima separuh paket) |
| Jumlah sumber | `n_src` | `1`, `multi` (IP sumber acak) |
| Vektor | `proto`, `dst_port` | UDP 53, UDP 123, UDP port acak (`dst_port` = 0), TCP SYN 80 |
| Laju | `interval_us` | low 10000, mid 5000, stealth 100000 (sama dengan S1) |
| Port sumber | `sport_mode` | `fixed`, `random`. `random` membuat tiap paket jadi flow sendiri, `fixed` menghasilkan flow raksasa seperti S1 |
| Latar | `background` | `normal`, `wide`, `flash` (serangan berjalan bersamaan dengan benign sulit) |
| Subnet korban | `subnet` | `198.51.100.0/24`, `203.0.113.0/24` |

Alasan tiap faktor:
- `dst` 4 sampai 12 dan `spread = skewed` menutup celah M1: carpet sempit dan carpet yang tidak rata, sehingga entropy saja tidak cukup.
- Vektor selain UDP 53 dan benign yang banyak UDP memutus pintasan "hampir semua UDP berarti serangan".
- `background = flash` saat carpet menurunkan entropy jendela carpet. `background = wide` saat focused menaikkan jumlah tujuan jendela focused. Dua-duanya memaksa model membaca lebih dari satu fitur.

### 3.3 Skenario benign sulit (label 0, dicatat di log)

| `scenario` | Isi | Yang diuji |
|---|---|---|
| `benign-wide` | Klien normal (DNS, HTTP, HTTPS, SSH, ICMP) mengakses 20 sampai 60 host di /24 korban dengan laju wajar | Banyak tujuan tidak selalu serangan |
| `benign-flash` | Banyak klien membanjiri satu layanan sah (unduhan besar, banyak permintaan HTTP ke satu host) | Volume besar terpusat yang bukan serangan |
| `benign-sweep` | Sapuan pemantauan admin: ping atau cek port ke seluruh /24 dengan laju rendah | Sebaran rata bervolume rendah yang bukan DDoS |

Untuk baris benign sulit: `n_src`, `interval_us`, `payload` diisi apa adanya dari alat pembangkit, `attacker_ip` diisi `-`.

### 3.4 Jumlah run per sesi

| Kelompok | Sesi penuh | Minimum |
|---|---|---|
| Carpet | 20 (tiap nilai `dst` minimal 2 kali) | 10 (tiap nilai `dst` 4 sampai 32 minimal 1 kali) |
| Focused | 10 | 6 |
| Benign sulit | 6 (tiap jenis 2 kali) | 4 |
| **Total run** | **36, sekitar 9,6 jam** | **20, sekitar 5,3 jam** |
| Benign murni | 2 jam (awal + akhir) | 2 jam |

Syarat tambahan dalam tiap sesi, dicek otomatis oleh DS-2:
- Minimal 4 run carpet dengan `dst` di bawah 16, minimal 4 dengan `spread = skewed`.
- Tiap vektor muncul minimal 2 kali di carpet dan minimal 1 kali di focused.
- `n_src = 1` dan `multi` masing-masing minimal 40 persen run serangan.
- Minimal 3 run serangan dengan `background` bukan `normal`.
- Minimal 20 persen run memakai subnet kedua (jika K5 = ya).
- Tidak pernah ada tiga run berturut-turut dari kelompok yang sama.

## 4. Tugas

### DS-1 [MODEL] Skema log serangan v2

Tujuan: satu format log yang dipakai skrip serangan dan pembaca pipeline.

Langkah:
1. Tulis `dataset/LOG_SCHEMA.md` (file baru, boleh, bukan data mentah) berisi kolom berurutan:
   `run_id, scenario, subnet, dst, start_ts, end_ts, interval_us, payload, n_src, attacker_ip, proto, dst_port, spread, sport_mode, background, capture`
2. Untuk tiap kolom tulis tipe, nilai yang sah (dari tabel 3.2 dan 3.3), dan contoh satu baris.
3. `start_ts` dan `end_ts` adalah epoch detik UTC, sama seperti log lama.
4. Sepuluh kolom pertama identik dengan log lama (`io.LOG_COLUMNS`). Jangan ubah urutan atau namanya.

Penerimaan: file ada, 16 kolom, tiap kolom punya nilai sah. Tunjukkan ke manusia sebelum DS-2.

### DS-2 [MODEL] Generator `run_plan.csv`

Tujuan: jadwal run teracak yang memenuhi semua syarat 3.4, supaya manusia tinggal menjalankan.

Langkah:
1. Buat `scripts/make_run_plan.py`. Argumen: `--session A|B`, `--size full|min`, `--start "YYYY-MM-DD HH:MM"` (UTC), `--seed` (default `config.SEED` + 1 untuk A, + 2 untuk B).
2. Keluaran `dataset/sesi<X>/run_plan.csv`: kolom skema DS-1 tanpa `end_ts` aktual, ditambah `planned_start`, `planned_end`, `role`.
3. Jadwal: 60 menit benign murni, lalu tiap run 12 menit + jeda 4 menit, lalu 60 menit benign murni. `planned_start` selalu kelipatan 60 detik.
4. Faktor dibagi merata dengan pengacakan berseed, lalu syarat 3.4 dicek dengan `assert`. Kalau gagal, acak ulang dengan seed turunan (maksimal 1000 kali), lalu gagal dengan pesan jelas.
5. `role`: sesi A semua `train`, sesi B semua `holdout` (K1 dua sesi). Kalau K1 = satu sesi, 35 persen run per kelompok diberi `holdout`.

Penerimaan:
- Seed sama menghasilkan file yang identik byte demi byte.
- Skrip mencetak tabel hitungan per faktor dan semua syarat 3.4 lulus.
- `pytest -q` hijau. Satu tes kecil: jadwal tidak tumpang tindih dan semua `run_id` unik.

Berhenti dan tanya jika: syarat 3.4 tidak bisa dipenuhi dengan jumlah run yang diminta.

### DS-3 [MANUSIA] Siapkan testbed

1. Tambah subnet korban kedua (K5) dan host benign di kedua subnet, minimal 60 host aktif per subnet.
2. Pembangkit benign: DNS, HTTP, HTTPS, SSH, ICMP, NTP, transfer berkas. Benign harus punya UDP yang cukup banyak, bukan hanya TCP.
3. Skrip serangan membaca `run_plan.csv`, menunggu `planned_start`, menjalankan serangan sesuai faktor, lalu menulis baris `attack_log.csv` dengan `start_ts` dan `end_ts` **aktual**.
4. Skrip benign sulit dijadwalkan dari `run_plan.csv` yang sama.
5. Catat ke `dataset/sesi<X>/CAPTURE_NOTES.md`: versi dan parameter CICFlowMeter (terutama flow timeout), alat serangan dan versinya, IP penyerang, daftar IP klien benign, zona waktu, topologi.

Catatan untuk skripsi: Bab 3.2.6 proposal menulis victim `192.168.1.0/24` dan attacker `192.168.1.201`. Data nyata memakai `198.51.100.0/24` dan `192.168.1.65`. Topologi di naskah harus mengikuti yang benar-benar dipakai.

### DS-4 [MANUSIA + MODEL] Uji coba kecil

Sebelum sesi panjang, jalankan 4 run pendek (1 carpet sempit, 1 focused, 1 benign-wide, 1 carpet TCP SYN), masing-masing 3 menit.

Cek oleh model (skrip sekali pakai, tidak perlu masuk repo):
1. Log punya 16 kolom dan 4 baris.
2. Flow penyerang pertama tiap run muncul dalam 5 detik dari `start_ts`. Kalau selisihnya berjam-jam, itu masalah zona waktu: berhenti dan lapor, jangan digeser sendiri.
3. Jumlah IP tujuan unik dari flow penyerang per run sama dengan kolom `dst`.
4. Di luar empat run tidak ada flow dari IP penyerang.
5. Durasi flow terpanjang tidak melebihi timeout yang dicatat di `CAPTURE_NOTES.md`.

Kalau satu cek gagal: perbaiki testbed, ulangi DS-4. Jangan lanjut ke DS-5.

### DS-5, DS-6 [MANUSIA] Tangkap sesi A dan sesi B

1. Buat jadwal dengan DS-2. Sesi B di hari kalender yang berbeda dari sesi A.
2. Jalankan tanpa campur tangan manual. Kalau satu run gagal, biarkan, tandai di `CAPTURE_NOTES.md`, jangan diulang di tengah jadwal.
3. Simpan PCAP per potongan 5 menit seperti S1.
4. Sesi B adalah hold-out v2. **Jangan dibuka, diplot, atau diringkas isinya** selain oleh skrip validasi DS-8 yang tidak menampilkan fitur per label.

### DS-7 [MANUSIA] PCAP ke flow

1. CICFlowMeter versi dan parameter **sama** untuk sesi A, sesi B, dan MAWI. Idealnya sama dengan S1; kalau S1 tidak tercatat, tulis itu sebagai keterbatasan.
2. Satu CSV gabungan per sesi: `dataset/sesi<X>/csv/sesi<X>_all.csv`.
3. Header harus identik dengan CSV S1 (84 kolom).

### DS-8 [MODEL] Validasi tangkapan

Tujuan: memastikan data baru layak sebelum masuk pipeline. Buat `scripts/validate_capture.py --session A|B`, hanya membaca.

Cek, masing-masing mencetak angka dan lulus/gagal:
1. Header CSV sama dengan S1. Jumlah baris = baris berkas dikurangi header.
2. Tidak ada timestamp yang gagal diurai dengan `config.TIMESTAMP_FORMAT`.
3. Log: 16 kolom, `run_id` unik dan tidak bentrok dengan log S1, `end_ts > start_ts`, tidak ada dua run tumpang tindih, jeda antar run minimal 180 detik.
4. Tiap run serangan: flow penyerang pertama dalam 5 detik dari `start_ts`, terakhir tidak lewat `end_ts` + timeout flow.
5. Tiap run serangan: jumlah tujuan unik flow penyerang sama dengan `dst`.
6. Di luar semua run: jumlah flow penyerang per jendela 60 detik di bawah `UNLOGGED_MIN_FLOWS`. Laporkan jendela yang melanggar.
7. Tiap run punya minimal 10 jendela penuh.
8. Celah tangkapan (menit tanpa flow sama sekali): daftar lengkap.
9. Hitungan run per faktor dibanding syarat 3.4.
10. Untuk sesi B: cetak hanya hitungan dan lulus/gagal. Tidak ada statistik fitur per kelas.

Penerimaan: laporan `reports/tables/capture_validation_<X>.csv` dan ringkasan satu layar. Semua cek lulus, atau tiap kegagalan dilaporkan ke manusia dengan pilihan (buang run itu, ulang tangkapan, terima dengan catatan).

Berhenti dan tanya jika: lebih dari 2 run gagal cek 4 atau 5, atau cek 6 menemukan serangan tak tercatat.

### DS-9 [MANUSIA + MODEL] MAWI/MAWILab

Peran: uji alarm palsu pada trafik nyata. Tidak pernah masuk pelatihan, tuning, atau pemilihan ambang (proposal 3.2.1.2).

[MANUSIA]
1. Unduh dua trace 15 menit samplepoint-F (K7) dari arsip MAWI dan berkas label MAWILab untuk tanggal yang sama. Pastikan dulu label MAWILab memang tersedia untuk tanggal itu.
2. Simpan di `dataset/mawi/<tanggal>/`. Catat URL, tanggal unduh, dan ukuran berkas di `dataset/mawi/SOURCE.md`.
3. Jalankan CICFlowMeter dengan parameter DS-7. Kalau PCAP terlalu besar, potong dulu jadi 5 potongan 3 menit dengan `editcap`, lalu gabungkan CSV-nya.

[MODEL]
4. Cetak header CSV MAWI dan bandingkan dengan S1. Laporkan perbedaan, jangan diperbaiki diam-diam.
5. Hitung dan laporkan: jumlah flow, jumlah /24 tujuan, sebaran flow per (subnet, jendela).
6. Ubah label MAWILab menjadi tabel `(subnet, w) -> mawilab_label` dengan aturan: sebuah jendela-subnet diberi `anomalous` jika ada anomali MAWILab berkategori `anomalous` yang IP tujuannya di subnet itu dan waktunya menyentuh jendela itu; selain itu `other`. Cetak dulu format asli berkas label, jangan menebak nama kolom.

Hal yang wajib ditulis di skripsi: alamat IP MAWI dianonimkan dengan cara yang mempertahankan prefix, jadi pengelompokan /24 masih bermakna; payload dipotong; label MAWILab adalah label anomali umum, bukan label carpet bombing.

Berhenti dan tanya jika: jumlah (subnet, jendela) lebih dari satu juta (perlu saringan lalu lintas minimum, keputusan P9 di `PLAN_PIPELINE.md`).

### DS-10 [MODEL] CIC-DDoS2019, hanya jika K6 = ya

Peran: sumber serangan berlabel untuk pelatihan, direkonstruksi menjadi skenario carpet (proposal 3.2.2.4).

Langkah:
1. [MANUSIA] Unduh CSV flow resmi CIC-DDoS2019 ke `dataset/cicddos2019/`. Vektor yang dipakai: DNS, NTP, UDP, dan Syn; ditambah baris `BENIGN`.
2. Cetak nama kolom apa adanya (banyak yang berawalan spasi) dan buat tabel pemetaan ke nama kolom S1. Kolom yang tidak ada padanannya dilaporkan. Minimal harus terpetakan: IP, port, protokol, timestamp, `Total Fwd Packet`, `Total Length of Fwd Packet`, `Flow Duration`, dan 11 kolom `config.FLOW_SUMMARY_COLUMNS`.
3. Rekonstruksi, parameter ditulis di `config.py` dan dilaporkan:
   - Ambil irisan waktu 60 detik dari satu vektor serangan. Satu irisan = satu bahan jendela.
   - Carpet: petakan ulang `Dst IP` flow serangan ke `k` host dalam satu /24 sintetis, `k` dari {4, 8, 16, 32, 64}, sebaran `uniform` atau `skewed`.
   - Focused: petakan ke 1 sampai 3 host.
   - Benign: flow `BENIGN` apa adanya, dipetakan ke /24 yang sama.
   - Statistik flow asli tidak diubah. Hanya `Dst IP` dan pergeseran waktu.
4. `group` = (vektor, blok 15 menit dari waktu asli). Irisan dari blok yang sama tidak boleh terbelah antara latih dan uji.
5. Label dicatat saat konstruksi, bukan dihitung dari hasil.

Penerimaan: tabel jumlah jendela per (vektor, kelas, k), pemetaan kolom, dan daftar kolom yang tidak terpetakan.

Batas yang harus ditulis jujur di skripsi: sebaran tujuan pada data ini adalah hasil konstruksi, jadi fitur sebaran tujuan terpisah sempurna secara desain. Data ini berguna untuk keragaman vektor dan fitur flow, bukan sebagai bukti kemampuan deteksi sebaran.

## 5. Yang tidak dikerjakan

- Tidak mengubah, menghapus, atau menamai ulang apa pun di `dataset/` lama, `flows_csv-*`, `pcap_dataset-*`.
- Tidak membuat data sintetis dengan menyunting fitur jendela. Kasus sulit harus berasal dari trafik yang benar-benar ditangkap (atau rekonstruksi CIC yang dicatat sebagai rekonstruksi).
- Tidak mencampur MAWI ke data latih dengan alasan apa pun.
- Tidak membuka sesi B sebelum evaluasi final v2 (`PLAN_PIPELINE.md` PL-12).

## 6. Selesai jika

- [ ] K1 sampai K7 dicentang dan tercatat di `IMPLEMENTATION.md`.
- [ ] Sesi A dan B lulus DS-8.
- [ ] MAWI punya CSV flow, tabel label per (subnet, jendela), dan `SOURCE.md`.
- [ ] K6 diputuskan; jika ya, DS-10 lulus penerimaan.
- [ ] `CAPTURE_NOTES.md` tiap sesi lengkap, dan Bab 3.2.6 naskah diperbarui mengikuti testbed yang nyata.
