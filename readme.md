# Sistem Pemilihan Majelis REC Indonesia

Aplikasi web berbasis PHP untuk mengelola proses pemilihan kandidat Majelis REC Indonesia secara digital, mulai dari voting jemaat hingga proses wawancara dan penilaian scorecard kandidat.

---

## Daftar Isi

- [Gambaran Umum](#gambaran-umum)
- [Fitur Utama](#fitur-utama)
- [Persyaratan Sistem](#persyaratan-sistem)
- [Struktur File & Penyimpanan Data](#struktur-file--penyimpanan-data)
- [Peran Pengguna (Role)](#peran-pengguna-role)
- [Alur Aplikasi](#alur-aplikasi)
- [Halaman & Fungsionalitas](#halaman--fungsionalitas)
- [Import Data via Excel](#import-data-via-excel)
- [Sistem Scorecard Wawancara](#sistem-scorecard-wawancara)
- [Keamanan](#keamanan)
- [Konfigurasi](#konfigurasi)
- [Data Default](#data-default)

---

## Gambaran Umum

Sistem ini adalah aplikasi PHP single-file (`index.php`) yang mengelola seluruh siklus pemilihan Majelis gereja, mencakup:

1. **Voting** — Jemaat memilih kandidat untuk setiap bidang pelayanan.
2. **Flagging & Seleksi** — Admin menandai kandidat yang lolos untuk lanjut proses.
3. **Wawancara** — Pewawancara meng-input form kesediaan dan scorecard penilaian kandidat.
4. **Dashboard Rekap** — Admin memantau progress voting dan log aktivitas.

Deadline pemilihan: **31 Maret 2026**.

---

## Fitur Utama

| Fitur | Keterangan |
|---|---|
| Voting per bidang | Setiap user memilih satu kandidat per bidang pelayanan |
| Konfirmasi sebelum submit | Modal konfirmasi sebelum vote disimpan (tidak bisa diubah) |
| Import data Excel | Upload file `.xlsx` untuk impor data pemilih & kandidat sekaligus |
| Manajemen kandidat | Top 10 kandidat per bidang ditampilkan otomatis berdasarkan suara |
| Flagging kandidat | Admin menandai kandidat "lanjut proses" dan "lolos screening" |
| Assignment pewawancara | Admin menetapkan pewawancara per kandidat |
| Form kesediaan | Pewawancara meng-upload dokumen kesediaan kandidat & keluarga |
| Scorecard wawancara | Penilaian terstruktur per bagian dengan bobot dan skor akhir otomatis |
| Submit scorecard | Scorecard dikunci setelah disubmit; admin dapat membatalkan kunci |
| Rate limiting login | Proteksi brute force per user & per IP |
| Log vote | Rekam jejak seluruh aktivitas voting |
| Filter proses kandidat | Filter tampilan berdasarkan status proses kandidat |

---

## Persyaratan Sistem

- **PHP** 8.1 atau lebih baru
- **Ekstensi PHP**: `session`, `json`, `zip`, `fileinfo`, `dom`, `libxml`
- **Web server**: Apache (disarankan, dengan dukungan `.htaccess`) atau Nginx
- **Izin tulis** pada direktori penyimpanan data (`majelis_secure_data/` di luar webroot)
- **HTTPS** sangat direkomendasikan (cookie session otomatis diamankan jika HTTPS terdeteksi)

---

## Struktur File & Penyimpanan Data

```
/
├── index.php                        ← Seluruh aplikasi (single file)
├── .htaccess                        ← Dibuat otomatis; melindungi file .json & session
│
└── majelis_secure_data/             ← Direktori data utama (di luar webroot, direkomendasikan)
    ├── users.json                   ← Data user & kredensial login
    ├── bidang.json                  ← Daftar bidang pelayanan
    ├── kandidat.json                ← Daftar kandidat per cabang
    ├── pemilihan.json               ← Rekap hasil voting
    ├── vote_log.json                ← Log aktivitas voting
    ├── flagging.json                ← Status flagging kandidat
    ├── wawancara_assignment.json    ← Assignment pewawancara per kandidat
    ├── kesediaan_form.json          ← Data form kesediaan kandidat
    ├── scorecard_templates.json     ← Template scorecard per bidang
    ├── scorecard_submissions.json   ← Hasil pengisian scorecard
    ├── login_rate.json              ← Data rate limiting login
    ├── sessions/                    ← File session PHP
    └── uploads/
        └── kesediaan/               ← Dokumen kesediaan yang diupload
```

> **Catatan:** Direktori `majelis_secure_data` secara default berada dua level di atas direktori `index.php`. Lokasi ini dapat dikustomisasi melalui konstanta `PRIMARY_DATA_DIR` di bagian atas file.

---

## Peran Pengguna (Role)

| Role | Akses |
|---|---|
| `user` | Login, melihat bidang, melakukan voting |
| `admin` | Semua akses user + dashboard rekap, import Excel, manajemen kandidat (flagging, assignment, batal submit scorecard) |
| `pewawancara` | Halaman wawancara: input form kesediaan dan scorecard untuk kandidat yang di-assign kepadanya |

---

## Alur Aplikasi

```
Login
  │
  ├─► [user] Halaman Bidang → Pilih Kandidat per Bidang → Konfirmasi → Vote Tersimpan
  │
  ├─► [admin] Dashboard → Import Excel / Rekap Voting / Log Vote
  │         ↓
  │      Halaman Kandidat → Lihat Top 10 per Bidang
  │         → Assign Pewawancara
  │         → Tandai Lanjut Proses (butuh form kesediaan)
  │         → Tandai Lolos Screening
  │         → Batalkan Submit Scorecard (jika perlu revisi)
  │
  └─► [pewawancara / admin] Halaman Wawancara
         → Input Form Kesediaan (PDF/gambar, per pihak)
         → Lihat Form Kesediaan yang Sudah Diinput
         → Input / Edit Scorecard (jika kandidat Lolos Screening)
         → Submit Scorecard (kunci permanen)
```

---

## Halaman & Fungsionalitas

### `/index.php?page=login`
Halaman login dengan perlindungan CSRF dan rate limiting. Menampilkan popup sambutan satu kali per sesi browser. Setelah login, user diarahkan ke halaman bidang.

### `/index.php?page=bidang`
Halaman utama setelah login. Menampilkan semua bidang pelayanan beserta status voting user. Bidang yang sudah divote ditandai hijau dan tidak bisa dipilih ulang.

### `/index.php?page=pemilihan&bidang=...`
Halaman voting untuk satu bidang. User mencari kandidat dari cabangnya sendiri via input dengan datalist. Terdapat modal konfirmasi sebelum vote disimpan.

### `/index.php?page=dashboard`
Khusus admin. Menampilkan:
- Status deadline pemilihan
- Form import Excel
- Statistik total vote, pemilih unik, bidang terisi
- Progress bar voting keseluruhan
- Log seluruh aktivitas voting

### `/index.php?page=kandidat`
Khusus admin. Menampilkan Top 10 kandidat per bidang dengan fitur:
- Filter berdasarkan status proses (belum assign, belum lanjut proses, lanjut proses, lolos screening, sudah submit scorecard)
- Dropdown assignment pewawancara (submit otomatis saat berubah)
- Tombol "Lanjut Proses" (aktif setelah ada form kesediaan)
- Tombol "Tandai Screening" / "Batalkan Screening"
- Tombol "Batal Submit Score Card" (jika sudah disubmit)

### `/index.php?page=wawancara`
Untuk admin dan pewawancara. Menampilkan kandidat yang di-assign. Fitur:
- Input form kesediaan (upload dokumen PDF/gambar)
- Lihat rekap form kesediaan yang sudah diinput
- Input / edit scorecard (hanya untuk kandidat Lolos Screening)
- Submit scorecard (tidak dapat diubah setelah disubmit)

### `/index.php?page=kesediaan_file&form_id=...`
Endpoint untuk menampilkan atau mengunduh dokumen kesediaan yang diupload. Mendukung tampilan inline (PDF/gambar) maupun download.

### `/index.php?page=logout`
Logout via POST dengan validasi CSRF. Menghapus seluruh data sesi.

---

## Import Data via Excel

Admin dapat meng-upload file `.xlsx` dengan dua sheet:

### Sheet: `MASTER PEMILIH`
| Kolom Wajib | Keterangan |
|---|---|
| `NAMA LENGKAP` | Nama lengkap pemilih |
| `NOMOR TELPON` | Digunakan untuk generate password (6 digit terakhir angka) |
| `CABANG` | Nama cabang gereja |

- Username di-generate otomatis: nama depan + inisial nama berikutnya (contoh: `natanaelwt`)
- Password: 6 digit terakhir dari nomor telepon
- Role otomatis: `user`
- Jika user sudah ada (nama + cabang sama), data akan diperbarui

### Sheet: `MASTER KANDIDAT`
| Kolom | Status | Keterangan |
|---|---|---|
| `NAMA LENGKAP` | Wajib | Nama lengkap kandidat |
| `CABANG` | Wajib | Nama cabang gereja |
| `TIPE PENCALONAN` | Opsional | `SEMUA`, `SEMUA_KECUALI_KETUA_LOKAL`, atau `KETUA_LOKAL_SAJA` |

- ID kandidat di-generate otomatis dari nama + cabang
- Jika kandidat sudah ada, data akan diperbarui
- Jika `TIPE PENCALONAN` kosong atau kolom tidak disertakan, kandidat baru default ke semua posisi dan kandidat lama mempertahankan tipe pencalonan sebelumnya
- `SEMUA`: bisa dipilih untuk semua posisi, termasuk Ketua Pengurus Lokal
- `SEMUA_KECUALI_KETUA_LOKAL`: bisa dipilih untuk semua posisi selain Ketua Pengurus Lokal
- `KETUA_LOKAL_SAJA`: hanya bisa dipilih untuk Ketua Pengurus Lokal

**Batas ukuran file:** 8 MB

---

## Sistem Scorecard Wawancara

Scorecard digunakan untuk penilaian terstruktur kandidat yang sudah lolos screening. Sistem ini mendukung dua template bawaan:

### Template 1: Scorecard Wawancara Ketua Majelis
Khusus bidang **Ketua Majelis**, terdiri dari 4 bagian:

| Bagian | Topik | Bobot |
|---|---|---|
| A | Kesesuaian Teologis & Visi | 30% |
| B | Karakter & Spiritualitas | 30% |
| C | Kepemimpinan & Tata Kelola | 25% |
| D | Studi Kasus / Penyelesaian Masalah | 15% |

### Template 2: Scorecard Wawancara Majelis (Generic)
Untuk semua bidang lainnya, terdiri dari 4 bagian:

| Bagian | Topik | Bobot |
|---|---|---|
| A | Panggilan & Visi Pelayanan | 30% |
| B | Karakter & Spiritualitas | 30% |
| C | Kompetensi Pelayanan & Kolaborasi | 25% |
| D | Studi Kasus & Eksekusi | 15% |

### Skala Penilaian
- **1** = Sangat Kurang (ada red flag signifikan)
- **3** = Cukup / Memenuhi Syarat
- **5** = Sangat Baik / Ideal

### Kriteria Skor Akhir (Rekomendasi Otomatis)

| Rentang Skor | Label |
|---|---|
| 1.00 – 1.80 | Sangat Tidak Direkomendasikan |
| 1.81 – 2.60 | Tidak Direkomendasikan |
| 2.61 – 3.40 | Dipertimbangkan Kembali |
| 3.41 – 4.20 | Direkomendasikan |
| 4.21 – 5.00 | Sangat Direkomendasikan |

Skor akhir dihitung otomatis: rata-rata skor per bagian dikalikan bobot masing-masing bagian, lalu dijumlahkan.

---

## Keamanan

- **CSRF Protection** — Token CSRF pada setiap form POST
- **Session Security** — Cookie HttpOnly, SameSite=Strict, Secure (HTTPS), mode strict
- **Rate Limiting Login** — Maksimum 6 percobaan per user per IP dalam 15 menit; 25 percobaan per IP; blokir 15 menit
- **Password Hashing** — Semua password disimpan menggunakan `password_hash()` (bcrypt); password lama (plaintext) di-upgrade otomatis saat pertama kali dibaca
- **File Upload Validation** — Validasi MIME type via `fileinfo`, bukan hanya ekstensi; hanya PDF dan format gambar yang diizinkan
- **Atomic File Write** — Penulisan data JSON menggunakan file sementara + rename untuk mencegah korupsi data
- **Path Traversal Protection** — Validasi jalur file dokumen kesediaan sebelum disajikan
- **X-Frame-Options, CSP, HSTS headers** — Security headers dikirim di setiap response
- **Perlindungan direktori** — File `.htaccess` dibuat otomatis untuk memblokir akses langsung ke `.json` dan direktori session
- **Fingerprinting sesi** — Sesi diverifikasi dengan hash User-Agent untuk mendeteksi pembajakan sesi
- **Auth key session** — Sesi divalidasi ulang dengan hash password tersimpan

---

## Konfigurasi

Konstanta konfigurasi berada di bagian atas `index.php`:

```php
// Lokasi direktori data utama (di luar webroot)
const PRIMARY_DATA_DIR = __DIR__ . '/../../majelis_secure_data';

// Batas ukuran file
const DATA_MAX_BYTES = 3 * 1024 * 1024;        // Maks baca file data JSON: 3 MB
const IMPORT_MAX_BYTES = 8 * 1024 * 1024;      // Maks upload Excel: 8 MB
const KESEDIAAN_UPLOAD_MAX_BYTES = 8 * 1024 * 1024; // Maks upload dokumen: 8 MB

// Rate limiting login
const LOGIN_MAX_ATTEMPTS = 6;           // Maks percobaan per user per IP
const LOGIN_MAX_ATTEMPTS_PER_IP = 25;  // Maks percobaan per IP
const LOGIN_WINDOW_SECONDS = 15 * 60;  // Jendela waktu: 15 menit
const LOGIN_BLOCK_SECONDS = 15 * 60;   // Durasi blokir: 15 menit

// Deadline pemilihan
const ELECTION_DEADLINE_END = '2026-03-31 23:59:59';
const ELECTION_DEADLINE_LABEL = '31 Maret 2026';
```

Lokasi direktori session dapat dikonfigurasi melalui environment variable:
```
MAJELIS_SESSION_DIR=/path/to/session/dir
```

---

## Data Default

Saat pertama kali dijalankan, sistem membuat data awal secara otomatis:

### User Bawaan

| Nama Lengkap | Username | Password | Cabang | Role |
|---|---|---|---|---|
| Natanael Wijaya Tiono | `natanaelwt` | `010180` | REC Kutisari | admin |
| Budi Santoso | `budis` | `150190` | REC Kutisari | user |
| Sinta Anggraini | `sintaa` | `200292` | REC Nginden | user |
| David Wijaya | `davidw` | `081289` | REC Darmo | user |
| Rani Kristina | `ranik` | `031195` | REC Merr | user |
| Ferry Halim | `ferryh` | `270793` | REC Galaxy Mall | user |
| Lisa Gunawan | `lisag` | `120498` | REC Batam | user |

> **Penting:** Ganti password default segera setelah instalasi melalui fitur import Excel atau edit langsung file `users.json`.

### Bidang Pelayanan Bawaan
- Ketua Majelis
- Sekretaris Majelis
- Bendahara Majelis
- Majelis Bidang Pemuridan
- Majelis Bidang Misi
- Majelis Bidang Diakonia
- Majelis Bidang Ibadah
- Ketua Pengurus Lokal *(di-generate per cabang)*

### Cabang Bawaan
REC Kutisari · REC Nginden · REC Darmo · REC Merr · REC Galaxy Mall · REC Batam

---

## Catatan Teknis

- Seluruh aplikasi berjalan dalam satu file `index.php` tanpa framework eksternal.
- Data disimpan dalam format JSON; tidak memerlukan database.
- File JSON dilindungi dari akses publik melalui `.htaccess` yang dibuat otomatis.
- Bidang "Ketua Pengurus Lokal" secara otomatis di-personalisasi per cabang user yang login.
- Kandidat dapat dibatasi untuk semua posisi, semua posisi kecuali Ketua Pengurus Lokal, atau Ketua Pengurus Lokal saja.
- Voting bersifat **satu kali per bidang per user** dan tidak dapat diubah setelah disimpan.
- Dokumen kesediaan yang diupload disimpan dengan nama acak (random hex) di direktori aman.
