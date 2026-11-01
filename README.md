# DevOps_cheatsheet


*Lingkungan praktik: Ubuntu Server / WSL2 · 5 modul · 3 lab insiden · cheatsheet audit cepat*

## 0. Persiapan Lingkungan

Jalankan sekali sebelum memulai:

```bash
sudo apt update && sudo apt install -y \
  net-tools lsof tcpdump dnsutils ufw htop curl wget acl psmisc openssh-server
```

Catatan khusus **WSL2**:

- Aktifkan systemd agar `systemctl` dan `journalctl` berfungsi. Edit `/etc/wsl.conf`, isi `[boot]` dengan `systemd=true`, lalu jalankan `wsl --shutdown` dari PowerShell dan buka ulang terminal.
- `ufw`/`iptables` bisa dipakai di WSL2 modern, tetapi trafik dari Windows host tidak selalu melewatinya. Anggap ini sandbox latihan, bukan firewall produksi.
- Folder Windows (`/mnt/c/...`) tidak menyimpan permission Linux dengan benar. **Selalu berlatih di `~` (home Linux).**
- Semua latihan memakai user biasa. Awali `sudo` hanya bila disebutkan.

---

## 1. Matriks Keterampilan CLI DevSecOps

| Modul | Fokus | Perintah inti | Kemampuan yang dikuasai |
| --- | --- | --- | --- |
| **1. Identity, Access & Permissions** | Siapa boleh melakukan apa | `chmod`, `chown`, `umask`, setuid/setgid, `sudoers`, `ssh-keygen` | Menerapkan *least privilege*, menemukan privilege escalation path |
| **2. Network Inspection & Firewall** | Apa yang terbuka dan siapa yang bicara | `ss`, `lsof`, `ufw`, `iptables`, `tcpdump`, `curl`, `dig` | Memetakan attack surface, membuat aturan firewall, menangkap trafik |
| **3. Log Analysis & Threat Hunting** | Jejak apa yang tertinggal | `grep`, `awk`, `sed`, `journalctl`, `tail`, `find` | Mendeteksi brute force, anomali, dan file mencurigakan |
| **4. System Monitoring & Process Isolation** | Apa yang sedang berjalan | `ps`, `top`/`htop`, `kill`, `systemctl`, `/proc` | Menginvestigasi proses, menghentikan ancaman, mengisolasi service |
| **5. Hardening & Automation Scripting** | Mengubah manual jadi otomatis | env var, pipe/redirect, `set -euo pipefail`, bash audit | Membuat script audit yang aman dan *repeatable* |

**Urutan belajar yang disarankan:** Modul 1 → 2 → 3 → 4 → 5, lalu kerjakan Lab 1 sampai 3. Setiap modul memakai format yang sama: **Flag penting**, **Use case**, **Contoh & output**, **Pitfall**.

---

## Modul 1: Identity, Access & Permissions

> Prinsip utama: **least privilege**. Setiap user, proses, dan file hanya mendapat akses minimum yang dibutuhkan.

### 1.1 `chmod`: mengatur permission

**Flag penting:** `chmod 600 file`, `chmod -R u=rwX,g=rX,o= dir/`, `chmod u+s`, `chmod g+s`, `chmod +t`. Pembantu: `stat -c '%a %U:%G %n' file`.

**Use case DevSecOps:** mengunci file `.env`, kunci privat, kubeconfig, dan file secret CI/CD agar hanya pemilik yang bisa membaca.

**Contoh & output:**

```bash
$ echo 'DB_PASS=rahasia' > ~/app.env
$ ls -l ~/app.env
-rw-rw-r-- 1 dev dev 16 Nov  1 10:00 /home/dev/app.env   # dunia bisa baca!

$ chmod 600 ~/app.env
$ stat -c '%a %U:%G %n' ~/app.env
600 dev:dev /home/dev/app.env
```

Angka octal: `r=4, w=2, x=1`. Contoh `640` = pemilik `rw-`, grup `r--`, lainnya `---`.

**Pitfall:**

- `chmod 777` "biar jalan" adalah antipola. Cari akar masalah ownership-nya.
- `chmod -R 755 dir/` membuat **semua file** ikut executable. Pakai `X` (huruf besar) agar hanya direktori yang mendapat `x`.
- File secret dengan `644` ikut terbaca semua user lokal dan container yang me-mount volume-nya.

### 1.2 `chown`: mengatur kepemilikan

**Flag penting:** `chown user:group file`, `chown -R`, `chown -h` (untuk symlink), `chown --reference=ref target`.

**Use case:** setelah deploy sebagai root, pastikan aplikasi berjalan sebagai user non-root yang hanya memiliki direktori datanya.

```bash
$ sudo useradd -r -s /usr/sbin/nologin appsvc
$ sudo mkdir -p /srv/app/data
$ sudo chown -R appsvc:appsvc /srv/app/data
$ ls -ld /srv/app/data
drwxr-xr-x 2 appsvc appsvc 4096 Nov  1 10:05 /srv/app/data
```

**Pitfall:**

- Variabel kosong berbahaya: `chown -R appsvc:appsvc $APPDIR/` saat `$APPDIR` kosong menjadi `chown -R appsvc:appsvc /`. Selalu gunakan `"${APPDIR:?}"` di script.
- Menjalankan service sebagai root "supaya tidak ada masalah permission" memperbesar blast radius jika service dibobol.

### 1.3 `umask`: default permission file baru

**Flag penting:** `umask` (lihat), `umask 027` (set), `umask -S` (format simbolik).

**Use case:** memastikan file yang dibuat script/service tidak otomatis terbaca user lain.

```bash
$ umask
0022
$ touch a.txt && mkdir adir && stat -c '%a %n' a.txt adir
644 a.txt
755 adir

$ umask 027
$ touch b.txt && mkdir bdir && stat -c '%a %n' b.txt bdir
640 b.txt
750 bdir
```

Rumus: file baru = `666 − umask`, direktori baru = `777 − umask`.

**Pitfall:**

- `umask` hanya memengaruhi file **baru**, bukan file yang sudah ada.
- Setting di shell tidak berlaku untuk service systemd. Gunakan `UMask=0027` di unit file.
- Untuk permanen per user, taruh di `~/.profile`. Untuk seluruh sistem, ubah `UMASK` di `/etc/login.defs`.

### 1.4 setuid, setgid, sticky bit

**Flag penting:** `chmod u+s file` (4xxx), `chmod g+s dir` (2xxx), `chmod +t dir` (1xxx). Audit: `find / -perm -4000 -type f 2>/dev/null`.

**Use case:** mendeteksi binary SUID yang tidak seharusnya ada. Ini salah satu vektor privilege escalation paling klasik.

```bash
$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/su
/usr/bin/mount
/usr/bin/chfn
/home/dev/rootshell          # <-- MENCURIGAKAN

$ ls -ld /tmp
drwxrwxrwt 12 root root 4096 Nov  1 10:10 /tmp   # huruf 't' = sticky bit
```

- **SUID:** program berjalan dengan hak pemilik file (misalnya root).
- **SGID pada direktori:** file baru mewarisi grup direktori. Berguna untuk folder kolaborasi.
- **Sticky bit:** hanya pemilik file yang boleh menghapus filenya (contoh `/tmp`).

**Pitfall:**

- SUID pada interpreter atau tool umum (`find`, `vim`, `python`, `bash`) = root shell instan. Cocokkan temuan dengan daftar **GTFOBins**.
- Kernel Linux mengabaikan SUID pada *shell script*, jadi "fix" ini tidak akan bekerja, dan percobaannya sendiri adalah red flag.
- Simpan baseline daftar SUID, lalu `diff` secara berkala untuk mendeteksi penambahan.

### 1.5 `/etc/sudoers` & `sudo`

**Flag penting:** `sudo visudo` (selalu), `sudo visudo -f /etc/sudoers.d/nama`, `sudo visudo -c` (cek sintaks), `sudo -l` (lihat hak sendiri), `sudo -l -U user`.

**Use case:** memberi tim deploy hak untuk me-restart satu service saja, bukan root penuh.

```bash
$ sudo visudo -f /etc/sudoers.d/deploy
# isi file:
deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart myapp.service

$ sudo visudo -c
/etc/sudoers: parsed OK
/etc/sudoers.d/deploy: parsed OK

$ sudo -l -U deploy
User deploy may run the following commands on host:
    (root) NOPASSWD: /usr/bin/systemctl restart myapp.service
```

**Pitfall:**

- `NOPASSWD: ALL` memberi root tanpa batas. Hindari, terutama pada akun yang bisa diakses lewat jaringan.
- Wildcard berbahaya: `/bin/cat /var/log/*` bisa dieksploitasi dengan `cat /var/log/../../etc/shadow`.
- Mengedit `/etc/sudoers` langsung dengan `nano` dan salah sintaks bisa mengunci semua akses sudo. **Selalu `visudo`.**
- File di `/etc/sudoers.d/` harus berizin `0440`, dan nama file tidak boleh mengandung titik atau `~`, kalau tidak akan diabaikan.
- Command yang membuka shell (`less`, `vi`, `find`) di sudoers = *shell escape* ke root.

### 1.6 SSH Key Management

**Flag penting:** `ssh-keygen -t ed25519 -C "komentar" -f ~/.ssh/nama`, `ssh-keygen -lf key.pub` (fingerprint), `ssh-copy-id -i key.pub user@host`, `ssh-add -l`, `sshd -t` (uji config).

**Use case:** mengganti login password dengan kunci, lalu mengunci `sshd` agar tahan brute force.

```bash
$ ssh-keygen -t ed25519 -C "dev@wsl-lab" -f ~/.ssh/lab_ed25519
Enter passphrase (empty for no passphrase): ********

$ ssh-keygen -lf ~/.ssh/lab_ed25519.pub
256 SHA256:Zk3...abc dev@wsl-lab (ED25519)

$ chmod 700 ~/.ssh && chmod 600 ~/.ssh/lab_ed25519 ~/.ssh/authorized_keys
```

Hardening minimum di `/etc/ssh/sshd_config`:

```text
PasswordAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
MaxAuthTries 3
AllowUsers deploy dev
```

```bash
$ sudo sshd -t && sudo systemctl reload ssh   # uji dulu, baru reload
```

**Pitfall:**

- Kunci privat **tanpa passphrase** yang bocor = akses langsung. Gunakan passphrase dan `ssh-agent`.
- Permission longgar (`~/.ssh` bukan 700, kunci bukan 600) membuat SSH menolak kunci: `UNPROTECTED PRIVATE KEY FILE`.
- Jangan commit `id_*` atau `*.pem` ke Git. Tambahkan ke `.gitignore` dan pasang secret scanner.
- `ssh -A` (agent forwarding) ke host tidak tepercaya memungkinkan host itu memakai kunci Anda. Pakai `ProxyJump` sebagai gantinya.
- Saat mengubah `sshd_config`, **jangan tutup sesi aktif** sampai Anda menguji login dari sesi baru.

---

## Modul 2: Network Inspection & Firewall

> Prinsip utama: **kenali attack surface**. Apa yang listening, siapa yang terkoneksi, dan apa yang boleh lewat.

### 2.1 `ss -tulpn` (pengganti `netstat`)

**Flag penting:** `-t` TCP, `-u` UDP, `-l` listening, `-p` proses, `-n` numerik (tanpa DNS), `-a` semua, `-s` ringkasan. Variasi: `ss -tnp state established`.

**Use case:** menemukan port yang terbuka liar di server atau di dalam container. Ini langkah pertama hampir setiap audit.

```bash
$ sudo ss -tulpn
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      511    127.0.0.1:5432     0.0.0.0:*     users:(("postgres",pid=901,fd=5))
tcp   LISTEN 0      511    0.0.0.0:6379       0.0.0.0:*     users:(("redis-server",pid=1450,fd=6))
```

Cara baca: `0.0.0.0` atau `[::]` berarti terekspos di **semua** interface. `127.0.0.1` berarti hanya lokal. Pada contoh, Redis di `0.0.0.0:6379` adalah temuan serius. Padanan lama: `netstat -tulpn`.

**Pitfall:**

- Tanpa `sudo`, kolom `Process` kosong untuk proses milik user lain.
- Port yang dipublish Docker (`-p 6379:6379`) memasang aturan iptables sendiri dan **melewati ufw**. Port tampak "terblokir" di ufw padahal terbuka.
- Jangan lupa `-n`. Tanpa itu resolusi DNS membuat output lambat dan menyesatkan.

### 2.2 `lsof`: file dan socket yang dibuka proses

**Flag penting:** `lsof -nP -iTCP -sTCP:LISTEN`, `lsof -i :8080`, `lsof -p PID`, `lsof -u user`, `lsof +L1` (file sudah dihapus tapi masih terbuka).

**Use case:** mengetahui proses mana yang memegang port tertentu, atau menemukan malware yang menghapus binary-nya sendiri setelah berjalan.

```bash
$ sudo lsof -nP -iTCP -sTCP:LISTEN
COMMAND   PID     USER FD TYPE NODE NAME
sshd      812     root 3u IPv4 TCP  *:22 (LISTEN)
node     2210      dev 18u IPv4 TCP  *:8080 (LISTEN)

$ sudo lsof +L1
COMMAND PID USER FD TYPE SIZE/OFF NLINK NAME
update 3301 dev  txt REG  1048576     0 /tmp/.x (deleted)   # <-- mencurigakan
```

**Pitfall:**

- Tanpa `-n -P`, `lsof` melakukan lookup DNS dan nama service sehingga lambat dan hasilnya kurang jelas.
- File `(deleted)` yang masih berjalan = indikasi klasik fileless atau *self-deleting malware*. Salin dari `/proc/PID/exe` sebelum membunuh prosesnya.

### 2.3 `ufw`: firewall sederhana

**Flag penting:** `ufw default deny incoming`, `ufw default allow outgoing`, `ufw allow from 10.0.0.0/24 to any port 22 proto tcp`, `ufw limit 22/tcp` (rate limit), `ufw status numbered verbose`, `ufw delete N`.

**Use case:** baseline firewall server: tolak semua masuk, izinkan hanya yang dibutuhkan dari sumber tertentu.

```bash
$ sudo ufw default deny incoming
$ sudo ufw default allow outgoing
$ sudo ufw allow from 10.0.0.0/24 to any port 22 proto tcp
$ sudo ufw allow 443/tcp
$ sudo ufw enable
$ sudo ufw status numbered
Status: active
     To                         Action      From
[ 1] 22/tcp                     ALLOW IN    10.0.0.0/24
[ 2] 443/tcp                    ALLOW IN    Anywhere
```

**Pitfall:**

- Mengaktifkan ufw sebelum mengizinkan SSH di server remote = **mengunci diri sendiri**. Urutan: allow SSH, baru enable.
- Container Docker melewati ufw (lihat 2.1). Batasi lewat chain `DOCKER-USER` atau bind ke `127.0.0.1`.
- `ufw allow 22` membuka SSH ke seluruh internet. Batasi dengan `from <CIDR>` atau gunakan `ufw limit`.

### 2.4 `iptables`: kontrol firewall tingkat rendah

**Flag penting:** `iptables -L -n -v --line-numbers`, `iptables -S`, `-A` (append), `-I` (insert di posisi), `-D` (hapus), `-j ACCEPT|DROP|LOG`, `iptables-save`.

**Use case:** memblokir IP penyerang secara cepat saat insiden, atau memeriksa aturan yang dipasang Docker.

```bash
$ sudo iptables -I INPUT 1 -s 203.0.113.50 -j DROP        # blok IP penyerang
$ sudo iptables -L INPUT -n -v --line-numbers
num  pkts bytes target  prot opt in out source          destination
1       0     0 DROP    all  --  *  *   203.0.113.50    0.0.0.0/0

$ sudo iptables-save > ~/iptables.backup                    # cadangkan sebelum utak-atik
```

**Pitfall:**

- **Urutan aturan menentukan hasil.** Aturan ACCEPT di atas DROP bisa membatalkan blokir Anda. Gunakan `-I` untuk meletakkan di posisi teratas.
- Aturan tidak permanen. Setelah reboot hilang kecuali disimpan (`iptables-persistent`/`netfilter-persistent`).
- Mengubah policy menjadi `DROP` (`iptables -P INPUT DROP`) sebelum mengizinkan SSH = terkunci.
- Ubuntu modern memakai backend nftables (`iptables-nft`). Jangan mencampur `iptables` dan `nft` tanpa paham konsekuensinya.

### 2.5 `tcpdump`: menangkap paket

**Flag penting:** `-i any`, `-nn` (tanpa resolusi nama/port), `-c 20` (batasi jumlah), `-A` (ASCII), `-w file.pcap` / `-r file.pcap`, filter `host`, `port`, `net`.

**Use case:** membuktikan apakah sebuah proses benar-benar berkomunikasi ke IP luar, atau melihat query DNS yang mencurigakan.

```bash
$ sudo tcpdump -i any -nn -c 5 port 53
listen on any, link-type LINUX_SLL2
10:15:01.101 IP 172.24.0.2.48211 > 172.24.0.1.53: 4711+ A? example.com. (29)
10:15:01.130 IP 172.24.0.1.53 > 172.24.0.2.48211: 4711 1/0/0 A 93.184.216.34 (45)

$ sudo tcpdump -i any -nn -w ~/cap.pcap host 203.0.113.50   # simpan untuk analisis
```

**Pitfall:**

- Tanpa filter dan tanpa `-c`, output membanjiri terminal dan CPU.
- File `.pcap` bisa berisi kredensial dan token dalam plaintext. Perlakukan sebagai data sensitif.
- Tidak bisa membaca isi trafik HTTPS. Anda hanya melihat metadata (IP, port, ukuran, SNI).
- Di WSL2, antarmuka utamanya biasanya `eth0`. `-i any` aman untuk latihan.

### 2.6 `curl` / `wget`: uji endpoint dan header

**Flag penting:** `curl -sSI URL` (hanya header), `-o /dev/null -w '%{http_code} %{time_total}s\n'`, `-v` (verbose TLS), `--resolve host:443:IP`, `-H @file`; `wget --spider URL`.

**Use case:** memverifikasi security header, status TLS, redirect, dan health endpoint dari sisi luar.

```bash
$ curl -sSI https://example.com | grep -iE 'strict-transport|x-frame|content-security|x-content-type'
strict-transport-security: max-age=31536000; includeSubDomains
x-content-type-options: nosniff

$ curl -sS -o /dev/null -w '%{http_code} %{time_total}s\n' https://example.com/health
200 0.142s
```

**Pitfall:**

- `curl -k` mematikan verifikasi sertifikat TLS. Boleh untuk debugging, jangan di script produksi.
- `curl URL | bash` mengeksekusi kode dari internet tanpa dicek. Unduh dulu, periksa checksum, baru jalankan.
- Token di baris perintah (`-H "Authorization: Bearer xxx"`) terlihat di `ps` dan `~/.bash_history`. Ambil dari file atau variabel lingkungan: `-H @header.txt`.

### 2.7 `dig` / `nslookup`: investigasi DNS

**Flag penting:** `dig +short A domain`, `dig @1.1.1.1 domain MX`, `dig TXT domain`, `dig -x IP` (reverse), `dig +trace domain`.

**Use case:** memeriksa apakah domain mengarah ke IP yang benar, mengecek SPF/DKIM lewat TXT, dan mendeteksi DNS hijacking atau domain C2.

```bash
$ dig +short A example.com
93.184.216.34

$ dig +short TXT example.com
"v=spf1 -all"

$ dig -x 8.8.8.8 +short
dns.google.
```

**Pitfall:**

- Di Ubuntu, resolver lokal berada di `127.0.0.53` (systemd-resolved). Gunakan `resolvectl status` untuk melihat DNS upstream yang sebenarnya.
- Hasil bisa berbeda antar resolver karena cache. Bandingkan dengan `dig @1.1.1.1` dan `dig @8.8.8.8`.
- Query DNS dengan subdomain sangat panjang atau acak (`a8f3k29x...attacker.com`) adalah ciri **DNS exfiltration/tunneling**.

---

## Modul 3: Log Analysis & Threat Hunting

> Prinsip utama: **log adalah bukti**. Baca, saring, dan korelasikan, tetapi jangan pernah mengubahnya.

### 3.1 `grep`: mencari pola

**Flag penting:** `-r` rekursif, `-n` nomor baris, `-i` abaikan kapitalisasi, `-E` regex extended, `-I` lewati file biner, `-v` kebalikan, `-c` hitung, `-o` hanya bagian yang cocok, `-A/-B/-C N` konteks, `--exclude-dir=.git`.

**Use case:** memindai repositori atau direktori konfigurasi untuk secret yang bocor (password, API key, private key).

```bash
$ grep -rnIE '(AKIA[0-9A-Z]{16}|password\s*=|BEGIN (RSA|OPENSSH) PRIVATE KEY)' ~/project --exclude-dir=.git
/home/dev/project/config.py:12:DB_PASSWORD = "Sup3rS3cret"
/home/dev/project/deploy/key.pem:1:-----BEGIN RSA PRIVATE KEY-----

$ sudo grep -c 'Failed password' /var/log/auth.log
187
```

**Pitfall:**

- `grep` hanya melihat kondisi file **saat ini**. Secret yang pernah di-commit lalu dihapus masih ada di riwayat Git. Periksa dengan `git log -p -S'password'`.
- Regex terlalu longgar menghasilkan *false positive* banyak, sedangkan terlalu ketat melewatkan temuan. Uji pola pada data contoh dulu.
- Mengetik secret langsung sebagai argumen grep tersimpan di history. Gunakan `grep -f patterns.txt`.

### 3.2 `awk`: mengolah kolom dan agregasi

**Flag penting:** `-F:` (pemisah), `'{print $1}'`, `$NF` (kolom terakhir), kondisi `'$3==0'`, array asosiatif `c[$1]++`, blok `END{...}`.

**Use case:** menghitung IP penyerang dari log SSH, atau mencari akun dengan UID 0 selain root.

```bash
# Top IP yang gagal login SSH
$ sudo grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -5
    142 203.0.113.50
     31 198.51.100.7
      9 192.0.2.44

# Akun dengan UID 0 (seharusnya hanya root)
$ awk -F: '$3==0 {print $1}' /etc/passwd
root
toor          # <-- backdoor account

# Ringkasan status HTTP dari access log nginx
$ awk '{c[$9]++} END{for(k in c) print k, c[k]}' /var/log/nginx/access.log | sort
200 5821
404 312
500 7
```

**Pitfall:**

- Nomor kolom bergantung pada format log. Cek satu baris dulu (`head -1 log | awk '{print NF; print $0}'`) sebelum membuat one-liner.
- `sort | uniq -c` mensyaratkan `sort` lebih dulu, karena `uniq` hanya menggabung baris yang berdekatan.
- Log yang dirotasi berada di `auth.log.1` dan `auth.log.2.gz`. Pakai `zgrep` atau `zcat` agar tidak melewatkan data historis.

### 3.3 `sed`: transformasi dan penyamaran data

**Flag penting:** `sed -n '10,20p'` (cetak rentang), `sed -E 's/pola/ganti/g'`, `sed -i.bak` (edit dengan cadangan), `sed '/pola/d'` (hapus baris).

**Use case:** menyamarkan token dan password sebelum membagikan log ke tim atau tiket insiden.

```bash
$ echo 'login ok token=eyJhbGciOi.abc.def user=dev' | sed -E 's/(token=)[^ ]+/\1****/'
login ok token=**** user=dev

$ sed -n '100,105p' /var/log/syslog        # baca sebagian saja
```

**Pitfall:**

- `sed -i` tanpa sufiks cadangan tidak bisa dibatalkan. Gunakan `-i.bak`.
- **Jangan mengedit file log asli** (selain rotasi resmi). Mengubah log menghancurkan nilai forensiknya. Kerjakan pada salinan.
- Jika pola mengandung `/` (path), pakai pemisah lain: `s|/etc/ssh|/tmp/ssh|`.

### 3.4 `journalctl`: log systemd

**Flag penting:** `-u unit`, `--since "1 hour ago"`, `-p err..alert` (filter prioritas), `-f` (follow), `-b -1` (boot sebelumnya), `-k` (kernel), `-o json`, `--no-pager`, `_UID=1000`.

**Use case:** menyelidiki service yang crash atau restart tidak wajar, dan melihat login SSH tanpa membuka file log manual.

```bash
$ sudo journalctl -u ssh --since "1 hour ago" --no-pager | grep -E 'Failed|Accepted'
Nov 01 10:20:11 host sshd[2301]: Failed password for invalid user admin from 203.0.113.50 port 41822 ssh2
Nov 01 10:22:40 host sshd[2355]: Accepted publickey for dev from 10.0.0.5 port 50112 ssh2

$ sudo journalctl -p err..alert -b --no-pager | tail -5
```

**Pitfall:**

- Jika `/var/log/journal` tidak ada, journal bersifat *volatile* dan **hilang saat reboot**. Buat direktorinya dan restart `systemd-journald` untuk persistensi.
- Nama unit SSH di Ubuntu adalah `ssh`, bukan `sshd`.
- Tanpa systemd aktif (WSL2 lama), `journalctl` kosong. Lihat bagian Persiapan.

### 3.5 `tail`: memantau log real-time

**Flag penting:** `tail -n 100`, `tail -F` (huruf besar: tetap mengikuti walau file dirotasi), `tail -f`.

**Use case:** memantau percobaan serangan secara langsung saat insiden.

```bash
$ sudo tail -F /var/log/auth.log | grep --line-buffered -E 'Failed|Invalid user'
Nov  1 10:30:02 host sshd[3012]: Invalid user test from 203.0.113.50 port 51000
```

**Pitfall:**

- `tail -f` berhenti mengikuti setelah *logrotate*. Gunakan `-F`.
- Tanpa `--line-buffered`, `grep` pada pipa menahan output sehingga terlihat "macet".

### 3.6 `find` dengan parameter keamanan

**Flag penting:** `-perm -4000` (SUID), `-perm -o+w` (world-writable), `-nouser -nogroup` (tanpa pemilik valid), `-mtime -1` / `-newermt "2026-11-01"` (baru diubah), `-xdev`, `-type f`, `-name`, `-size +50M`, `-print0 | xargs -0`.

**Use case:** menemukan file yang berubah setelah insiden, file writable oleh semua orang, dan file kredensial yang tercecer.

```bash
# File world-writable (abaikan symlink), tetap di satu filesystem
$ find / -xdev -type f -perm -o+w 2>/dev/null
/var/tmp/.cache_x
/opt/app/config.yml            # <-- config bisa ditimpa siapa saja

# File berubah dalam 24 jam terakhir di direktori sensitif
$ sudo find /etc /usr/local/bin -type f -mtime -1
/etc/crontab
/usr/local/bin/updater

# File tanpa pemilik (sisa user yang dihapus atau malware)
$ sudo find / -xdev \( -nouser -o -nogroup \) 2>/dev/null

# Cari file kunci/credential
$ find ~ -type f \( -name 'id_rsa' -o -name '*.pem' -o -name '.env' -o -name '*.kdbx' \) 2>/dev/null
```

**Pitfall:**

- `-exec rm {} \;` langsung berbahaya. **Jalankan dengan `-print` dulu**, tinjau hasilnya, baru hapus.
- Nama file dengan spasi merusak pipa biasa. Gunakan `-print0 | xargs -0`.
- Di WSL2, `find /` ikut menelusuri `/mnt/c` (sangat lambat). Pakai `-xdev` atau batasi path.
- `2>/dev/null` menyembunyikan *Permission denied*. Jalankan dengan `sudo` agar tidak ada area yang terlewat.

---

## Modul 4: System Monitoring & Process Isolation

> Prinsip utama: **kenali baseline normal**. Anomali hanya terlihat jika Anda tahu kondisi sehat.

### 4.1 `ps`: snapshot proses

**Flag penting:** `ps aux --sort=-%cpu | head`, `ps -ef --forest` (pohon parent-child), `ps -eo pid,ppid,user,%cpu,%mem,etime,cmd --sort=-%mem`, `ps -p PID -o pid,ppid,user,cmd`.

**Use case:** menemukan proses yang memakan CPU, berjalan dari lokasi aneh (`/tmp`, `/dev/shm`), atau punya parent mencurigakan.

```bash
$ ps -eo pid,ppid,user,%cpu,%mem,etime,cmd --sort=-%cpu | head -4
  PID  PPID USER  %CPU %MEM     ELAPSED CMD
 3301  3290 dev   97.3  1.2       12:44 /tmp/.x --pool stratum+tcp://203.0.113.9:3333
  812     1 root   0.0  0.1     2-03:10 sshd: /usr/sbin/sshd -D
```

**Pitfall:**

- Nama proses bisa dipalsukan (misalnya menyamar jadi `[kworker]`). Verifikasi dengan `readlink /proc/PID/exe`.
- Argumen command-line terlihat oleh semua user. Jangan pernah menaruh password di argumen.
- Proses dalam kurung siku `[kthreadd]` adalah kernel thread. Proses user yang meniru format ini patut dicurigai.

### 4.2 `top` / `htop`: pemantauan real-time

**Flag penting:** `top -o %CPU`, `top -u user`, `top -b -n1 | head -15` (mode batch untuk script), `htop` (`F5` tree, `F6` sort, `F9` kill, `F4` filter).

**Use case:** melihat lonjakan CPU/memori dan load average saat investigasi *resource hijacking* (misalnya cryptominer).

```bash
$ top -b -n1 | head -12
top - 10:40:01 up 2 days,  1:12,  1 user,  load average: 1.95, 1.60, 1.10
Tasks: 112 total,   2 running, 110 sleeping,   0 stopped,   0 zombie
%Cpu(s): 98.0 us,  1.0 sy,  0.0 ni,  1.0 id
  PID USER   PR NI    VIRT   RES  %CPU %MEM   TIME+ COMMAND
 3301 dev    20  0  704812  62344  97.3  1.2  12:44.31 .x
```

**Pitfall:**

- *Load average* bukan persentase CPU. Bandingkan dengan jumlah core (`nproc`).
- `%CPU` per proses bisa melebihi 100% pada mesin multi-core.
- `top` hanyalah snapshot. Rootkit dapat menyembunyikan proses dari tool user-space, jadi bandingkan dengan `ls /proc`.

### 4.3 `kill` / `pkill` / `killall`: mengendalikan proses

**Flag penting:** `kill -15 PID` (TERM, sopan), `kill -9 PID` (KILL, paksa), `kill -STOP PID` / `kill -CONT PID` (bekukan/lanjutkan), `pkill -u user`, `pkill -f 'pola cmdline'`, `killall nama`.

**Use case:** menghentikan proses berbahaya **tanpa menghilangkan bukti**: bekukan dulu, kumpulkan data, baru bunuh.

```bash
$ sudo kill -STOP 3301            # bekukan, proses & memori tetap utuh
$ sudo cp /proc/3301/exe ~/evidence/sample.bin
$ sudo ls -l /proc/3301/fd > ~/evidence/fd.txt
$ sudo kill -9 3301               # setelah bukti aman
$ ps -p 3301 || echo "proses sudah mati"
```

**Pitfall:**

- `kill -9` tidak memberi proses kesempatan membersihkan resource (file lock, temp file). Coba `-15` dahulu untuk service normal.
- `pkill -f` mencocokkan **seluruh baris perintah**, sehingga bisa membunuh proses yang tidak diinginkan (termasuk shell Anda sendiri bila polanya umum). Cek dulu dengan `pgrep -af 'pola'`.
- Membunuh proses induk tanpa memeriksa persistensi (cron, systemd, `.bashrc`) hanya sementara. Proses akan hidup lagi.

### 4.4 `systemctl`: mengelola dan mengisolasi service

**Flag penting:** `systemctl list-units --type=service --state=running`, `list-unit-files --state=enabled`, `status`, `cat`, `edit` (drop-in override), `disable --now`, `mask`, `systemd-analyze security UNIT`.

**Use case:** audit service yang aktif, mematikan yang tidak perlu, dan memberi sandbox pada service sendiri lewat direktif keamanan systemd.

```bash
$ systemctl list-unit-files --state=enabled --type=service | head
$ systemctl status myapp.service --no-pager
● myapp.service - My App
     Loaded: loaded (/etc/systemd/system/myapp.service; enabled)
     Active: active (running) since Sun 2026-11-01 09:00:12 WIB; 1h 40min ago

$ sudo systemctl disable --now cups-browsed.service   # matikan yang tidak dipakai
```

Contoh drop-in hardening (`sudo systemctl edit myapp.service`):

```ini
[Service]
User=appsvc
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/srv/app/data
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
```

```bash
$ systemd-analyze security myapp.service | tail -2   # skor eksposur: makin kecil makin aman
```

**Pitfall:**

- `stop` hanya menghentikan sementara. Service tetap aktif setelah reboot kecuali `disable`. Untuk benar-benar memblokir, gunakan `mask`.
- Jangan mengedit file di `/lib/systemd/system/` langsung (tertimpa saat update paket). Gunakan `systemctl edit`.
- Setelah mengubah unit file, jalankan `sudo systemctl daemon-reload`.
- Unit mencurigakan di `/etc/systemd/system/` atau `~/.config/systemd/user/` adalah lokasi persistensi malware yang umum.

### 4.5 `/proc` filesystem: mengintip proses dari dalam

**Path penting:** `/proc/PID/exe` (binary asli), `/proc/PID/cmdline`, `/proc/PID/cwd`, `/proc/PID/environ`, `/proc/PID/fd/`, `/proc/PID/status`, `/proc/PID/maps`, `/proc/net/tcp`.

**Use case:** membuktikan identitas sebenarnya dari proses mencurigakan, dan memulihkan binary yang sudah dihapus dari disk.

```bash
$ sudo readlink /proc/3301/exe
/tmp/.x (deleted)

$ sudo tr '\0' ' ' < /proc/3301/cmdline; echo
/tmp/.x --pool stratum+tcp://203.0.113.9:3333

$ sudo readlink /proc/3301/cwd
/tmp

$ sudo ls -l /proc/3301/fd | head

$ sudo cp /proc/3301/exe ~/evidence/sample.bin     # selamatkan binary yang sudah dihapus
```

**Pitfall:**

- `/proc/PID/environ` bisa berisi secret dan token milik proses. Itu sebabnya hanya user pemilik atau root yang boleh membaca. Perlakukan sebagai data sensitif.
- Mount `/proc` dengan opsi `hidepid=2` untuk menyembunyikan proses user lain dari user biasa.
- `/proc` adalah kondisi **hidup**, bukan image forensik. Salin bukti secepatnya, sebelum proses mati.

---

## Modul 5: Hardening & Automation Scripting

> Prinsip utama: **apa yang Anda lakukan dua kali, otomatiskan, dan buat aman saat gagal.**

### 5.1 Variabel lingkungan & penanganan secret

**Flag/sintaks penting:** `export VAR=...`, `env`, `printenv VAR`, `unset VAR`, `${VAR:?pesan}` (wajib ada), `${VAR:-default}`, `read -rs VAR` (input tersembunyi), `env -i cmd` (jalankan dengan lingkungan bersih).

**Use case:** menyuntikkan secret saat runtime (bukan hard-code di script atau image), dan memeriksa kebocoran secret di lingkungan.

```bash
$ read -rsp 'API token: ' API_TOKEN; echo
$ export API_TOKEN
$ curl -sS -H "Authorization: Bearer ${API_TOKEN:?API_TOKEN belum di-set}" https://api.example.com/me
$ unset API_TOKEN

$ env | grep -iE 'key|token|secret|pass'      # audit cepat variabel sensitif
```

**Pitfall:**

- Variabel lingkungan terbaca di `/proc/PID/environ` oleh pemilik dan root, dan diwariskan ke semua *child process*.
- `set -x` (debug) mencetak nilai variabel termasuk secret ke log CI. Matikan di bagian yang menyentuh secret.
- `export SECRET=...` di `~/.bashrc` membuat secret permanen di setiap sesi. Gunakan secret manager (Vault, SOPS, `pass`) untuk jangka panjang.
- Spasi di awal baris (dengan `HISTCONTROL=ignorespace`) tidak menyimpan perintah ke history. Itu pelindung tambahan, bukan pengganti praktik yang benar.

### 5.2 Pipe & redirection

**Sintaks penting:** `|`, `>` (timpa), `>>` (tambah), `2>` (stderr), `2>&1`, `&>`, `<`, `<<<`, `tee`, `/dev/null`.

**Use case:** merangkai tool kecil menjadi pipeline audit, menyimpan hasil, dan memisahkan output normal dari error.

```bash
$ sudo ss -tulpn 2>/dev/null | awk 'NR>1 && $5 ~ /^0\.0\.0\.0|^\[::\]/ {print $5, $7}' | tee ~/exposed_ports.txt
0.0.0.0:22 users:(("sshd",pid=812,fd=3))
0.0.0.0:6379 users:(("redis-server",pid=1450,fd=6))

# Menulis ke file milik root: redirect dijalankan oleh SHELL Anda, bukan sudo
$ echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-hardening.conf
```

**Pitfall:**

- `sudo echo x > /etc/file` **gagal**, karena redirection dieksekusi sebelum sudo. Gunakan `| sudo tee`.
- Urutan penting: `cmd > out.txt 2>&1` benar, `cmd 2>&1 > out.txt` salah (stderr tetap ke terminal).
- `2>/dev/null` pada audit bisa menyembunyikan *Permission denied* dan menghasilkan **false negative** ("tidak ada temuan" padahal tidak bisa membaca).
- `>` menimpa tanpa tanya. Aktifkan `set -o noclobber` untuk pengaman.

### 5.3 Error handling: `set -euo pipefail`

**Arti tiap flag:**

- `-e`: script berhenti jika sebuah perintah gagal (exit code bukan 0).
- `-u`: error jika memakai variabel yang belum didefinisikan (mencegah `rm -rf "$DIR/"` jadi `rm -rf /`).
- `-o pipefail`: pipeline gagal jika **salah satu** perintah di dalamnya gagal, bukan hanya yang terakhir.

**Use case:** membuat script otomasi yang *fail fast* dan tidak melanjutkan dengan state setengah rusak.

```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
trap 'echo "[ERROR] gagal di baris $LINENO" >&2' ERR

BACKUP_DIR="${1:?Usage: $0 <backup_dir>}"
mkdir -p "$BACKUP_DIR"
tar czf "$BACKUP_DIR/etc-$(date +%F).tgz" /etc 2>/dev/null
echo "backup selesai"
```

```bash
$ ./backup.sh
backup.sh: line 6: 1: Usage: ./backup.sh <backup_dir>
```

**Pitfall:**

- `grep` mengembalikan exit code 1 jika tidak ada kecocokan, sehingga script **mati** padahal itu hasil normal. Tulis `grep ... || true` atau `if grep -q ...; then`.
- `set -e` tidak aktif di dalam kondisi `if`, rantai `&&`/`||`, dan sisi kiri pipa. Jangan menganggapnya jaring pengaman total.
- `((count++))` mengembalikan status 1 saat nilai awalnya 0, sehingga mematikan script di bawah `-e`. Pakai `count=$((count+1))`.
- **Selalu kutip variabel**: `"$var"`. Jalankan `shellcheck script.sh` (`sudo apt install shellcheck`) sebelum dipakai.

### 5.4 Dasar bash untuk audit

**Sintaks penting:** fungsi `name() { ...; }`, `[[ ... ]]`, `command -v tool`, `stat -c '%a'`, `id -u`, `mktemp`, `$?`, exit code (`0` = sukses).

**Use case:** membungkus pemeriksaan keamanan menjadi fungsi kecil yang melaporkan PASS/FAIL, sebagai fondasi Lab 3.

```bash
check() {                       # check "deskripsi" perintah arg...
  local desc=$1; shift
  if "$@" >/dev/null 2>&1; then
    echo "[PASS] $desc"
  else
    echo "[FAIL] $desc"
  fi
}

check "Root login SSH dimatikan" grep -Eq '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config
check "ufw aktif" bash -c 'ufw status | grep -q "Status: active"'
```

```text
[FAIL] Root login SSH dimatikan
[PASS] ufw aktif
```

**Pitfall:**

- Script audit yang butuh root harus memeriksa dirinya sendiri: `[[ $EUID -eq 0 ]] || { echo "Jalankan dengan sudo" >&2; exit 1; }`.
- File temporer harus dibuat dengan `mktemp` (permission 600, nama tak bisa ditebak), bukan `/tmp/hasil.txt` yang rentan *symlink attack*.
- Script audit **read-only** secara prinsip: melaporkan temuan, bukan langsung "memperbaiki" tanpa persetujuan.

---

## 3. Skenario Tantangan Praktis (Hands-On Labs)

Semua lab berjalan **lokal dan aman** di WSL2/Ubuntu. Data dan "malware" hanyalah file buatan sendiri. Jangan jalankan di server produksi. Kerjakan tugasnya dulu, baru lihat bagian *Kunci jawaban*.

| Lab | Skenario | Modul yang dipakai | Estimasi |
| --- | --- | --- | --- |
| **1** | Audit permission file sensitif dan token bocor | 1, 3 | 30 menit |
| **2** | Melacak proses mencurigakan dan koneksi tak dikenal | 2, 3, 4 | 45 menit |
| **3** | Membuat script health & security check | 3, 4, 5 | 60 menit |

### Lab 1: Audit Hak Akses File Sensitif & Token Bocor

**Cerita:** Anda mewarisi sebuah direktori deploy dari tim lain. Ada kecurigaan banyak secret tersimpan sembarangan dengan permission longgar. Tugas Anda: temukan, perbaiki, dan buktikan sudah bersih.

**Setup (menanam "kesalahan"):**

```bash
mkdir -p ~/lab1/{app,deploy,backup} && cd ~/lab1

echo 'DB_PASSWORD=Sup3rS3cret'                       > app/.env
echo 'token: ghp_abcdefghijklmnopqrstuvwxyz0123456789' > app/config.yml
echo 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'        > deploy/creds.sh
ssh-keygen -q -t ed25519 -N '' -f deploy/id_ed25519
cp app/.env backup/env.bak

chmod 777 app/.env
chmod 666 app/config.yml deploy/id_ed25519
chmod 644 deploy/creds.sh backup/env.bak

# binary SUID "nyasar" (butuh sudo)
cp /usr/bin/find ./myfind && sudo chown root:root ./myfind && sudo chmod u+s ./myfind
```

**Tugas:**

1. Temukan semua file yang bisa **ditulis oleh semua orang** (world-writable).
2. Temukan semua file yang bisa **dibaca oleh grup atau dunia** padahal berisi secret.
3. Cari secret (password, token GitHub, AWS key, private key) memakai `grep`.
4. Temukan binary SUID di `~/lab1`.
5. Perbaiki semuanya dengan prinsip *least privilege*.
6. Verifikasi bahwa tidak ada temuan tersisa.

**Kunci jawaban Lab 1** (kerjakan dulu, baru lihat):

```bash
# 1. World-writable
$ find ~/lab1 -type f -perm -o+w -ls
... -rwxrwxrwx ... /home/dev/lab1/app/.env
... -rw-rw-rw- ... /home/dev/lab1/app/config.yml
... -rw-rw-rw- ... /home/dev/lab1/deploy/id_ed25519

# 2. File yang terbuka untuk grup/dunia (selain .pub)
$ find ~/lab1 -type f -perm /077 ! -name '*.pub' -printf '%m %p\n'
777 /home/dev/lab1/app/.env
666 /home/dev/lab1/app/config.yml
666 /home/dev/lab1/deploy/id_ed25519
644 /home/dev/lab1/deploy/creds.sh
644 /home/dev/lab1/backup/env.bak
4755 /home/dev/lab1/myfind

# 3. Cari secret
$ grep -rnIE '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|password\s*=|BEGIN OPENSSH PRIVATE KEY)' ~/lab1
/home/dev/lab1/app/.env:1:DB_PASSWORD=Sup3rS3cret
/home/dev/lab1/app/config.yml:1:token: ghp_abcdefghijklmnopqrstuvwxyz0123456789
/home/dev/lab1/deploy/creds.sh:1:AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
/home/dev/lab1/deploy/id_ed25519:1:-----BEGIN OPENSSH PRIVATE KEY-----
/home/dev/lab1/backup/env.bak:1:DB_PASSWORD=Sup3rS3cret      # <-- secret terduplikasi di backup

# 4. SUID
$ find ~/lab1 -perm -4000 -type f
/home/dev/lab1/myfind

# 5. Perbaikan
$ chmod 600 app/.env app/config.yml deploy/id_ed25519 deploy/creds.sh backup/env.bak
$ chmod 700 app deploy backup
$ sudo rm ~/lab1/myfind                # binary SUID tidak punya alasan ada

# 6. Verifikasi (harus kosong)
$ find ~/lab1 -type f -perm /077 ! -name '*.pub'
$ find ~/lab1 -perm -4000
```

**Pertanyaan refleksi:**

- Mengapa mengubah permission **tidak cukup** jika token pernah terlihat orang lain? (*Jawab: token harus di-revoke dan di-rotate.*)
- Mengapa `backup/env.bak` termasuk temuan? (*Jawab: salinan secret memperbesar attack surface.*)
- Bagaimana mencegah ini terulang? (*Pre-commit hook secret scanner, `.gitignore`, secret manager, `umask 077` untuk user deploy.*)

**Cleanup:** `sudo rm -rf ~/lab1`

---

### Lab 2: Melacak Proses Mencurigakan & Koneksi Tak Dikenal

**Cerita:** Alert monitoring menyebut sebuah host memakai CPU 100% dan membuka koneksi keluar yang tidak dikenal. Anda menjadi *first responder*. Lab ini mensimulasikan "cryptominer" lengkap dengan persistensi cron.

**Setup (butuh 3 terminal):**

```bash
sudo apt install -y netcat-openbsd
```

Terminal A: "server C2" palsu

```bash
nc -lk 127.0.0.1 4444
```

Terminal B: menanam "malware"

```bash
cat > /tmp/.x <<'EOF'
#!/usr/bin/env bash
exec 3<>/dev/tcp/127.0.0.1/4444      # koneksi keluar ke "C2"
while :; do :; done                  # membakar CPU
EOF
chmod +x /tmp/.x
nohup /tmp/.x --pool fake >/dev/null 2>&1 &
(crontab -l 2>/dev/null; echo '@reboot /tmp/.x --pool fake') | crontab -
```

Terminal C: **Anda sebagai investigator.** Anggap Anda tidak tahu apa yang ditanam di Terminal B.

**Tugas (ikuti urutan IR: Identifikasi → Kumpulkan → Isolasi → Eradikasi → Verifikasi):**

1. **Identifikasi:** temukan proses dengan CPU tertinggi dan catat PID, user, parent, dan command line-nya.
2. **Jaringan:** temukan koneksi yang dimiliki PID itu (IP dan port tujuan).
3. **Verifikasi lewat `/proc`:** binary apa sebenarnya, working directory-nya, dan file descriptor apa yang terbuka?
4. **Persistensi:** cari mekanisme yang membuatnya hidup lagi (cron, systemd, file tersembunyi).
5. **Kontainmen & bukti:** bekukan proses, simpan bukti, baru hentikan.
6. **Eradikasi & verifikasi:** hapus semua jejak dan buktikan sistem bersih.

**Kunci jawaban Lab 2** (kerjakan dulu, baru lihat):

```bash
# 1. Identifikasi
$ ps -eo pid,ppid,user,%cpu,etime,cmd --sort=-%cpu | head -3
  PID  PPID USER  %CPU     ELAPSED CMD
 4120  3988 dev   99.8       02:10 /bin/bash /tmp/.x --pool fake

# 2. Jaringan
$ sudo ss -tnp | grep 4120
ESTAB 0 0 127.0.0.1:50122 127.0.0.1:4444 users:(("x",pid=4120,fd=3))
$ sudo lsof -nP -p 4120 -a -i
COMMAND PID USER FD TYPE NODE NAME
bash   4120  dev  3u IPv4 TCP 127.0.0.1:50122->127.0.0.1:4444 (ESTABLISHED)

# 3. /proc
$ sudo readlink /proc/4120/exe              # /usr/bin/bash
$ sudo readlink /proc/4120/cwd              # direktori awal malware
$ sudo tr '\0' ' ' < /proc/4120/cmdline; echo
/bin/bash /tmp/.x --pool fake
$ sudo ls -l /proc/4120/fd                  # fd 3 -> socket:[...]

# 4. Persistensi
$ crontab -l
@reboot /tmp/.x --pool fake                 # <-- persistensi
$ ls -la /tmp /dev/shm                      # file tersembunyi berawalan titik
$ systemctl list-timers --all

# 5. Kontainmen & bukti
$ mkdir -p ~/evidence
$ sudo kill -STOP 4120
$ cp /tmp/.x ~/evidence/x.sample && sha256sum ~/evidence/x.sample | tee ~/evidence/x.sha256
$ crontab -l > ~/evidence/crontab.txt
$ sudo ss -tnp > ~/evidence/ss.txt

# 6. Eradikasi & verifikasi
$ sudo kill -9 4120
$ rm -f /tmp/.x
$ crontab -l | grep -v '/tmp/.x' | crontab -
$ pgrep -af '/tmp/.x' || echo "bersih: proses"
$ crontab -l | grep -c '/tmp/.x' || echo "bersih: cron"
$ ss -tn | grep 4444 || echo "bersih: koneksi"
```

**Pertanyaan refleksi:**

- Mengapa `kill -STOP` sebelum `kill -9`? (*Memori dan state proses tetap tersedia untuk bukti.*)
- Apa yang terjadi jika hanya membunuh proses tanpa memeriksa cron? (*Proses hidup lagi setelah reboot.*)
- Di dunia nyata, apa langkah tambahan? (*Isolasi host dari jaringan, cari tahu vektor masuk lewat log, rotasi kredensial, dan rebuild host dari image bersih.*)

**Cleanup:** hentikan `nc` di Terminal A (`Ctrl+C`), lalu `rm -rf ~/evidence`.

---

### Lab 3: Script Health & Security Check

**Cerita:** Setiap server baru harus melewati pemeriksaan hardening dasar sebelum masuk produksi. Tugas Anda: buat script **read-only** yang memberi laporan `PASS / WARN / FAIL` dan exit code non-zero jika ada FAIL, sehingga bisa dipakai di pipeline CI/CD.

**Persyaratan:**

- Memakai `set -euo pipefail` dan `trap ERR`.
- Cek minimal: SSH (root login, password auth), firewall, port terekspos, akun UID 0 ganda, password kosong, permission `/etc/shadow`, `NOPASSWD` di sudoers, jumlah binary SUID, file world-writable di `/etc`, disk, load, dan percobaan login SSH gagal.
- Tidak mengubah apa pun di sistem.

**Solusi referensi** (simpan sebagai `security-check.sh`, lalu `chmod 700 security-check.sh && sudo ./security-check.sh`):

```bash
#!/usr/bin/env bash
# security-check.sh: health & security quick audit (READ-ONLY)
set -euo pipefail
IFS=$'\n\t'
trap 'echo "[ERROR] gagal di baris $LINENO" >&2' ERR

SUID_BASELINE=30      # sesuaikan dengan baseline server Anda
DISK_WARN=80

if [[ $EUID -ne 0 ]]; then
  echo "Jalankan dengan sudo: sudo $0" >&2
  exit 1
fi

PASS=0; WARN=0; FAIL=0
pass() { printf '[PASS] %s\n' "$1"; PASS=$((PASS+1)); }
warn() { printf '[WARN] %s\n' "$1"; WARN=$((WARN+1)); }
fail() { printf '[FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }

printf '== Security Check: %s @ %s ==\n' "$(hostname)" "$(date -Is)"

# --- SSH ---
sshd_opt() { sshd -T 2>/dev/null | awk -v k="$1" '$1==k {print $2}' || true; }
if command -v sshd >/dev/null 2>&1; then
  v=$(sshd_opt permitrootlogin)
  [[ "$v" == "no" ]] && pass "SSH: PermitRootLogin=no" || fail "SSH: PermitRootLogin=${v:-tidak terbaca}"
  v=$(sshd_opt passwordauthentication)
  [[ "$v" == "no" ]] && pass "SSH: PasswordAuthentication=no" || warn "SSH: PasswordAuthentication=${v:-tidak terbaca}"
else
  warn "sshd tidak terpasang, cek SSH dilewati"
fi

# --- Firewall (hindari 'cmd | grep -q' di bawah pipefail: bisa kena SIGPIPE) ---
if command -v ufw >/dev/null 2>&1; then
  out=$(ufw status 2>&1 || true)
  [[ "$out" == *"Status: active"* ]] && pass "ufw aktif" || fail "ufw tidak aktif"
else
  warn "ufw tidak terpasang"
fi

# --- Port terekspos ke semua interface ---
n=$(ss -tulnH | awk '$5 ~ /^(0\.0\.0\.0|\[::\]|\*):/ {n++} END{print n+0}')
if (( n <= 3 )); then
  pass "Listener terekspos: $n"
else
  warn "Listener terekspos: $n (periksa: ss -tulpn)"
fi

# --- Akun & kredensial ---
extra=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd)
[[ -z "$extra" ]] && pass "Tidak ada akun UID 0 selain root" || fail "Akun UID 0 ganda: $extra"

empty=$(awk -F: '$2=="" {print $1}' /etc/shadow)
[[ -z "$empty" ]] && pass "Tidak ada password kosong" || fail "Password kosong: $empty"

perm=$(stat -c '%a' /etc/shadow)
[[ "$perm" == "640" || "$perm" == "600" || "$perm" == "000" ]] \
  && pass "Permission /etc/shadow=$perm" || fail "Permission /etc/shadow=$perm"

np=$(grep -rhE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null || true)
[[ -z "$np" ]] && pass "Tidak ada NOPASSWD di sudoers" || warn "NOPASSWD ditemukan: $(printf '%s' "$np" | head -n1)"

# --- Filesystem ---
suid=$(find / -xdev -perm -4000 -type f 2>/dev/null | wc -l || true)
(( suid <= SUID_BASELINE )) && pass "Binary SUID: $suid" || warn "Binary SUID: $suid (> baseline $SUID_BASELINE)"

ww=$(find /etc -xdev -type f -perm -o+w 2>/dev/null || true)
[[ -z "$ww" ]] && pass "Tidak ada file world-writable di /etc" || fail "World-writable di /etc: $(printf '%s' "$ww" | head -n3 | tr '\n' ' ')"

# --- Kesehatan sistem ---
disk=$(df --output=pcent / | tail -n1 | tr -dc '0-9')
(( disk < DISK_WARN )) && pass "Disk / terpakai ${disk}%" || warn "Disk / terpakai ${disk}%"

load=$(awk '{print $1}' /proc/loadavg); cores=$(nproc)
awk -v l="$load" -v c="$cores" 'BEGIN{exit !(l < c)}' \
  && pass "Load $load (< $cores core)" || warn "Load $load tinggi untuk $cores core"

# --- Indikator serangan ---
if command -v journalctl >/dev/null 2>&1; then
  failed=$(journalctl -u ssh --since '1 hour ago' --no-pager 2>/dev/null | grep -c 'Failed password' || true)
  failed=${failed:-0}
  (( failed < 10 )) && pass "Login SSH gagal 1 jam terakhir: $failed" || warn "Login SSH gagal 1 jam terakhir: $failed (kemungkinan brute force)"
fi

dpkg -s unattended-upgrades >/dev/null 2>&1 \
  && pass "unattended-upgrades terpasang" || warn "unattended-upgrades belum terpasang"

printf '\n== Ringkasan: PASS=%d WARN=%d FAIL=%d ==\n' "$PASS" "$WARN" "$FAIL"
if (( FAIL > 0 )); then exit 1; fi
```

**Contoh output yang diharapkan:**

```text
== Security Check: wsl-lab @ 2026-11-01T11:05:42+07:00 ==
[FAIL] SSH: PermitRootLogin=prohibit-password
[WARN] SSH: PasswordAuthentication=yes
[FAIL] ufw tidak aktif
[PASS] Listener terekspos: 1
[PASS] Tidak ada akun UID 0 selain root
[PASS] Tidak ada password kosong
[PASS] Permission /etc/shadow=640
[PASS] Tidak ada NOPASSWD di sudoers
[PASS] Binary SUID: 22
[PASS] Tidak ada file world-writable di /etc
[PASS] Disk / terpakai 12%
[PASS] Load 0.15 (< 8 core)
[PASS] Login SSH gagal 1 jam terakhir: 0
[WARN] unattended-upgrades belum terpasang

== Ringkasan: PASS=10 WARN=2 FAIL=2 ==
```

Uji pula status exit-nya: `sudo ./security-check.sh; echo "exit=$?"` (akan `1` jika ada FAIL).

**Hal yang sengaja dipraktikkan di script ini:**

- Variabel dikutip dan `set -u` mencegah variabel kosong lolos.
- `|| true` hanya dipakai di tempat "tidak ada hasil" adalah kondisi normal, bukan untuk membungkam error sembarangan.
- Tidak memakai `cmd | grep -q` di bawah `pipefail` karena `grep -q` menutup pipa lebih awal dan bisa menyebabkan *false failure* (SIGPIPE).
- Tidak memakai `((x++))` karena bisa mengembalikan status 1 dan mematikan script di bawah `-e`.
- Script bersifat **read-only**, jadi aman dijalankan berulang.

**Tantangan lanjutan:**

1. Tambahkan flag `--json` untuk keluaran mesin yang bisa dibaca SIEM atau pipeline.
2. Tambahkan cek: `PermitEmptyPasswords`, kernel parameter (`sysctl net.ipv4.conf.all.rp_filter`), dan paket dengan update keamanan tertunda.
3. Jalankan harian lewat **systemd timer** dan kirim hasil ke file log berizin `600`.
4. Lulus `shellcheck security-check.sh` tanpa peringatan.

---

## 4. Cheatsheet & Best Practices

### 4.1 One-Liner Audit Cepat

**Identitas & akses**

```bash
find / -xdev -perm -4000 -type f 2>/dev/null                       # semua binary SUID
find / -xdev -type f -perm -o+w 2>/dev/null                        # file world-writable
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null                  # file yatim tanpa pemilik
awk -F: '$3==0{print $1}' /etc/passwd                              # akun UID 0
sudo awk -F: '$2==""{print $1}' /etc/shadow                        # password kosong
sudo grep -rhE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/       # sudo tanpa password
getent group sudo                                                  # siapa saja admin
last -n 20; sudo lastb -n 20                                       # login sukses / gagal terakhir
w                                                                  # siapa login & sedang apa
```

**Jaringan**

```bash
sudo ss -tulpn                                                     # semua listener + proses
sudo ss -tnp state established                                     # koneksi aktif + proses
sudo ss -tn state established | awk 'NR>1{print $4}' | sed 's/:[0-9]*$//' | sort | uniq -c | sort -rn | head   # top IP lawan bicara
sudo lsof -nP -iTCP -sTCP:LISTEN                                   # listener TCP (alternatif)
sudo iptables -L -n -v --line-numbers; sudo ufw status numbered    # aturan firewall
sudo tcpdump -i any -nn -c 50 'not port 22'                        # sampel trafik non-SSH
curl -sSI https://domain | grep -iE 'strict-transport|x-frame|content-security|x-content-type'
dig +short A domain; dig +short TXT domain; dig -x IP +short       # investigasi DNS
```

**Log & threat hunting**

```bash
sudo grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head   # top penyerang SSH
sudo grep 'Accepted' /var/log/auth.log | awk '{print $9, $11}' | sort | uniq -c                           # siapa berhasil masuk dari mana
sudo grep -E 'sudo:.*COMMAND' /var/log/auth.log | tail -20                                               # aktivitas sudo terbaru
sudo zgrep -h 'Failed password' /var/log/auth.log*                                                       # termasuk log terarsip
sudo journalctl -p err..alert -b --no-pager                                                              # error serius sejak boot
sudo journalctl -u ssh --since today --no-pager | grep -c 'Failed'                                       # hitung kegagalan SSH hari ini
sudo find /etc /usr/local /var/spool/cron -type f -mtime -1                                              # file penting yang baru berubah
sudo find / -xdev -type f -newermt "2026-11-01" ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -50  # perubahan sejak tanggal tertentu
```

**Proses & persistensi**

```bash
ps -eo pid,ppid,user,%cpu,%mem,etime,cmd --sort=-%cpu | head       # pemakai CPU teratas
ps -ef --forest                                                    # pohon proses (cari parent aneh)
sudo ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E '\(deleted\)|/tmp/|/dev/shm/'   # binary dari lokasi mencurigakan
sudo lsof +L1                                                      # file dihapus tapi masih berjalan
systemctl list-unit-files --state=enabled --type=service           # service yang auto-start
systemctl list-timers --all                                        # timer terjadwal
crontab -l; sudo ls -la /etc/cron.* /var/spool/cron/crontabs 2>/dev/null   # cron job
systemctl --failed                                                 # service gagal
```

**Pencarian secret & integritas**

```bash
grep -rnIE '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|password\s*[=:])' . --exclude-dir=.git
git log -p -S'password' --all                                      # secret di riwayat Git
env | grep -iE 'key|token|secret|pass'                             # secret di environment
history | grep -iE 'password|token|secret'                         # secret di history shell
sudo dpkg -V 2>/dev/null | grep -v ' c '                            # file paket yang dimodifikasi (selain konfigurasi)
sha256sum file                                                     # hash untuk bukti & verifikasi
```

**Pengumpulan bukti**

```bash
sudo kill -STOP PID                                                # bekukan, jangan langsung bunuh
sudo cp /proc/PID/exe ./evidence/sample.bin                        # selamatkan binary (bahkan yang dihapus)
sudo tr '\0' ' ' < /proc/PID/cmdline; sudo ls -l /proc/PID/fd       # command line & file descriptor
sudo ss -tnp > ./evidence/ss.txt; ps auxf > ./evidence/ps.txt      # snapshot jaringan & proses
sha256sum ./evidence/* > ./evidence/SHA256SUMS                     # segel integritas bukti
```

### 4.2 Urutan Respons Insiden (Ringkas)

1. **Identifikasi:** apa yang aneh, di host mana, sejak kapan?
2. **Kumpulkan bukti volatil dulu:** proses, koneksi, memori (`/proc`) sebelum hilang.
3. **Kontainmen:** bekukan proses atau blokir IP, isolasi host bila perlu.
4. **Eradikasi:** hapus malware **dan** persistensinya (cron, systemd, SSH `authorized_keys`, akun baru).
5. **Pemulihan:** rotasi semua secret yang mungkin terekspos. Pertimbangkan *rebuild* dari image bersih.
6. **Pelajaran:** catat timeline, akar masalah, dan perbaikan pencegahan.

### 4.3 Best Practices

- **Least privilege di setiap lapisan:** user non-root, `sudoers` spesifik, `NoNewPrivileges`, `umask 027`, firewall default-deny.
- **Baseline lalu bandingkan:** simpan daftar SUID, listener, service enabled, dan cron saat kondisi sehat; `diff` secara berkala.
- **Jangan mengubah bukti:** kerjakan pada salinan, catat hash, dan jangan edit log asli.
- **Secret tidak pernah di kode, argumen CLI, atau history:** pakai secret manager dan environment runtime; scan repo secara otomatis.
- **Uji sebelum menerapkan perubahan akses:** `sshd -t`, `visudo -c`, dan selalu pertahankan satu sesi terbuka saat mengubah SSH atau firewall.
- **Script defensif:** `set -euo pipefail`, kutip variabel, `mktemp`, `shellcheck`, dan pisahkan mode *audit* (read-only) dari mode *fix*.
- **Verifikasi hasil, bukan asumsi:** setelah memperbaiki, jalankan ulang perintah pendeteksi dan pastikan hasilnya kosong.
- **Ingat batasan alat:** `ps`/`top` bisa dikelabui rootkit, `2>/dev/null` bisa menyembunyikan kegagalan, dan firewall host bisa dilewati Docker.
- **Otomatiskan yang berulang:** ubah checklist manual menjadi script, lalu jadwalkan lewat systemd timer atau pipeline CI.

### 4.4 Rencana Belajar 4 Minggu (Saran)

| Minggu | Fokus | Output |
| --- | --- | --- |
| 1 | Modul 1 + Lab 1 | Bisa mengaudit permission dan SSH hardening |
| 2 | Modul 2 + 3 | Bisa memetakan port dan memburu anomali di log |
| 3 | Modul 4 + Lab 2 | Bisa menginvestigasi dan menangani proses jahat |
| 4 | Modul 5 + Lab 3 | Punya script audit sendiri yang lulus `shellcheck` |

**Langkah lanjut:** pelajari `auditd`, `fail2ban`, AppArmor, `nftables`, Lynis (`sudo apt install lynis && sudo lynis audit system`), dan integrasikan script Lab 3 ke pipeline CI/CD.
