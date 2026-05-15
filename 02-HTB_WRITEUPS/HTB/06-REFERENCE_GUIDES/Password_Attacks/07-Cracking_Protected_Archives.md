# 07 — Cracking Protected Archives

## Overview

Archives consolidate multiple files into one — and are often password-protected. Different archive types require different extraction tools and cracking approaches. This section covers ZIP, OpenSSL-encrypted GZIP, and BitLocker-encrypted drives.

---

## Common Archive Types

| Extension | Notes |
|-----------|-------|
| `.zip` | Native password support, most common |
| `.rar` | Native password support |
| `.7z` | Native password support |
| `.tar.gz` / `.gzip` | No native password — encrypted via `openssl` or `gpg` |
| `.vhd` / `.vhdx` | BitLocker-encrypted virtual drives |
| `.kdbx` | KeePass database |
| `.deb` | Debian package |
| `.vmdk` / `.vmx` | VMware disk images |

```bash
# Scrape all known archive extensions from FileInfo
curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt
```
> Fetches the FileInfo compressed types page, converts HTML to text, lowercases, and filters for lines with dots (file extensions). Saves to a file with `tee`. Useful for building a comprehensive extension list.

---

## Cracking ZIP Files

```bash
# Extract hash
zip2john ZIP.zip > zip.hash

# Crack
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash

# View result
john zip.hash --show
# ZIP.zip/customers.csv:1234
```
> `zip2john` extracts a crackable hash from the ZIP's encryption header. Crack with JtR, then display results with `--show`. Use the recovered password to open the ZIP with `unzip -P <password> ZIP.zip`.

---

## Cracking OpenSSL-Encrypted GZIP Files

### Identify the Format

```bash
file GZIP.gzip
# GZIP.gzip: openssl enc'd data with salted password
```
> The `file` command reads the magic bytes to identify the true format. "openssl enc'd data with salted password" means it was encrypted with `openssl enc`, not standard gzip compression.

> `file` command reveals it's OpenSSL-encrypted, not a standard gzip.

### Brute-Force with Loop

JtR can produce false positives on OpenSSL files. A more reliable approach is to attempt decryption directly:

```bash
for i in $(cat rockyou.txt); do
  openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null | tar xz
done
```
> Tries every password in rockyou.txt as the AES-256-CBC decryption key. Wrong passwords produce errors (suppressed by `2>/dev/null`). The correct password silently extracts the tarball. Check the directory afterward for new files.

- Ignore `gzip: stdin: not in gzip format` errors — they mean wrong password
- When the correct password is found, the file extracts silently
- Check current directory for newly extracted files after completion

```bash
ls
# customers.csv  GZIP.gzip  rockyou.txt
```
> Confirms the extracted file appeared. Run this after the brute-force loop completes to see what was extracted.

---

## Cracking BitLocker-Encrypted Drives

### Extract Hashes

```bash
# Extract all 4 hashes (2 password + 2 recovery key)
bitlocker2john -i Backup.vhd > backup.hashes

# Filter for password hash only ($bitlocker$0$...)
grep "bitlocker\$0" backup.hashes > backup.hash
```
> `bitlocker2john` extracts four hashes from the BitLocker header. Only the `$bitlocker$0$` (password) hashes are worth cracking. Filter them out with `grep` to avoid wasting time on the 48-digit recovery key hashes.

| Hash Prefix | Type | Crackable? |
|-------------|------|------------|
| `$bitlocker$0$` | Password hash | Yes — target this |
| `$bitlocker$1$` | Recovery key hash | Impractical (48-digit random) |

### Crack with Hashcat

```bash
hashcat -a 0 -m 22100 backup.hash /usr/share/wordlists/rockyou.txt
```
> `-m 22100` is BitLocker. Very slow due to AES encryption with high iteration count. Expect ~25–200 H/s on CPU. Use GPU if available. Targeted wordlists are essential here.

| Detail | Value |
|--------|-------|
| Hashcat mode | `-m 22100` |
| Encryption | AES 128/256-bit |
| Speed | Very slow (~25 H/s on CPU) |

### Mount on Windows

1. Double-click the `.vhd` file (initial error is normal — it mounts anyway)
2. Double-click the BitLocker volume in File Explorer
3. Enter the cracked password when prompted

### Mount on Linux

```bash
# Install dislocker
sudo apt-get install dislocker

# Create mount points
sudo mkdir -p /media/bitlocker
sudo mkdir -p /media/bitlockermount

# Set up loop device, decrypt, and mount
sudo losetup -f -P Backup.vhd
sudo dislocker /dev/loop0p2 -u<password> -- /media/bitlocker
sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount

# Browse files
ls -la /media/bitlockermount/

# Unmount when done
sudo umount /media/bitlockermount
sudo umount /media/bitlocker
```
> `losetup -f -P` attaches the VHD as a loop device and creates partition entries. `dislocker` decrypts the BitLocker partition into `/media/bitlocker/dislocker-file`. Then `mount -o loop` mounts that decrypted image. Check with `ls /dev/loop0*` first to find the correct partition (p1 or p2).

---

## Cracking Method Summary

| Archive Type | Hash Tool | Crack Tool | Notes |
|-------------|-----------|------------|-------|
| ZIP | `zip2john` | JtR / hashcat (`-m 17200`) | Fast, common |
| RAR | `rar2john` | JtR / hashcat | Similar workflow |
| 7-Zip | `7z2john.pl` | JtR / hashcat | Similar workflow |
| OpenSSL GZIP | N/A | `for` loop with `openssl` | Direct decryption attempts |
| BitLocker | `bitlocker2john` | hashcat (`-m 22100`) | Very slow — AES |
| KeePass | `keepass2john` | JtR / hashcat | High-value target |

---

## Exercise: Cracking a BitLocker-Encrypted VHD

**File**: `cracking-protected-archives.zip` → contains `Private.vhd` (BitLocker-encrypted)

### Step 1: Extract the ZIP

```bash
unzip cracking-protected-archives.zip
# inflating: Private.vhd
```
> Extracts the unencrypted outer ZIP to get the VHD file inside. The BitLocker encryption is on the VHD, not the ZIP container.

### Step 2: Extract BitLocker hashes

```bash
bitlocker2john -i Private.vhd > bitlocker.hashes

# Filter for password hash only (not recovery key)
grep "bitlocker\$0" bitlocker.hashes > bitlocker.hash
```
> Extracts all BitLocker hashes from the VHD, then filters down to just the password hash. The filtered file is what you feed to hashcat.

### Step 3: Crack with hashcat

```bash
hashcat -a 0 -m 22100 bitlocker.hash /usr/share/wordlists/rockyou.txt
```
> Cracks the BitLocker password hash. Took ~14 seconds for `francisco` — a simple rockyou word. Complex passwords would require days.

```
$bitlocker$0$16$b3c105c7ab7faaf544e84d712810da65$...:francisco

Status...........: Cracked
Speed.#01........:      190 H/s
Time: ~14 seconds
```

**Answer: `francisco`**

> **Lesson**: BitLocker cracking is slow (~190 H/s on CPU) due to AES + 1M iterations, but weak passwords in rockyou still fall quickly. Always filter for `$bitlocker$0$` — the recovery key hashes are impractical to crack.

### Step 4: Mount the decrypted VHD and get the flag

```bash
# Install dislocker
sudo apt-get install -y dislocker

# Create mount points
sudo mkdir -p /media/bitlocker /media/bitlockermount

# Set up loop device (note: partition was p1, not p2 on this VHD)
sudo losetup -f -P Private.vhd
losetup -l | grep Private
# /dev/loop0  ...  /tmp/Private.vhd

# Check partitions
ls /dev/loop0*
# /dev/loop0  /dev/loop0p1

# Decrypt with cracked password
sudo dislocker /dev/loop0p1 -ufrancisco -- /media/bitlocker

# Mount decrypted volume
sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount

# Read the flag
cat /media/bitlockermount/flag.txt
# 43d95aeed3114a53ac66f01265f9b7af

# Cleanup
sudo umount /media/bitlockermount
sudo umount /media/bitlocker
sudo losetup -d /dev/loop0
```
> Full Linux mount chain: attach VHD as loop device, identify the partition number, decrypt with dislocker using `-u<password>` (no space), mount the resulting dislocker-file, read files, then unmount and detach everything.

**Flag: `43d95aeed3114a53ac66f01265f9b7af`**

> **Note**: The partition was `/dev/loop0p1` (not `p2` as in the module example). Always check with `ls /dev/loop0*` to find the correct partition.

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **`file` command reveals true format** | OpenSSL-encrypted files look like regular archives |
| **Not all archives support native passwords** | TAR/GZIP use external tools (openssl, gpg) |
| **ZIP cracking is fast** | `zip2john` + JtR handles most cases instantly |
| **OpenSSL = brute-force with loop** | JtR gives false positives; direct decryption is more reliable |
| **BitLocker = very slow cracking** | AES + high iteration count; target password hash, not recovery key |
| **`dislocker` for Linux mounting** | `losetup` → `dislocker` → `mount` pipeline |
| **Always `grep "bitlocker\$0"`** | Filter for password hash, skip recovery key hashes |
