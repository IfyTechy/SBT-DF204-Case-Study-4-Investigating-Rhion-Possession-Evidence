# SBT-DF204 Case Study 4: Investigating Rhino Possession Evidence

**Student:** Nebeuwa Ifeanyichukwu Raphael
**Registration number:** 202520850LE

> **Status:** Examination complete (Q1–Q8). Full Word report also available: `SBTDF204_CaseStudy4_202520850LE.docx`.

I investigate a simulated possession case from the DFRWS 2005 "Rhino Hunt" challenge (NIST CFReDS). The evidence is a seized USB image (`RHINOUSB.dd`) and three network captures (`rhino.log`, `rhino2.log`, `rhino3.log`). In the scenario, possessing nine or more *unique* rhinoceros images is a crime. I document every command and result so anyone can reproduce my work, and I keep observations separate from interpretations throughout.

## Handling of illegal content

- I do not publish evidence images, the disk image, packet captures, or screenshots that show images.
- I redact passwords and credentials in this repository and in every screenshot (marked `REDACTED`).
- I did not execute `rhino.exe`, connect to any address found in it, or submit any hash to an online scanner.
- I plan to shred the recovered images only after my work is assessed: `shred -vzn 3 <file>`.

## Progress

| Stage | Status |
|---|---|
| Evidence preservation | Done |
| Disk-image analysis | Done |
| File recovery with PhotoRec | Done |
| Steganography | Done |
| FTP capture and protected zip | Done |
| HTTP captures | Done |
| Timeline, correlation and conclusion | Done |
| Final report (Word) | Done |

## Environment and tools

I work in a Kali Linux (rolling) virtual machine. I record every tool version I use.

- The Sleuth Kit (`mmls`, `img_stat`, `fsstat`, `fls`, `istat`, `icat`, `blkls`, `blkstat`), `dd`, `xxd`, `file`, `sha256sum`, `md5sum`, `fdisk`
- PhotoRec 7.2 (February 2024)
- ExifTool 13.50, ImageMagick `montage`, Eye of GNOME (`eog`), `jpeginfo`
- stegdetect and stegbreak 0.6.1 (commit `46a09e93320cd63b6731e0bc5b22c11c588a0e81`)
- jpseek 0.51 (jphs 0.5) running under Wine
- `fcrackzip`
- Wireshark and `tshark`

## Folder layout

```
~/case4/
├── original/     # downloaded zip (read-only)
├── working/      # extracted evidence copies (read-only)
├── evidence/     # command outputs, hashes and logs (published, redacted)
├── recovered/    # PhotoRec output (recup_dir.1, recup_dir.2)
├── analysis/     # copies of recovered images, contact sheet
├── steg/         # steganography working copies and extractions
├── ftp/          # files rebuilt from the FTP capture
├── tools/        # stegdetect, jphs tools
└── screenshots/
```

## 1. Evidence preservation (Q1)

I created the folders and recorded the session start in UTC:

```bash
mkdir -p ~/case4/{original,working,evidence,screenshots}
date -u | tee ~/case4/evidence/session_start_utc.txt
```
Session start: **2026-10-25 10:35:21 UTC**.

I searched for any pre-existing copies, downloaded the course package, and hashed it before touching it:

```bash
find ~ -iname "*rhino*" -o -iname "*RODEO*" 2>/dev/null
wget https://raw.githubusercontent.com/frankwxu/digital-forensics-lab/main/Illegal_Possession_Images/USB_image/DFRWS2005-RODEO.zip
sha256sum DFRWS2005-RODEO.zip | tee ../evidence/hashes_original.txt
md5sum DFRWS2005-RODEO.zip >> ../evidence/hashes_original_md5.txt
chmod 444 DFRWS2005-RODEO.zip
```
Saved: 3,614,418 bytes at 06:40:44 -0400 (10:40:44 UTC).

I extracted into `working/`, hashed the contents, and set everything read-only:

```bash
cd ~/case4/working
unzip ../original/DFRWS2005-RODEO.zip
sha256sum RHINOUSB.dd rhino.log rhino2.log rhino3.log | tee ../evidence/hashes_working_sha256.txt
md5sum RHINOUSB.dd rhino.log rhino2.log rhino3.log | tee ../evidence/hashes_working_md5.txt
chmod 444 RHINOUSB.dd rhino.log rhino2.log rhino3.log
```

I compared the MD5 values with a published reference list: all four matched `OK`.

| File | Size (bytes) | SHA-256 |
|---|---|---|
| `DFRWS2005-RODEO.zip` | 3,614,418 | `e83459a800baed6a3c37551d413ab59fe8dac54c879ed5408001cfed171a0aaa` |
| `RHINOUSB.dd` | 259,506,176 | `ce550424200a997c61b413941c8ef4df9619a2f96579674952294a176a32be65` |
| `rhino.log` | 3,187,907 | `64e6d55b76660eb3aaa41572c1d04e4452510a343bbf42e844424827dedfddb2` |
| `rhino2.log` | 292,604 | `41939d5de0556b70279056572dee44b6fd84cd05b0788cfd0b6f52f37b161dde` |
| `rhino3.log` | 226,094 | `7b0304f5e88a30c305a99b5a1e2977bced5b9c94da6f458f887bb39966bbfc46` |

## 2. Disk-image analysis (Q2)

```bash
file RHINOUSB.dd
mmls RHINOUSB.dd; echo "exit: $?"
fdisk -l RHINOUSB.dd
img_stat RHINOUSB.dd
fsstat RHINOUSB.dd
fls -r -p RHINOUSB.dd
fls -r -d -p RHINOUSB.dd
istat RHINOUSB.dd 4
istat RHINOUSB.dd 6
icat RHINOUSB.dd 4
icat RHINOUSB.dd 6
```

**Observations**

- 259,506,176 bytes = 506,848 sectors of 512 bytes.
- `mmls` prints nothing and exits 1; `fdisk -l` shows a "dos" label with identifier `0x00000000` and no partitions. `fsstat` reports 0 sectors before the file system, so this is a single FAT16 volume starting at sector 0 with no partition table.
- FAT16, OEM `mkdosfs`, volume ID `0x4092d9d1`, no label. FAT1: sectors 1–248; FAT2: 249–496; root directory: 497–528; cluster area: 529–506840 (4,096-byte clusters).
- Only two allocated files: `gumbo1.txt` (2,815 bytes, entry 4) and `gumbo2.txt` (1,293 bytes, entry 6), both recipes, written 2004-04-30 18:11:20 and 18:11:24.
- `fls -d` found no deleted directory entries.
- Unallocated space: 259,227,136 bytes, of which 201,794,898 bytes are non-zero (volume was not wiped).

## 3. File recovery with PhotoRec (Q3)

```bash
photorec /log /d ~/case4/recovered/ ~/case4/working/RHINOUSB.dd
```

I selected the whole-disk FAT16 partition and file-system type "Other."

**Observations**

- I ran PhotoRec twice (`recup_dir.1`, `recup_dir.2`); the two runs are identical except for PhotoRec's own `report.xml`. I treat `recup_dir.1` as primary.
- Each run carved 132 files: 122 txt, 7 jpg, 2 gif, 1 doc.
- 133 unique hashes across both runs (131 unique carved contents). One duplicate pair: `f0105873.jpg` = `f0335081.jpg` (264,600 bytes, identical SHA-256).
- Every carved image header verified at its start-sector offset in the original image (`FFD8FFE0` for JPEG, `GIF8` for GIF), and `blkstat` confirms all nine start sectors are **Not Allocated**.

| File | Start sector | Size (bytes) | Type |
|---|---|---|---|
| `f0104057.jpg` | 104057 | 95,814 | JPEG 528×792 |
| `f0104249.jpg` | 104249 | 415,534 | JPEG 1349×900 |
| `f0105065.jpg` | 105065 | 411,361 | JPEG 1686×1122 |
| `f0105873.jpg` | 105873 | 264,600 | JPEG 1024×768 |
| `f0106393.jpg` | 106393 | 6,809 | JPEG 169×228 |
| `f0106409.jpg` | 106409 | 230,665 | JPEG 1024×685 |
| `f0106865.gif` | 106865 | 11,407 | GIF 290×246 |
| `f0106889.gif` | 106889 | 4,105 | GIF 150×87 |
| `f0335081.jpg` | 335081 | 264,600 | JPEG 1024×768 (= `f0105873.jpg`) |

**Carved Word document.** Title "She died in February at the age of 74", company "University of New Orleans", internal dates in August 2005. Body text (claims only, not verified) mentions rhino photos, "zapping" a hard drive into the Mississippi River, planning to reformat a USB key, and a "gnome" account.

**Large filler files.** `f0106905.txt` (116,793,344 bytes, repeating "CHARLIE") and `f0000545.txt` (52,998,144 bytes, repeating "SORRY") account for most of the non-zero unallocated space. A keyword search (`password|ftp|gnome|steg|hide|jpg`) across the carved text files found nothing.

## 4. Steganography (Q4)

I built stegdetect from source (commit `46a09e93320cd63b6731e0bc5b22c11c588a0e81`). The current compiler defaults to C23, where `false` is reserved and stegdetect uses it as a variable name — fixed by passing old-C flags to `make` itself:

```bash
linux32 make CFLAGS="-std=gnu89 -fcommon -g -O2 -Wno-error=implicit-function-declaration -Wno-error=int-conversion -Wno-error=incompatible-pointer-types"
./stegdetect -V   # Stegdetect Version 0.6.1
./stegdetect ~/case4/steg/*.jpg
./stegdetect -s 3 ~/case4/steg/*.jpg
```

| File | Default | `-s 3` | stegbreak | Extraction |
|---|---|---|---|---|
| `f0104057.jpg` | negative | negative | not tested | n/a |
| `f0104249.jpg` | jphide(\*) | jphide(\*\*\*) | password found (withheld) | valid JPEG |
| `f0105065.jpg` | skipped | skipped | password found (withheld) | valid JPEG |
| `f0105873.jpg` (=`f0335081.jpg`) | negative | jphide(\*) | inconclusive (crash) | n/a |
| `f0106393.jpg` | negative | negative | not tested | n/a |
| `f0106409.jpg` | negative | jphide(\*) | inconclusive (crash) | n/a |

I cracked passphrases with `stegbreak` and Kali's `rockyou.txt`. The main run found two hits, then crashed (segfault); I re-ran the two remaining candidates separately and both crashed again (exit 139). I confirmed the two hits were real with a two-word verification list, which completed cleanly (`Processed 2 files, found 2 embeddings.`).

I extracted with `jpseek.exe` under Wine (needs `wine32:i386`):

```bash
wine jpseek.exe f0104249.jpg out_f0104249.jpg   # prompts for passphrase
wine jpseek.exe f0105065.jpg out_f0105065.jpg
```

| Extracted file | Type | SHA-256 |
|---|---|---|
| `out_f0104249.jpg` | JPEG 384×256, Exif "ACD Systems Digital Imaging", 2005:08:08 21:04:10 — shows three rhinoceroses | `6dbf775b8999a006ffa74c65127e5add64234184bd2f425b2ad644e8c0d19345` |
| `out_f0105065.jpg` | JPEG 400×340, NIKON E950, 2005:08:08 21:05:43 — close-up of a rhinoceros head | `bc9c605372fdf9cc00faf17ae9ce0fdb6d26bb9db28cdff742d9ddbe1470ec16` |

Neither extracted image matches any image recovered from disk, and all seven carrier files re-verified unchanged.

## 5. FTP capture: `rhino.log` (Q5)

Three FTP logins as account **gnome** from `137.30.122.253` to `137.30.120.40`:

| Session | Control / data stream | File uploaded | STOR time (UTC) | 226 time (UTC) | Bytes |
|---|---|---|---|---|---|
| 1 | 69 / 1657 | `rhino1.jpg` | 2004-04-26 22:21:49.954 | 22:21:50.180 | 65,703 |
| 2 | 72 / 1660 | `rhino3.jpg` (ASCII mode — bare-linefeed warning) | 2004-04-26 22:22:08.906 | 22:22:09.040 | 96,899 |
| 3 | 305 / 307 | `contraband.zip` | 2004-04-26 22:26:46.672 | 22:26:46.877 | 230,566 |

`STOR` = client uploads to server. The server's reported byte counts match the files I rebuilt for sessions 1 and 3. `rhino1.jpg` and `rhino3.jpg` were validated: correct headers/trailers, `jpeginfo -c` reports both `OK`.

## 6. Protected archive: `contraband.zip` (Q6)

Rebuilt from data stream 307 with `tshark follow,tcp,raw`: 230,566 bytes, SHA-256 `b7091a0b4295a561bf76969073ede126a5ca75899bb115447e67272f95d5a29f`. Structure validated: local-header signature present, end-of-central-directory record at the expected offset (230,544), one entry (`rhino2.jpg`, encrypted — flag bit 0 set).

```bash
sha256sum /usr/share/wordlists/rockyou.txt
date -u
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt contraband.zip
date -u
```
Run completed in 13 seconds (11:03:04 to 11:03:05 UTC). Password found (withheld in this repository).

```bash
unzip -P '<password>' contraband.zip -d ~/case4/evidence/contraband_extracted
```

Extracted `rhino2.jpg`: JPEG 1024×685, zip-internal timestamp 2004-04-26 17:00:12 (no time zone).

**Cross-match.** `rhino2.jpg`'s SHA-256 (`b4f6bbb8d846d6505c9b5b87f115656fdf980a484aa441078a838a3ffc2ac705`) is identical to the disk-carved `f0106409.jpg`. Same content in two independent evidence sources — this does not establish which was the original.

## 7. HTTP captures (Q7)

### `rhino2.log`

13 HTTP GET requests, all from client `137.30.123.234`, mostly to `www.cs.uno.edu` (`/~gnome/...`). Two image objects retrieved:

| File | Time (UTC) | Size | Type |
|---|---|---|---|
| `rhino4.jpg` | 2004-04-28 21:08:38.073 | 153,191 bytes | JPEG 1531×2286, comment "U-Lead Systems, Inc." — a surrealist painting containing a rhinoceros as one element among other symbolic figures |
| `rhino5.gif` | 2004-04-28 21:08:44.189 | 85,137 bytes | GIF 400×275 — a graphite sketch of an origami-style rhinoceros, signed "K." |

Both validated against Content-Length, correct headers/trailers. SHA-256 comparison against every other image source (disk, steganography, FTP) found **no match**. I confirmed both by opening each directly in `eog`.

### `rhino3.log`

Same client searches Google for **"rhino.exe"** at 21:15:48 UTC, then Google Groups for the same term at 21:15:55 UTC, then (35 seconds after the first search) requests `/~gnome/rhino.exe` at 21:16:23.343 UTC — a `200 application/octet-stream` reply of **145,920 bytes** at 21:16:24.214 UTC.

```bash
tshark -r rhino3.log -q --export-objects http,./http3_objects
cd http3_objects
file rhino.exe
sha256sum rhino.exe
xxd rhino.exe | head -2
xxd rhino.exe | tail -2
strings -n 8 rhino.exe | head -30
```

**Static-check results.** `file` identifies it as a **PE32 executable for MS Windows 4.00 (console), Intel i386, 3 sections** — a genuine Windows program, not a renamed image. It begins with `4D5A` ("MZ") and ends in zero padding, consistent with a complete file. `strings` shows links to standard Windows DLLs (`KERNEL32.dll`, `USER32.dll`, `ADVAPI32.dll`, `RPCRT4.dll`, `ole32.dll`, `SETUPAPI.dll`) and `mscoree.dll` (the .NET/CLR loader), plus generic C-runtime error strings. SHA-256: `93e70049b60bf5691b43d9e256ca8f459f6bfac832097985bcc6a9040b5ca555`.

I did **not** execute `rhino.exe`, connect to any address in it, or submit its hash to an online service.

## 8. Correlation, timeline and conclusion (Q8)

**Master image hash table:** 16 image files across all sources → **14 unique hashes**. Duplicates: `f0105873.jpg` = `f0335081.jpg` (disk), and `f0106409.jpg` (disk) = `rhino2.jpg` (FTP archive).

**Visual count:** I viewed every one of the 14 unique images directly and confirmed **10 depict a rhinoceros**: 6 on the USB image alone (4 carved + 2 steganographically hidden), 2 new from FTP uploads, and 2 new from HTTP downloads (including `rhino4.jpg`, a painting rather than a photograph).

| Source | Unique rhinoceros images | Running total |
|---|---|---|
| USB image, carved | 4 | 4 |
| USB image, steganography | 2 | **6 on the USB image alone** |
| FTP uploads | 2 | 8 |
| HTTP downloads | 2 | **10 in total** |

**Timeline (UTC except where noted):**

| Time | Event |
|---|---|
| 2004-04-26 22:21:49 – 22:26:48 | Three FTP uploads as "gnome": rhino1.jpg, rhino3.jpg, contraband.zip |
| 2004-04-28 21:08:38 – 21:08:44 | HTTP retrieval of rhino4.jpg and rhino5.gif from `/~gnome/` |
| 2004-04-28 21:15:48 – 21:16:24 | Google search for "rhino.exe", then download of `/~gnome/rhino.exe` |
| 2004-04-30 18:11:20 / 18:11:24 (zone unknown) | Latest FAT directory times on the USB volume (gumbo1.txt, gumbo2.txt) |
| 2005-08-08 to 09 | Embedded dates in the carved document and extracted JPEGs (unreliable — later than all other evidence) |

**Conclusion.** The combined evidence contains **10 unique rhinoceros images**, confirmed by direct viewing. The USB image alone holds 6 — below the threshold of nine. The threshold is reached only by combining USB-image content with images seen in the FTP and HTTP captures, which show transfer/retrieval, not stored possession on a device. The FTP login and the HTTP path share the name "gnome," but no technical artefact ties the FTP client, the HTTP client, and the USB device to one person.

**Confidence.** High for the technical facts (hash-verified, header/trailer-validated, byte-count-matched, every image directly viewed). Moderate for the FTP–HTTP link (a shared account/path name only). Low for any attribution to a specific person.

## Limitations

- FAT, zip, and document timestamps carry no time zone; my VM's `-0400`/`EDT` label is local to my machine, not the evidence.
- The 2005 dates embedded in the carved document and extracted JPEGs conflict with the 2004 dates everywhere else and are not used for ordering.
- stegbreak crashed on two candidates (`f0105873.jpg`/`f0335081.jpg`, `f0106409.jpg`); those results are inconclusive, not negative.
- `rhino3.jpg` was transferred in ASCII mode; the server's stored copy may differ from the bytes I rebuilt.
- The Google Groups responses are absent from `rhino3.log`, and I did not analyse the small number of IMAP/MSN Messenger frames present.
- A hash-unique image count is not the same as a picture-unique count (a re-encoded copy changes the hash).
- Of the 10 confirmed rhinoceros images, 6 are photographs, 3 are drawings/renderings, and 1 is a painting — whether non-photographic depictions count under the scenario's law is not something I decide here.
- Claims inside the recovered Word document are unverified statements, not established facts.
- `rhino.exe` was examined statically only; its behaviour is unknown.

## References

- NIST CFReDS, Rhino Hunt: https://www.cfreds.nist.gov/dfrws/Rhino_Hunt.html
- Course materials and dataset: https://github.com/frankwxu/digital-forensics-lab
- stegdetect (maintained fork): https://github.com/poizan42/stegdetect
- JPHIDE and JPSEEK (jphs 0.5) by Allan Latham
