# hybridcrypt 0.3.0 – Testbericht

Stand: 24.09.2026 · Plattform: macOS · Werkzeuge: `cargo test`, `cargo-fuzz` (libFuzzer, AddressSanitizer, Nightly)

## 1. Zusammenfassung

| Bereich | Umfang | Ergebnis |
|---|---|---|
| Unit-Tests | 16 Tests + 1 Hilfstest | 16 bestanden, 0 fehlgeschlagen (3,18 s) |
| Fuzzing | 3 Ziele, ca. 60,6 Mio. Ausführungen | kein Crash, kein Panic, kein ASan-Fehler |


## 2. Unit-Tests (`cargo test`)

### 2.1 Chunk-Ebene (fester Schlüssel, ohne KEM/Argon2)

| Test | Prüfung | Ergebnis |
|---|---|---|
| `chunk_roundtrip_verschiedene_groessen` | Roundtrip für 11 Größen (0 B bis 5 × 64 KiB + 3); Chunk-Anzahl und Containerlänge | bestanden |
| `nonces_sind_pro_zaehler_eindeutig` | 3 Basis-Nonces × 200.000 Zählerwerte + Grenzwerte (`u64::MAX`, 2^32, 2^63); Nonces paarweise verschieden | bestanden |
| `chunk_aad_unterscheidet_zaehler_und_last_flag` | AAD ändert sich bei anderem Zähler bzw. Last-Flag | bestanden |
| `chunk_jedes_manipulierte_bit_in_struktur_bereichen_wird_erkannt` | Zwei Chunks. Alle Bits in Längenfeldern und Tags, Ciphertext stichprobenartig. Jede Manipulation muss scheitern und darf nur einen korrekten Klartext-Präfix ausgeben | bestanden |
| `chunk_jede_kuerzung_wird_erkannt` | Drei Chunks. Kürzung an und um (±3 Byte) jede Chunk-Grenze sowie in Schritten von 997 Byte | bestanden |
| `chunk_umsortieren_duplizieren_loeschen_anhaengen_wird_erkannt` | 10 Fälle: Vertauschen, Duplizieren, Löschen (erster/mittlerer/letzter), Anhängen von Chunk, Byte oder Nullfeld | bestanden |
| `chunk_ueberlange_laengenfelder_werden_abgelehnt` | Längenfeld 64 KiB + 1, 0x80000000, `u32::MAX` → `BadContainer`, keine Ausgabe | bestanden |
| `chunk_zufallsdaten_und_mutationen_nie_akzeptiert_und_nie_panic` | 20.000 Zufallseingaben (0–299 B) und 20.000 Mutationen (1–3 Byte) eines gültigen Containers; feste PRNG-Seed | bestanden |

### 2.2 Konfiguration und Schlüsseldatei

| Test | Prüfung | Ergebnis |
|---|---|---|
| `cargo_toml_hat_overflow_checks_im_release_profil` | `overflow-checks = true` vorhanden (Abbruch statt Überlauf des `u64`-Zählers) | bestanden |
| `keyfile_parameter_ueber_grenze_werden_ohne_argon2_abgelehnt` | 6 präparierte `.hkey`-Header mit `m_cost`/`t_cost`/`lanes` über dem Maximum → `BadKeyFile`, Laufzeit < 2 s | bestanden |
| `keyfile_zu_kurz_oder_falsche_magic_wird_abgelehnt` | leere, zu kurze und falsche Magic-Bytes → `BadKeyFile` | bestanden |

### 2.3 Gesamtstapel (ML-KEM-1024, P-384, Argon2id)

| Test | Prüfung | Ergebnis |
|---|---|---|
| `voll_roundtrip` | Verschlüsseln/Entschlüsseln für 0 B, 1 B, 64 KiB + 1 | bestanden |
| `voll_falscher_empfaenger_wird_abgelehnt` | Container für Schlüssel A mit Schlüssel B → Fehler, keine Ausgabe | bestanden |
| `voll_falsche_passphrase_wird_abgelehnt` | falsche Passphrase → `BadPassphrase`, keine Ausgabe | bestanden |
| `voll_manipulierter_header_wird_erkannt_und_gibt_nichts_aus` | je ein Bitflip an 13 Header-Positionen (Magic, Längenfelder, KEM-Ciphertext, ephemerer Punkt, `base_nonce`) → Fehler, keine Ausgabe | bestanden |
| `voll_wiederholtes_verschluesseln_liefert_immer_neue_zufallswerte` | 300 Verschlüsselungen derselben Daten; KEM-Ciphertext, ephemerer Punkt, `base_nonce` und Gesamtcontainer jeweils einzigartig | bestanden |

### 2.4 Hilfstest

| Test | Zweck | Ergebnis |
|---|---|---|
| `schreibe_fuzz_seed_corpus` (`#[ignore]`) | schreibt 4 gültige Startdateien für den Fuzzer (Klartext 0 B, 10 B, 300 B, 64 KiB + 5) | separat ausgeführt: bestanden |

## 3. Fuzzing (`cargo fuzz`)

| Ziel | Eigenschaft | Ausführungen | Dauer | Ergebnis |
|---|---|---|---|---|
| `roundtrip` | Roundtrip stimmt; jede Ein-Bit-Manipulation wird erkannt; Ausgabe nur korrekter Präfix | 137.964 | 301 s | kein Befund |
| `chunks` | `decrypt_chunks` mit beliebigen Bytes: kein Panic, kein Speicherfehler | 1.168.621 | 601 s | kein Befund |
| `parsers` | `read_u32_prefixed`, `read_opt_u32`, `take_u32_prefixed`, `take_exact` mit beliebigen Bytes | 59.291.792 | 121 s | kein Befund |

Coverage `roundtrip`: cov 629, ft 1543, Korpus 72 Einträge (22 KB).

## 4. Grenzen der Aussagekraft

- Im `roundtrip`-Lauf blieb die Eingabelänge bei ca. 1,7 KB (`lim: 1670`). Mehrere Chunks (> 64 KiB) wurden dort nicht erreicht; sie sind nur durch die Unit-Tests abgedeckt.
- `chunks` prüft praktisch nur Fehlerpfade, da der Fuzzer keine gültigen Poly1305-Tags erzeugen kann.
- Nicht getestet: `decrypt_stream` als Ganzes im Fuzzer (Argon2, ML-KEM, Punktvalidierung), `secure.rs`, `hardening.rs`, GUI, Prozesshärtung (`mlock`, Zeroize, Core-Dumps).
- Nicht durchgeführt: unabhängige Reimplementierung nach Spezifikation, `cargo audit`, `cargo clippy`.
- Kurze Fuzz-Läufe (2–10 min) 

## 5. Beobachtungen aus dem Code-Review

- `decrypt_stream` gibt bereits authentifizierte Chunks aus, bevor ein späterer Fehler (z. B. Kürzung) erkannt wird. Die GUI löscht die Teilausgabe bei Worker-Exit-Code ≠ 0 (`wipe_and_remove`, `gui.rs`).
- Kein Aufruf von `wipe_and_remove`, wenn `run_worker` selbst mit Fehler zurückkehrt; eine bereits angelegte Ausgabedatei bleibt bestehen.
- Bei hartem Abbruch der GUI (Absturz, `kill -9`, Stromausfall) bleibt der bis dahin geschriebene Klartext-Präfix auf dem Datenträger.

## 6. Reproduktion

```
cargo test
cargo test schreibe_fuzz_seed_corpus -- --ignored
cargo +nightly fuzz run roundtrip -- -max_len=140000 -max_total_time=300
cargo +nightly fuzz run chunks    -- -max_len=140000 -max_total_time=600
cargo +nightly fuzz run parsers   -- -max_total_time=120
```

---

# Ergänzung (Stand 02.10.2026)

> Die Abschnitte 1–6 oben bleiben unverändert. Diese Ergänzung enthält (A) die Ergebnisse weiterer Testläufe und (B) die Beschreibung der neu bereitgestellten Testvektor-Suite für ML-KEM-1024 und P-384.

## 7. Ergebnisse weiterer Testläufe

### 7.1 Herkunft und Rahmenbedingungen

- Quelle: Konsolenausgaben der Läufe (Datei „Testergebnisse“), übernommen ohne Nacharbeit. Das Log enthält kein Datum; Plattform laut Pfaden und Toolchain-Namen: macOS, `x86_64-apple-darwin`, Nightly-Toolchain; Clippy-Hinweis-URL nennt `rust-1.98.0`. Geprüftes Crate: `hybridcrypt v0.3.0`. Aufrufe mit `--no-default-features` (ohne GUI).
- Lokale Dateipfade wurden aus dieser Ergänzung bewusst weggelassen.
- Die Tests und Fuzz-Ziele dieser Ergänzung (`kats`, `roundtrip`, `negative`, `property`; `decrypt_container`, `encrypt_recipient_blob`, `decrypt_keyfile`) tragen andere Namen als die in Abschnitt 2 und 3. Es handelt sich um eine zweite Testsuite, nicht um eine Wiederholung. Die Ergebnisse in Abschnitt 2 und 3 werden dadurch weder bestätigt noch ersetzt.
- Abschnitt 4 nennt `cargo audit` und `cargo clippy` als „nicht durchgeführt“. Beide liegen jetzt vor (7.5, 7.6); Abschnitt 4 wurde nicht geändert.

### 7.2 Übersicht

| Bereich | Umfang | Ergebnis |
|---|---|---|
| Known-Answer-Tests (`kats`) | 6 Tests | 6 bestanden, 0 fehlgeschlagen (0,01 s) |
| Roundtrip (`roundtrip`, Debug) | 18 Tests | 16 bestanden, 2 ignoriert (`--ignored` nötig), 0 fehlgeschlagen (121,85 s) |
| Roundtrip (`roundtrip`, Release, `--ignored`) | 2 Tests | 2 bestanden (2,57 s) |
| Negativtests (`negative`) | 30 Tests | 30 bestanden, 0 fehlgeschlagen (469,69 s) |
| Property-Tests (`property`) | 3 Tests | 3 bestanden, 0 fehlgeschlagen (529,04 s) |
| Fuzzing | 3 Ziele, mindestens ca. 4,6 Mio. Ausführungen | im Log kein Crash, kein Panic, kein Sanitizer-Fehler gemeldet; 1 Slow-Unit (91 s) bei `decrypt_keyfile` |
| Miri (`secure.rs`) | Lauf abgebrochen | **Fehler:** Stacked-Borrows-Verstoß, Befund offen (7.4) |
| Clippy (`-D warnings`) | Lauf abgebrochen | **Fehler:** 1 Lint (`len_without_is_empty`), Befund offen (7.5) |
| `cargo audit` | 400 Abhängigkeiten, 1277 Advisories | 0 Schwachstellen, 1 Warnung (`ttf-parser` unmaintained) |

Insgesamt 57 bestandene Tests (55 im Debug-Lauf, 2 zusätzlich im Release-Lauf mit `--ignored`).

### 7.3 Unit-, Roundtrip-, Negativ- und Property-Tests

#### 7.3.1 Known-Answer-Tests

| Test | Prüfung | Ergebnis |
|---|---|---|
| `hkdf_sha256_rfc5869_test_case_1` | HKDF-SHA-256 gegen RFC 5869, Test Case 1 | bestanden |
| `hkdf_sha256_rfc5869_test_case_3_empty_salt_and_info` | HKDF-SHA-256 gegen RFC 5869, Test Case 3 (leeres Salt/Info) | bestanden |
| `chacha20poly1305_rfc8439_section_2_8_2` | ChaCha20-Poly1305 gegen RFC 8439, Abschnitt 2.8.2 | bestanden |
| `chacha20poly1305_tampered_tag_from_kat_is_rejected` | derselbe Vektor mit verändertem Tag wird abgelehnt | bestanden |
| `argon2id_rfc9106_section_5_3` | Argon2id gegen RFC 9106, Abschnitt 5.3 | bestanden |
| `argon2id_different_salt_gives_different_output` | anderes Salt ergibt andere Ausgabe | bestanden |

#### 7.3.2 Roundtrip

| Test | Prüfung | Ergebnis |
|---|---|---|
| `roundtrip_0_bytes`, `_1_byte`, `_15_bytes`, `_16_bytes`, `_63_bytes`, `_64_bytes`, `_65_bytes` | Verschlüsseln/Entschlüsseln, kleine Größen | bestanden |
| `roundtrip_65535_bytes_one_below_chunk`, `_65536_bytes_exactly_one_chunk`, `_65537_bytes_one_above_chunk` | Chunk-Grenze (64 KiB) | bestanden |
| `roundtrip_last_chunk_is_short`, `roundtrip_multi_chunk_sizes`, `roundtrip_all_boundary_sizes_in_one_pass` | mehrere Chunks, kurzer letzter Chunk, alle Grenzgrößen | bestanden |
| `roundtrip_all_zero_plaintext`, `roundtrip_all_0xff_plaintext` | Extremmuster | bestanden |
| `same_plaintext_encrypts_differently_each_time` | gleicher Klartext ergibt verschiedene Container | bestanden |
| `roundtrip_several_mib`, `roundtrip_several_hundred_mib` | große Datenmengen (nur mit `--ignored`, im Release-Lauf) | bestanden |

#### 7.3.3 Negativtests (30)

| Gruppe | Anzahl | Geprüft (Testnamen sinngemäß) | Ergebnis |
|---|---|---|---|
| Bitflips in Header-Feldern | 4 | Magic, ephemerer P-384-Punkt, KEM-Ciphertext, `base_nonce` | alle abgelehnt |
| Längenfelder | 6 | Chunk-Länge passt nicht, `eph_pk`-Länge absurd, `kem_ct`-Länge absurd bzw. mit Bitflip, letzten Chunk verlängert/verkürzt ohne Längenfeld | alle abgelehnt |
| Chunk-Manipulation | 9 | Bitflip in Tag bzw. Ciphertext, mittleren/letzten Chunk löschen, Chunk (letzten) duplizieren, ersten Chunk ans Ende, alle Chunks umkehren, zwei Chunks vertauschen | alle abgelehnt |
| Anhängen | 2 | Fremddaten bzw. plausibler zusätzlicher Chunk am Ende | beide abgelehnt |
| Kürzung | 5 | nur Magic, 0 Byte, genau ohne Tag, zwischen Chunks, mitten im Chunk-Ciphertext | alle abgelehnt |
| Schlüssel/Passphrase | 3 | falsche Passphrase, falscher Schlüssel-Blob, falscher Empfänger | alle abgelehnt |
| Systematischer Sweep | 1 | Manipulation an jedem 97. Byte | bestanden |

#### 7.3.4 Property-Tests

| Test | Ergebnis |
|---|---|
| `roundtrip_random_plaintext` | bestanden |
| `random_single_bit_flip_never_succeeds_with_wrong_plaintext` | bestanden |
| `random_chunk_shuffling_never_succeeds_with_wrong_plaintext` | bestanden |

Alle drei Tests liefen jeweils länger als 60 Sekunden (Debug-Build).

### 7.4 Fuzzing

Aufrufe: `cargo +nightly fuzz run decrypt_container -- -max_len=200000`, `cargo +nightly fuzz run encrypt_recipient_blob`, `cargo +nightly fuzz run decrypt_keyfile`. Alle drei Läufe wurden mit Strg+C beendet („run interrupted“). Die Laufzeit ist im Log nicht festgehalten. Die Werte stammen aus der jeweils letzten ausgegebenen Statuszeile.

| Ziel | Ausführungen (mind.) | cov | ft | Korpus | exec/s | RSS | Befund |
|---|---|---|---|---|---|---|---|
| `decrypt_container` | 3.559.084 | 1776 | 2058 | 41 Einträge / 53 KB | 788 | 447 MB | kein Crash im Log |
| `encrypt_recipient_blob` | 1.005.800 | 1058 | 1177 | 25 Einträge / 34 KB | 810 | 430 MB | kein Crash im Log |
| `decrypt_keyfile` | 35.558 | 2238 | 3755 | 71 Einträge / 13.576 Byte | 21 | 1302 MB | **Slow-Unit: 91 s** |

**Slow-Unit bei `decrypt_keyfile`.** libFuzzer hat eine Eingabe als `slow-unit-…` abgelegt; ein `crash-…`-Artefakt ist im Log nicht aufgeführt. Die Eingabe (71 Byte) beginnt mit der Magic `HSK2`; die Parameter im Header sind `m_cost` = 26 904 KiB (ca. 26 MiB), `t_cost` = 5, `lanes` = 3. Diese Werte liegen innerhalb der Grenzen in `open_private_blob` (`ARGON_M_COST_MAX` = 1 GiB, `ARGON_T_COST_MAX` = 10, `ARGON_LANES_MAX` = 4) und werden daher nicht vorab abgelehnt; die Argon2-Ableitung läuft, bevor der AEAD-Tag geprüft wird. Zum Vergleich: die eigenen Standardwerte sind 128 MiB, `t_cost` = 4, `lanes` = 1. Die Ursache der 91 s wurde nicht untersucht (der Fuzz-Build läuft mit Sanitizer; ein Lauf ohne Sanitizer wurde nicht gemessen). Der theoretische Höchstwert innerhalb der erlaubten Grenzen (1 GiB, `t_cost` = 10, `lanes` = 4) ist deutlich größer als der hier beobachtete Fall.

Einschränkungen: Die Läufe sind kurz, die Coverage stagniert bei `decrypt_container` (der AEAD-Tag weist mutierte Eingaben früh ab), und `decrypt_keyfile` kam wegen der Argon2-Kosten nur auf etwa 35.000 Ausführungen.

### 7.5 Statische Analyse und Abhängigkeiten

**Clippy** (`cargo clippy --no-default-features --all-targets -- -D warnings`): Abbruch mit einem Fehler.

| Datei | Lint | Meldung |
|---|---|---|
| `src/secure.rs:359` | `clippy::len_without_is_empty` | `SecureBuf` hat eine öffentliche Methode `len`, aber keine `is_empty` |

Da der Build abbrach, sind weitere Lints (falls vorhanden) nicht ausgewertet. Status: offen.

**cargo audit:** 1277 Advisories geladen, `Cargo.lock` mit 400 Abhängigkeiten geprüft. Keine Schwachstelle gemeldet; eine erlaubte Warnung:

| Crate | Version | Art | ID |
|---|---|---|---|
| `ttf-parser` | 0.25.1 | unmaintained | RUSTSEC-2026-0192 (Advisory vom 28.06.2026) |

Woher die Abhängigkeit kommt (z. B. über die GUI-Bibliotheken), wurde nicht geprüft. `cargo audit` liest `Cargo.lock` unabhängig von den Build-Features.

### 7.6 Miri (`secure.rs`)

Aufruf: `cargo +nightly miri test --no-default-features --lib`. Ergebnis: **Fehler, Lauf abgebrochen** („aborting due to 1 previous error“).

| Feld | Inhalt |
|---|---|
| Fehlerklasse | Stacked-Borrows-Verstoß (Miri weist darauf hin, dass die Regeln noch experimentell sind) |
| Test | `secure::tests::capacity_exactly_page_size` (`src/secure.rs:493`) |
| Aufrufkette | `SecureBuf::from_slice` (Zeile 316) → `SecureBuf::push_bytes` (Zeilen 330–334, `copy_nonoverlapping`) |
| Ursache laut Miri | Der Zeiger aus `storage.as_mut_ptr()` (Zeile 234) wird durch das Verschieben von `storage` in das Feld `miri_storage` (Zeile 241) ungültig und anschließend über `self.mem` benutzt |
| Betroffener Code | das Feld `miri_storage` gehört laut `TESTING.md` zu einem Backend, das nur unter Miri verwendet wird; der mmap-/`mlock`-Pfad der normalen Builds war nicht Gegenstand dieses Befunds |
| Status | offen |

Hinweise: Im mitgelieferten Quellarchiv `hybridcrypt-0_3_0.zip` ist dieses Miri-Backend nicht enthalten (kein `miri_storage`, `secure.rs` mit 334 Zeilen); die Zuordnung zum reinen Miri-Backend beruht daher auf der Beschreibung in `TESTING.md` und dem Miri-Log, nicht auf einer Prüfung des getesteten Codes. Da Miri bei der ersten Verletzung abbricht, ist für die übrigen Tests in `secure.rs` unter Miri kein Ergebnis belegt.

### 7.7 Im Log nicht enthalten

`cargo deny`, AddressSanitizer-/UBSan-Läufe der Unit-Tests, Guard-Page-Test, Worker-IPC-Tests, Tests von `hardening.rs`/GUI sowie die Ergebnisse der Tests aus `secure.rs` im normalen (Nicht-Miri-)Lauf sind in der vorliegenden Ausgabe nicht enthalten und werden hier nicht bewertet.

### 7.8 Reproduktion (Ergänzung)

```
cargo test --no-default-features --test kats
cargo test --no-default-features --test roundtrip
cargo test --no-default-features --test negative
cargo test --no-default-features --test property
cargo test --release --no-default-features --test roundtrip -- --ignored
cargo +nightly fuzz run decrypt_container -- -max_len=200000
cargo +nightly fuzz run encrypt_recipient_blob
cargo +nightly fuzz run decrypt_keyfile
cargo +nightly miri test --no-default-features --lib
cargo clippy --no-default-features --all-targets -- -D warnings
cargo audit
```

(Die genauen Testaufrufe zu 7.3 stehen nicht im Log; die Zeilen oben sind aus den Namen der Testdateien im Log abgeleitet und nicht als Original-Eingabe zu verstehen.)

## 8. Testvektor-Suite: ML-KEM-1024 (NIST ACVP) und P-384-ECDH (Wycheproof)

### 8.1 Status

| Punkt | Stand |
|---|---|
| Datei | `tests/vectors.rs` (zusätzlich `scripts/fetch_vectors.sh`, `VECTORS.md`) |
| Vektorquellen | NIST ACVP-Server (`ML-KEM-keyGen-FIPS203`, `ML-KEM-encapDecap-FIPS203`), Wycheproof (`ecdh_secp384r1_test.json`, `ecdh_secp384r1_ecpoint_test.json`) |
| Vektordateien | nicht im Lieferumfang; werden mit `scripts/fetch_vectors.sh` geladen und mit SHA-256 protokolliert |
| Zustand der Suite | geschrieben, **nicht kompiliert und nicht ausgeführt** (Entwicklungsumgebung ohne Rust-Toolchain und ohne Netzwerk) |
| Ergebnisse | **ausstehend** (Tabelle 8.4) |

### 8.2 Enthaltene Tests

| Test | Prüfung | Vektordatei nötig |
|---|---|---|
| `acvp_ml_kem_1024_keygen` | `generate_deterministic(d, z)` liefert exakt `ek` und `dk` der ACVP-Vektoren; `dk` enthält dasselbe `ek` | ja |
| `acvp_ml_kem_1024_encap_decap` | Encapsulation mit festem `m` ergibt `c` und `k`; Decapsulation (inkl. ungültiger Ciphertexte, implizite Ablehnung) ergibt `k`; `encapsulationKeyCheck` (Modulus-Prüfung nach FIPS 203, 7.2) stimmt mit `testPassed` überein | ja |
| `wycheproof_ecdh_secp384r1_ecpoint` | ECDH mit SEC1-Punkt: `valid` muss das erwartete Geheimnis liefern, `invalid` muss abgelehnt werden, `acceptable` darf ablehnen, aber nie ein falsches Ergebnis liefern | ja |
| `wycheproof_ecdh_secp384r1_der` | wie oben, öffentlicher Schlüssel als X.509-SPKI (DER) | ja |
| `selbsttest_ml_kem_deterministisch_und_roundtrip` | gleiche Seeds ergeben gleiche Schlüssel; Encaps/Decaps stimmen überein; Modulus-Prüfung erkennt manipuliertes `ek` | nein |
| `selbsttest_p384_ecdh_symmetrie_und_spki` | `DH(a, B) = DH(b, A)`; SPKI-Hilfsfunktion Rundlauf | nein |
| `p384_ungueltige_punkte_werden_abgelehnt` | Identität, leere Eingabe, Punkt außerhalb der Kurve, Koordinate ≥ p, falsche Präfixe/Längen werden von `from_sec1_bytes` abgelehnt (selbst konstruierte Fälle, keine Fremdvektoren) | nein |

Aufrufe der Bibliotheken entsprechen denen in `hybrid.rs` (`MlKem1024`, `Decapsulate`, `Ciphertext`, `Encoded`, `P384Public::from_sec1_bytes`, `P384Secret::from_slice`, `diffie_hellman`).

Nicht abgedeckt: ACVP-`decapsulationKeyCheck` (benötigt SHA3-256, wird gezählt und als „übersprungen“ ausgewiesen), P-384-ECDSA, ML-KEM-512/-768 (werden gezählt und nicht geprüft), Wycheproof-ML-KEM-Dateien.

### 8.3 Reproduktion

```
./scripts/fetch_vectors.sh
cargo test --no-default-features --test vectors -- --nocapture
```

Fehlen die Vektordateien, schlagen die vier Vektortests mit einer Anleitung fehl (kein stilles Überspringen). Mit `HYBRIDCRYPT_VECTORS_OPTIONAL=1` werden sie stattdessen als „SKIPPED“ ausgegeben und gelten dann **nicht** als geprüft.

### 8.4 Ergebnisse (nach Ausführung einzutragen)

| Test | Ausgeführt | Übersprungen | Fremde Parametersätze/Kurven | Fehler | Ergebnis |
|---|---|---|---|---|---|
| `acvp_ml_kem_1024_keygen` | – | – | – | – | ausstehend |
| `acvp_ml_kem_1024_encap_decap` | – | – | – | – | ausstehend |
| `wycheproof_ecdh_secp384r1_ecpoint` | – | – | – | – | ausstehend |
| `wycheproof_ecdh_secp384r1_der` | – | – | – | – | ausstehend |
| `selbsttest_ml_kem_deterministisch_und_roundtrip` | – | – | – | – | ausstehend |
| `selbsttest_p384_ecdh_symmetrie_und_spki` | – | – | – | – | ausstehend |
| `p384_ungueltige_punkte_werden_abgelehnt` | – | – | – | – | ausstehend |

SHA-256 der verwendeten Vektordateien: aus `tests/vectors/SHA256SUMS.txt` zu übernehmen.
