# hybridcrypt 0.3.0 – Testbericht

Stand: 24.09.2026 · Plattform: macOS · Werkzeuge: `cargo test`, `cargo-fuzz` (libFuzzer, AddressSanitizer, Nightly)

## 1. Zusammenfassung

| Bereich | Umfang | Ergebnis |
|---|---|---|
| Unit-Tests | 16 Tests + 1 Hilfstest | 16 bestanden, 0 fehlgeschlagen (3,18 s) |
| Fuzzing | 3 Ziele, ca. 60,6 Mio. Ausführungen | kein Crash, kein Panic, kein ASan-Fehler |

## 2. Änderungen am Code

- Die Chunk-Schleifen wurden aus `encrypt_stream` und `decrypt_stream` in `encrypt_chunks` und `decrypt_chunks` ausgelagert. Das Verhalten ist unverändert. Dadurch lässt sich die Chunk-Logik ohne KEM und Argon2 testen und fuzzen.
- `Cargo.toml`: `[profile.test]` mit `opt-level = 3`. Das Release-Profil ist unverändert.
- Neu: `src/hybrid_tests.rs`, `fuzz/`.

## 3. Unit-Tests (`cargo test`)

### 3.1 Chunk-Ebene (fester Schlüssel, ohne KEM/Argon2)

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

### 3.2 Konfiguration und Schlüsseldatei

| Test | Prüfung | Ergebnis |
|---|---|---|
| `cargo_toml_hat_overflow_checks_im_release_profil` | `overflow-checks = true` vorhanden (Abbruch statt Überlauf des `u64`-Zählers) | bestanden |
| `keyfile_parameter_ueber_grenze_werden_ohne_argon2_abgelehnt` | 6 präparierte `.hkey`-Header mit `m_cost`/`t_cost`/`lanes` über dem Maximum → `BadKeyFile`, Laufzeit < 2 s | bestanden |
| `keyfile_zu_kurz_oder_falsche_magic_wird_abgelehnt` | leere, zu kurze und falsche Magic-Bytes → `BadKeyFile` | bestanden |

### 3.3 Gesamtstapel (ML-KEM-1024, P-384, Argon2id)

| Test | Prüfung | Ergebnis |
|---|---|---|
| `voll_roundtrip` | Verschlüsseln/Entschlüsseln für 0 B, 1 B, 64 KiB + 1 | bestanden |
| `voll_falscher_empfaenger_wird_abgelehnt` | Container für Schlüssel A mit Schlüssel B → Fehler, keine Ausgabe | bestanden |
| `voll_falsche_passphrase_wird_abgelehnt` | falsche Passphrase → `BadPassphrase`, keine Ausgabe | bestanden |
| `voll_manipulierter_header_wird_erkannt_und_gibt_nichts_aus` | je ein Bitflip an 13 Header-Positionen (Magic, Längenfelder, KEM-Ciphertext, ephemerer Punkt, `base_nonce`) → Fehler, keine Ausgabe | bestanden |
| `voll_wiederholtes_verschluesseln_liefert_immer_neue_zufallswerte` | 300 Verschlüsselungen derselben Daten; KEM-Ciphertext, ephemerer Punkt, `base_nonce` und Gesamtcontainer jeweils einzigartig | bestanden |

### 3.4 Hilfstest

| Test | Zweck | Ergebnis |
|---|---|---|
| `schreibe_fuzz_seed_corpus` (`#[ignore]`) | schreibt 4 gültige Startdateien für den Fuzzer (Klartext 0 B, 10 B, 300 B, 64 KiB + 5) | separat ausgeführt: bestanden |

## 4. Fuzzing (`cargo fuzz`)

| Ziel | Eigenschaft | Ausführungen | Dauer | Ergebnis |
|---|---|---|---|---|
| `roundtrip` | Roundtrip stimmt; jede Ein-Bit-Manipulation wird erkannt; Ausgabe nur korrekter Präfix | 137.964 | 301 s | kein Befund |
| `chunks` | `decrypt_chunks` mit beliebigen Bytes: kein Panic, kein Speicherfehler | 1.168.621 | 601 s | kein Befund |
| `parsers` | `read_u32_prefixed`, `read_opt_u32`, `take_u32_prefixed`, `take_exact` mit beliebigen Bytes | 59.291.792 | 121 s | kein Befund |

Coverage `roundtrip`: cov 629, ft 1543, Korpus 72 Einträge (22 KB).

## 5. Grenzen der Aussage

- Im `roundtrip`-Lauf blieb die Eingabelänge bei ca. 1,7 KB (`lim: 1670`). Mehrere Chunks (> 64 KiB) wurden dort nicht erreicht; sie sind nur durch die Unit-Tests abgedeckt.
- `chunks` prüft praktisch nur Fehlerpfade, da der Fuzzer keine gültigen Poly1305-Tags erzeugen kann.
- Nicht getestet: `decrypt_stream` als Ganzes im Fuzzer (Argon2, ML-KEM, Punktvalidierung), `secure.rs`, `hardening.rs`, GUI, Prozesshärtung (`mlock`, Zeroize, Core-Dumps).
- Nicht durchgeführt: unabhängige Reimplementierung nach Spezifikation, `cargo audit`, `cargo clippy`.
- Kurze Fuzz-Läufe (2–10 min) sind kein Sicherheitsbeleg.

## 6. Beobachtungen aus dem Code-Review

- `decrypt_stream` gibt bereits authentifizierte Chunks aus, bevor ein späterer Fehler (z. B. Kürzung) erkannt wird. Die GUI löscht die Teilausgabe bei Worker-Exit-Code ≠ 0 (`wipe_and_remove`, `gui.rs`).
- Kein Aufruf von `wipe_and_remove`, wenn `run_worker` selbst mit Fehler zurückkehrt; eine bereits angelegte Ausgabedatei bleibt bestehen.
- Bei hartem Abbruch der GUI (Absturz, `kill -9`, Stromausfall) bleibt der bis dahin geschriebene Klartext-Präfix auf dem Datenträger.

## 7. Reproduktion

```
cargo test
cargo test schreibe_fuzz_seed_corpus -- --ignored
cargo +nightly fuzz run roundtrip -- -max_len=140000 -max_total_time=300
cargo +nightly fuzz run chunks    -- -max_len=140000 -max_total_time=600
cargo +nightly fuzz run parsers   -- -max_total_time=120
```
