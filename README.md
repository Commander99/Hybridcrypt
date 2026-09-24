# hybridcrypt

**Dateiverschlüsselung als natives Desktop-Tool - entwickelt für Mac OS 13.7 und Tails OS.**

Dieses README ist ausschließlich aus dem Quellcode (`src/*.rs`, `Cargo.toml`) von hybridcrypt 0.3.0 abgeleitet.
Große Teile des Codes und der Kommentare wurden mit Unterstützung von Claude Opus 5 geschrieben. Hierzu wurde das 
Konzept des Loop-Engineerings genutzt, wobei Claude Opus 5 die Programmierarbeit übernahm, GPT5 anschließend auf Basis 
des Codes eine Audit Liste schrieb und eine vollständig neue Instanz von Opus 5 diese anhand des Codes abarbeitete und 
anpasste. Das Prinzip wurde so lange wiederholt (5 Durchgänge), bis eine im Rahmen des Projekts ausreichende Härtung erreicht 
wurde und die Audits keine sicherheitsrelevanten Fehler mehr fanden.
Zu guter letzt wurde der Code noch einmal manuell begutachtet. 

**Die detaillierten Ergebnisse der ausgeführten Testläufe liegen in Hybridcrypt 0.3.0-Fuzzing-Unit-Tests.md**

Die Kryptografie beruht auf einer hybriden Kombination von ML-KEM-1024 × P-384 × SHA-256 · ChaCha20-Poly1305.

Es handelt sich um ein proof-of-concept. Nicht geeignet zur Volume Verschlüsselung, sondern nur für einzelne Dateien.
Einzige halbwegs sinnvolle Nutzung ist der Schutz gegen "Harvest now - decrypt later" (HNDL) - Angriffe, für Daten die über mehrere Jahrzehnte relevant bleiben.
Hybridcrypt ist kein Ersatz für lokale Passwort-Verschlüsselung (AES-256 z.b. ist bereits quantenresistent) 

![Version](https://img.shields.io/badge/version-0.3.0-blue) ![Sprache](https://img.shields.io/badge/language-Rust-orange) ![Plattform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%2FTails-lightgrey)

---

## Inhaltsverzeichnis

1. [Überblick](#überblick)
2. [Version](#version)
3. [Installation & Bauen](#installation--bauen)
4. [Nutzungsanleitung](#nutzungsanleitung)
5. [Architektur](#architektur)
6. [Dateiformate](#dateiformate)
7. [Fehler- und Exit-Codes](#fehler--und-exit-codes)
8. [Restrisiken](#restrisiken)
9. [Bewusst nicht enthalten](#bewusst-nicht-enthalten)

---

## Überblick

hybridcrypt (`main.rs`) ist ein einzelnes Rust-Binary mit nativer Oberfläche (`eframe`/`egui`, `gui.rs`), das drei Operationen anbietet:

- **Schlüsselpaar erzeugen** — legt eine öffentliche Datei (`.hpub`) und eine passphrasengeschützte private Datei (`.hkey`) an (`hybrid::generate_keypair`)
- **Verschlüsseln** — mit dem `.hpub` eines Empfängers, ohne eigene Passphrase (`hybrid::encrypt_stream`)
- **Entschlüsseln** — mit der eigenen `.hkey` und deren Passphrase (`hybrid::decrypt_stream`)

Der Prozess ist zweigeteilt: ein Fensterprozess (Rolle „GUI") und ein per Re-Exec gestarteter Kindprozess (Rolle „Worker", `--worker`), der die gesamte Kryptografie ausführt. 
---

## Version

Aus `Cargo.toml`:

```toml
[package]
name = "hybridcrypt"
version = "0.3.0"
edition = "2021"
```

Die Formatkennungen im Code (`MAGIC_PUB = "HPB2"`, `MAGIC_KEY = "HSK2"`, `MAGIC_CT = "HCX3"` in `hybrid.rs`) sowie mehrere Kommentare, die auf ein „Audit HC-01" bis „HC-15" und eine „Vorversion" verweisen (u. a. in `secure.rs`, `proc.rs`, `hybrid.rs`), zeigen, dass es sich um eine überarbeitete Version einer vorherigen Formatgeneration handelt (`HCX2` wird im aktuellen Code nirgends mehr erzeugt oder akzeptiert). Frühere Versionsstände sind in diesem Quellcode nicht enthalten und werden hier deshalb nicht behauptet.

---

## Installation & Bauen

```sh
cargo build --release --locked
```

Ergebnis ist ein einzelnes Binary `target/release/hybridcrypt` ohne separate Assets — die Oberfläche ist über `eframe`/`egui` statisch eingebunden, es gibt kein `assets/`-Verzeichnis im Quellbaum.

**Release-Profil** (`Cargo.toml`, `[profile.release]`):

```toml
opt-level = 3
lto = true
codegen-units = 1
strip = true            # keine Debug-Symbole im Binary
overflow-checks = true  # harter Abbruch bei Integer-Overflow statt stillem Wrap
```

`panic = "unwind"` ist die Voreinstellung und wird bewusst **nicht** auf `"abort"` umgestellt — ein Kommentar im Profil begründet das: Bei `"abort"` liefen keine `Drop`-Implementierungen, also auch kein `zeroize()` der gesperrten Puffer im Panik-Fall.

**Build-Voraussetzungen laut `Cargo.toml`:** kein `cmake`, kein C++-Toolchain — alle Abhängigkeiten sind ausschließlich Rust-Crates. `eframe` wird mit `default-features = false` und den Features `glow`, `x11`, `wayland`, `default_fonts` eingebunden; die Default-Features `accesskit`, `persistence` und `web_screen_reader` sind explizit abgewählt (siehe [Architektur](#architektur)).

**macOS:** Ein per `cargo build` erzeugtes Binary ist nicht signiert; Gatekeeper greift beim ersten Start. Ein Kommentar in `proc.rs` verweist für den dortigen TOCTOU-Umgang (siehe [Architektur](#architektur)) explizit auf Code-Signing/Gatekeeper **und** eine Installation in einem nur für root beschreibbaren Verzeichnis als Grundvoraussetzung.

---

## Nutzungsanleitung

Die Oberfläche (`gui.rs`, `App::update`) zeigt drei Tabs, deren Ablauf sich direkt aus `keygen_tab`, `encrypt_tab` und `decrypt_tab` ergibt:

### Schlüsselpaar erzeugen
- Zwei Passphrase-Felder (Eingabe + Wiederholung), verglichen über einen zeitkonstanten Vergleich (`ct_eq`)
- Der „Erzeugen"-Button ist erst aktiv, wenn beide Eingaben übereinstimmen **und** mindestens `MIN_PASSPHRASE_CHARS` (12) Zeichen lang sind — das ist nur ein billiger UI-Vorfilter; die eigentliche Stärkeprüfung läuft ausschließlich im Worker-Prozess (siehe [Architektur](#architektur))
- Zielordner und Basisname wählbar; erzeugt `<name>.hpub` und `<name>.hkey`
- Nach Erfolg zeigt die GUI einen **Fingerabdruck** des öffentlichen Schlüssels an (`hybrid::pubkey_fingerprint`, aus der gerade geschriebenen `.hpub`-Datei gelesen)

### Verschlüsseln
- Auswahl der `.hpub`-Datei des Empfängers über den eingebauten Dateibrowser (`filepick.rs`)
- Beim Auswählen wird deren Fingerabdruck angezeigt, mit dem Hinweis im UI-Text, ihn „AUSSERHALB dieses Programms" mit dem Empfänger abzugleichen
- Eingabedatei, Zielordner und Ausgabename wählbar; keine Passphrase erforderlich

### Entschlüsseln
- Auswahl der eigenen `.hkey`-Datei, Eingabe der Passphrase, Auswahl der verschlüsselten Datei sowie Zielordner/-name

### Gemeinsame Eigenschaften
- Bestehende Ausgabedateien werden nie überschrieben: `create_output()` öffnet mit `create_new(true)` und Modus `0600` (`OpenOptionsExt::mode`); bei Namenskollision meldet die GUI „existiert bereits — bitte anderen Namen wählen"
- Schlägt eine Operation fehl (Exit-Code ≠ 0 und ≠ 8), wird eine bereits teilweise geschriebene Ausgabedatei durch `wipe_and_remove()` mit Nullen überschrieben und gelöscht
- Während eine Operation läuft, sind die Tabs über `ui.add_enabled_ui(!busy, …)` deaktiviert

---

## Architektur

### Prozessmodell (`main.rs`, `proc.rs`)

```rust
let is_worker = std::env::args_os().any(|a| a == "--worker");
hardening::harden_process(if is_worker { Role::Worker } else { Role::Gui });
if is_worker { worker::run(); }
gui::run()
```

`harden_process()` läuft in **beiden** Rollen als Allererstes, noch vor jeder Pufferallokation — der Kommentar in `main.rs` benennt das ausdrücklich als Grund, warum die Rollenerkennung vor allem anderen steht.

Der Worker wird nicht per rohem `fork()` gestartet, sondern per **Re-Exec** über `std::process::Command`. Die Begründung steht direkt im Modul-Kommentar von `proc.rs`: `fork()` würde den kompletten Elternspeicher inklusive aller vom GUI-Toolkit angelegten Kopien ins Kind spiegeln, und ist in einem Mehr-Thread-Prozess (jedes GUI-Toolkit hat Threads) nach POSIX nur eingeschränkt zulässig — Mutexe anderer Threads blieben im Kind für immer gesperrt. Re-Exec liefert stattdessen einen frischen Adressraum ab `main()`.

**Deskriptor-Übergabe** (`proc.rs`, `run_worker`):

| fd | Bedeutung |
|---|---|
| 0 (stdin) | Eingabedatei, vom Elternprozess geöffnet und weitergereicht |
| 1 (stdout) | Ausgabedatei, ebenso |
| 2 (stderr) | `Stdio::null()` |
| 3 | Steuerkanal (Pipe): Operation, öffentlicher Schlüssel, Passphrase |
| 4 | zweite Ausgabedatei, nur bei Schlüsselerzeugung (`FD_KEY_OUT`) |

Zwischen `fork` und `exec` (`pre_exec`) werden die Steuerkanal- und ggf. Schlüssel-Deskriptoren zunächst auf hohe Nummern dupliziert (`dup_high`, ab fd 10) und danach exakt auf 3 bzw. 4 platziert (`place_fd`, `dup2`), bevor **alle** Deskriptoren `≥ 5` bis zur Nummer 1024 geschlossen werden (`close_fds_from`). Die Operation selbst (`OP_KEYGEN`/`OP_ENCRYPT`/`OP_DECRYPT`) sowie Public Key und Passphrase gehen ausschließlich über fd 3, nicht über `argv` — ein Kommentar in `proc.rs` begründet das damit, dass `argv` für jeden lokalen Nutzer über `ps`/`/proc/<pid>/cmdline` sichtbar ist. Sichtbar bleibt laut Code lediglich, dass der Prozess mit dem Argument `--worker` läuft (`cmd.arg("--worker")`).

**TOCTOU-Schutz beim Pfad zum Worker-Binary** (`proc.rs::worker_exe_path`):

```rust
#[cfg(target_os = "linux")]
{
    let p = std::path::PathBuf::from("/proc/self/exe");
    if p.exists() { return Ok(p); }
    std::env::current_exe() // Fallback ohne /proc
}
#[cfg(not(target_os = "linux"))]
{
    std::env::current_exe()
}
```

Der Modul-Kommentar erklärt die Motivation: `current_exe()` liefert nur einen Pfad-String zurück; zwischen dessen Ermittlung und dem tatsächlichen `execve` in `Command::spawn()` könnte ein Angreifer mit Schreibrecht auf diesen Pfad die Datei austauschen. `/proc/self/exe` ist dagegen ein vom Kernel gepflegter Verweis auf das *gerade laufende* Programm-Image. Unter macOS gibt es dieses Konstrukt nicht — dort verbleibt `current_exe()`, laut Kommentar „abgesichert durch Code-Signing/Gatekeeper und eine übliche Installation in einem nur für root beschreibbaren Verzeichnis".

### Prozesshärtung (`hardening.rs`)

`harden_process(role)` führt unabhängig von der Rolle aus:

- `disable_core_dumps()` — `RLIMIT_CORE = 0`
- `restrict_umask()` — `umask(0o077)`, damit neu erzeugte Dateien nur für den eigenen Nutzer lesbar sind
- `deny_debugger()` — unter Linux `PR_SET_DUMPABLE = 0` (verhindert `ptrace`-Attach und `/proc/<pid>/mem`-Zugriff), unter macOS `PT_DENY_ATTACH`; auf anderen Zielsystemen eine No-Op
- `raise_memlock_limit()` — versucht, `RLIMIT_MEMLOCK` (weiches Limit) auf das erlaubte Maximum (`rlim_max`) zu heben

Nur in der Rolle `Worker` wird zusätzlich `try_mlockall()` versucht — `mlockall(MCL_CURRENT | MCL_FUTURE)`, aber laut Kommentar **nur**, wenn das ermittelte Limit mindestens `MEMLOCK_NEEDED` (320 MiB, Reserve für den 128-MiB-Argon2-Puffer plus Binary/Stack/Heap) beträgt. Der Kommentar begründet das explizit: Ein erfolgreiches `MCL_FUTURE` mit zu kleinem Limit würde jede spätere Allokation, die das Limit sprengt, mit `ENOMEM` scheitern lassen — im GUI-Prozess (GPU-/Font-Puffer) oder im Worker (Argon2) wäre das ein Absturz. Der GUI-Prozess ruft `try_mlockall` daher nie auf.

### Speicherprimitive für Geheimnisse (`secure.rs`)

Jedes Geheimnis liegt in einer **eigenen, exklusiven `mmap`-Anonymous-Region** (`MmapSecret`), nie geteilt mit einer anderen Allokation:

```
mmap(PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, len = data_cap + 2·page)
mprotect(erste Seite,  PROT_NONE)   // Guard-Page vorn
mprotect(letzte Seite, PROT_NONE)   // Guard-Page hinten
mlock(mittlerer Bereich)            // Fehlschlag wird gezählt, nicht ignoriert
madvise(MADV_DONTDUMP)              // zusätzlich, nur Linux
```

Ein Pufferüberlauf über die Nutzgrenze hinaus löst dadurch einen sofortigen Segfault aus, statt still benachbarten Speicher zu lesen oder zu überschreiben. Beim `Drop` von `MmapSecret` wird der Nutzbereich zuerst mit der `zeroize`-Crate volatil überschrieben, **danach erst** `munlock`, danach `munmap` — in dieser Reihenfolge, wie der Code zeigt.

Ein `mlock`-Fehlschlag führt nicht zum Abbruch der Operation, sondern wird gezählt (`LOCK_FAILURES`, ein `AtomicU32`) und am Ende ausgewertet:

- **Normalmodus:** Operation läuft weiter; war mindestens ein `mlock` erfolglos, meldet `worker::run()` `EXIT_CODE_DEGRADED_LOCK` (8) statt 0
- **`HYBRIDCRYPT_STRICT_MLOCK=1`** (ausgewertet in `worker::run()` über `secure::set_strict_mode`): `record_lock_failure()` beendet den Prozess **sofort** mit `EXIT_CODE_STRICT_MLOCK_FAILED` (7), sobald die erste Sperrung fehlschlägt

`SecureBuf` reallokiert laut Kommentar bewusst nie (feste Kapazität bei Konstruktion), „damit nie ein alter, ungezeroizter Block im Allokator zurückbleibt". Derselbe `MmapSecret`-Unterbau trägt auch `SecureBytes`, das u. a. für den Argon2-Arbeitsspeicher verwendet wird (`hybrid.rs::LockedBlocks`) — Argon2s eigener Speicher wird also nicht dem normalen Heap überlassen, sondern selbst gestellt (`hash_password_into_with_memory`).

Der Modul-Kommentar von `secure.rs` benennt selbst die Grenzen dieses Mechanismus: er verhindert Swap, Core-Dumps und Nachbarschafts-Leaks zwischen den eigenen Puffern, **nicht** Cold-Boot-Angriffe auf laufendes RAM, Zugriff durch einen Angreifer mit Kernel-Rechten zur Laufzeit, oder Kopien, die die verwendeten Fremdbibliotheken (`ml-kem`, `argon2`/intern `blake2`, `p384`) selbst auf dem normalen Heap anlegen.

### Kryptografischer Kern (`hybrid.rs`)

Läuft ausschließlich im Worker-Prozess. Verwendete Suite laut Imports und Konstanten:

- **ML-KEM-1024** (`ml_kem::MlKem1024`, Crate-Feature `zeroize` explizit aktiviert)
- **P-384** über ECDH (`p384`, `default-features = false`, Features `ecdh` + `std`)
- **HKDF-SHA-256** (`hkdf::Hkdf<Sha256>`) zur Kombination beider Shared Secrets
- **ChaCha20-Poly1305** für die Nutzdaten, in Chunks von `CHUNK_SIZE = 64 * 1024` Byte
- **Argon2id** (`argon2`, Version `V0x13`) zur Ableitung des Key-Encryption-Keys aus der Passphrase

Sitzungsschlüssel-Ableitung (`derive_session_key`):

```rust
IKM  = ML-KEM-SharedSecret || ECDH-SharedSecret
info = b"hybridcrypt-v3" || Container-Header || recipient_binding
HKDF-SHA256(None, IKM).expand(info, out)
```

`recipient_binding()` bildet SHA-256 über die kanonischen Bytes von ML-KEM-Encapsulation-Key und P-384-Punkt des Empfängers. Beim Entschlüsseln wird dieselbe Bindung aus dem **eigenen** privaten Schlüssel abgeleitet (`kem_dk.encapsulation_key()`, `p384_sk.public_key()`); weicht sie ab, schlägt bereits die HKDF-Ableitung und damit jeder AEAD-Tag fehl.

**Argon2-Parameter** (`derive_kek`):

| Konstante | Wert | Verwendung |
|---|---|---|
| `ARGON_M_COST` | 128 · 1024 KiB (128 MiB) | Standard beim Erzeugen neuer Schlüssel |
| `ARGON_T_COST` | 4 | Standard |
| `ARGON_LANES` | 1 | Standard |
| `ARGON_M_COST_MAX` | 1024 · 1024 KiB (1 GiB) | Obergrenze beim Öffnen einer `.hkey` |
| `ARGON_T_COST_MAX` | 10 | Obergrenze |
| `ARGON_LANES_MAX` | 4 | Obergrenze |

`open_private_blob()` liest die in der `.hkey`-Datei gespeicherten Parameter und lehnt sie ab, wenn sie diese Obergrenzen überschreiten — **bevor** der teure Argon2-Lauf gestartet wird. In `decrypt_stream()` wird zudem der Container-Header (`.hcx`) strukturell geprüft, **bevor** überhaupt die (Argon2-geschützte) `.hkey`-Datei geöffnet wird — laut Kommentar, damit eine offensichtlich kaputte oder fremde Container-Datei keinen vollen Argon2-Lauf mehr erzwingt.

**Passphrasen-Stärkeprüfung** (`check_passphrase_strength`, nur bei der Schlüsselerzeugung, nicht beim Öffnen bestehender Schlüssel):

```rust
const MIN_ZXCVBN_SCORE: u8 = 4;
const MIN_LOG10_GUESSES: f64 = 12.0;
pub const MIN_PASSPHRASE_CHARS: usize = 12;
```

Geprüft wird mit der `zxcvbn`-Crate; verlangt werden mindestens 12 Zeichen, Score 4 (von 0–4) **und** mindestens 10¹² geschätzte Rateversuche — die Kombination aus beidem lehnt laut Kommentar auch klassische, aber vorhersehbare „sichere" Muster ab. Ein eigener Kommentar merkt an, dass die von `zxcvbn`/`NFKC`-Normalisierung intern erzeugten Zwischenkopien auf dem normalen Heap landen, aber ausschließlich innerhalb desselben gehärteten Worker-Prozesses, der ohnehin die echte Passphrase verarbeitet.

Vor jeder Verwendung wird die Passphrase per **NFKC** normalisiert (`unicode-normalization`-Crate), damit dieselbe Eingabe unabhängig von der jeweiligen Normalform der Eingabemethode denselben Schlüssel ergibt.

**Öffentlicher Fingerabdruck** (`pubkey_fingerprint`): SHA-256 über den kompletten `.hpub`-Blob, davon die ersten 10 Byte (80 Bit) Base32-kodiert (Alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`, 16 Zeichen), durch Leerzeichen in fünf Gruppen unterteilt (nach den Bytes 2, 4, 6 und 8) — z. B. in der Form `AAAA QEA YEA UDA OCAJ` (Beispiel, keine echte Ausgabe).

### Oberfläche (`gui.rs`, `filepick.rs`)

`eframe`/`egui` wird mit `default-features = false` eingebunden; laut Kommentar im `Cargo.toml` sind dadurch bewusst ausgeschlossen:

- `accesskit` — würde UI-Text über AT-SPI/D-Bus an andere Prozesse geben
- `persistence` — würde Fenster-/App-Zustand nach `~/.local/share` schreiben
- `web_screen_reader` — irrelevant, nur zusätzliche Angriffsfläche

**Passphrase-Eingabe** läuft nicht über `egui::TextEdit`, sondern über ein selbst gezeichnetes Feld (`passphrase_field`). Begründung im Modul-Kommentar: `egui::TextEdit` hält in seinem Undo-Puffer vollständige `String`-Kopien der Eingabe im ungesperrten Heap. Das eigene Feld liest `egui::Event::Text`/`Event::Paste` direkt aus der Event-Warteschlange, kopiert die Zeichen in einen `SecureBuf` (`SecureString`) und überschreibt anschließend die vom Event-System gelieferte `String`-Kopie sofort mit Nullen. Dargestellt werden nur Punkte (`•`), nie der Klartext. Zeichenvergleich zweier Passphrase-Eingaben (Wiederholung beim Erzeugen) läuft über eine eigene, zeitkonstante Vergleichsfunktion (`ct_eq`).

Der **eingebaute Dateibrowser** (`filepick.rs`) ersetzt native Systemdialoge. Modul-Kommentar zur Begründung: GTK- und XDG-Portal-Implementierungen schreiben jede geöffnete Datei nach `~/.local/share/recently-used.xbel`, macOS führt äquivalente „Recent Items"-Listen — der eigene Dialog liest laut Kommentar nur Verzeichnisse und schreibt nichts. Als Kurzwahlen bietet er plattformabhängig u. a. `/dev/shm` und `/tmp` (Linux/Tails) bzw. `$TMPDIR` (macOS, mit Kommentar-Hinweis „plattenbasiert (APFS)") sowie `/home/amnesia/Persistent`, `/media`, `/Volumes` und das Persönliche Verzeichnis (`$HOME`).

Beim `on_exit`-Callback der App (`eframe::App::on_exit`) werden alle drei Passphrase-Puffer (`kg_pass`, `kg_pass_repeat`, `dec_pass`) explizit geleert, statt sich auf die Drop-Reihenfolge beim Prozessende zu verlassen.

---

## Dateiformate

Alle Angaben direkt aus den Konstanten und Lese-/Schreibfunktionen in `hybrid.rs`.

```
.hpub   "HPB2" | u32-len | ML-KEM-Encapsulation-Key | u32-len | P-384-Punkt (SEC1, unkomprimiert)
        encrypt_stream() lehnt jeden überzähligen Rest-Byte-Strom nach diesen
        beiden Feldern ab (cursor.is_empty()-Prüfung).

.hkey   "HSK2" | m_cost:u32 | t_cost:u32 | lanes:u32 | salt[16] | nonce[12]
              | ChaCha20-Poly1305( u32-len|ML-KEM-Decapsulation-Key || u32-len|P-384-Skalar )
              | tag[16]
        AAD des AEAD = alles vor dem Ciphertext (also inkl. Argon2-Parametern) -
        ein Downgrade der Argon2-Parameter fällt beim Entschlüsseln auf,
        weil das AAD dann nicht mehr passt.

.hcx    Header = "HCX3" | u32-len|ML-KEM-Ciphertext | u32-len|eph. P-384-Punkt | base_nonce[12]
        danach 1..n Chunks: u32-len | Ciphertext | tag[16]
        Nonce = base_nonce XOR counter (little-endian, in den letzten 8 Byte)
        AAD   = counter (8 Byte LE) || last_flag (1 Byte)
```

`last_flag` wird beim Verschlüsseln durch einen **Vorgriff-Puffer** bestimmt: `encrypt_stream()` hält zwei Chunk-Puffer (`cur`, `look`), liest den jeweils nächsten Chunk immer schon vor der Verschlüsselung des aktuellen, und setzt `last = look.len() == 0`. Da `last_flag` Teil des AAD jedes Chunks ist, würde ein Abschneiden der Datei bei der Authentifizierung des vorherigen Chunks aussehen, als fehle das korrekte `last_flag` — `decrypt_stream()` liest entsprechend ebenfalls immer einen Chunk voraus (`next_len = read_opt_u32(input)?` vor der Entschlüsselung des aktuellen Chunks), um zu wissen, ob der gerade gelesene Chunk der letzte ist.

Größenobergrenzen beim Lesen eines Containers (`decrypt_stream`, über `read_u32_prefixed(..., max: …)`): ML-KEM-Ciphertext-Feld max. 4096 Byte, eph. P-384-Punkt-Feld max. 256 Byte.

---

## Fehler- und Exit-Codes

Direkt aus `CryptoError::exit_code()` (`hybrid.rs`) sowie den beiden Konstanten in `secure.rs`, wie sie in `worker::run()` verwendet werden:

| Code | Herkunft | Bedeutung |
|---|---|---|
| 0 | — | Erfolg, alle Sperrungen gelungen |
| 1 | `CryptoError::Internal` | interner Fehler |
| 2 | `CryptoError::BadPassphrase` | falsche Passphrase oder manipulierte `.hkey` (AEAD-Tag der Schlüsseldatei ungültig) |
| 3 | `CryptoError::BadKeyFile` | Schlüsseldatei strukturell unbrauchbar / falsches Format |
| 4 | `CryptoError::BadContainer` | `.hcx` beschädigt, gekürzt oder manipuliert (AEAD-Tag eines Chunks oder Header ungültig) |
| 5 | `CryptoError::Io` | Ein-/Ausgabefehler |
| 6 | `CryptoError::WeakPassphrase` | neu gewählte Passphrase besteht die Stärkeprüfung nicht (nur bei Schlüsselerzeugung) |
| 7 | `secure::EXIT_CODE_STRICT_MLOCK_FAILED` | Speichersperrung fehlgeschlagen, `HYBRIDCRYPT_STRICT_MLOCK=1` aktiv → sofortiger Abbruch |
| 8 | `secure::EXIT_CODE_DEGRADED_LOCK` | Operation im Übrigen erfolgreich, aber mindestens eine Speichersperrung ist fehlgeschlagen |

Die GUI (`gui.rs::exit_code_message`) übersetzt diese Codes in Klartextmeldungen und behandelt Code 8 ausdrücklich **nicht** als Fehler: Die Ausgabedatei gilt als vollständig und korrekt und wird — anders als bei jedem anderen Code ≠ 0 — nicht per `wipe_and_remove()` gelöscht, sondern nur mit einer Warnung quittiert.

---

## Restrisiken

Ausschließlich Punkte, die sich direkt aus Code oder Code-Kommentaren ergeben:

1. **Speichersperrung ist nicht garantiert.** Ob `mlock` für ein einzelnes Secret gelingt, hängt von `RLIMIT_MEMLOCK` ab (`hardening.rs::raise_memlock_limit`). Reicht das Limit nicht, schlägt `mlock` fehl (`secure.rs::MmapSecret::new`); im Normalmodus läuft die Operation trotzdem weiter (Exit-Code 8, siehe oben), im strengen Modus (`HYBRIDCRYPT_STRICT_MLOCK=1`) bricht sie sofort ab. Der Standard ist also **nicht** fail-closed.

2. **`mlockall` läuft nur im Worker, und nur oberhalb eines Schwellwerts.** `try_mlockall()` wird laut Kommentar in `hardening.rs` bewusst übersprungen, wenn `RLIMIT_MEMLOCK` unter 320 MiB liegt, um nicht andere Allokationen mit `ENOMEM` scheitern zu lassen. Der GUI-Prozess ruft `mlockall` nie auf.

3. **Fremdbibliotheken legen eigene, nicht gesperrte Kopien an.** Wörtlich aus dem Modul-Kommentar von `secure.rs`: Die eigenen Speicherprimitive verhindern *nicht* Cold-Boot-Angriffe auf laufendes RAM, Zugriff durch einen Angreifer mit Kernel-Rechten zur Laufzeit, oder Kopien, die `ml-kem`, `argon2` (intern `blake2`) und `p384` selbst auf dem normalen Heap anlegen. Zusätzlich benannt in `hybrid.rs`: `zxcvbn` (Passphrasen-Stärkeprüfung) und die NFKC-Normalisierung erzeugen beim Aufruf externer APIs kurzzeitige Kopien auf dem normalen Heap, die der Code jeweils unmittelbar danach selbst überschreibt — aber eben erst *nachdem* die Fremdbibliothek ihre eigene Kopie bereits angelegt hatte.

4. **`ml-kem`s `DecapsulationKey` liegt während seiner Lebensdauer auf dem crate-eigenen Heap.** Das aktivierte `zeroize`-Feature (`Cargo.toml`) sorgt dafür, dass die Struktur beim `Drop` überschrieben wird — sie liegt aber nicht in einer der eigenen `SecureBuf`/`SecureBytes`-Regionen, solange sie lebt.

5. **macOS hat kein `/proc`-Äquivalent für den TOCTOU-Schutz.** `worker_exe_path()` nutzt `/proc/self/exe` nur unter Linux; unter macOS bleibt `std::env::current_exe()` mit dem im Code benannten Restrisiko eines ausgetauschten Binarys zwischen Pfadermittlung und `execve` — dort hängt der Schutz laut Kommentar von Code-Signing/Gatekeeper und einer Installation in einem nur für root beschreibbaren Verzeichnis ab, nicht von einer im Programm selbst umgesetzten Garantie.

6. **Entschlüsselte Chunks werden direkt in die Zieldatei geschrieben.** `decrypt_stream()` ruft `output.write_all(buf.as_slice())` pro Chunk unmittelbar auf den übergebenen Ausgabe-Deskriptor; es gibt im Code keine temporäre Datei und kein abschließendes atomares Umbenennen nach vollständiger Verifikation. Bricht die Operation vor dem letzten Chunk ab, kann bereits geschriebener Klartext bis zum expliziten Aufräumen (`wipe_and_remove`) auf der Platte liegen bleiben.

7. **Nur die Nutzdaten sind verschlüsselt, nicht der Dateiname.** Keines der drei Formate (`.hpub`, `.hkey`, `.hcx`) enthält ein Feld für den ursprünglichen Dateinamen — dieser bleibt also dem Ausgabenamen überlassen, den die Bedienperson vergibt.

8. **Der Worker ist über `ps`/`argv` als solcher erkennbar.** `proc.rs` startet ihn mit `cmd.arg("--worker")`; dass eine kryptografische Operation läuft, ist damit für andere lokale Prozesse desselben Systems sichtbar — welche Operation und mit welchen Schlüsseln, nicht, da diese ausschließlich über fd 3 übertragen werden.

9. **Kein Modulus-Check von ML-KEM-Schlüsseln.** `encrypt_stream()` dekodiert den Encapsulation-Key eines fremden `.hpub` über `Encoded::<…>::try_from(...)` und `EncapsulationKey::from_bytes(...)` aus der `ml-kem`-Crate; ob dabei der in FIPS 203 geforderte Modulus-Check erfolgt, liegt außerhalb dieses Quellcodes

10. **`PT_DENY_ATTACH`/`PR_SET_DUMPABLE=0` schützen nur vor Debugger-Attach.** Beide Aufrufe in `hardening.rs::deny_debugger()` verhindern laut ihrer dokumentierten Semantik ausschließlich das Anhängen eines Debuggers/`ptrace` bzw. den Zugriff über `/proc/<pid>/mem` — sie sind kein Schutz gegen Angreifer mit weitergehenden Rechten auf dem System.

---

## Bewusst nicht enthalten

Aus der Abwesenheit entsprechender Typen/Funktionen im Quellcode:

- **Keine Signatur oder Absenderauthentizität.** Weder `hybrid.rs` noch die Dateiformate enthalten ein Signaturschema (z. B. ML-DSA); `.hpub` und `.hkey` bestehen ausschließlich aus KEM-/ECDH-Schlüsselmaterial. Der AEAD-Tag jedes `.hcx`-Chunks beweist Integrität des Inhalts, nicht Urheberschaft — wer die `.hpub` eines Empfängers besitzt, kann eine für ihn gültige Datei erzeugen.
- **Kein Padding von Dateinamen oder -größe.** Die Containergröße hängt direkt und ohne Ausgleich von der Klartextgröße ab (`push_u32_prefixed`/Chunk-Längen).
- **Kein zusätzliches Keyfile als zweiter Argon2-Faktor.** `derive_kek()` nimmt ausschließlich `salt` und die (normalisierte) Passphrase entgegen.

