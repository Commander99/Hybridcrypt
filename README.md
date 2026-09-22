# hybridcrypt 0.3.0

Dateiverschlüsselung mit **ML-KEM-1024 (FIPS 203) × P-384 ECDH × HKDF-SHA-256**,
Nutzdaten mit ChaCha20-Poly1305. Ein einziges Binary, native Oberfläche

Ziel: macOS 13.7 und Tails.

---

## 0. Versionsüberblick

| Version | Anlass |
|---|---|
| 0.1 | Erste Fassung: lokaler HTTP-Server, `multipart/form-data`-Upload |
| 0.2 | Multipart-Parser-Fehler gefunden; komplette Web-Architektur durch native GUI ersetzt; erster interner Sicherheitsdurchgang (§7) |
| 0.2.1 | Zwei GUI-Fehler auf macOS behoben: Tastatureingabe funktionierte in keinem Feld, Kontrast unzureichend (§6) |
| **0.3.0** | Reaktion auf ein **externes** Audit (§8): Speicherprimitive komplett neu gebaut (exklusive `mmap`-Regionen mit Guard-Pages statt `Vec<u8>`), Passphrasen-Stärkeprüfung, Schlüssel-Fingerabdruck, Empfänger-Bindung im KDF, TOCTOU-Fix beim Worker-Start, engere Parametergrenzen




---



## 2. Architektur

```
main.rs
 ├─ Rolle "GUI" (Standardstart)
 │    hardening::harden_process(Role::Gui)   <- IMMER zuerst
 │    - natives Fenster, kein Netzwerk, kein Port
 │    - eigener Dateibrowser (kein GTK/XDG-Portal)
 │    - eigenes Passphrase-Feld, schreibt direkt in gesperrten Speicher
 │    - oeffnet Ein-/Ausgabedateien und reicht nur DESKRIPTOREN weiter
 │
 └─ Rolle "Worker" (`--worker`, per Re-Exec gestartet)
      hardening::harden_process(Role::Worker)  <- IMMER zuerst, auch hier
      fd 0 = Eingabedatei      fd 1 = Ausgabedatei      fd 2 = /dev/null
      fd 3 = Steuerkanal (Operation, Public Key, Passphrase)
      fd 4 = zweite Ausgabedatei (nur Schluesselerzeugung)
      - macht die Kryptografie, endet danach sofort
      - Fehler verlassen den Prozess NUR als Exit-Code
```

### Re-Exec statt `fork()`

Rohes `fork()` würde den **kompletten** Elternspeicher erben, inklusive aller
Kopien, die das GUI-Toolkit von Eingaben angelegt hat, und ist in einem Prozess
mit mehreren Threads (jedes GUI-Toolkit hat welche) nach POSIX nur eingeschränkt
zulässig. Re-Exec gibt einen jungfräulichen Adressraum ab `main()`.

**Seit 0.3.0 (Audit HC-10):** der Worker wird unter Linux über `/proc/self/exe`
gestartet, nicht über den von `current_exe()` gelieferten Pfad-STRING. Der
Unterschied: `current_exe()` liefert nur einen Pfad; zwischen dem Ermitteln
dieses Pfads und dem tatsächlichen `execve` in `Command::spawn()` könnte ein
Angreifer mit Schreibrecht auf diesen Pfad die Datei austauschen (TOCTOU).
`/proc/self/exe` ist ein vom Kernel gepflegter Verweis auf das GERADE LAUFENDE
Programm-Image und zeigt nach `fork()` im Kind (das bis zum `exec` noch exakt
dasselbe Image ausführt) zuverlaessig auf genau dieses Image. macOS kennt kein
Äquivalent zu `/proc`; dort bleibt `current_exe()` — abgesichert durch
Code-Signing/Gatekeeper und eine Installation in einem nur für root
beschreibbaren Verzeichnis, siehe §12.10. Zusaetzlich schließt der Worker vor
dem `exec` alle Deskriptoren `>= 5`, damit nichts unbeabsichtigt vererbt wird.

### Warum der Klartext den GUI-Prozess nie berührt

Der Elternprozess öffnet Eingabe- und Ausgabedatei und übergibt dem Kind nur
die **Deskriptoren**. Der Klartext fließt Datei → Kind → Datei. Im GUI-Prozess
liegt davon kein einziges Byte. Die Operation steht **nicht** in `argv` — `argv`
ist für jeden lokalen Nutzer in `ps` und `/proc/<pid>/cmdline` lesbar. Sie geht
über fd 3.

---

## 3. Dateiformate (Version 3)

```
.hpub   "HPB2" | u32 | ML-KEM-EK | u32 | P-384-Punkt (SEC1)
        Keine ueberzaehligen Bytes danach erlaubt (seit 0.3.0, Audit HC-15).

.hkey   "HSK2" | m_cost u32 | t_cost u32 | lanes u32 | salt[16] | nonce[12]
              | ChaCha20-Poly1305( u32|ML-KEM-DK || u32|P-384-Skalar ) | tag[16]
        AAD = alles vor dem Ciphertext

.hcx    Header = "HCX3" | u32 | ML-KEM-CT | u32 | eph. P-384-Punkt | base_nonce[12]
        danach 1..n Chunks:  u32 len | Ciphertext | tag[16]
        Nonce = base_nonce XOR counter (LE, letzte 8 Byte)
        AAD   = counter(8, LE) || last_flag(1)
```

Sitzungsschlüssel (seit 0.3.0):
```
HKDF-SHA256(
    IKM  = ML-KEM-SS || ECDH-SS,
    info = "hybridcrypt-v3" || Header || SHA256(Empfaenger-ML-KEM-EK || Empfaenger-P384-Punkt)
)
```

---

## 4. Erster interner Sicherheitsdurchgang (im Rahmen von 0.2)

| Befund | Bewertung | Status |
|---|---|---|
| Truncation-Angriff auf `.hcx` (Chunks abschneidbar, Erfolg gemeldet) | hoch | behoben (`last_flag`) |
| ML-KEM-Ciphertext als `Encoded<EncapsulationKey>` geparst — kompilierte nur, weil beide zufaellig 1568 Byte sind | mittel | korrekter `Ciphertext<MlKem1024>` |
| `mlock()` auf rohem `Vec`-Zeiger ohne Seitenausrichtung — auf macOS regelmaessig `EINVAL`, Sperre still wirkungslos | hoch | page-aligned (0.2), inzwischen durch eigene `mmap`-Region ersetzt (0.3.0, §8) |
| Klartext-Chunks in **ungesperrten** `Vec`s | hoch | durchgehend In-Place in `SecureBuf` |
| Argon2 allokierte seine 64 MiB selbst: ungesperrt, ohne Zeroize | hoch | `hash_password_into_with_memory` mit eigenem gesperrtem Block-Array |
| `mlockall(MCL_FUTURE)` in **jedem** Prozess: jede Allokation ueber `RLIMIT_MEMLOCK` haette mit ENOMEM fehlgeschlagen | hoch | Limit erst anheben, nur im Worker, nur wenn es reicht |
| `panic = "abort"` → kein Drop → kein Zeroize | mittel | auf `unwind` umgestellt |
| Systemdateidialog schreibt jeden Dateinamen nach `recently-used.xbel` | mittel (forensisch) | eigener Dateibrowser, schreibt nichts |
| `egui::TextEdit`-Undo-Puffer haelt `String`-Kopien der Passphrase im Heap | mittel | eigenes Eingabefeld |
| Ausgabedateien wurden stillschweigend ueberschrieben | mittel (Datenverlust) | `create_new` + `umask(0077)` → 0600 |

---

## 5. Externes Audit (0.3.0)

Ein unabhängiges Audit des Standes 0.2.1 (vollstaendiger Quelltext, `Cargo.lock`,
README; ohne Compiler, ohne Netzwerk, ohne Ausführung) kam zu folgendem
Gesamturteil: **keine gebrochene Kryptografie, keine aus der Ferne ausnutzbare
Parser-Schwachstelle.** Alle Funde lagen in drei Bereichen: Speicherhärtung,
Schlüssel-/Passphrasenbehandlung, Lieferketten-Absicherung.

Die folgende Tabelle bildet jeden Befund auf seine Kennung im Audit ab. Jede Zeile
wurde tatsaechlich im Code umgesetzt und danach getestet (§9) — nicht nur als
Uebersicht behauptet.

| ID | Befund | Umsetzung |
|---|---|---|
| HC-01 | `mlock`-Fehlschlaege wurden verschluckt; UI/README behaupteten pauschal "alle Geheimnisse gesperrt" | Jeder Sperrfehlschlag wird gezaehlt (`secure::lock_failure_count()`). Erfolgreiche, aber degradierte Operationen melden einen eigenen Exit-Code (8) statt blossem Erfolg; die GUI zeigt das als gelbe Warnung mit Klartext-Erklaerung, behaelt aber die (kryptografisch korrekte) Ausgabedatei. Optionaler strenger Modus `HYBRIDCRYPT_STRICT_MLOCK=1`: bricht beim ERSTEN Sperrfehlschlag sofort ab (Exit 7), bevor die Operation fortgesetzt wird. Die frueher falsche Statuszeile ist entfernt. |
| HC-02 | Keine Fingerabdruck-/Identitaetspruefung fuer `.hpub` — Schluessel-Substitution ist der realistischste Angriff auf ein solches Werkzeug | `pubkey_fingerprint()`: SHA-256 der kanonischen `.hpub`-Bytes, als 4er-Gruppen Base32 dargestellt. Wird nach der Schluesselerzeugung UND beim Auswaehlen eines Empfaenger-Schluessels im Verschluesseln-Tab angezeigt, mit dem Hinweis, ihn ausserhalb des Programms abzugleichen. |
| HC-03 | Passphrasen-Policy pruefte nur die Zeichenzahl — "Summer2026!!" (12 Zeichen, ~10⁸ Rateversuche) waere akzeptiert worden | Ersetzt durch `zxcvbn` (Score 4 UND ≥10¹² geschaetzte Rateversuche), ausschliesslich im Worker-Prozess ausgefuehrt (siehe Restrisiko §12.2). Lehnt kalibriert genau die im Audit genannten und verwandte Problemfaelle ab (getestet, §9). Zusaetzlich: NFKC-Normalisierung der Passphrase vor jeder KDF-Nutzung, damit macOS und Tails bei unterschiedlicher Sonderzeichen-Normalisierung denselben Schluessel ableiten. Gilt nur fuer NEU erzeugte Passphrasen, nie rueckwirkend beim Entschluesseln. |
| HC-04 | `ml-kem`/`argon2` zeroizen ihre interne Kopie des Schluesselmaterials nicht ohne explizites Feature bzw. gar nicht | `ml-kem`s `zeroize`-Feature aktiviert (war nicht in den Defaults) — die volle `DecapsulationKey`-Struktur wird jetzt beim Drop ueberschrieben. Fuer Argon2s internen Blake2b/H0-Zustand gibt es in der Crate **keine** Zeroize-Anbindung; das bleibt ein dokumentiertes Restrisiko (§12.2), das ohne Fork der Fremd-Crate nicht schliessbar ist. |
| HC-05 | `wipe_raw` nutzte `ptr::write_bytes` + `compiler_fence` — kein von Rust garantierter Schutz gegen Dead-Store-Elimination | Ersetzt durch die `Zeroize`-Implementierung der `zeroize`-Crate (garantiert volatile Schreibzugriffe) fuer jede Nullung in `secure.rs` und `hybrid.rs`. |
| HC-06 | Der entschluesselte Ausgabestrom lief durch einen `BufWriter`: jeder Chunk unter 64 KiB (mindestens der letzte jeder Datei) landete zusaetzlich in einer ungesperrten, nie geleerten Heap-Kopie | Der Worker schreibt den Klartext-Ausgabestrom beim Entschluesseln jetzt UNGEPUFFERT — `hybrid.rs` schreibt ohnehin schon in 64-KiB-Chunks, ein `BufWriter` hatte keinen Geschwindigkeitsvorteil, nur die zusaetzliche Kopie. Encrypt- und Keygen-Ausgaben (kein Klartext) bleiben gepuffert. |
| HC-07 | `mlock`/`munlock` sperren auf Linux/macOS ganze SEITEN und stapeln sich nicht (POSIX/Linux-Manpage: "Memory locks do not stack") — zwei kleine Secrets auf derselben Seite haetten sich beim Drop des einen gegenseitig entsperrt | `secure.rs` komplett neu gebaut: jeder `SecureBuf`/`SecureBytes` bekommt eine **eigene, exklusive `mmap`-Anonymous-Region**, niemals geteilt mit irgendeiner anderen Allokation. Zusaetzlich Guard-Pages (`PROT_NONE`) vor und hinter jedem Puffer — ein Off-by-one fuehrt zu einem sofortigen Segfault statt zu stillem Lesen/Schreiben von Nachbarspeicher. |
| HC-08 | Entschluesselte Chunks werden direkt in die Zieldatei geschrieben; bei Abbruch/Manipulation bleibt bereits geschriebener Klartext bis zum expliziten Aufraeumen liegen | Nicht veraendert — siehe Einordnung und Restrisiko in §12.1. Eine atomare Variante (`O_TMPFILE` + `linkat` nach Verifikation des letzten Chunks) ist eine sinnvolle Erweiterung, aber aus Zeitgruenden in dieser Runde nicht umgesetzt; siehe §13. |
| HC-09 | Argon2 lief vor jeder Pruefung des `.hcx`-Headers (teurer KDF-Lauf schon fuer offensichtlichen Muell); `.hkey` erlaubte `m_cost` bis 4 GiB / `t_cost` bis 64 / `lanes` bis 16 | Container-Header wird jetzt VOR dem Oeffnen der (Argon2-geschuetzten) Schluesseldatei gelesen und strukturell validiert. Argon2-Parametergrenzen auf 1 GiB / t=10 / p=4 verschaerft (deckt die eigenen Default-Parameter 128 MiB/t=4/p=1 klar ab). `.hpub`/`.hkey`-Dateien werden in der GUI nur noch bis 1 MiB gelesen. |
| HC-10 | Worker-Start ueber einen von `current_exe()` gelieferten PFAD-STRING (TOCTOU-Fenster zwischen Pfadermittlung und `execve`); Deskriptor-Hygiene unvollstaendig | Start ueber `/proc/self/exe` unter Linux (§3). Alle Deskriptoren `>= 5` werden vor `exec` geschlossen; die zuvor offene hohe Kopie der umplatzierten Steuerkanal-/Ausgabe-Deskriptoren wird zusaetzlich explizit geschlossen. |
| HC-11 | Tastaturereignisse koennten teilweise an unserem Abfangen vorbeigehen (IME/Totzeichen unbestaetigt) | Nicht veraendert — bleibt dokumentiertes Restrisiko (§12.5), da eine vollstaendige Kontrolle ueber winit/IME-interne Kopien ohne Fork dieser Bibliotheken nicht moeglich ist. |
| HC-12 | KDF bindet die statischen Empfaenger-Schluessel nicht — kein bekannter Angriff, aber unueblich fuer diese Art Protokoll | SHA-256 der Empfaenger-Schluessel zusaetzlich in `info` gebunden, symmetrisch auf beiden Seiten abgeleitet (§4). Format-Bump `HCX2` → `HCX3`. |
| HC-13 | Diverse Dokumentationsfehler: `mlock` verhindert keine Hibernation-Images; Dateigroessen-Angabe war ungenau; `/dev/shm` existiert nicht unter macOS | Alle drei korrigiert: Hibernation-Hinweis in §12.3 praezisiert; exakte Groessenformel in §9 ergaenzt; Dateibrowser-Kurzwahl jetzt plattformabhaengig (macOS bekommt `$TMPDIR` mit Hinweis auf Plattenbasis statt eines toten `/dev/shm`-Knopfes). |
| HC-14 | Abhaengigkeiten unaudited/vor 1.0; `p384` zog per Default `ecdsa`/`pem`/`pkcs8` unnoetig mit | `p384` jetzt mit `default-features = false`, nur `ecdh` + `std`. `cargo audit` durchlaufen (§9): keine Sicherheitsluecken, eine Low-Risk-Meldung zu einer transitiven Font-Rendering-Abhaengigkeit von `egui` selbst (`ttf-parser`, "unmaintained", beruehrt keine Kryptografie). |
| HC-15 | Kleinere Parser-/Robustheitspunkte: `.hpub` akzeptierte ueberzaehlige Bytes; kein Retry bei `EINTR`; ML-KEM-EK-Modulus-Check unbestaetigt; Zaehlerueberlauf ungeprueft | Ueberzaehlige Bytes in `.hpub` werden abgelehnt (getestet, §9). `EINTR` wird beim Lesen jetzt korrekt wiederholt statt als Fehler propagiert. `overflow-checks = true` im Release-Profil. Der ML-KEM-Modulus-Check bleibt ein dokumentiertes, nur senderseitig relevantes Restrisiko (§12.6), da er innerhalb der `ml-kem`-Crate liegt. |

### 8.1 Bewusste Abweichung von einer Audit-Empfehlung

Das Audit schlug fuer HC-01 vor, standardmaessig fail-closed zu arbeiten (Abbruch
bei jedem Sperrfehlschlag) und ein `--allow-unlocked`-Opt-out anzubieten. Diese
Version macht es umgekehrt: **Standard ist die ehrliche Warnung, strenges
Fail-Closed ist Opt-in** (`HYBRIDCRYPT_STRICT_MLOCK=1`). Begruendung: macOS'
Standard-`RLIMIT_MEMLOCK` und erst recht der auf manchen Tails-Konfigurationen
gueltige Wert reichen fuer den 128-MiB-Argon2-Puffer haeufig nicht aus, ohne dass
der Nutzer das beeinflussen koennte. Ein standardmaessig fail-closed arbeitendes
Sicherheitswerkzeug, das bei vielen Nutzern von vornherein gar nicht startet,
fuehrt erfahrungsgemaess dazu, dass Nutzer auf weniger sichere Alternativen
ausweichen — ein schlechteres Ergebnis als eine ehrliche, sichtbare Warnung bei
weiterhin korrekter Kryptografie. Wer die staerkere Garantie will, aktiviert sie
explizit.

---

## 9. Verifikation

Alle folgenden Angaben stammen aus tatsaechlichen Laeufen des ausgelieferten
Release-Builds (rustc 1.91, Linux x86_64). `cargo check` laeuft fehler- **und**
warnungsfrei.

**Round-Trip ueber die Chunk-Grenzen**, erneut nach dem kompletten Umbau von
`secure.rs` geprueft (Ausgabe jeweils Byte-fuer-Byte identisch zur Eingabe):

```
size=0       enc=0 dec=0 ct=1709    OK   <- leere Datei
size=1       enc=0 dec=0 ct=1710    OK
size=1000    enc=0 dec=0 ct=2709    OK
size=65535   enc=0 dec=0 ct=67244   OK
size=65536   enc=0 dec=0 ct=67245   OK   <- exakt eine Chunk-Groesse
size=65537   enc=0 dec=0 ct=67266   OK
size=131072  enc=0 dec=0 ct=132801  OK
size=300000  enc=0 dec=0 ct=301789  OK
```

Exakte Container-Groesse: `1689 + N + 20 · max(1, ⌈N/65536⌉)` Byte fuer N Byte
Klartext (Audit HC-13 — die vorherige Beschreibung "auf ~64 KiB genau" war
ungenau formuliert).

**Negativtests** (Exit-Code des Workers):

```
falsche Passphrase              -> 2
manipulierte .hkey (1 Bitflip)  -> 2
Argon2-Parameter heruntergedreht-> 2
.hpub als .hkey untergeschoben  -> 3
fremdes Schluesselpaar          -> 4
letzter Chunk abgeschnitten     -> 4
5 Bytes abgeschnitten           -> 4
Bitflip in den Nutzdaten        -> 4
Bitflip im Header (Basis-Nonce) -> 4
zwei Chunks vertauscht          -> 4
zu schwache Passphrase (Keygen) -> 6   <- NEU (Audit HC-03), inkl. exakt
                                          "Summer2026!!" aus dem Audit-Beispiel
ueberzaehlige Bytes in .hpub    -> 3   <- NEU (Audit HC-15)
m_cost = 4 GiB (altes Limit)    -> 3   <- NEU (Audit HC-09, jetzt abgelehnt)
```

**Speichersperre, jetzt inklusive der neuen Exit-Codes** — getestet als
unprivilegierter Nutzer mit `ulimit -l 8` (garantiert zu wenig fuer den
128-MiB-Argon2-Puffer):

```
Normalmodus:                              Exit 8 (Dateien korrekt UND vorhanden)
HYBRIDCRYPT_STRICT_MLOCK=1:               Exit 7 (Dateien 0 Byte, nichts geschrieben)
```

Der mit fehlgeschlagener Sperrung erzeugte Schluessel wurde zusaetzlich auf
kryptografische Korrektheit geprueft: Verschluesseln/Entschluesseln damit
funktioniert einwandfrei — die Speichersperre ist eine zusaetzliche
Haertungsmassnahme, keine Voraussetzung fuer korrekte Kryptografie.

**Fingerabdruck** (`pubkey_fingerprint`): deterministisch (zweimalige Berechnung
desselben Schluessels ergibt dieselbe Zeichenkette) und kollisionsfrei zwischen
zwei verschiedenen, tatsaechlich erzeugten Schluesselpaaren getestet.

**`cargo audit`**: 389 Abhaengigkeiten gescannt, **0 Sicherheitsluecken**, eine
Warnung zu `ttf-parser` (transitiv ueber `egui`s Font-Rendering, "unmaintained",
siehe HC-14).

**Prozess- und Deskriptorpfad.** Der vollstaendige Weg GUI → `proc.rs` → Worker
(Pipe auf fd 3, zweite Ausgabe auf fd 4, Ein-/Ausgabe als Deskriptoren auf
fd 0/1, Exit-Code-Propagierung, Start ueber `/proc/self/exe`) wurde erneut mit
mehreren hundert KiB Nutzdaten durchlaufen: Keygen, Verschluesseln und
Entschluesseln jeweils korrekt, Roundtrip byteidentisch. Alle erzeugten Dateien
hatten Modus `0600`.

**Oberflaeche.** Unter Xvfb mit echtem Fenstermanager erneut durchlaufen:
Passphrase-Eingabe (jetzt mit realer Staerkepruefung), Fingerabdruck-Anzeige nach
Schluesselerzeugung sichtbar und korrekt formatiert, korrigierte (nicht mehr
pauschale) Statuszeile sichtbar.

**Was in dieser Umgebung weiterhin NICHT verifiziert ist:**
- Das Verhalten auf echtem macOS 13.7 und echter Tails-Hardware (kein Zugriff in
  dieser Umgebung).
- Die vom Audit selbst vorgeschlagenen KATs (NIST ACVP fuer ML-KEM, Wycheproof
  fuer P-384-ECDH, RFC-Vektoren fuer HKDF/ChaCha20-Poly1305/Argon2id) und
  Fuzzing der Parser — beides erfordert Testvektor-Infrastruktur bzw.
  Langzeitlaeufe, die im Rahmen dieser Antwort nicht aufgebaut wurden. Die in
  diesem Abschnitt gezeigten Tests sind gezielte Fallunterscheidungen
  (Grenzwerte, Manipulationen, Negativfaelle), kein Ersatz fuer systematisches
  Fuzzing.
- Ob `hybrid-array`s eigene `Zeroize`-Implementierung fuer `Array<T,N>` in
  diesem konkreten Build durch Feature-Unifikation aktiv ist. Das ist ohne
  Belang fuer die Korrektheit: der Code ueberschreibt jede von einer
  Fremd-API zurueckgegebene Kopie eines Secrets explizit selbst (`.as_mut()`
  gefolgt von `.zeroize()`), unabhaengig davon, ob die Bibliothek das beim
  Drop zusaetzlich auch selbst taete.

---

## 10. Bauen

```sh
cargo build --release --locked
# Ergebnis: target/release/hybridcrypt  (eine Datei, keine Assets)
```

`--locked` verwendet exakt die in `Cargo.lock` eingetragenen, mit `cargo audit`
geprueften Versionen (Audit HC-14) statt neuere, ungeprüfte Versionen aufzuloesen.

Kein `cmake`, kein C++-Toolchain, keine `-dev`-Pakete noetig.

**Rust-Version:** gebaut und getestet mit rustc 1.91. Untergrenze ist die MSRV
von `eframe 0.33`, also Rust 1.85.
Tails ist amnesisch — bau das Binary auf einem separaten Rechner und bring es
auf einem Stick mit.

**macOS:** ein per `cargo build` erzeugtes Binary ist nicht signiert. Beim ersten
Start greift Gatekeeper; Rechtsklick → „Oeffnen", oder `xattr -d com.apple.quarantine`.
Installiere das Binary in ein nur fuer root beschreibbares Verzeichnis (z.B.
`/usr/local/bin` mit restriktiven Rechten) — das ist die Grundlage, auf der sich
§3s Aussage zum TOCTOU-Restrisiko auf macOS stuetzt.

**Sicherheitsrelevante Umgebungsvariable:**
`HYBRIDCRYPT_STRICT_MLOCK=1 ./hybridcrypt` — bricht jede Operation sofort ab,
sobald eine Speichersperrung fehlschlaegt, statt mit einer Warnung fortzufahren
(§8, HC-01/8.1).

---

## 11. Bedienung

* **Schluessel erzeugen** — legt `<name>.hpub` (weitergeben) und `<name>.hkey`
  (geheim halten) an. Die Passphrase schuetzt ausschliesslich die `.hkey` und
  muss eine echte Staerkepruefung bestehen (§8, HC-03) — reine Zeichenzahl reicht
  nicht. Nach der Erzeugung wird ein Fingerabdruck angezeigt (§8, HC-02); den
  ausserhalb dieses Programms weitergeben.
* **Verschluesseln** — braucht die `.hpub` des Empfaengers, keine Passphrase.
  Beim Auswaehlen wird deren Fingerabdruck angezeigt — **vor dem Verschluesseln
  mit dem Empfaenger ausserhalb dieses Programms abgleichen** (Telefon, zweiter
  Kanal). Das ist der wirksamste Einzelschritt gegen eine ausgetauschte
  Schluesseldatei.
* **Entschluesseln** — braucht deine `.hkey` und deren Passphrase.

Bestehende Dateien werden nie ueberschrieben; waehle bei Bedarf einen anderen Namen.

---

## 12. Restrisiken

1. **Die entschlüsselte Datei liegt auf der Platte.** Das ist der Zweck der
   Übung, aber es ist die grösste Spur. Auf SSDs ist Ueberschreiben wegen
   Wear-Levelling und FTL-Remapping **keine** Garantie. Lege Ausgaben auf ein
   RAM-Dateisystem (`/dev/shm` unter Linux/Tails; unter macOS gibt es
   standardmaessig keins — der Dateibrowser bietet dort ersatzweise `$TMPDIR`
   an, das aber PLATTENBASIERT ist; fuer eine echte RAM-Disk unter macOS:
   `diskutil erasevolume HFS+ RAMDisk $(hdiutil attach -nomount ram://204800)`).
   Ungeloest bleibt ausserdem (Audit HC-08): entschluesselte Chunks werden
   direkt in die Zieldatei geschrieben, nicht erst nach vollstaendiger
   Verifikation atomar umbenannt — bei Abbruch oder Manipulation kann bereits
   geschriebener Klartext bis zum automatischen Aufraeumen (`wipe_and_remove`)
   kurzzeitig auf der Platte liegen.

2. **Kryptografische Bibliotheken legen eigene, nicht gesperrte Kopien an.**
   Zwei konkret benannte Faelle (Audit HC-04): Argon2s interner Blake2b/H0-
   Zustand hat keine Zeroize-Anbindung in der verwendeten Crate; die
   Staerkepruefung einer neuen Passphrase (`zxcvbn`) legt bei der Mustersuche
   Kopien von Teilen der Eingabe auf dem normalen Heap an — beide Bibliotheken
   sind nicht fuer Geheimnisse gebaut. Mildernd: beides laeuft ausschliesslich
   im selben gehaerteten, kurzlebigen Worker-Prozess (mlockall soweit moeglich,
   keine Core-Dumps, PTRACE-Deny), der ohnehin schon die echte Passphrase
   verarbeitet — es entsteht keine ZUSAETZLICHE Preisgabe an den GUI-Prozess
   oder nach aussen, nur ein Rest derselben Art wie bei Argon2 selbst. Ohne
   Fork dieser Fremd-Crates ist das nicht schliessbar.

3. **`RLIMIT_MEMLOCK`.** Als normaler Nutzer sind unter Linux typisch 8 MiB
   erlaubt. Der 128-MiB-Argon2-Puffer wird dann **nicht** gesperrt; das Programm
   meldet das seit 0.3.0 ehrlich (Exit-Code 8, gelbe Warnung in der GUI) statt
   pauschalen Erfolg zu behaupten, und bricht per Default trotzdem nicht ab
   (§8.1). Tails hat keinen Swap, dort ist der Effekt gering. Fuer erzwungenes
   Fail-Closed: `HYBRIDCRYPT_STRICT_MLOCK=1`. Fuer vollstaendige Sperrung ohne
   Abbruch: `ulimit -l unlimited` vor dem Start (root noetig).

4. **Cold-Boot und Kernel-Zugriff.** `mlock` verhindert Swap, **nicht**
   Hibernation-Images: `pmset -a hibernatemode 3` unter macOS schreibt das volle
   RAM inklusive gesperrter Seiten auf die Platte (Audit HC-13) — fuer
   vollstaendigen Schutz `hibernatemode 0` setzen oder Hibernation deaktivieren.
   `mlock` verhindert ausserdem nicht das Auslesen von laufendem RAM durch einen
   Angreifer mit physischem oder Kernel-Zugriff. `PT_DENY_ATTACH` (macOS)
   verhindert nur ptrace-Attach durch andere Prozesse desselben Nutzers und ist
   fuer root wirkungslos (Audit-Praezisierung).

5. **`DecapsulationKey` der `ml-kem`-Crate.** Seit 0.3.0 mit aktiviertem
   `zeroize`-Feature wird die volle Struktur beim Drop ueberschrieben (Audit
   HC-04, behoben) — sie liegt aber weiterhin auf dem normalen, **nicht
   gesperrten** Crate-eigenen Heap waehrend ihrer Lebensdauer (wenige
   Millisekunden im kurzlebigen Worker-Prozess), nicht in einer unserer
   `SecureBuf`-Regionen. Fenster entsprechend kurz.

6. **ML-KEM-Modulus-Check.** Ob `ml-kem` beim Dekodieren einer
   Encapsulation-Key den in FIPS 203 §7.2 geforderten Modulus-Check durchfuehrt,
   ist unbestaetigt (Audit-Feststellung, liegt in der Fremd-Crate). Betroffen
   waere ausschliesslich die SENDENDE Seite bei einem praeparierten `.hpub`.

7. **Tastatureingabe vor unserem Puffer.** Der Weg
   Kernel → Compositor/X11 → `winit` → `egui` ist nicht unter unserer Kontrolle.
   Wir nullen die `String`s, die die Ereignisschleife uns uebergibt, sofort —
   fruehere Kopien in diesen Schichten, insbesondere bei IME-Komposition
   (Totzeichen, ostasiatische Eingabemethoden), koennen wir nicht erreichen und
   nicht ausschliessen (Audit HC-11, unveraendert). Ein Keylogger auf dem Geraet
   schlaegt jede Anwendungshaertung ohnehin.

8. **Nur die Nutzdaten sind geschuetzt.** Dateigroesse (exakte Formel in §9),
   Zeitpunkt und die Tatsache, dass verschluesselt wurde, sind sichtbar. Wenn
   der Dateiname geheim bleiben soll, pack die Datei vorher in ein Archiv.

9. **`ps` zeigt weiterhin `hybridcrypt --worker`.** Dass verschluesselt wird, ist
   also lokal erkennbar — nur nicht, womit.

10. **macOS-TOCTOU-Restrisiko bleibt bestehen, nur gemildert.** Ohne `/proc`-
    Aequivalent kann macOS die in §3 beschriebene Kernel-Garantie nicht
    nachbilden; dort schuetzt nur eine korrekte Installation (root-beschreibbares
    Verzeichnis) und Code-Signing/Gatekeeper vor einem ausgetauschten Binary.

---

## 13. Was bewusst nicht drin ist / in dieser Runde offen blieb

* **Keine Signatur/Absenderauthentizitaet.** Wer die `.hpub` hat, kann eine Datei
  „an dich" erzeugen. Der Container beweist Integritaet, nicht Urheberschaft.
  Wenn du das brauchst, ist ML-DSA (FIPS 204) die passende Ergaenzung.
* **Kein Dateinamen- oder Groessen-Padding.**
* **Kein Schluesselverzeichnis, keine Schluesselverwaltung
* **Kein Diceware-Generator in der Oberflaeche.** Die Staerkepruefung (§8,
  HC-03) lehnt schwache Passphrasen ab, schlaegt aber keine vor. Ein
  eingebauter Generator (sieben Woerter aus einer festen Liste) waere eine
  sinnvolle Ergaenzung.
* **Kein optionales Keyfile als zusaetzliches Argon2-Secret.** Vom Audit als
  moegliche Haertung gegen einen gestohlenen `.hkey` vorgeschlagen; nicht
  umgesetzt.
* **Die vom Audit vorgeschlagenen KATs und das Fuzzing (§9)** sind nicht Teil
  dieser Antwort.
