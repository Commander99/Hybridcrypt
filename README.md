# hybridcrypt

**Post-Quantum-Dateiverschlüsselung als natives Desktop-Tool — kein Server, kein Browser, kein offener Port.**

Hybrider Schlüsselaustausch aus **ML-KEM-1024** (FIPS 203, quantensicher) und **P-384-ECDH**, kombiniert per **HKDF-SHA-256**. Nutzdaten werden mit **ChaCha20-Poly1305** verschlüsselt. Ein einziges Binary, native Oberfläche (egui/eframe), Zielplattformen **macOS 13.7** und **Tails**.

![Version](https://img.shields.io/badge/version-0.3.0-blue) ![Plattform](https://img.shields.io/badge/platform-macOS%20%7C%20Tails%20%2F%20Linux-lightgrey) ![Sprache](https://img.shields.io/badge/language-Rust-orange)

---

## Inhaltsverzeichnis

1. [Überblick](#überblick)
2. [Version 0.3.0 — Änderungen](#version-030--änderungen)
3. [Installation & Bauen](#installation--bauen)
4. [Nutzungsanleitung](#nutzungsanleitung)
5. [Architektur](#architektur)
6. [Dateiformate](#dateiformate)
7. [Sicherheitsmodell](#sicherheitsmodell)
8. [Audit-Historie](#audit-historie)
9. [Verifikation](#verifikation)
10. [Restrisiken](#restrisiken)
11. [Bewusst nicht enthalten](#bewusst-nicht-enthalten)

---

## Überblick

hybridcrypt verschlüsselt einzelne Dateien für einen bestimmten Empfänger. Es gibt drei Operationen:

- **Schlüssel erzeugen** → eine öffentliche Datei (`.hpub`, weitergeben) und eine private, passphrasengeschützte Schlüsseldatei (`.hkey`, geheim halten)
- **Verschlüsseln** → mit der `.hpub` des Empfängers, ohne eigene Passphrase
- **Entschlüsseln** → mit der eigenen `.hkey` und deren Passphrase

Das Programm läuft vollständig lokal, ohne Netzwerkzugriff, ohne HTTP-Server und ohne Browser-Abhängigkeit. Der Klartext berührt zu keinem Zeitpunkt den GUI-Prozess (siehe [Architektur](#architektur)).

---

## Version 0.3.0 — Änderungen

| Version | Anlass |
|---|---|
| 0.1 | Erste Fassung: lokaler HTTP-Server, `multipart/form-data`-Upload |
| 0.2 | Multipart-Parser-Fehler gefunden; komplette Web-Architektur durch native GUI ersetzt; erster interner Sicherheitsdurchgang |
| 0.2.1 | Zwei GUI-Fehler auf macOS behoben: Tastatureingabe funktionierte in keinem Feld, Kontrast unzureichend |
| **0.3.0** | Reaktion auf ein **externes** Sicherheitsaudit: Speicherprimitive komplett neu gebaut (exklusive `mmap`-Regionen mit Guard-Pages statt `Vec<u8>`), Passphrasen-Stärkeprüfung, Schlüssel-Fingerabdruck, Empfänger-Bindung im KDF, TOCTOU-Fix beim Worker-Start, engere Parametergrenzen, ehrliche Speicherstatus-Meldung statt Pauschalbehauptung |

**Breaking Change in 0.3.0:** `.hcx`-Container im alten Format (Magic `HCX2`) sind mit 0.3.0 nicht mehr lesbar. `.hpub`/`.hkey` sind unverändert; ein mit 0.2.x erzeugtes Schlüsselpaar funktioniert weiter — bereits verschlüsselte `.hcx`-Dateien müssen mit dem alten Schlüssel unter 0.3.0 erneut verschlüsselt werden.

<details>
<summary>Vorgeschichte: warum die Web-Architektur (0.1) aufgegeben wurde</summary>

Version 0.1 nutzte einen lokalen HTTP-Server mit `multipart/form-data`-Upload. Ein Parserfehler in `read_small_part()` verwarf beim Boundary-Fund bereits gelesene Bytes unwiederbringlich, wodurch nachfolgende Dateien fehlschlugen (`Multipart-Header zu lang`). Der Parser wäre reparabel gewesen — die Web-Architektur selbst war es nicht, aus drei Gründen:

1. **Der Browser ist kein Geheimnisspeicher.** Passphrasen lagen als JS-Strings im GC-Heap: kein `mlock`, kein Zeroize, beliebig viele Kopien, kein definierter Freigabezeitpunkt.
2. **Der lokale Port war ungeschützt.** `multipart/form-data` löst als *simple request* im Sinne von CORS keinen Preflight aus — eine beliebige Webseite im selben Browser hätte die Verschlüsselungs-API cross-origin ansprechen können.
3. **Der Browser hinterlässt eigene Spuren:** Cache, Session Store, Verlauf, Download-Historie.

Seit 0.2 ist die Oberfläche nativ (egui/eframe, reines Rust, statisch gelinkt). X11/EGL werden zur Laufzeit per `dlopen` geladen — es sind keine Dev-Pakete zum Bauen nötig. Bewusst ausgeschaltet: `accesskit` (UI-Text über AT-SPI/D-Bus an fremde Prozesse), `persistence` (Fenster-/App-State auf Platte), `web_screen_reader`.

</details>

---

## Installation & Bauen

```sh
cargo build --release --locked
# Ergebnis: target/release/hybridcrypt  (eine einzelne Datei, keine Assets)
```

`--locked` verwendet exakt die in `Cargo.lock` eingetragenen, per `cargo audit` geprüften Versionen statt neuere, ungeprüfte Versionen aufzulösen. Es wird kein `cmake`, kein C++-Toolchain und kein `-dev`-Paket benötigt.

**Rust-Version:** gebaut und getestet mit rustc 1.91. Untergrenze ist die MSRV von `eframe 0.33`, also Rust 1.85.

**Tails:** Tails ist amnesisch — das Binary auf einem separaten Rechner bauen und per Stick mitbringen.

**macOS:** Ein per `cargo build` erzeugtes Binary ist nicht signiert. Beim ersten Start greift Gatekeeper — Rechtsklick → „Öffnen", oder `xattr -d com.apple.quarantine <pfad>`. Das Binary sollte in ein **nur für root beschreibbares Verzeichnis** installiert werden (z. B. `/usr/local/bin` mit restriktiven Rechten) — darauf stützt sich die Aussage zum TOCTOU-Restrisiko unter [Restrisiken](#restrisiken).

**Sicherheitsrelevante Umgebungsvariable:**

```sh
HYBRIDCRYPT_STRICT_MLOCK=1 ./hybridcrypt
```

Bricht jede Operation sofort ab, sobald eine Speichersperrung fehlschlägt, statt mit einer Warnung fortzufahren. Details dazu unter [Sicherheitsmodell](#sicherheitsmodell).

---

## Nutzungsanleitung

**Schlüssel erzeugen**
Legt `<name>.hpub` (weitergeben) und `<name>.hkey` (geheim halten) an. Die Passphrase schützt ausschließlich die `.hkey` und muss eine echte Stärkeprüfung bestehen — reine Zeichenzahl reicht nicht. Nach der Erzeugung wird ein **Fingerabdruck** angezeigt; diesen außerhalb des Programms weitergeben (z. B. mündlich).

**Verschlüsseln**
Benötigt die `.hpub` des Empfängers, keine eigene Passphrase. Beim Auswählen der Datei wird deren Fingerabdruck angezeigt — **vor dem Verschlüsseln mit dem Empfänger über einen zweiten Kanal abgleichen** (Telefon, persönliches Treffen). Das ist der wirksamste Einzelschritt gegen eine ausgetauschte Schlüsseldatei.

**Entschlüsseln**
Benötigt die eigene `.hkey` und deren Passphrase.

**Hinweis:** Bestehende Dateien werden nie überschrieben (`create_new` + `umask 0077` → Modus `0600`); bei einem Namenskonflikt einen anderen Zielnamen wählen.

---

## Architektur

### Prozessmodell

```
main.rs
 ├─ Rolle "GUI" (Standardstart)
 │    hardening::harden_process(Role::Gui)   <- IMMER zuerst
 │    - natives Fenster, kein Netzwerk, kein offener Port
 │    - eigener Dateibrowser (kein GTK/XDG-Portal, keine Systemhistorie)
 │    - eigenes Passphrase-Feld, schreibt direkt in gesperrten Speicher
 │    - öffnet Ein-/Ausgabedateien und reicht nur DESKRIPTOREN weiter
 │
 └─ Rolle "Worker" (`--worker`, per Re-Exec gestartet)
      hardening::harden_process(Role::Worker)  <- IMMER zuerst, auch hier
      fd 0 = Eingabedatei      fd 1 = Ausgabedatei      fd 2 = /dev/null
      fd 3 = Steuerkanal (Operation, Public Key, Passphrase)
      fd 4 = zweite Ausgabedatei (nur bei Schlüsselerzeugung)
      - führt ausschließlich die Kryptografie aus, beendet sich danach sofort
      - Fehler verlassen den Prozess NUR als Exit-Code, nie als Logausgabe
```

Der Elternprozess (GUI) öffnet Ein- und Ausgabedatei und übergibt dem Kindprozess (Worker) ausschließlich die **Dateideskriptoren**. Der Klartext fließt Datei → Kind → Datei; im GUI-Prozess liegt davon kein einziges Byte. Die Operation selbst steht **nicht** in `argv` — `argv` ist für jeden lokalen Nutzer über `ps` und `/proc/<pid>/cmdline` lesbar — sondern wird ausschließlich über fd 3 übergeben.

### Re-Exec statt `fork()`

Rohes `fork()` würde den kompletten Elternspeicher erben, inklusive aller Kopien, die das GUI-Toolkit von Eingaben angelegt hat, und ist in einem Mehr-Thread-Prozess (jedes GUI-Toolkit erzeugt Threads) nach POSIX nur eingeschränkt zulässig. Re-Exec dagegen liefert einen jungfräulichen Adressraum ab `main()`.

Seit 0.3.0 wird der Worker unter Linux über `/proc/self/exe` gestartet, nicht über den von `current_exe()` gelieferten Pfad-String. Der Unterschied ist sicherheitsrelevant: `current_exe()` liefert nur einen Pfad; zwischen dessen Ermittlung und dem tatsächlichen `execve` in `Command::spawn()` könnte ein Angreifer mit Schreibrecht auf diesen Pfad die Datei austauschen (**TOCTOU**). `/proc/self/exe` ist dagegen ein vom Kernel gepflegter Verweis auf das *gerade laufende* Programm-Image und zeigt zuverlässig auf genau dieses Image. Zusätzlich schließt der Worker vor dem `exec` alle Deskriptoren `≥ 5`, damit nichts unbeabsichtigt vererbt wird.

macOS kennt kein Äquivalent zu `/proc`; dort verbleibt `current_exe()`, abgesichert durch Code-Signing/Gatekeeper und eine Installation in einem nur für root beschreibbaren Verzeichnis (siehe [Installation](#installation--bauen)). Dieses Restrisiko ist unter [Restrisiken](#restrisiken) dokumentiert, nicht verschwiegen.

### Warum eine native Oberfläche statt Web

Siehe [Vorgeschichte](#version-030--änderungen) oben — kurz zusammengefasst: der Browser ist kein geeigneter Geheimnisspeicher, ein lokaler Port ist ohne CORS-Preflight angreifbar, und Browser hinterlassen eigene forensische Spuren.

---

## Dateiformate

```
.hpub   "HPB2" | u32 | ML-KEM-EK | u32 | P-384-Punkt (SEC1)
        Keine überzähligen Bytes danach erlaubt (seit 0.3.0)

.hkey   "HSK2" | m_cost u32 | t_cost u32 | lanes u32 | salt[16] | nonce[12]
              | ChaCha20-Poly1305( u32|ML-KEM-DK || u32|P-384-Skalar ) | tag[16]
        AAD = alles vor dem Ciphertext

.hcx    Header = "HCX3" | u32 | ML-KEM-CT | u32 | eph. P-384-Punkt | base_nonce[12]
        danach 1..n Chunks:  u32 len | Ciphertext | tag[16]
        Nonce = base_nonce XOR counter (little-endian, letzte 8 Byte)
        AAD   = counter(8, LE) || last_flag(1)
```

**Sitzungsschlüssel** (seit 0.3.0 mit Empfänger-Bindung):

```
HKDF-SHA256(
    IKM  = ML-KEM-SS || ECDH-SS,
    info = "hybridcrypt-v3" || Header || SHA256(Empfänger-ML-KEM-EK || Empfänger-P384-Punkt)
)
```

Gegenüber Format-Version 2 ist neu, dass der SHA-256-Hash der öffentlichen Empfänger-Schlüssel zusätzlich in `info` gebunden ist (zusätzliche, in HPKE/X-Wing übliche Absicherung gegen Mehrempfänger-Szenarien; kein konkreter Angriff ohne diese Bindung ist bekannt). Beim Entschlüsseln wird dieselbe Bindung aus dem eigenen privaten Schlüssel abgeleitet und muss byteidentisch zur Bindung sein, die beim Verschlüsseln aus der ursprünglichen `.hpub` berechnet wurde — andernfalls schlägt die Ableitung und damit jeder AEAD-Tag fehl.

`last_flag` markiert den letzten Chunk kryptografisch; jede Kürzung der Datei schlägt bei der Authentifizierung fehl. Der Header ist an den Sitzungsschlüssel gebunden. Die Argon2-Parameter stehen in der Schlüsseldatei und sind per AAD mitauthentifiziert — ein Downgrade ist nicht möglich.

**Exakte Containergröße:** `1689 + N + 20 · max(1, ⌈N/65536⌉)` Byte für N Byte Klartext.

---

## Sicherheitsmodell

| Sicherheitsziel | Umsetzung |
|---|---|
| Kein Disk-I/O für Klartexte oder Secrets | Secrets ausschließlich in RAM + Pipe (fd 3), nie in einer Datei. Der GUI-Prozess sieht den Klartext nie — das Kind streamt Deskriptor → Deskriptor. |
| Fork-Isolation, kein Secret-Leak in den Eltern-Heap | Re-Exec statt `fork()`, über `/proc/self/exe` unter Linux. |
| `mlock` für alle sensiblen Puffer | Jeder sensible Puffer (Passphrase, KEK, Sitzungsschlüssel, ML-KEM-DK, P-384-Skalar, beide Shared Secrets, jeder Klartext-Chunk) sowie der Argon2-Arbeitsspeicher liegen seit 0.3.0 in einer eigenen, exklusiven `mmap`-Region mit Guard-Pages. Ob die Sperrung im Einzelfall gelang, wird ehrlich gezählt und gemeldet statt pauschal behauptet. |
| Kein `String`/`&str` für Secrets | Kein Geheimnis wird zu `String` außerhalb der beiden Stellen, die es aus Formatgründen müssen (NFKC-Normalisierung, Stärkeprüfung) — beide ausschließlich im isolierten Worker-Prozess. |
| Sofortige Zeroization nach Nutzung | Sensible Puffer nullen beim Drop die gesamte Kapazität volatil (`zeroize`-Crate statt bloßem Compiler-Fence), danach `munlock`, danach `munmap`. |
| Core Dumps deaktiviert | `RLIMIT_CORE = 0`, zusätzlich `PR_SET_DUMPABLE=0` (Linux) bzw. `PT_DENY_ATTACH` (macOS, eingeschränkte Wirkung — siehe Restrisiken), zusätzlich `MADV_DONTDUMP` pro Secret-Seite unter Linux. |
| Kein Logging sensibler Daten | Worker-stderr auf `/dev/null`. Fehler verlassen das Kind nur als Exit-Code. |
| Kein Downgrade der KDF-Parameter | Argon2-Parameter sind Teil der authentifizierten Daten (AAD) der `.hkey`-Datei. |

**Fail-closed vs. ehrliche Warnung:** Standard ist eine sichtbare Warnung statt eines harten Abbruchs bei fehlgeschlagener Speichersperrung, da macOS' Standard-`RLIMIT_MEMLOCK` (und mancher Tails-Konfigurationen) für den 128-MiB-Argon2-Puffer oft nicht ausreicht, ohne dass Nutzer das beeinflussen können. Ein standardmäßig fail-closed arbeitendes Werkzeug, das bei vielen Nutzern gar nicht erst startet, führt erfahrungsgemäß dazu, dass auf weniger sichere Alternativen ausgewichen wird. Wer die strengere Garantie will, aktiviert sie explizit mit `HYBRIDCRYPT_STRICT_MLOCK=1`.

---

## Audit-Historie

**Interner Sicherheitsdurchgang (0.2):** deckte unter anderem einen Truncation-Angriff auf `.hcx`, eine falsch typisierte ML-KEM-Ciphertext-Deserialisierung, nicht seitenausgerichtetes `mlock`, ungesperrte Klartext-Puffer und `panic = "abort"` (verhindert Drop/Zeroize) auf — alle Punkte wurden vor 0.2.1 behoben.

**Externes Audit (Grundlage für 0.3.0):** ein unabhängiges Audit des Stands 0.2.1 (vollständiger Quelltext, `Cargo.lock`, README; ohne Compiler, ohne Netzwerk, ohne Ausführung) kam zum Gesamturteil: **keine gebrochene Kryptografie, keine aus der Ferne ausnutzbare Parser-Schwachstelle.** Alle Funde lagen in drei Bereichen — Speicherhärtung, Schlüssel-/Passphrasenbehandlung, Lieferketten-Absicherung — und wurden bis auf zwei explizit dokumentierte Ausnahmen (Tastatureingabe-Pfad vor dem eigenen Puffer; direktes Schreiben entschlüsselter Chunks ohne atomare Umbenennung) behoben. Details siehe [Restrisiken](#restrisiken).

Das Audit selbst benannte auch sein eigenes Limit: die dort vorgeschlagenen Known-Answer-Tests und das Fuzzing der Parser wurden **nicht** durchgeführt (siehe [Verifikation](#verifikation)).

---

## Verifikation

Alle folgenden Angaben stammen aus tatsächlichen Läufen des ausgelieferten Release-Builds (rustc 1.91, Linux x86_64). `cargo check` läuft fehler- und warnungsfrei.

**Round-Trip über Chunk-Grenzen** (Ausgabe jeweils byteidentisch zur Eingabe), unter anderem geprüft bei 0, 1, 1.000, 65.535, 65.536 (exakte Chunk-Größe), 65.537, 131.072 und 300.000 Byte.

**Negativtests** (Exit-Code des Workers) — u. a. falsche Passphrase, manipulierte `.hkey` (1 Bitflip), heruntergedrehte Argon2-Parameter, vertauschte Rolle von `.hpub`/`.hkey`, fremdes Schlüsselpaar, abgeschnittener letzter Chunk, Bitflip in Nutzdaten oder Header, vertauschte Chunks, zu schwache Passphrase bei der Schlüsselerzeugung, überzählige Bytes in `.hpub`, zu großzügige Argon2-Parameter — jeweils mit definiertem, unterschiedlichem Exit-Code abgelehnt.

**Speichersperre** unter `ulimit -l 8` (garantiert zu wenig für den 128-MiB-Argon2-Puffer): im Normalmodus Exit-Code 8 bei ansonsten korrekt geschriebenen Dateien; mit `HYBRIDCRYPT_STRICT_MLOCK=1` Exit-Code 7, keine Datei wird geschrieben. Ein trotz fehlgeschlagener Sperrung erzeugter Schlüssel wurde zusätzlich auf kryptografische Korrektheit geprüft — die Speichersperre ist eine zusätzliche Härtungsmaßnahme, keine Voraussetzung für korrekte Kryptografie.

**`cargo audit`:** 389 Abhängigkeiten gescannt, 0 Sicherheitslücken, eine Warnung zu `ttf-parser` (transitiv über `egui`s Font-Rendering, „unmaintained", berührt keine Kryptografie).

**Nicht verifiziert:**
- Verhalten auf echter macOS-13.7- und Tails-Hardware
- Die vom Audit vorgeschlagenen Known-Answer-Tests (NIST ACVP für ML-KEM, Wycheproof für P-384-ECDH, RFC-Vektoren für HKDF/ChaCha20-Poly1305/Argon2id) und systematisches Fuzzing der Parser

---

## Restrisiken

Diese Punkte kann kein Userland-Programm vollständig abnehmen. Sie stehen hier bewusst, statt stillschweigend übergangen zu werden.

1. **Die entschlüsselte Datei liegt auf der Platte.** Das ist der Zweck der Übung, aber die größte Spur. Auf SSDs ist Überschreiben wegen Wear-Levelling und FTL-Remapping **keine** Garantie. Ausgaben sollten auf ein RAM-Dateisystem gelegt werden (`/dev/shm` unter Linux/Tails; unter macOS gibt es standardmäßig keins — der Dateibrowser bietet dort ersatzweise `$TMPDIR` an, das aber **plattenbasiert** ist). Zusätzlich ungelöst: entschlüsselte Chunks werden direkt in die Zieldatei geschrieben, nicht erst nach vollständiger Verifikation atomar umbenannt — bei Abbruch oder Manipulation kann bereits geschriebener Klartext bis zum automatischen Aufräumen kurzzeitig auf der Platte liegen.

2. **Kryptografische Bibliotheken legen eigene, nicht gesperrte Kopien an.** Konkret: Argon2s interner Blake2b/H0-Zustand hat in der verwendeten Crate keine Zeroize-Anbindung; die Stärkeprüfung einer neuen Passphrase (`zxcvbn`) legt bei der Mustersuche Kopien von Teilen der Eingabe auf dem normalen Heap an. Beide laufen ausschließlich im selben gehärteten, kurzlebigen Worker-Prozess, der ohnehin schon die echte Passphrase verarbeitet — es entsteht keine zusätzliche Preisgabe nach außen, nur ein Rest derselben Art wie bei Argon2 selbst.

3. **`RLIMIT_MEMLOCK`.** Als normaler Nutzer sind unter Linux typisch 8 MiB erlaubt. Der 128-MiB-Argon2-Puffer wird dann **nicht** gesperrt; das Programm meldet das seit 0.3.0 ehrlich (Exit-Code 8, Warnung in der GUI) statt pauschalen Erfolg zu behaupten, und bricht per Default trotzdem nicht ab. Tails hat keinen Swap, dort ist der Effekt gering. Für erzwungenes Fail-Closed: `HYBRIDCRYPT_STRICT_MLOCK=1`. Für vollständige Sperrung ohne Abbruch: `ulimit -l unlimited` vor dem Start (root nötig).

4. **Cold-Boot und Kernel-Zugriff.** `mlock` verhindert Swap, **nicht** Hibernation-Images: `pmset -a hibernatemode 3` unter macOS schreibt das volle RAM inklusive gesperrter Seiten auf die Platte — für vollständigen Schutz `hibernatemode 0` setzen oder Hibernation deaktivieren. `mlock` verhindert außerdem nicht das Auslesen von laufendem RAM durch einen Angreifer mit physischem oder Kernel-Zugriff. `PT_DENY_ATTACH` (macOS) verhindert nur ptrace-Attach durch andere Prozesse desselben Nutzers und ist für root wirkungslos.

5. **`DecapsulationKey` der `ml-kem`-Crate.** Seit 0.3.0 mit aktiviertem `zeroize`-Feature wird die volle Struktur beim Drop überschrieben — sie liegt aber während ihrer Lebensdauer (wenige Millisekunden im kurzlebigen Worker-Prozess) weiterhin auf dem normalen, nicht gesperrten Crate-eigenen Heap, nicht in einer eigenen gesicherten Speicherregion. Das Zeitfenster ist entsprechend kurz.

6. **ML-KEM-Modulus-Check.** Ob die verwendete `ml-kem`-Crate beim Dekodieren eines Encapsulation-Keys den in FIPS 203 §7.2 geforderten Modulus-Check durchführt, ist unbestätigt. Betroffen wäre ausschließlich die sendende Seite bei einer präparierten `.hpub`.

7. **Tastatureingabe vor dem eigenen Puffer.** Der Weg Kernel → Compositor/X11 → `winit` → `egui` liegt nicht unter eigener Kontrolle. Übergebene Strings werden sofort genullt — frühere Kopien in diesen Schichten, insbesondere bei IME-Komposition (Totzeichen, ostasiatische Eingabemethoden), lassen sich weder erreichen noch ausschließen. Ein Keylogger auf dem Gerät schlägt jede Anwendungshärtung ohnehin.

8. **Nur die Nutzdaten sind geschützt.** Dateigröße (exakte Formel siehe [Dateiformate](#dateiformate)), Zeitpunkt und die Tatsache, dass überhaupt verschlüsselt wurde, sind sichtbar. Soll der Dateiname geheim bleiben, muss die Datei vorher in ein Archiv gepackt werden.

9. **`ps` zeigt weiterhin `hybridcrypt --worker`.** Dass verschlüsselt wird, ist also lokal erkennbar — nur nicht, womit.

10. **macOS-TOCTOU-Restrisiko bleibt bestehen, nur gemildert.** Ohne `/proc`-Äquivalent kann macOS die unter [Architektur](#architektur) beschriebene Kernel-Garantie nicht nachbilden; dort schützt nur eine korrekte Installation (root-beschreibbares Verzeichnis) sowie Code-Signing/Gatekeeper vor einem ausgetauschten Binary.

---

## Bewusst nicht enthalten

- **Keine Signatur/Absenderauthentizität.** Wer die `.hpub` hat, kann eine Datei „an dich" erzeugen. Der Container beweist Integrität, nicht Urheberschaft. Für Authentizität wäre ML-DSA (FIPS 204) die passende Ergänzung.
- **Kein Dateinamen- oder Größen-Padding.**
- **Kein Schlüsselverzeichnis, keine Schlüsselverwaltung.** Bewusst: jede Verwaltung wäre eine weitere Datenbank mit forensischem Inhalt.
- **Atomares Schreiben des Klartexts** ist als Restrisiko dokumentiert (siehe oben), aber nicht umgesetzt — eine sinnvolle Erweiterung wäre `O_TMPFILE` + `linkat` nach Verifikation des letzten Chunks.
- **Kein Diceware-Generator in der Oberfläche.** Die Stärkeprüfung lehnt schwache Passphrasen ab, schlägt aber keine vor.
- **Kein optionales Keyfile als zusätzliches Argon2-Secret**, obwohl als Härtung gegen eine gestohlene `.hkey` denkbar.
- **Die vorgeschlagenen Known-Answer-Tests und das Fuzzing** (siehe [Verifikation](#verifikation)) sind nicht Teil dieser Version.

---

*Dieses README beschreibt den technischen Stand von hybridcrypt 0.3.0 vollständig und ohne Beschönigung, einschließlich bekannter, nicht vollständig geschlossener Restrisiken. Es ersetzt keine unabhängige Sicherheitsprüfung vor einem produktiven Einsatz mit hohem Schutzbedarf.*
