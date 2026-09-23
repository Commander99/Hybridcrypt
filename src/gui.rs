//! Native Oberflaeche (egui/eframe) - kein HTTP-Server, kein Browser.
//!
//! Warum das sicherer ist als das bisherige lokale Web-Frontend:
//!   1. Ein Browser ist als Geheimnis-Speicher ungeeignet: JS-Strings liegen im
//!      GC-Heap, werden beliebig oft kopiert und nie ueberschrieben; mlock gibt
//!      es dort nicht. Die Passphrase war damit ausserhalb jeder Kontrolle.
//!   2. `127.0.0.1:8791` ist fuer JEDEN lokalen Prozess erreichbar. Und weil
//!      `multipart/form-data` ein "simple request" ist, konnte auch eine
//!      beliebige Webseite im selben Browser die Endpunkte cross-origin
//!      anstossen - CSRF-Schutz gab es keinen. Ein offener Port entfaellt jetzt
//!      ersatzlos.
//!   3. Der Browser legt eigene Spuren an (Cache, Session, Verlauf, Downloads).
//!
//! Die Passphrase wird NICHT ueber `egui::TextEdit` eingegeben. Dessen
//! Undo-Puffer haelt vollstaendige `String`-Kopien des Eingabetextes im
//! ungesperrten Heap vor. Stattdessen unten ein eigenes Eingabefeld, das die
//! Tastatur-Ereignisse direkt in gesperrten Speicher schreibt und die von der
//! Ereignisschleife gelieferten `String`s sofort ueberschreibt.

use crate::hybrid;
use crate::proc::{run_worker, OP_DECRYPT, OP_ENCRYPT, OP_KEYGEN};
use crate::secure::{SecureBuf, EXIT_CODE_DEGRADED_LOCK};
use eframe::egui;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::mpsc::{channel, Receiver};

use crate::filepick::{FilePicker, PickMode, PickOutcome};

/// Obergrenze fuer eine Passphrase. Fest, damit der gesperrte Puffer nie
/// reallozieren muss (eine Reallokation wuerde eine ungenullte Kopie im Heap
/// zuruecklassen).
const MAX_PASSPHRASE: usize = 1024;

/// Audit HC-09: `.hpub`/`.hkey`-Dateien sind im Betrieb wenige KiB gross.
/// `std::fs::read` ohne Obergrenze wuerde einer versehentlich oder boeswillig
/// falsch ausgewaehlten, sehr grossen Datei erlauben, unbegrenzt Speicher im
/// GUI-Prozess zu belegen, bevor die eigentliche Formatpruefung greift.
const MAX_KEYFILE_BYTES: u64 = 1024 * 1024;

/// Wie `std::fs::read`, aber mit Groessenobergrenze (Audit HC-09).
fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("nicht lesbar: {}", e.kind()))?;
    if meta.len() > max {
        return Err(format!(
            "Datei ist mit {} Byte groesser als fuer dieses Format erwartet (Obergrenze {} Byte).",
            meta.len(),
            max
        ));
    }
    std::fs::read(path).map_err(|e| format!("nicht lesbar: {}", e.kind()))
}

// ---------------------------------------------------------------------------
// Passphrase in gesperrtem Speicher
// ---------------------------------------------------------------------------

pub struct SecureString {
    buf: SecureBuf,
}

impl SecureString {
    pub fn new() -> Self {
        SecureString {
            buf: SecureBuf::with_capacity(MAX_PASSPHRASE),
        }
    }

    fn push_str(&mut self, s: &str) {
        if self.buf.len() + s.len() <= MAX_PASSPHRASE {
            self.buf.push_bytes(s.as_bytes());
        }
    }

    /// Entfernt das letzte Zeichen (nicht das letzte Byte) - UTF-8-korrekt.
    fn pop_char(&mut self) {
        let bytes = self.buf.as_slice();
        let mut i = bytes.len();
        if i == 0 {
            return;
        }
        i -= 1;
        while i > 0 && (bytes[i] & 0b1100_0000) == 0b1000_0000 {
            i -= 1;
        }
        self.buf.truncate_wiped(i);
    }

    fn char_count(&self) -> usize {
        self.buf
            .as_slice()
            .iter()
            .filter(|b| (*b & 0b1100_0000) != 0b1000_0000)
            .count()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.buf.as_slice()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.len() == 0
    }

    fn clear(&mut self) {
        self.buf.clear();
    }
}

/// Zeitkonstanter Vergleich - verraet ueber die Laufzeit nicht, an welcher
/// Stelle sich zwei Eingaben unterscheiden.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    diff == 0
}

/// Passphrase-Eingabefeld. Zeichnet nur Punkte; der Klartext verlaesst den
/// gesperrten Puffer nie und wird nie an die Textdarstellung uebergeben.
fn passphrase_field(ui: &mut egui::Ui, id_salt: &str, target: &mut SecureString) {
    let width = ui.available_width().min(320.0);
    let id = ui.make_persistent_id(id_salt);

    // WICHTIG: Klick-Erkennung und Fokus-Tracking muessen dieselbe Id benutzen.
    // `ui.allocate_exact_size()` haette eine eigene, ANDERE Id fuer die Response
    // erzeugt. egui haelt intern pro Frame eine Liste der Ids, die tatsaechlich
    // interagiert haben (`used_ids`); ein fokussiertes Widget, dessen Id dort
    // nicht auftaucht, verliert den Fokus automatisch wieder (Totmann-Schalter
    // gegen Widgets, die verschwunden sind). Mit zwei verschiedenen Ids wurde
    // unsere Fokus-Id nie als "benutzt" registriert - der Fokus verschwand
    // dadurch exakt einen Frame nach dem Klick, bevor je eine Taste ankam.
    // `ui.interact(rect, id, ...)` registriert dieselbe Id, die wir fuer
    // `request_focus`/`has_focus` verwenden, und meldet sie damit auch als
    // interessiert an Fokus an (Sense::click() setzt intern FOCUSABLE) -
    // der vorherige manuelle `interested_in_focus`-Aufruf entfaellt dadurch.
    let (_auto_id, rect) = ui.allocate_space(egui::vec2(width, 26.0));
    let response = ui.interact(rect, id, egui::Sense::click());

    if response.clicked() {
        ui.memory_mut(|m| m.request_focus(id));
    }
    let focused = ui.memory(|m| m.has_focus(id));

    if focused {
        ui.ctx().input_mut(|input| {
            let events = std::mem::take(&mut input.events);
            let mut kept = Vec::with_capacity(events.len());
            for mut event in events {
                let consumed = match &mut event {
                    egui::Event::Text(text) => {
                        target.push_str(text);
                        // Die von der Ereignisschleife allokierte Kopie sofort
                        // ueberschreiben. Danach ist der String leer und damit
                        // weiterhin gueltiges UTF-8.
                        // SAFETY: nach dem Nullen hat der String Laenge 0.
                        unsafe {
                            let v = text.as_mut_vec();
                            v.iter_mut().for_each(|b| *b = 0);
                            v.clear();
                        }
                        true
                    }
                    egui::Event::Paste(text) => {
                        target.push_str(text);
                        // SAFETY: wie oben.
                        unsafe {
                            let v = text.as_mut_vec();
                            v.iter_mut().for_each(|b| *b = 0);
                            v.clear();
                        }
                        true
                    }
                    egui::Event::Key {
                        key: egui::Key::Backspace,
                        pressed: true,
                        ..
                    } => {
                        target.pop_char();
                        true
                    }
                    // Kopieren/Ausschneiden wird nicht an die Zwischenablage
                    // weitergereicht - es gibt nichts zu kopieren.
                    egui::Event::Copy | egui::Event::Cut => true,
                    _ => false,
                };
                if !consumed {
                    kept.push(event);
                }
            }
            input.events = kept;
        });
    }

    // Feste, opake Farben statt zweideutiger Theme-Werte. `visuals.faint_bg_color`
    // (die vorherige Wahl fuer den unfokussierten Zustand) ist bewusst ADDITIV
    // gedacht (Alpha 0 - siehe egui-Doc "additive white"). Mit `rect_filled`
    // gemalt ist das Feld dadurch praktisch unsichtbar und verschmilzt mit dem
    // Fensterhintergrund - was genau zu kaum lesbarem, "verwaschenem" Text
    // fuehrt. `text_edit_bg_color()` ist der fuer Textfelder vorgesehene,
    // GARANTIERT opake Wert (Standard: Grauwert 10 - identisch zum normalen
    // egui-TextEdit) und wird deshalb hier fuer beide Zustaende verwendet.
    let visuals = ui.style().visuals.clone();
    let bg = visuals.text_edit_bg_color();
    let border = if focused {
        egui::Stroke::new(1.5, visuals.selection.stroke.color)
    } else {
        visuals.widgets.inactive.bg_stroke
    };

    let painter = ui.painter();
    painter.rect_filled(rect, 4.0, bg);
    painter.rect_stroke(rect, 4.0, border, egui::StrokeKind::Inside);

    let dots: String = std::iter::repeat('•').take(target.char_count()).collect();
    let showing_placeholder = dots.is_empty() && !focused;
    // Feste, helle Textfarbe (Grauwert 230) statt `visuals.text_color()`: auf
    // dem jetzt garantiert dunklen `bg` liefert das einen Kontrast von deutlich
    // ueber 10:1. Der Platzhalter bleibt bewusst gedaempfter (Grauwert 140,
    // ca. 5:1 - genug zum Lesen, sichtbar als "nur Hinweistext").
    let text_color = if showing_placeholder {
        egui::Color32::from_gray(140)
    } else {
        egui::Color32::from_gray(230)
    };
    let text = if showing_placeholder {
        "(Passphrase eingeben)".to_string()
    } else {
        dots
    };
    painter.text(
        rect.left_center() + egui::vec2(8.0, 0.0),
        egui::Align2::LEFT_CENTER,
        text,
        egui::FontId::proportional(14.0),
        text_color,
    );
    if focused {
        // Als gezeichneter Balken statt als Textglyph ("▌"): das Zeichen fehlt
        // in manchen Systemschriften (sichtbar als Ersatz-Kaestchen), ein
        // gemaltes Rechteck ist dagegen auf jeder Plattform gleich.
        let x = rect.right() - 10.0;
        painter.rect_filled(
            egui::Rect::from_min_max(
                egui::pos2(x, rect.top() + 5.0),
                egui::pos2(x + 2.0, rect.bottom() - 5.0),
            ),
            0.0,
            egui::Color32::from_gray(190),
        );
    }
}

// ---------------------------------------------------------------------------
// Auftraege
// ---------------------------------------------------------------------------

enum Job {
    Keygen {
        passphrase: SecureString,
        pub_path: PathBuf,
        key_path: PathBuf,
    },
    Encrypt {
        recipient_pub: PathBuf,
        input: PathBuf,
        output: PathBuf,
    },
    Decrypt {
        key_file: PathBuf,
        passphrase: SecureString,
        input: PathBuf,
        output: PathBuf,
    },
}

/// Ergebnis eines Hintergrundauftrags. Anders als ein einfaches
/// `Result<String, String>` gibt es einen dritten Zustand: eine im
/// Ergebnis korrekte, aber mit Einschraenkung abgeschlossene Operation
/// (Audit HC-01 - siehe `EXIT_CODE_DEGRADED_LOCK`). Eine Warnung ist kein
/// Fehler: die Ausgabedatei ist vollstaendig und korrekt, wird also anders
/// als bei einem echten Fehler NICHT geloescht.
enum StatusMsg {
    Ok(String),
    Warn(String),
    Err(String),
}

fn exit_code_message(code: i32) -> String {
    match code {
        2 => "Falsche Passphrase oder manipulierte Schluesseldatei.".into(),
        3 => "Schluesseldatei ist unbrauchbar oder gehoert nicht zu diesem Format.".into(),
        4 => "Container beschaedigt, gekuerzt oder manipuliert - Authentifizierung fehlgeschlagen.".into(),
        5 => "Ein-/Ausgabefehler beim Lesen oder Schreiben.".into(),
        6 => format!(
            "Passphrase zu schwach - bitte laenger und weniger vorhersehbar waehlen \
             (mindestens {} Zeichen, keine Woerterbuch- oder Tastaturmuster; \
             am robustesten: sechs oder mehr zufaellige, durch Leerzeichen \
             getrennte Woerter).",
            hybrid::MIN_PASSPHRASE_CHARS
        ),
        7 => "Speichersperre fehlgeschlagen und strenger Modus (HYBRIDCRYPT_STRICT_MLOCK) \
              aktiv - Vorgang abgebrochen, bevor ein Geheimnis ungesperrt haette \
              existieren koennen. Siehe README fuer RLIMIT_MEMLOCK."
            .into(),
        _ => "Operation fehlgeschlagen.".into(),
    }
}

/// Legt eine neue Datei mit 0600 an und verweigert das Ueberschreiben
/// bestehender Dateien (`create_new`). Unbeabsichtigtes Zerstoeren einer
/// Schluesseldatei ist ein Datenverlust, von dem man sich nicht erholt.
fn create_output(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Bei Fehlschlag: bereits geschriebene Teilausgabe ueberschreiben und loeschen.
/// Auf SSDs ist Ueberschreiben wegen Wear-Levelling keine Garantie - darum die
/// Empfehlung im README, Ausgaben auf ein RAM-Dateisystem zu legen.
fn wipe_and_remove(path: &Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        if let Ok(mut f) = OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; 64 * 1024];
            let mut left = meta.len();
            while left > 0 {
                let n = left.min(zeros.len() as u64) as usize;
                if f.write_all(&zeros[..n]).is_err() {
                    break;
                }
                left -= n as u64;
            }
            let _ = f.sync_all();
        }
    }
    let _ = std::fs::remove_file(path);
}

fn write_field(pipe: &mut File, data: &[u8]) -> io::Result<()> {
    pipe.write_all(&(data.len() as u32).to_le_bytes())?;
    pipe.write_all(data)
}

fn execute(job: Job) -> StatusMsg {
    match execute_inner(job) {
        Ok(msg) => msg,
        Err(msg) => StatusMsg::Err(msg),
    }
}

fn execute_inner(job: Job) -> Result<StatusMsg, String> {
    match job {
        Job::Keygen {
            passphrase,
            pub_path,
            key_path,
        } => {
            let pub_file = create_output(&pub_path).map_err(|e| output_err(&pub_path, e))?;
            let key_file = create_output(&key_path).map_err(|e| output_err(&key_path, e))?;
            let code = run_worker(
                Stdio::null(),
                Stdio::from(pub_file),
                Some(key_file),
                |pipe| {
                    pipe.write_all(&[OP_KEYGEN])?;
                    write_field(pipe, passphrase.as_bytes())
                },
            )
            .map_err(|e| format!("Worker konnte nicht gestartet werden: {e}"))?;
            if code != 0 && code != EXIT_CODE_DEGRADED_LOCK {
                wipe_and_remove(&pub_path);
                wipe_and_remove(&key_path);
                return Err(exit_code_message(code));
            }
            // Fingerabdruck aus der gerade geschriebenen Datei - Audit HC-02.
            // Ein oeffentlicher Schluessel ist kein Geheimnis; das Lesen im
            // GUI-Prozess ist unbedenklich.
            let fingerprint = std::fs::read(&pub_path)
                .ok()
                .map(|b| hybrid::pubkey_fingerprint(&b));
            let fp_line = fingerprint
                .map(|f| format!("\nFingerabdruck (zum Weitergeben/Vergleichen): {f}"))
                .unwrap_or_default();
            let msg = format!(
                "Schluesselpaar erzeugt:\n{}\n{}{}",
                pub_path.display(),
                key_path.display(),
                fp_line
            );
            if code == EXIT_CODE_DEGRADED_LOCK {
                Ok(StatusMsg::Warn(format!(
                    "{msg}\n\nHinweis: Speichersperre (mlock) ist waehrend dieses Vorgangs \
                     mindestens einmal fehlgeschlagen (RLIMIT_MEMLOCK zu klein). Die Dateien \
                     sind korrekt, aber Geheimnisse lagen zeitweise ungesperrt im Speicher \
                     (koennten theoretisch ausgelagert werden). Siehe README, Abschnitt \
                     Speichersperre."
                )))
            } else {
                Ok(StatusMsg::Ok(msg))
            }
        }

        Job::Encrypt {
            recipient_pub,
            input,
            output,
        } => {
            // Oeffentlicher Schluessel - kein Geheimnis, darf im GUI-Heap liegen.
            let pub_blob = read_bounded(&recipient_pub, MAX_KEYFILE_BYTES)
                .map_err(|e| format!("Public-Key {e}"))?;
            let in_file =
                File::open(&input).map_err(|e| format!("Eingabedatei nicht lesbar: {}", e.kind()))?;
            let out_file = create_output(&output).map_err(|e| output_err(&output, e))?;
            let code = run_worker(
                Stdio::from(in_file),
                Stdio::from(out_file),
                None,
                |pipe| {
                    pipe.write_all(&[OP_ENCRYPT])?;
                    write_field(pipe, &pub_blob)
                },
            )
            .map_err(|e| format!("Worker konnte nicht gestartet werden: {e}"))?;
            if code != 0 && code != EXIT_CODE_DEGRADED_LOCK {
                wipe_and_remove(&output);
                return Err(exit_code_message(code));
            }
            let msg = format!("Verschluesselt nach:\n{}", output.display());
            if code == EXIT_CODE_DEGRADED_LOCK {
                Ok(StatusMsg::Warn(format!(
                    "{msg}\n\nHinweis: Speichersperre ist waehrend dieses Vorgangs mindestens \
                     einmal fehlgeschlagen (RLIMIT_MEMLOCK zu klein). Die Ausgabedatei ist \
                     korrekt; siehe README, Abschnitt Speichersperre."
                )))
            } else {
                Ok(StatusMsg::Ok(msg))
            }
        }

        Job::Decrypt {
            key_file,
            passphrase,
            input,
            output,
        } => {
            // Der .hkey-Blob ist bereits passphrasenverschluesselt.
            let key_blob = read_bounded(&key_file, MAX_KEYFILE_BYTES)
                .map_err(|e| format!("Schluesseldatei {e}"))?;
            let in_file =
                File::open(&input).map_err(|e| format!("Eingabedatei nicht lesbar: {}", e.kind()))?;
            let out_file = create_output(&output).map_err(|e| output_err(&output, e))?;
            let code = run_worker(
                Stdio::from(in_file),
                Stdio::from(out_file),
                None,
                |pipe| {
                    pipe.write_all(&[OP_DECRYPT])?;
                    write_field(pipe, &key_blob)?;
                    write_field(pipe, passphrase.as_bytes())
                },
            )
            .map_err(|e| format!("Worker konnte nicht gestartet werden: {e}"))?;
            if code != 0 && code != EXIT_CODE_DEGRADED_LOCK {
                wipe_and_remove(&output);
                return Err(exit_code_message(code));
            }
            let msg = format!("Entschluesselt nach:\n{}", output.display());
            if code == EXIT_CODE_DEGRADED_LOCK {
                Ok(StatusMsg::Warn(format!(
                    "{msg}\n\nHinweis: Speichersperre ist waehrend dieses Vorgangs mindestens \
                     einmal fehlgeschlagen (RLIMIT_MEMLOCK zu klein). Die Ausgabedatei ist \
                     korrekt; siehe README, Abschnitt Speichersperre."
                )))
            } else {
                Ok(StatusMsg::Ok(msg))
            }
        }
    }
}

fn output_err(path: &Path, e: io::Error) -> String {
    if e.kind() == io::ErrorKind::AlreadyExists {
        format!(
            "{} existiert bereits - bitte anderen Namen waehlen.",
            path.display()
        )
    } else {
        format!("{} nicht anlegbar: {}", path.display(), e.kind())
    }
}

// ---------------------------------------------------------------------------
// Anwendung
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Keygen,
    Encrypt,
    Decrypt,
}

#[derive(Clone, Copy)]
enum PickTarget {
    KeygenDir,
    EncryptPub,
    EncryptIn,
    EncryptOutDir,
    DecryptKey,
    DecryptIn,
    DecryptOutDir,
}

pub struct App {
    tab: Tab,

    kg_pass: SecureString,
    kg_pass_repeat: SecureString,
    kg_dir: Option<PathBuf>,
    kg_name: String,

    enc_pub: Option<PathBuf>,
    /// Audit HC-02: Fingerabdruck des gerade gewaehlten Empfaenger-Schluessels,
    /// zum Abgleich mit dem, was der Empfaenger ausserhalb dieses Programms
    /// mitgeteilt hat (Schutz gegen eine ausgetauschte `.hpub`-Datei).
    enc_pub_fingerprint: Option<String>,
    enc_in: Option<PathBuf>,
    enc_out_dir: Option<PathBuf>,
    enc_out_name: String,

    dec_key: Option<PathBuf>,
    dec_pass: SecureString,
    dec_in: Option<PathBuf>,
    dec_out_dir: Option<PathBuf>,
    dec_out_name: String,

    picker: Option<(FilePicker, PickTarget)>,
    job: Option<Receiver<StatusMsg>>,
    status: Option<StatusMsg>,
}

impl Default for App {
    fn default() -> Self {
        App {
            tab: Tab::Keygen,
            kg_pass: SecureString::new(),
            kg_pass_repeat: SecureString::new(),
            kg_dir: None,
            kg_name: "schluessel".into(),
            enc_pub: None,
            enc_pub_fingerprint: None,
            enc_in: None,
            enc_out_dir: None,
            enc_out_name: String::new(),
            dec_key: None,
            dec_pass: SecureString::new(),
            dec_in: None,
            dec_out_dir: None,
            dec_out_name: String::new(),
            picker: None,
            job: None,
            status: None,
        }
    }
}

impl App {
    fn busy(&self) -> bool {
        self.job.is_some()
    }

    fn start(&mut self, job: Job) {
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let _ = tx.send(execute(job));
        });
        self.job = Some(rx);
        self.status = None;
    }

    fn open_picker(&mut self, title: &str, mode: PickMode, target: PickTarget) {
        let start = match target {
            PickTarget::KeygenDir => self.kg_dir.clone(),
            PickTarget::EncryptPub | PickTarget::EncryptIn => self.enc_in.clone(),
            PickTarget::EncryptOutDir => self.enc_out_dir.clone(),
            PickTarget::DecryptKey | PickTarget::DecryptIn => self.dec_in.clone(),
            PickTarget::DecryptOutDir => self.dec_out_dir.clone(),
        };
        let start_dir = start.and_then(|p| {
            if p.is_dir() {
                Some(p)
            } else {
                p.parent().map(Path::to_path_buf)
            }
        });
        self.picker = Some((
            FilePicker::new(title, mode, start_dir.as_deref()),
            target,
        ));
    }

    fn apply_pick(&mut self, target: PickTarget, path: PathBuf) {
        match target {
            PickTarget::KeygenDir => self.kg_dir = Some(path),
            PickTarget::EncryptPub => {
                // Fingerabdruck sofort berechnen (Audit HC-02) - eine
                // unlesbare oder zu grosse Datei wird hier still ignoriert,
                // die eigentliche Formatpruefung erfolgt beim Verschluesseln
                // selbst und zeigt dann eine klare Fehlermeldung.
                self.enc_pub_fingerprint = read_bounded(&path, MAX_KEYFILE_BYTES)
                    .ok()
                    .map(|b| hybrid::pubkey_fingerprint(&b));
                self.enc_pub = Some(path);
            }
            PickTarget::EncryptIn => {
                if self.enc_out_name.is_empty() {
                    if let Some(name) = path.file_name() {
                        self.enc_out_name = format!("{}.hcx", name.to_string_lossy());
                    }
                }
                if self.enc_out_dir.is_none() {
                    self.enc_out_dir = path.parent().map(Path::to_path_buf);
                }
                self.enc_in = Some(path);
            }
            PickTarget::EncryptOutDir => self.enc_out_dir = Some(path),
            PickTarget::DecryptKey => self.dec_key = Some(path),
            PickTarget::DecryptIn => {
                if self.dec_out_name.is_empty() {
                    let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
                    if let Some(n) = name {
                        self.dec_out_name = n.strip_suffix(".hcx").unwrap_or("entschluesselt").to_string();
                    }
                }
                if self.dec_out_dir.is_none() {
                    self.dec_out_dir = path.parent().map(Path::to_path_buf);
                }
                self.dec_in = Some(path);
            }
            PickTarget::DecryptOutDir => self.dec_out_dir = Some(path),
        }
    }
}

fn path_row(ui: &mut egui::Ui, label: &str, value: &Option<PathBuf>) {
    ui.horizontal(|ui| {
        ui.label(label);
        let text = value
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "— nichts gewaehlt —".into());
        ui.label(egui::RichText::new(text).monospace().weak());
    });
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.job {
            match rx.try_recv() {
                Ok(result) => {
                    self.status = Some(result);
                    self.job = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.status = Some(StatusMsg::Err("Worker unerwartet beendet.".into()));
                    self.job = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(std::time::Duration::from_millis(120));
                }
            }
        }

        if let Some((picker, target)) = &mut self.picker {
            let target = *target;
            match picker.show(ctx) {
                PickOutcome::Pending => {}
                PickOutcome::Cancelled => self.picker = None,
                PickOutcome::Chosen(path) => {
                    self.picker = None;
                    self.apply_pick(target, path);
                }
            }
        }

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Keygen, "Schluessel erzeugen");
                ui.selectable_value(&mut self.tab, Tab::Encrypt, "Verschluesseln");
                ui.selectable_value(&mut self.tab, Tab::Decrypt, "Entschluesseln");
            });
            ui.add_space(4.0);
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.add_space(4.0);
            if self.busy() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Arbeitet … (Argon2id braucht auf aelteren Rechnern einige Sekunden)");
                });
            } else {
                match &self.status {
                    Some(StatusMsg::Ok(msg)) => {
                        ui.colored_label(egui::Color32::from_rgb(90, 180, 110), msg);
                    }
                    Some(StatusMsg::Warn(msg)) => {
                        ui.colored_label(egui::Color32::from_rgb(210, 160, 60), msg);
                    }
                    Some(StatusMsg::Err(msg)) => {
                        ui.colored_label(egui::Color32::from_rgb(220, 90, 90), msg);
                    }
                    None => {
                        // Audit HC-01/HC-13: hier stand zuvor die pauschale,
                        // unbedingte Behauptung "alle Geheimnisse in
                        // gesperrtem Speicher" - unabhaengig davon, ob das
                        // Sperren im konkreten Lauf tatsaechlich gelungen
                        // war. Der Text beschreibt jetzt nur noch, was das
                        // Programm versucht, nicht was es garantiert; ob eine
                        // konkrete Operation vollstaendig gesperrt war, zeigt
                        // die Erfolgs- bzw. Warnmeldung danach.
                        ui.weak("ML-KEM-1024 × P-384 × SHA-256 · ChaCha20-Poly1305 · \
                                 Geheimnisse werden nach Moeglichkeit in gesperrtem Speicher gehalten");
                    }
                }
            }
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            let busy = self.busy();
            ui.add_enabled_ui(!busy, |ui| match self.tab {
                Tab::Keygen => self.keygen_tab(ui),
                Tab::Encrypt => self.encrypt_tab(ui),
                Tab::Decrypt => self.decrypt_tab(ui),
            });
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Explizit, statt sich auf die Reihenfolge beim Prozessende zu verlassen.
        self.kg_pass.clear();
        self.kg_pass_repeat.clear();
        self.dec_pass.clear();
    }
}

impl App {
    fn keygen_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Neues Schluesselpaar");
        ui.label("Erzeugt zwei Dateien: <name>.hpub (weitergeben) und <name>.hkey (geheim halten).");
        ui.add_space(8.0);

        ui.label("Passphrase");
        passphrase_field(ui, "kg_pass", &mut self.kg_pass);
        ui.label("Passphrase wiederholen");
        passphrase_field(ui, "kg_pass2", &mut self.kg_pass_repeat);

        let matching = ct_eq(self.kg_pass.as_bytes(), self.kg_pass_repeat.as_bytes());
        if !self.kg_pass_repeat.is_empty() && !matching {
            ui.colored_label(
                egui::Color32::from_rgb(220, 90, 90),
                "Die Eingaben stimmen nicht ueberein.",
            );
        }
        let long_enough = self.kg_pass.char_count() >= hybrid::MIN_PASSPHRASE_CHARS;
        if !self.kg_pass.is_empty() && !long_enough {
            ui.colored_label(
                egui::Color32::from_rgb(210, 160, 60),
                format!(
                    "Mindestens {} Zeichen.",
                    hybrid::MIN_PASSPHRASE_CHARS
                ),
            );
        }
        // Die Zeichenzahl ist nur ein billiger Vorfilter, der den Button
        // ueberhaupt erst anklickbar macht. Die tatsaechliche Pruefung
        // (Woerterbuecher, Tastaturmuster, Wiederholungen - siehe Audit
        // HC-03) laeuft ausschliesslich im Worker beim Erzeugen selbst, weil
        // sie dieselbe Isolation braucht wie Argon2 (kein Byte der
        // Passphrase soll den GUI-Prozess je erreichen). Eine zu schwache
        // Passphrase wird dort abgelehnt, mit einer erklaerenden Meldung.
        ui.weak(
            "Wird beim Erzeugen auf tatsaechliche Staerke geprueft (nicht nur Laenge) - \
             am robustesten: sechs oder mehr zufaellige, durch Leerzeichen getrennte Woerter.",
        );

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("Zielordner waehlen …").clicked() {
                self.open_picker("Zielordner", PickMode::Directory, PickTarget::KeygenDir);
            }
        });
        path_row(ui, "Ordner:", &self.kg_dir);
        ui.horizontal(|ui| {
            ui.label("Basisname:");
            ui.text_edit_singleline(&mut self.kg_name);
        });

        ui.add_space(12.0);
        let ready = matching && long_enough && self.kg_dir.is_some() && !self.kg_name.is_empty();
        if ui
            .add_enabled(ready, egui::Button::new("Schluesselpaar erzeugen"))
            .clicked()
        {
            let dir = self.kg_dir.clone().unwrap();
            let job = Job::Keygen {
                passphrase: std::mem::replace(&mut self.kg_pass, SecureString::new()),
                pub_path: dir.join(format!("{}.hpub", self.kg_name)),
                key_path: dir.join(format!("{}.hkey", self.kg_name)),
            };
            self.kg_pass_repeat.clear();
            self.start(job);
        }
    }

    fn encrypt_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Datei verschluesseln");
        ui.label("Fuer den Besitzer des gewaehlten oeffentlichen Schluessels. Keine Passphrase noetig.");
        ui.add_space(8.0);

        if ui.button("Oeffentlichen Schluessel (.hpub) waehlen …").clicked() {
            self.open_picker("Oeffentlicher Schluessel", PickMode::File, PickTarget::EncryptPub);
        }
        path_row(ui, "Empfaenger:", &self.enc_pub);
        if let Some(fp) = &self.enc_pub_fingerprint {
            ui.horizontal(|ui| {
                ui.weak("Fingerabdruck:");
                ui.label(egui::RichText::new(fp).monospace().strong());
            });
            ui.weak(
                "Vor dem Verschluesseln mit dem Empfaenger AUSSERHALB dieses Programms \
                 abgleichen (z.B. per Telefon oder einem zweiten Kanal) - so wird eine \
                 ausgetauschte Schluesseldatei erkennbar.",
            );
        }

        if ui.button("Eingabedatei waehlen …").clicked() {
            self.open_picker("Eingabedatei", PickMode::File, PickTarget::EncryptIn);
        }
        path_row(ui, "Eingabe:", &self.enc_in);

        if ui.button("Ausgabeordner waehlen …").clicked() {
            self.open_picker("Ausgabeordner", PickMode::Directory, PickTarget::EncryptOutDir);
        }
        path_row(ui, "Ausgabeordner:", &self.enc_out_dir);
        ui.horizontal(|ui| {
            ui.label("Ausgabename:");
            ui.text_edit_singleline(&mut self.enc_out_name);
        });

        ui.add_space(12.0);
        let ready = self.enc_pub.is_some()
            && self.enc_in.is_some()
            && self.enc_out_dir.is_some()
            && !self.enc_out_name.is_empty();
        if ui
            .add_enabled(ready, egui::Button::new("Verschluesseln"))
            .clicked()
        {
            let job = Job::Encrypt {
                recipient_pub: self.enc_pub.clone().unwrap(),
                input: self.enc_in.clone().unwrap(),
                output: self.enc_out_dir.clone().unwrap().join(&self.enc_out_name),
            };
            self.start(job);
        }
    }

    fn decrypt_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Datei entschluesseln");
        ui.add_space(8.0);

        if ui.button("Eigene Schluesseldatei (.hkey) waehlen …").clicked() {
            self.open_picker("Schluesseldatei", PickMode::File, PickTarget::DecryptKey);
        }
        path_row(ui, "Schluessel:", &self.dec_key);

        ui.label("Passphrase");
        passphrase_field(ui, "dec_pass", &mut self.dec_pass);

        if ui.button("Verschluesselte Datei waehlen …").clicked() {
            self.open_picker("Verschluesselte Datei", PickMode::File, PickTarget::DecryptIn);
        }
        path_row(ui, "Eingabe:", &self.dec_in);

        if ui.button("Ausgabeordner waehlen …").clicked() {
            self.open_picker("Ausgabeordner", PickMode::Directory, PickTarget::DecryptOutDir);
        }
        path_row(ui, "Ausgabeordner:", &self.dec_out_dir);
        ui.horizontal(|ui| {
            ui.label("Ausgabename:");
            ui.text_edit_singleline(&mut self.dec_out_name);
        });

        ui.add_space(12.0);
        let ready = self.dec_key.is_some()
            && !self.dec_pass.is_empty()
            && self.dec_in.is_some()
            && self.dec_out_dir.is_some()
            && !self.dec_out_name.is_empty();
        if ui
            .add_enabled(ready, egui::Button::new("Entschluesseln"))
            .clicked()
        {
            let job = Job::Decrypt {
                key_file: self.dec_key.clone().unwrap(),
                passphrase: std::mem::replace(&mut self.dec_pass, SecureString::new()),
                input: self.dec_in.clone().unwrap(),
                output: self.dec_out_dir.clone().unwrap().join(&self.dec_out_name),
            };
            self.start(job);
        }
    }
}

pub fn run() -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([780.0, 600.0])
            .with_min_inner_size([620.0, 480.0])
            .with_title("hybridcrypt"),
        ..Default::default()
    };
    eframe::run_native(
        "hybridcrypt",
        options,
        Box::new(|_cc| Ok(Box::new(App::default()))),
    )
    .map_err(|e| format!("Fenster konnte nicht geoeffnet werden: {e}"))
}
