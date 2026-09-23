//! Eingebauter Dateibrowser.
//!
//! Warum nicht der Systemdialog (GTK / XDG-Portal / NSOpenPanel)?
//! Weil genau der forensische Spuren hinterlaesst, die du ausgeschlossen haben
//! willst: GTK und die Portal-Implementierungen schreiben jede geoeffnete Datei
//! nach `~/.local/share/recently-used.xbel`, macOS fuehrt aequivalente
//! "Recent Items"-Listen. Dort stuenden anschliessend die Namen deiner
//! Schluessel- und Klartextdateien - dauerhaft und fuer jeden lesbar, der das
//! Benutzerverzeichnis auswertet. Dieser Dialog liest nur Verzeichnisse und
//! schreibt nichts.
//!
//! Zusaetzlicher Nebeneffekt: keine Abhaengigkeit von GTK oder D-Bus, was die
//! Angriffsflaeche und die Build-Voraussetzungen auf Tails deutlich senkt.

use eframe::egui;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PickMode {
    /// Eine bestehende Datei auswaehlen.
    File,
    /// Ein Verzeichnis auswaehlen (Ziel fuer neue Dateien).
    Directory,
}

pub enum PickOutcome {
    Pending,
    Cancelled,
    Chosen(PathBuf),
}

pub struct FilePicker {
    pub title: String,
    mode: PickMode,
    cwd: PathBuf,
    dirs: Vec<(String, PathBuf)>,
    files: Vec<(String, PathBuf)>,
    error: Option<String>,
}

impl FilePicker {
    pub fn new(title: impl Into<String>, mode: PickMode, start: Option<&Path>) -> Self {
        let cwd = start
            .map(Path::to_path_buf)
            .filter(|p| p.is_dir())
            .unwrap_or_else(home_dir);
        let mut p = FilePicker {
            title: title.into(),
            mode,
            cwd,
            dirs: Vec::new(),
            files: Vec::new(),
            error: None,
        };
        p.refresh();
        p
    }

    fn refresh(&mut self) {
        self.dirs.clear();
        self.files.clear();
        self.error = None;
        let read = match std::fs::read_dir(&self.cwd) {
            Ok(r) => r,
            Err(e) => {
                self.error = Some(format!("Verzeichnis nicht lesbar: {}", e.kind()));
                return;
            }
        };
        for entry in read.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => self.dirs.push((name, path)),
                Ok(_) => self.files.push((name, path)),
                Err(_) => {}
            }
        }
        self.dirs.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
        self.files.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
    }

    fn goto(&mut self, path: PathBuf) {
        self.cwd = path;
        self.refresh();
    }

    pub fn show(&mut self, ctx: &egui::Context) -> PickOutcome {
        let mut outcome = PickOutcome::Pending;
        let mut open = true;

        egui::Window::new(&self.title)
            .collapsible(false)
            .resizable(true)
            .default_size([560.0, 420.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Persoenlicher Ordner").clicked() {
                        self.goto(home_dir());
                    }
                    for (label, path) in shortcuts() {
                        if Path::new(&path).is_dir() && ui.button(label).clicked() {
                            self.goto(PathBuf::from(&path));
                        }
                    }
                });
                ui.separator();

                ui.horizontal(|ui| {
                    if ui.button("⬆ Uebergeordnet").clicked() {
                        if let Some(parent) = self.cwd.parent() {
                            let p = parent.to_path_buf();
                            self.goto(p);
                        }
                    }
                    ui.label(egui::RichText::new(self.cwd.display().to_string()).monospace());
                });

                if let Some(err) = &self.error {
                    ui.colored_label(egui::Color32::from_rgb(220, 90, 90), err);
                }
                ui.separator();

                let mut navigate: Option<PathBuf> = None;
                let mut chosen: Option<PathBuf> = None;

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .max_height(260.0)
                    .show(ui, |ui| {
                        for (name, path) in &self.dirs {
                            if ui.button(format!("📁 {name}")).clicked() {
                                navigate = Some(path.clone());
                            }
                        }
                        if self.mode == PickMode::File {
                            for (name, path) in &self.files {
                                if ui.button(format!("📄 {name}")).clicked() {
                                    chosen = Some(path.clone());
                                }
                            }
                        }
                    });

                ui.separator();
                if self.mode == PickMode::Directory {
                    ui.label("Dateien werden in diesem Verzeichnis abgelegt.");
                    if ui.button("Dieses Verzeichnis waehlen").clicked() {
                        chosen = Some(self.cwd.clone());
                    }
                }

                if let Some(p) = navigate {
                    self.goto(p);
                }
                if let Some(p) = chosen {
                    outcome = PickOutcome::Chosen(p);
                }
            });

        if !open {
            return PickOutcome::Cancelled;
        }
        outcome
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Orte, die auf den Zielsystemen praktisch sind: der Tails-Persistenzordner,
/// eingehaengte Wechseldatentraeger und - besonders relevant - `/dev/shm`
/// bzw. `/tmp`, die auf Tails reine RAM-Dateisysteme sind.
/// Audit HC-13: `/dev/shm` existiert unter macOS grundsaetzlich nicht (kein
/// Standard-tmpfs) - die vorherige Version zeigte den Kurzwahl-Knopf trotzdem
/// an; er filtert zwar dank der `is_dir()`-Pruefung im Aufrufer still heraus,
/// bot macOS-Nutzern damit aber gar keine RAM-aehnliche Alternative an, ohne
/// dass das sichtbar würde. Jetzt plattformabhaengig: unter Linux/Tails der
/// echte, RAM-gestuetzte `/dev/shm`; unter macOS stattdessen `$TMPDIR` (immer
/// vorhanden, wird vom System periodisch geleert) PLUS ein Hinweis in der
/// Anwendung selbst, dass das - anders als `/dev/shm` - plattenbasiert ist.
fn shortcuts() -> Vec<(&'static str, String)> {
    let mut v = vec![
        ("Persistent (Tails)", "/home/amnesia/Persistent".into()),
        ("Datentraeger", "/media".into()),
        ("Volumes (macOS)", "/Volumes".into()),
    ];
    #[cfg(target_os = "macos")]
    {
        // Kein `/dev/shm` unter macOS. `$TMPDIR` ist plattenbasiert (APFS),
        // aber immer vorhanden und wird vom System periodisch geleert - siehe
        // README fuer eine Anleitung, bei Bedarf eine echte RAM-Disk
        // (`hdiutil attach ram://...`) einzurichten.
        if let Some(t) = std::env::var_os("TMPDIR") {
            v.push(("Temporaer (Platte, kein RAM)", t.to_string_lossy().into_owned()));
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        v.push(("RAM (/dev/shm)", "/dev/shm".into()));
        v.push(("/tmp", "/tmp".into()));
    }
    v.push(("Wurzel /", "/".into()));
    v
}
