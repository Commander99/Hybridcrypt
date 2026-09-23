//! Prozess-Isolation.
//!
//! Jede Kryptooperation laeuft in einem frisch per `execve` gestarteten
//! Kindprozess. Bewusst Re-Exec statt rohem `fork()`:
//!   - `fork()` wuerde den KOMPLETTEN Elternspeicher (inklusive aller Kopien,
//!     die das GUI-Toolkit von Eingaben angelegt hat) ins Kind spiegeln -
//!     also genau das Gegenteil von Isolation.
//!   - `fork()` in einem Prozess mit mehreren Threads (jedes GUI-Toolkit hat
//!     welche) ist in POSIX ohnehin nur eingeschraenkt zulaessig: im Kind lebt
//!     nur der aufrufende Thread weiter, von anderen Threads gehaltene Mutexe
//!     bleiben fuer immer gesperrt.
//! Re-Exec gibt einen jungfraeulichen Adressraum ab `main()` - dieselbe
//! Isolationszusage, ohne die Nebenwirkungen.
//!
//! Datenwege (KEIN Klartext geht jemals durch den GUI-Prozess):
//!   fd 0 (stdin)  = Eingabedatei, vom Elternprozess geoeffnet und weitergereicht
//!   fd 1 (stdout) = Ausgabedatei, ebenso
//!   fd 2 (stderr) = /dev/null  -> kein Logging, auch nicht versehentlich
//!   fd 3          = Steuerkanal (Pipe): Operation, oeffentlicher Schluessel,
//!                   Passphrase. Niemals in argv - `argv` ist fuer jeden
//!                   lokalen Nutzer in `ps`/`/proc` sichtbar.
//!   fd 4          = zweite Ausgabedatei, nur bei der Schluesselerzeugung
//!
//! Audit-Reaktion (HC-10):
//!   - Der Worker wird auf Linux ueber `/proc/self/exe` statt ueber den von
//!     `current_exe()` gelieferten PFAD gestartet. `current_exe()` liefert
//!     nur einen String zurueck; zwischen dem Ermitteln dieses Pfads und dem
//!     tatsaechlichen `execve` in `Command::spawn()` koennte ein Angreifer
//!     mit Schreibzugriff auf diesen Pfad die Datei austauschen (klassisches
//!     TOCTOU). `/proc/self/exe` ist dagegen ein vom Kernel gepflegter,
//!     magischer Verweis auf das GERADE LAUFENDE Programm-Image - er zeigt
//!     nach `fork()` im Kind (das bis zum `exec` noch exakt dasselbe,
//!     bereits laufende Image ausfuehrt) zuverlaessig auf genau dieses Image,
//!     unabhaengig davon, ob die Datei auf der Platte inzwischen ersetzt
//!     wurde. Das ist eine Standardtechnik gegen genau diese Race-Bedingung.
//!     macOS kennt kein Aequivalent zu `/proc`; dort bleibt `current_exe()`,
//!     abgesichert durch Code-Signing/Gatekeeper und eine uebliche Installation
//!     in einem nur fuer root beschreibbaren Verzeichnis (siehe README).
//!   - Alle Deskriptoren >= 5 werden im Kind vor dem `exec` geschlossen, damit
//!     keine vom Elternprozess (oder von einer tieferen Aufrufkette) geerbten
//!     Deskriptoren unbeabsichtigt im Worker landen.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

pub const FD_CONTROL: RawFd = 3;
pub const FD_KEY_OUT: RawFd = 4;
/// Niedrigste Deskriptornummer, die im Worker vor dem `exec` NICHT
/// geschlossen wird (0,1,2 = Standardstroeme, 3 = Steuerkanal, 4 = zweite
/// Ausgabe bei Keygen).
const FIRST_CLOSEABLE_FD: RawFd = 5;
/// Obergrenze fuer das Schliessen "verwaister" Deskriptoren. `close()` auf
/// einer nicht offenen Nummer ist ein billiger, ignorierter Fehlschlag - die
/// Schleife bis 1024 kostet in der Praxis deutlich unter einer Millisekunde
/// und deckt jeden realistischen `RLIMIT_NOFILE` ab, ohne von
/// `close_range` (nicht auf jedem Zielsystem/Kernel verfuegbar) abzuhaengen.
const CLOSE_SWEEP_UPPER_BOUND: RawFd = 1024;

pub const OP_KEYGEN: u8 = 1;
pub const OP_ENCRYPT: u8 = 2;
pub const OP_DECRYPT: u8 = 3;

/// Startet den Worker, uebergibt ihm die Deskriptoren, schreibt den Steuerkanal
/// und wartet auf das Ende. Rueckgabe ist der Exit-Code des Kindes.
pub fn run_worker<F>(
    stdin: Stdio,
    stdout: Stdio,
    key_out: Option<File>,
    write_control: F,
) -> io::Result<i32>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    let (ctl_read, mut ctl_write) = make_pipe()?;

    let mut cmd = Command::new(worker_exe_path()?);
    cmd.arg("--worker")
        .stdin(stdin)
        .stdout(stdout)
        .stderr(Stdio::null());

    let ctl_raw = ctl_read.as_raw_fd();
    let key_raw = key_out.as_ref().map(|f| f.as_raw_fd());

    // SAFETY: im Kind zwischen fork und exec sind nur async-signal-sichere
    // Aufrufe erlaubt. Hier werden ausschliesslich fcntl/dup2/close benutzt.
    unsafe {
        cmd.pre_exec(move || {
            // Erst beide Quellen auf hohe Deskriptornummern ausweichen lassen,
            // damit das anschliessende dup2 auf 3/4 nichts ueberschreibt, was
            // noch gebraucht wird.
            let ctl_high = dup_high(ctl_raw)?;
            let key_high = match key_raw {
                Some(fd) => Some(dup_high(fd)?),
                None => None,
            };
            place_fd(ctl_high, FD_CONTROL)?;
            libc::close(ctl_high); // die hohe Kopie wird nicht mehr gebraucht
            if let Some(fd) = key_high {
                place_fd(fd, FD_KEY_OUT)?;
                libc::close(fd);
            }
            // Alles jenseits der bewusst platzierten fds 0-4 schliessen -
            // fuer den Fall, dass sonst noch etwas geerbt wurde.
            close_fds_from(FIRST_CLOSEABLE_FD);
            Ok(())
        });
    }

    let mut child = cmd.spawn()?;
    drop(ctl_read); // Leseende gehoert jetzt dem Kind
    drop(key_out); // dito

    // Der Steuerkanal ist klein (< 8 KiB) und passt garantiert in den
    // Pipe-Puffer des Kernels - kein Deadlock, obwohl noch niemand liest.
    let write_result = write_control(&mut ctl_write);
    drop(ctl_write); // EOF -> Worker weiss, dass der Steuerkanal vollstaendig ist
    write_result?;

    let status = child.wait()?;
    Ok(status.code().unwrap_or(1))
}

/// Der Pfad, unter dem der Worker gestartet wird. Siehe Modul-Dokumentation
/// zur TOCTOU-Ueberlegung.
fn worker_exe_path() -> io::Result<std::path::PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let p = std::path::PathBuf::from("/proc/self/exe");
        if p.exists() {
            return Ok(p);
        }
        // Sehr ungewoehnliche Umgebung ohne /proc (z.B. bestimmte Container-
        // Konfigurationen) - Rueckfall auf den regulaeren Weg.
        std::env::current_exe()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::current_exe()
    }
}

/// Schliesst alle Deskriptoren `>= from` bis zur Sweep-Obergrenze.
///
/// # Safety
/// Nur zwischen fork und exec aufzurufen (async-signal-sicher: ausschliesslich
/// `close()`-Aufrufe, deren Fehlschlagen absichtlich ignoriert wird).
unsafe fn close_fds_from(from: RawFd) {
    for fd in from..CLOSE_SWEEP_UPPER_BOUND {
        libc::close(fd);
    }
}

fn make_pipe() -> io::Result<(OwnedFd, File)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: gueltiger Zeiger auf ein Array der geforderten Groesse.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: frisch erzeugte, noch niemandem gehoerende Deskriptoren.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { File::from_raw_fd(fds[1]) };
    set_cloexec(fds[0])?;
    set_cloexec(fds[1])?;
    Ok((read, write))
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl auf einem gueltigen Deskriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: wie oben.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Dupliziert `fd` auf eine Nummer >= 10 (ohne FD_CLOEXEC).
///
/// # Safety
/// Nur zwischen fork und exec aufzurufen.
unsafe fn dup_high(fd: RawFd) -> io::Result<RawFd> {
    let new = libc::fcntl(fd, libc::F_DUPFD, 10);
    if new < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(new)
}

/// Legt `src` exakt auf die Nummer `dst` und stellt sicher, dass der
/// Deskriptor `exec` ueberlebt (`dup2` loescht FD_CLOEXEC auf dem Ziel).
///
/// # Safety
/// Nur zwischen fork und exec aufzurufen.
unsafe fn place_fd(src: RawFd, dst: RawFd) -> io::Result<()> {
    if libc::dup2(src, dst) < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
