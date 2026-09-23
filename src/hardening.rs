//! Prozesshaertung. Wird als ALLERERSTES in `main()` aufgerufen - in beiden
//! Rollen (GUI-Elternprozess und per Re-Exec gestarteter Krypto-Worker), da
//! beide durch denselben `main()`-Einstieg laufen.
//!
//! Wichtige Korrektur gegenueber der Vorversion: `mlockall(MCL_FUTURE)` wird
//! NICHT mehr pauschal in jedem Prozess gesetzt. Wenn MCL_FUTURE aktiv ist,
//! scheitert JEDE weitere Allokation, die `RLIMIT_MEMLOCK` sprengt, mit ENOMEM
//! - der GUI-Prozess (GPU-/Font-Puffer) oder Argon2 mit 128 MiB wuerden dann
//! zuverlaessig abstuerzen. Deshalb: Limit erst anheben, und mlockall nur, wenn
//! das Limit dafuer tatsaechlich reicht.

/// Welche Rolle dieser Prozess hat. Bestimmt, wie aggressiv gesperrt wird.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Elternprozess mit Fenster. Haelt nur die Passphrase kurzzeitig.
    Gui,
    /// Kindprozess, macht die Kryptografie. Speicherbedarf ist bekannt und begrenzt.
    Worker,
}

/// Untergrenze, ab der `mlockall` im Worker riskiert wird: Argon2-Speicher
/// (128 MiB) plus Reserve fuer Binary, Stack und Heap.
const MEMLOCK_NEEDED: u64 = 320 * 1024 * 1024;

/// RLIMIT_CORE = 0 -> ein Absturz schreibt niemals einen Core-Dump mit Secrets.
fn disable_core_dumps() {
    let rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: gueltige rlimit-Struktur, bekannte Ressource.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &rlim);
    }
}

/// Neu erzeugte Dateien (Schluessel, Container, entschluesselte Ausgaben)
/// bekommen so 0600 statt 0644 - kein Mitlesen durch andere lokale Nutzer.
fn restrict_umask() {
    // SAFETY: umask hat keine Fehlerfaelle.
    unsafe {
        libc::umask(0o077);
    }
}

/// Versucht, `RLIMIT_MEMLOCK` auf das erlaubte Maximum zu heben.
/// Gibt das danach geltende weiche Limit zurueck.
fn raise_memlock_limit() -> u64 {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: gueltiger Zeiger auf lokale Struktur.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) } != 0 {
        return 0;
    }
    if rlim.rlim_cur < rlim.rlim_max {
        let want = libc::rlimit {
            rlim_cur: rlim.rlim_max,
            rlim_max: rlim.rlim_max,
        };
        // SAFETY: wie oben; Fehlschlag ist unkritisch.
        unsafe {
            libc::setrlimit(libc::RLIMIT_MEMLOCK, &want);
        }
        return want.rlim_cur as u64;
    }
    rlim.rlim_cur as u64
}

/// Sperrt den gesamten Adressraum - nur wenn das Limit das hergibt.
fn try_mlockall(limit: u64) -> bool {
    if limit != libc::RLIM_INFINITY as u64 && limit < MEMLOCK_NEEDED {
        // Absichtlich NICHT versuchen: ein erfolgreiches MCL_FUTURE mit zu
        // kleinem Limit macht spaetere Allokationen unmoeglich.
        return false;
    }
    // SAFETY: konstante, gueltige Flags.
    unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0 }
}

/// Linux/Tails: PR_SET_DUMPABLE=0 verbietet ptrace-Attach durch andere Prozesse
/// desselben Nutzers und unterbindet /proc/<pid>/mem-Zugriff.
/// Das Flag wird bei `execve` zurueckgesetzt - deshalb ruft auch der per
/// Re-Exec gestartete Worker `harden_process` erneut auf.
#[cfg(target_os = "linux")]
fn deny_debugger() {
    // SAFETY: prctl mit konstanten Argumenten.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// macOS: PT_DENY_ATTACH (= 31) verhindert, dass sich ein Debugger anhaengt.
#[cfg(target_os = "macos")]
fn deny_debugger() {
    const PT_DENY_ATTACH: libc::c_int = 31;
    // SAFETY: dokumentierter Darwin-Aufruf ohne Speicherzugriff.
    unsafe {
        libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn deny_debugger() {}

pub fn harden_process(role: Role) {
    disable_core_dumps();
    restrict_umask();
    deny_debugger();

    let limit = raise_memlock_limit();
    if role == Role::Worker {
        // Nur der kurzlebige Krypto-Prozess mit bekanntem Speicherprofil.
        // Schlaegt es fehl, greift weiterhin das Sperren pro SecureBuf.
        let _ = try_mlockall(limit);
    }
}
