//! Speicher-Primitive fuer Geheimnisse.
//!
//! Version 2 (Audit-Reaktion). Die Vorversion legte Geheimnisse in einem
//! `Vec<u8>` ab, dessen Speicher vom normalen Allokator kommt, und sperrte
//! anschliessend den seitenausgerichteten Bereich per `mlock`. Das Audit
//! (HC-07) hat dabei zu Recht bemaengelt: `mlock`/`munlock` sperren auf
//! Linux und macOS ganze SEITEN, nicht Allokationen, und stapeln sich nicht
//! (POSIX/Linux man-page: "Memory locks do not stack" - ein einzelnes
//! `munlock` entsperrt die Seite vollstaendig, unabhaengig davon, wie oft sie
//! vorher gesperrt wurde). Lagen zwei kleine Secrets zufaellig auf derselben
//! Speicherseite, entsperrte das Drop des einen die Seite des jeweils ANDEREN
//! noch lebenden Secrets mit - ein garantierter, mit der man-page belegbarer
//! Fehler, kein hypothetisches Risiko.
//!
//! Jeder `SecureBuf` bekommt deshalb jetzt eine EIGENE, exklusive `mmap`-
//! Anonymous-Mapping - niemals geteilt mit irgendeiner anderen Allokation,
//! auch nicht mit einem anderen `SecureBuf`. `mlock`/`munlock` auf dieser
//! Mapping betreffen dann garantiert nur dieses eine Secret. Zusaetzlich
//! bekommt jede Mapping vorn und hinten eine Guard-Page (`PROT_NONE`): ein
//! Off-by-one-Zugriff ueber die Puffergrenze hinaus loest einen sofortigen
//! Segfault aus, statt still benachbarten (Secret-)Speicher zu lesen oder zu
//! ueberschreiben.
//!
//! Zum Nullen wird nicht mehr `ptr::write_bytes` + `compiler_fence` verwendet
//! (Audit HC-05: ein Compiler-Fence ist keine von Rust garantierte Zusicherung
//! gegen Dead-Store-Elimination), sondern die `Zeroize`-Implementierung fuer
//! `[u8]`, die nachweislich volatile Schreibzugriffe benutzt.
//!
//! Grenzen (weiterhin bewusst benannt): das alles verhindert Swap, Core-Dumps
//! und Nachbarschafts-Leaks zwischen unseren eigenen Puffern. Es verhindert
//! NICHT Cold-Boot-Angriffe auf laufendes RAM, Zugriff durch einen Angreifer
//! mit Kernel-Rechten zur Laufzeit, oder Kopien, die Fremdbibliotheken
//! (ml-kem, argon2/blake2, p384) intern auf dem normalen Heap anlegen - siehe
//! README, Abschnitt Restrisiken, fuer die dort explizit verbleibenden Faelle.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use zeroize::Zeroize;

/// Exit-Code, wenn der strenge Modus (`HYBRIDCRYPT_STRICT_MLOCK=1`) aktiv ist
/// und eine Sperrung fehlschlaegt. Siehe [`set_strict_mode`].
pub const EXIT_CODE_STRICT_MLOCK_FAILED: i32 = 7;

/// Exit-Code fuer eine im UEBRIGEN erfolgreiche Operation, bei der aber
/// mindestens eine Sperrung fehlgeschlagen ist (Standardmodus, nicht streng).
/// Die Ausgabedatei(en) sind korrekt und vollstaendig - die Meldung ist eine
/// ehrliche Warnung, kein Fehler (Audit HC-01: das Programm hat vorher
/// pauschal "alle Geheimnisse gesperrt" behauptet, unabhaengig davon, ob das
/// tatsaechlich gelungen war).
pub const EXIT_CODE_DEGRADED_LOCK: i32 = 8;

/// Wird global (pro Prozess) gezaehlt: wie oft eine `mlock`-Sperrung fuer ein
/// Secret fehlgeschlagen ist. Der Worker liest das am Ende einer Operation
/// aus, um ehrlich zu berichten, statt pauschal "alle Geheimnisse gesperrt"
/// zu behaupten (Audit HC-01).
static LOCK_FAILURES: AtomicU32 = AtomicU32::new(0);

/// Strenger Modus: sobald EINE Sperrung fehlschlaegt, wird der Prozess sofort
/// beendet (fail-closed), statt die Operation mit einer Warnung fortzusetzen.
static STRICT_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_strict_mode(on: bool) {
    STRICT_MODE.store(on, Ordering::SeqCst);
}

pub fn lock_failure_count() -> u32 {
    LOCK_FAILURES.load(Ordering::SeqCst)
}

fn record_lock_failure() {
    LOCK_FAILURES.fetch_add(1, Ordering::SeqCst);
    if STRICT_MODE.load(Ordering::SeqCst) {
        // Bewusst SOFORT hier, nicht erst am Ende der Operation: im strengen
        // Modus soll kein einziges Secret auch nur voruebergehend ungesperrt
        // existieren, waehrend die Operation weiterlaeuft.
        std::process::exit(EXIT_CODE_STRICT_MLOCK_FAILED);
    }
}

fn page_size() -> usize {
    // SAFETY: sysconf ist immer sicher aufrufbar.
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 {
        v as usize
    } else {
        4096
    }
}

fn round_up_to_page(n: usize, page: usize) -> usize {
    n.div_ceil(page) * page
}

/// Eine einzelne, exklusive, gesperrte `mmap`-Region mit Guard-Pages davor
/// und dahinter. Das ist das gemeinsame Fundament sowohl fuer [`SecureBuf`]
/// als auch fuer den Argon2-Arbeitsspeicher in `hybrid.rs`.
struct MmapSecret {
    /// Beginn der GESAMTEN Mapping (erste Guard-Page).
    base: *mut u8,
    /// Groesse der gesamten Mapping inklusive beider Guard-Pages.
    total_len: usize,
    /// Beginn des nutzbaren Bereichs (`base + page_size`).
    data: *mut u8,
    /// Groesse des nutzbaren Bereichs (auf volle Seiten aufgerundet).
    data_cap: usize,
    locked: bool,
}

// SAFETY: MmapSecret verwaltet ausschliesslich eine eigene, exklusive
// mmap-Region ohne Bezug zu Thread-lokalem Zustand; Zugriffe auf die Region
// selbst sind durch die aufrufenden Typen (SecureBuf) synchronisiert.
unsafe impl Send for MmapSecret {}

impl MmapSecret {
    /// Reserviert mindestens `min_bytes` nutzbaren, gesperrten Speicher.
    fn new(min_bytes: usize) -> Self {
        let page = page_size();
        let data_cap = round_up_to_page(min_bytes.max(1), page);
        let total_len = data_cap + 2 * page;

        // SAFETY: konstante, gueltige Flags; kein Dateideskriptor beteiligt.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            // Kein sinnvoller Fortbetrieb moeglich: ohne Speicher fuer
            // Geheimnisse kann das Programm seine Kernfunktion nicht erfuellen.
            // Das ist bewusst ein harter Abbruch, kein degradiertes Fortfahren
            // wie bei einem blossen mlock-Fehlschlag.
            panic!(
                "mmap fuer gesperrten Speicher fehlgeschlagen (errno {}) - \
                 kein freier virtueller Adressraum mehr",
                std::io::Error::last_os_error()
            );
        }
        let base = base as *mut u8;

        // Guard-Pages: vor und hinter dem Nutzbereich je eine Seite ohne
        // jeden Zugriff. Ein Pufferueberlauf fuehrt zu SIGSEGV statt zu
        // stillem Lesen/Schreiben benachbarten Speichers.
        // SAFETY: `base` und `base + data_cap + page` liegen beide innerhalb
        // der eben erfolgreich erzeugten Mapping.
        unsafe {
            libc::mprotect(base as *mut libc::c_void, page, libc::PROT_NONE);
            libc::mprotect(
                base.add(page + data_cap) as *mut libc::c_void,
                page,
                libc::PROT_NONE,
            );
        }

        let data = unsafe { base.add(page) };

        // SAFETY: `data`/`data_cap` bezeichnen exakt den PROT_READ|PROT_WRITE
        // Mittelteil der Mapping.
        let lock_rc = unsafe { libc::mlock(data as *const libc::c_void, data_cap) };
        let locked = lock_rc == 0;
        if !locked {
            record_lock_failure();
        }

        // Linux-spezifisch: aus Core-Dumps ausschliessen. Redundant zu
        // RLIMIT_CORE=0 (hardening.rs), aber eine zusaetzliche, unabhaengige
        // Schutzschicht falls ein Dump durch einen anderen Weg ausgeloest wird
        // (z.B. durch ein Debug-Tool, das RLIMIT_CORE ignoriert).
        #[cfg(target_os = "linux")]
        // SAFETY: wie oben, gueltiger Bereich innerhalb der Mapping.
        unsafe {
            libc::madvise(
                data as *mut libc::c_void,
                data_cap,
                libc::MADV_DONTDUMP,
            );
        }

        MmapSecret {
            base,
            total_len,
            data,
            data_cap,
            locked,
        }
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data
    }
}

impl Drop for MmapSecret {
    fn drop(&mut self) {
        // 1) Nutzbereich mit garantiert volatilen Schreibzugriffen nullen -
        //    IMMER, unabhaengig davon, ob das Sperren zuvor gelang.
        // SAFETY: `data`/`data_cap` sind gueltig bis zu diesem Drop.
        let slice = unsafe { std::slice::from_raw_parts_mut(self.data, self.data_cap) };
        slice.zeroize();

        // 2) erst danach entsperren
        if self.locked {
            // SAFETY: exakt der zuvor gesperrte Bereich.
            unsafe { libc::munlock(self.data as *const libc::c_void, self.data_cap) };
        }

        // 3) gesamte Mapping (inklusive beider Guard-Pages) freigeben.
        // SAFETY: `base`/`total_len` stammen aus dem erfolgreichen `mmap` in `new`.
        unsafe { libc::munmap(self.base as *mut libc::c_void, self.total_len) };
    }
}

pub struct SecureBuf {
    mem: MmapSecret,
    /// Vom Aufrufer angefragte Kapazitaet. Die zugrundeliegende `mmap`-Region
    /// ist auf volle Seiten aufgerundet und damit fast immer GROESSER als
    /// dieser Wert (siehe `MmapSecret::new`) - das ist gewollt (Guard-Pages,
    /// Seitenausrichtung fuer `mlock`). `fill_to_capacity()` und die
    /// Kapazitaetspruefung in `push_bytes` beziehen sich bewusst auf DIESEN
    /// angeforderten Wert, nicht auf die tatsaechliche mmap-Groesse - sonst
    /// wuerde z.B. ein 32-Byte-Schluesselpuffer beim Auffuellen auf die volle
    /// Seitengroesse (4096 Byte) aufgeblasen.
    requested_cap: usize,
    /// Aktuell benutzte Laenge innerhalb von `requested_cap`.
    len: usize,
}

impl SecureBuf {
    /// Reserviert `capacity` Bytes exklusiven, gesperrten Speicher.
    /// Die Kapazitaet (und damit die Adresse) aendert sich danach nie mehr -
    /// ein `SecureBuf` reallokiert nie.
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        SecureBuf {
            mem: MmapSecret::new(capacity),
            requested_cap: capacity,
            len: 0,
        }
    }

    pub fn from_slice(src: &[u8]) -> Self {
        let mut b = Self::with_capacity(src.len());
        b.push_bytes(src);
        b
    }

    pub fn push_bytes(&mut self, extra: &[u8]) {
        assert!(
            self.len + extra.len() <= self.requested_cap,
            "SecureBuf: Kapazitaet ueberschritten - ein SecureBuf reallokiert \
             absichtlich nie, damit nie ein alter, ungezeroizter Block im \
             Allokator zurueckbleibt"
        );
        // SAFETY: `self.len + extra.len() <= requested_cap <= mem.capacity()`,
        // gerade geprueft.
        unsafe {
            std::ptr::copy_nonoverlapping(
                extra.as_ptr(),
                self.mem.as_mut_ptr().add(self.len),
                extra.len(),
            );
        }
        self.len += extra.len();
    }

    /// Setzt die Laenge auf die vom Aufrufer angeforderte Kapazitaet (mit
    /// Nullen gefuellt), damit der Puffer als `&mut [u8]` direkt befuellt
    /// werden kann (z.B. `Read::read`). Bewusst NICHT die tatsaechliche,
    /// seitengerundete `mmap`-Groesse (siehe Feld-Dokumentation oben).
    pub fn fill_to_capacity(&mut self) {
        self.len = self.requested_cap;
    }

    /// Kuerzt auf `n` Bytes und nullt den abgeschnittenen Rest volatil.
    pub fn truncate_wiped(&mut self, n: usize) {
        if n < self.len {
            // SAFETY: `n..self.len` liegt innerhalb der Kapazitaet.
            let tail = unsafe {
                std::slice::from_raw_parts_mut(self.mem.as_mut_ptr().add(n), self.len - n)
            };
            tail.zeroize();
            self.len = n;
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `self.len <= capacity`, Speicher ist initialisiert (jede
        // Erweiterung ueber push_bytes/fill_to_capacity schreibt den Bereich).
        unsafe { std::slice::from_raw_parts(self.mem.data, self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: wie oben.
        unsafe { std::slice::from_raw_parts_mut(self.mem.as_mut_ptr(), self.len) }
    }

    /// Nullt den Inhalt volatil und setzt die Laenge auf 0 (Kapazitaet bleibt
    /// reserviert und gesperrt).
    pub fn clear(&mut self) {
        self.as_mut_slice().zeroize();
        self.len = 0;
    }
}

// Drop von SecureBuf braucht keinen eigenen Code: `mem: MmapSecret` wird
// automatisch gedroppt und nullt/entsperrt/unmapped sich selbst.

/// Roher, gesperrter Speicherblock fester Groesse ohne "Laenge"-Konzept -
/// fuer Faelle, in denen der Aufrufer den Speicher selbst typisiert
/// interpretiert (z.B. als `&mut [argon2::Block]` fuer den Argon2-
/// Arbeitsspeicher in hybrid.rs). Nutzt dieselbe exklusive, guard-page-
/// geschuetzte `mmap`-Region wie `SecureBuf`.
pub struct SecureBytes {
    mem: MmapSecret,
}

impl SecureBytes {
    pub fn new(min_bytes: usize) -> Self {
        SecureBytes {
            mem: MmapSecret::new(min_bytes),
        }
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.mem.as_mut_ptr()
    }
}
