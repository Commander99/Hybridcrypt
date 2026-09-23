//! Laeuft NUR im Kindprozess (`hybridcrypt --worker`).
//!
//! Dieser Prozess hat kein Fenster, kein Netzwerk und keine Argumente ausser
//! dem Rollen-Flag. Er liest seine Anweisungen aus fd 3, die Nutzdaten aus
//! stdin und schreibt das Ergebnis nach stdout (bzw. fd 4). Danach endet er -
//! das Betriebssystem gibt den kompletten Adressraum frei, in dem ueberhaupt
//! jemals Schluesselmaterial lag.
//!
//! Fehler verlassen den Prozess ausschliesslich als Exit-Code. Es wird bewusst
//! kein Text nach aussen gegeben: eine Meldung koennte ueber Laengen, Formate
//! oder Zustaende mehr verraten als noetig, und stderr liegt ohnehin auf
//! /dev/null.
//!
//! Audit-Reaktion (HC-01, HC-06):
//!   - Vor jeder Operation wird `HYBRIDCRYPT_STRICT_MLOCK` ausgewertet. Ist
//!     die Variable auf "1" gesetzt, bricht jede fehlschlagende
//!     Speichersperrung SOFORT ab (secure::record_lock_failure), statt die
//!     Operation mit einer Warnung fortzusetzen.
//!   - Im Normalmodus wird am Ende gezaehlt, ob ueberhaupt eine Sperrung
//!     fehlgeschlagen ist, und ein davon UNTERSCHIEDLICHER Exit-Code benutzt,
//!     statt unconditional Erfolg zu melden - die GUI zeigt das dann als
//!     ehrliche Warnung statt als pauschale Erfolgsmeldung.
//!   - Der Klartext-Ausgabestrom beim Entschluesseln ist bewusst NICHT
//!     gepuffert: ein `BufWriter` wuerde jeden Chunk unter 64 KiB (mindestens
//!     den letzten jeder Datei) zusaetzlich in einem gewoehnlichen,
//!     ungesperrten und nie geleerten Heap-Puffer zwischenlagern.

use crate::hybrid::{self, CryptoError};
use crate::proc::{FD_KEY_OUT, OP_DECRYPT, OP_ENCRYPT, OP_KEYGEN};
use crate::secure::{self, SecureBuf, EXIT_CODE_DEGRADED_LOCK};
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::os::fd::FromRawFd;

/// Obergrenze fuer ein einzelnes Feld im Steuerkanal (Schluesselblobs sind
/// wenige KiB gross) - verhindert Speichererschoepfung bei kaputter Eingabe.
const MAX_CONTROL_FIELD: usize = 1 << 20;

pub fn run() -> ! {
    // Muss VOR jeder SecureBuf-Allokation stehen, damit der strenge Modus ab
    // dem allerersten Secret greift.
    if std::env::var("HYBRIDCRYPT_STRICT_MLOCK").as_deref() == Ok("1") {
        secure::set_strict_mode(true);
    }

    let code = match execute() {
        Ok(()) if secure::lock_failure_count() > 0 => EXIT_CODE_DEGRADED_LOCK,
        Ok(()) => 0,
        Err(e) => e.exit_code(),
    };
    std::process::exit(code)
}

fn execute() -> Result<(), CryptoError> {
    // SAFETY: fd 3 wurde vom Elternprozess vor exec eingerichtet.
    let mut control = unsafe { File::from_raw_fd(crate::proc::FD_CONTROL) };
    // SAFETY: stdin/stdout sind vom Elternprozess auf Dateien gesetzt worden.
    let mut input = unsafe { File::from_raw_fd(0) };
    // SAFETY: wie oben. Wird je nach Operation gepuffert oder direkt benutzt
    // (siehe Modul-Dokumentation, HC-06).
    let stdout_file = unsafe { File::from_raw_fd(1) };

    let mut op = [0u8; 1];
    control
        .read_exact(&mut op)
        .map_err(|_| CryptoError::Internal)?;

    match op[0] {
        OP_KEYGEN => {
            let passphrase = read_secret_field(&mut control)?;
            let mut pub_out = BufWriter::with_capacity(hybrid::CHUNK_SIZE, stdout_file);
            // SAFETY: fd 4 wurde vom Elternprozess vor exec eingerichtet.
            let mut key_out = BufWriter::new(unsafe { File::from_raw_fd(FD_KEY_OUT) });
            hybrid::generate_keypair(&passphrase, &mut pub_out, &mut key_out)?;
            key_out.flush()?;
            pub_out.flush()?;
        }
        OP_ENCRYPT => {
            let recipient_pub = read_public_field(&mut control)?;
            // Ausgabe ist Ciphertext, kein Klartext - Puffern ist unbedenklich
            // und spart Systemaufrufe.
            let mut output = BufWriter::with_capacity(hybrid::CHUNK_SIZE, stdout_file);
            hybrid::encrypt_stream(&recipient_pub, &mut input, &mut output)?;
            output.flush()?;
        }
        OP_DECRYPT => {
            // Der .hkey-Blob ist bereits mit der Passphrase verschluesselt,
            // muss also nicht selbst als Geheimnis behandelt werden.
            let key_blob = read_public_field(&mut control)?;
            let passphrase = read_secret_field(&mut control)?;
            // Audit HC-06: HIER ist die Ausgabe Klartext. Bewusst UNGEPUFFERT
            // schreiben - hybrid.rs::decrypt_stream schreibt ohnehin schon in
            // 64-KiB-Chunks, ein zusaetzlicher BufWriter haette also keinerlei
            // Geschwindigkeitsvorteil gebracht, nur eine zusaetzliche,
            // ungesperrte und nie geleerte Kopie jedes Chunks unter 64 KiB
            // (mindestens des letzten jeder Datei) im normalen Heap hinterlassen.
            let mut output = stdout_file;
            hybrid::decrypt_stream(&key_blob, &passphrase, &mut input, &mut output)?;
            output.flush()?;
        }
        _ => return Err(CryptoError::Internal),
    }

    Ok(())
}

fn read_len(control: &mut File) -> Result<usize, CryptoError> {
    let mut b = [0u8; 4];
    control
        .read_exact(&mut b)
        .map_err(|_| CryptoError::Internal)?;
    let len = u32::from_le_bytes(b) as usize;
    if len > MAX_CONTROL_FIELD {
        return Err(CryptoError::Internal);
    }
    Ok(len)
}

/// Liest ein Geheimnis DIREKT in gesperrten Speicher - es existiert zu keinem
/// Zeitpunkt eine Zwischenkopie auf dem normalen Heap.
fn read_secret_field(control: &mut File) -> Result<SecureBuf, CryptoError> {
    let len = read_len(control)?;
    let mut buf = SecureBuf::with_capacity(len.max(1));
    buf.fill_to_capacity();
    control
        .read_exact(&mut buf.as_mut_slice()[..len])
        .map_err(|_| CryptoError::Internal)?;
    buf.truncate_wiped(len);
    Ok(buf)
}

/// Liest ein oeffentliches bzw. bereits verschluesseltes Feld.
fn read_public_field(control: &mut File) -> Result<Vec<u8>, CryptoError> {
    let len = read_len(control)?;
    let mut buf = vec![0u8; len];
    control
        .read_exact(&mut buf)
        .map_err(|_| CryptoError::Internal)?;
    Ok(buf)
}
