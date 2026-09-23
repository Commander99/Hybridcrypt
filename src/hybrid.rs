//! Kryptografischer Kern. Laeuft AUSSCHLIESSLICH im per Re-Exec gestarteten
//! Worker-Prozess (siehe `worker.rs`) - der GUI-Prozess ruft hier nie etwas auf.
//!
//! Suite: **ML-KEM-1024 x P-384 x SHA-256**
//!   SS = HKDF-SHA256(IKM = ML-KEM-SharedSecret || ECDH-P384-SharedSecret,
//!                    info = "hybridcrypt-v3" || Container-Header || SHA256(Empfaenger-Oeffentlich))
//!   Datenverschluesselung: ChaCha20-Poly1305, 64-KiB-Chunks.
//!
//! Aenderungen gegenueber v2 (Reaktion auf ein externes Audit, siehe README
//! Abschnitt 0): Empfaenger-Bindung im KDF (Audit HC-12), Header-Validierung
//! VOR statt nach Argon2 (HC-09), engere Argon2-Parametergrenzen (HC-09),
//! Passphrasen-Staerkepruefung per zxcvbn statt reiner Zeichenzahl (HC-03),
//! NFKC-Normalisierung der Passphrase (HC-03), Public-Key-Fingerprint (HC-02),
//! Zurueckweisung ueberzaehliger Bytes in `.hpub` (HC-15).
//!
//! Dateiformate
//! ------------
//! Public-Key `.hpub` (unbedenklich, darf verteilt werden):
//!     "HPB2" | u32 len | ML-KEM-EK | u32 len | P-384-Punkt (SEC1, unkomprimiert)
//!     Keine ueberzaehligen Bytes danach erlaubt (Audit HC-15).
//!
//! Private-Key `.hkey` (mit Passphrase geschuetzt):
//!     "HSK2" | m_cost u32 | t_cost u32 | lanes u32 | salt[16] | nonce[12]
//!           | ChaCha20-Poly1305(u32|ML-KEM-DK || u32|P-384-Skalar) | tag[16]
//!     AAD = alles vor dem Ciphertext -> Argon2-Parameter sind mit-authentifiziert
//!     und koennen nicht heruntergedreht werden.
//!
//! Container `.hcx` (Version 3):
//!     Header = "HCX3" | u32 len | ML-KEM-CT | u32 len | eph. P-384-Punkt | base_nonce[12]
//!     danach 1..n Chunks:  u32 len | Ciphertext | tag[16]
//!     Nonce  = base_nonce XOR counter(LE, in den letzten 8 Bytes)
//!     AAD    = counter(8, LE) || last_flag(1)
//!
//! Das `last_flag` markiert den letzten Chunk kryptografisch; jede Kuerzung
//! der Datei schlaegt bei der Authentifizierung fehl (Truncation-Schutz).
//! Der Header ist ueber `info` an den Sitzungsschluessel gebunden, ebenso
//! (neu in v3) ein Hash der oeffentlichen Empfaenger-Schluessel - nicht weil
//! ein konkreter Angriff ohne diese Bindung bekannt waere (das Audit nennt
//! ausdruecklich keinen), sondern als zusaetzliche, in HPKE/X-Wing uebliche
//! Absicherung gegen Mehrempfaenger-Schluesselkompromittierungs-Szenarien.
//!
//! Hinweis zur Wahl SHA-256: CNSA 2.0 nutzt zu P-384 ueblicherweise SHA-384.
//! Du hast SHA-256 vorgegeben - das ist hier 1:1 umgesetzt und mit 256 Bit
//! Ausgabe fuer einen 256-Bit-AEAD-Schluessel voellig ausreichend.

use crate::secure::{SecureBuf, SecureBytes};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem1024};
use p384::ecdh::diffie_hellman;
use p384::{PublicKey as P384Public, SecretKey as P384Secret};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io::{ErrorKind, Read, Write};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

pub const MAGIC_PUB: &[u8; 4] = b"HPB2";
pub const MAGIC_KEY: &[u8; 4] = b"HSK2";
pub const MAGIC_CT: &[u8; 4] = b"HCX3";

pub const CHUNK_SIZE: usize = 64 * 1024;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// Argon2id-Parameter fuer den Key-Encryption-Key der privaten Schluesseldatei.
/// 128 MiB / 4 Durchlaeufe sind deutlich ueber dem OWASP-Minimum und machen
/// GPU-/ASIC-gestuetztes Durchprobieren teuer.
const ARGON_M_COST: u32 = 128 * 1024; // KiB
const ARGON_T_COST: u32 = 4;
const ARGON_LANES: u32 = 1;

/// Audit HC-09: die alte Obergrenze (4 GiB / t=64 / p=16) liess eine
/// praeparierte `.hkey`-Datei einen mehrminuetigen, mehrere GiB grossen
/// Argon2-Lauf erzwingen, den die GUI nicht abbrechen kann. Diese engeren
/// Grenzen decken jeden mit den obigen ARGON_*-Konstanten selbst erzeugten
/// Schluessel klar ab und begrenzen trotzdem den maximal moeglichen Schaden
/// durch eine manipulierte Datei.
const ARGON_M_COST_MAX: u32 = 1024 * 1024; // 1 GiB in KiB
const ARGON_T_COST_MAX: u32 = 10;
const ARGON_LANES_MAX: u32 = 4;

/// Audit HC-03: Mindest-Staerke fuer eine bei der Schluesselerzeugung neu
/// gewaehlte Passphrase. `zxcvbn` schaetzt die Zahl der Rateversuche unter
/// Beruecksichtigung von Woerterbuechern, Tastaturmustern, Wiederholungen
/// und Jahreszahlen - eine reine Laengenpruefung haette z.B. "Summer2026!!"
/// (12 Zeichen, aber log10(guesses) = 8.0) klaglos akzeptiert.
/// Schwelle: zxcvbn-Score 4 (von 0-4) UND mindestens 10^12 geschaetzte
/// Rateversuche. Das lehnt u.a. klassische "sichere" Muster wie
/// "Tr0ub4dor&3" ab (Score 4, aber nur 10^11 - genau das XKCD-936-Beispiel
/// dafuer, dass Kompositionsregeln allein nicht ausreichen) und verlangt
/// der Sache nach mindestens eine kurze Diceware-Phrase oder eine echt
/// zufaellige Passphrase vergleichbarer Staerke.
const MIN_ZXCVBN_SCORE: u8 = 4;
const MIN_LOG10_GUESSES: f64 = 12.0;
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// Fehler ohne jeden Bezug auf Schluesselmaterial. Wird im Worker in einen
/// Exit-Code uebersetzt; es werden nie Details ueber innere Zustaende nach
/// aussen gegeben.
#[derive(Debug)]
pub enum CryptoError {
    /// Passphrase falsch oder Schluesseldatei manipuliert.
    BadPassphrase,
    /// Schluesseldatei strukturell unbrauchbar.
    BadKeyFile,
    /// Container beschaedigt, gekuerzt oder manipuliert.
    BadContainer,
    Io,
    /// Audit HC-03: neu gewaehlte Passphrase zu schwach.
    WeakPassphrase,
    Internal,
}

impl CryptoError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CryptoError::BadPassphrase => 2,
            CryptoError::BadKeyFile => 3,
            CryptoError::BadContainer => 4,
            CryptoError::Io => 5,
            CryptoError::WeakPassphrase => 6,
            CryptoError::Internal => 1,
        }
    }
}

impl From<std::io::Error> for CryptoError {
    fn from(_: std::io::Error) -> Self {
        CryptoError::Io
    }
}

type Result<T> = std::result::Result<T, CryptoError>;

// ---------------------------------------------------------------------------
// Argon2-Arbeitsspeicher: gesperrt, guard-page-geschuetzt, am Ende ueberschrieben
// ---------------------------------------------------------------------------

/// Argon2 haelt seinen kompletten Zustand (aus dem sich die Passphrase
/// teilweise rekonstruieren liesse) in diesem Block-Array. `hash_password_into`
/// wuerde es intern auf dem normalen Heap allokieren - ungesperrt und ohne
/// Zeroize. Deshalb stellen wir den Speicher selbst: eine eigene, exklusive
/// `mmap`-Region mit Guard-Pages (siehe secure.rs, Audit HC-07), niemals
/// geteilt mit irgendeiner anderen Allokation.
struct LockedBlocks {
    raw: SecureBytes,
    count: usize,
}

impl LockedBlocks {
    fn new(count: usize) -> Self {
        let count = count.max(1);
        let raw = SecureBytes::new(count * Block::SIZE);
        LockedBlocks { raw, count }
    }

    fn as_mut_blocks(&mut self) -> &mut [Block] {
        // SAFETY: `raw` ist mindestens `count * Block::SIZE` Bytes gross,
        // mmap-Speicher ist seitenausgerichtet (>> Alignment von Block, das
        // aus `[u64; N]` besteht), und durch MAP_ANONYMOUS bereits genullt -
        // exakt der Zustand, den `Block::default()` auch herstellen wuerde.
        unsafe {
            std::slice::from_raw_parts_mut(self.raw.as_mut_ptr() as *mut Block, self.count)
        }
    }
}
// Kein eigenes Drop noetig: `raw: SecureBytes` nullt/entsperrt/unmapped sich
// selbst (siehe secure.rs).

fn derive_kek(
    passphrase: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    lanes: u32,
    out: &mut [u8],
) -> Result<()> {
    let params = Params::new(m_cost, t_cost, lanes, Some(out.len()))
        .map_err(|_| CryptoError::BadKeyFile)?;
    let mut memory = LockedBlocks::new(params.block_count());
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into_with_memory(passphrase, salt, out, memory.as_mut_blocks())
        .map_err(|_| CryptoError::Internal)
    // `memory` wird hier ueberschrieben und entsperrt (Drop)
}

/// Audit HC-03: dieselbe Passphrase muss auf macOS und Tails denselben
/// Schluessel ergeben, auch wenn die jeweilige Eingabemethode Sonderzeichen
/// (Umlaute, Akzente) unterschiedlich normalisiert (z.B. "e" + Combining-
/// Acute vs. das vorkomponierte "é"). NFKC vereinheitlicht das vor jeder
/// Verwendung in der KDF.
///
/// Die von `.nfkc().collect()` erzeugte `String` landet unvermeidlich kurz
/// auf dem normalen, ungesperrten Heap (die Unicode-Normalisierungs-API
/// arbeitet nicht mit gesperrtem Speicher) - deshalb wird sie hier sofort
/// nach dem Kopieren in einen `SecureBuf` volatil ueberschrieben, genau wie
/// an den anderen Stellen, an denen Fremd-APIs uns Klartext in normalen
/// Puffern zurueckgeben.
fn normalize_passphrase(input: &SecureBuf) -> Result<SecureBuf> {
    let s = std::str::from_utf8(input.as_slice()).map_err(|_| CryptoError::Internal)?;
    let mut normalized: String = s.nfkc().collect();
    let out = SecureBuf::from_slice(normalized.as_bytes());
    // SAFETY: `normalized` ist ein lebender String, den wir exklusiv besitzen.
    unsafe {
        let v = normalized.as_mut_vec();
        v.zeroize();
    }
    normalized.clear();
    Ok(out)
}

/// Audit HC-03: echte Staerkepruefung statt reiner Zeichenzahl. Wird nur bei
/// der SCHLUESSELERZEUGUNG angewendet - eine bereits bestehende Passphrase
/// wird beim Entschluesseln nie nachtraeglich abgelehnt (das wuerde bei einer
/// Verschaerfung der Regel Nutzer aus ihren eigenen, laengst erzeugten
/// Schluesseln aussperren).
///
/// Wie bei `normalize_passphrase` gilt: `zxcvbn` erwartet `&str` und legt bei
/// der Mustersuche intern Kopien von Teilen der Eingabe auf dem normalen Heap
/// an (das ist keine Bibliothek fuer Geheimnisse). Das ist ein bewusst in
/// Kauf genommener Kompromiss: die Pruefung laeuft AUSSCHLIESSLICH in diesem
/// Worker-Prozess - demselben gehaerteten, kurzlebigen Prozess (mlockall,
/// keine Core-Dumps, PTRACE-Deny), der ohnehin schon die echte
/// Argon2-Berechnung mit der Passphrase durchfuehrt. Es entsteht dadurch
/// keine neue Preisgabe an den GUI-Prozess oder nach aussen, nur ein
/// zusaetzlicher, gleich gearteter Rest wie bei Argon2/Blake2 selbst (siehe
/// README, Restrisiken).
fn check_passphrase_strength(passphrase: &SecureBuf) -> Result<()> {
    let s = std::str::from_utf8(passphrase.as_slice()).map_err(|_| CryptoError::WeakPassphrase)?;
    if s.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(CryptoError::WeakPassphrase);
    }
    let estimate = zxcvbn::zxcvbn(s, &[]);
    let score: u8 = estimate.score().into();
    if score < MIN_ZXCVBN_SCORE || estimate.guesses_log10() < MIN_LOG10_GUESSES {
        return Err(CryptoError::WeakPassphrase);
    }
    Ok(())
}

/// Audit HC-12: SHA-256 ueber die kanonischen Bytes der oeffentlichen
/// Empfaenger-Schluessel, gebunden in die HKDF-`info`. Kein aus dem Audit
/// bekannter Angriff haengt daran - es ist zusaetzliche, in HPKE/X-Wing
/// uebliche Absicherung dagegen, dass bei mehreren Empfaenger-Schluesseln
/// eine Kompromittierung des einen Auswirkungen auf einen anderen hat.
fn recipient_binding(kem_ek_bytes: &[u8], p384_pk_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(kem_ek_bytes);
    hasher.update(p384_pk_bytes);
    hasher.finalize().into()
}

/// Audit HC-02: kurzer, von Menschen ausserhalb des Programms vergleichbarer
/// Fingerabdruck eines `.hpub`-Blobs. Schutz gegen Schluessel-Substitution -
/// die realistischste Schwachstelle jedes solchen Werkzeugs, gegen die keine
/// Kryptografie allein hilft. Format: 4 Gruppen aus je 4 Grossbuchstaben/
/// Ziffern (Base32 der ersten 10 Bytes von SHA-256), z.B. "K7QP RTM2 9ZXA H4LD".
pub fn pubkey_fingerprint(pub_blob: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let digest = Sha256::digest(pub_blob);
    // 10 Bytes = 80 Bit, in 16 Base32-Zeichen zu je 5 Bit.
    let mut bits = 0u64;
    let mut bit_len = 0u32;
    let mut out = String::with_capacity(19);
    for (i, byte) in digest.iter().take(10).enumerate() {
        bits = (bits << 8) | (*byte as u64);
        bit_len += 8;
        while bit_len >= 5 {
            bit_len -= 5;
            let idx = ((bits >> bit_len) & 0x1F) as usize;
            out.push(ALPHABET[idx] as char);
        }
        if i % 2 == 1 && i != 9 {
            out.push(' ');
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Schluesselerzeugung
// ---------------------------------------------------------------------------

/// Erzeugt ein Schluesselpaar und schreibt die beiden Blobs direkt in die
/// uebergebenen Senken (im Betrieb: zwei Datei-Deskriptoren, die der
/// GUI-Prozess geoeffnet und weitergereicht hat - er sieht den Inhalt nie).
pub fn generate_keypair<W1: Write, W2: Write>(
    passphrase: &SecureBuf,
    pub_out: &mut W1,
    key_out: &mut W2,
) -> Result<()> {
    // Zuerst die billige Pruefung, bevor irgendein Schluessel erzeugt oder
    // auch nur der teure Argon2-Lauf gestartet wird.
    check_passphrase_strength(passphrase)?;
    let passphrase = normalize_passphrase(passphrase)?;

    let mut rng = OsRng;

    // --- ML-KEM-1024 ---
    let (kem_dk, kem_ek) = MlKem1024::generate(&mut rng);
    let kem_ek_bytes = kem_ek.as_bytes(); // oeffentlich
    let mut kem_dk_enc = kem_dk.as_bytes();
    let kem_dk_bytes = SecureBuf::from_slice(&kem_dk_enc);
    // die von der Fremd-API gelieferte Kopie sofort ueberschreiben
    {
        let view: &mut [u8] = kem_dk_enc.as_mut();
        view.zeroize();
    }

    // --- P-384 ---
    let p384_sk = P384Secret::random(&mut rng);
    let p384_pk_bytes = p384_sk.public_key().to_sec1_bytes(); // oeffentlich
    let mut p384_sk_enc = p384_sk.to_bytes();
    let p384_sk_bytes = SecureBuf::from_slice(&p384_sk_enc);
    p384_sk_enc.zeroize();

    // --- oeffentlicher Blob ---
    let mut public_blob = Vec::with_capacity(16 + kem_ek_bytes.len() + p384_pk_bytes.len());
    public_blob.extend_from_slice(MAGIC_PUB);
    push_u32_prefixed(&mut public_blob, &kem_ek_bytes);
    push_u32_prefixed(&mut public_blob, &p384_pk_bytes);

    // --- privater Klartext-Blob, ausschliesslich in gesperrtem Speicher ---
    let plain_len = 4 + kem_dk_bytes.len() + 4 + p384_sk_bytes.len();
    let mut secret_payload = SecureBuf::with_capacity(plain_len + TAG_LEN);
    secret_payload.push_bytes(&(kem_dk_bytes.len() as u32).to_le_bytes());
    secret_payload.push_bytes(kem_dk_bytes.as_slice());
    secret_payload.push_bytes(&(p384_sk_bytes.len() as u32).to_le_bytes());
    secret_payload.push_bytes(p384_sk_bytes.as_slice());
    drop(kem_dk_bytes);
    drop(p384_sk_bytes);

    // --- Header + KEK ---
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);

    let mut header = Vec::with_capacity(4 + 12 + SALT_LEN + NONCE_LEN);
    header.extend_from_slice(MAGIC_KEY);
    header.extend_from_slice(&ARGON_M_COST.to_le_bytes());
    header.extend_from_slice(&ARGON_T_COST.to_le_bytes());
    header.extend_from_slice(&ARGON_LANES.to_le_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce_bytes);

    let mut kek = SecureBuf::with_capacity(KEY_LEN);
    kek.fill_to_capacity();
    derive_kek(
        passphrase.as_slice(),
        &salt,
        ARGON_M_COST,
        ARGON_T_COST,
        ARGON_LANES,
        kek.as_mut_slice(),
    )?;
    drop(passphrase);

    let cipher =
        ChaCha20Poly1305::new_from_slice(kek.as_slice()).map_err(|_| CryptoError::Internal)?;
    drop(kek);

    // In-place-Verschluesselung IM gesperrten Puffer - es entsteht zu keinem
    // Zeitpunkt eine ungesperrte Kopie des privaten Schluessels.
    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&nonce_bytes),
            &header,
            secret_payload.as_mut_slice(),
        )
        .map_err(|_| CryptoError::Internal)?;

    key_out.write_all(&header)?;
    key_out.write_all(secret_payload.as_slice())?;
    key_out.write_all(&tag)?;
    key_out.flush()?;

    pub_out.write_all(&public_blob)?;
    pub_out.flush()?;

    salt.zeroize();
    nonce_bytes.zeroize();
    Ok(())
}

/// Entschluesselt eine `.hkey`-Datei und liefert die Rohbytes beider privater
/// Schluessel in gesperrtem Speicher.
fn open_private_blob(blob: &[u8], passphrase: &SecureBuf) -> Result<(SecureBuf, SecureBuf)> {
    const HEADER_LEN: usize = 4 + 12 + SALT_LEN + NONCE_LEN;
    if blob.len() < HEADER_LEN + TAG_LEN || &blob[..4] != MAGIC_KEY {
        return Err(CryptoError::BadKeyFile);
    }
    let header = &blob[..HEADER_LEN];
    let m_cost = u32::from_le_bytes(blob[4..8].try_into().unwrap());
    let t_cost = u32::from_le_bytes(blob[8..12].try_into().unwrap());
    let lanes = u32::from_le_bytes(blob[12..16].try_into().unwrap());
    let salt = &blob[16..16 + SALT_LEN];
    let nonce_bytes = &blob[16 + SALT_LEN..HEADER_LEN];
    let body = &blob[HEADER_LEN..];
    let (ct, tag) = body.split_at(body.len() - TAG_LEN);

    // Audit HC-09: Schutz gegen praeparierte Schluesseldateien, die den
    // Rechner mit einem absurden m_cost lahmlegen (der Wert ist zwar per AAD
    // authentifiziert, die Pruefung erfolgt aber erst NACH dem Ableiten -
    // also vorher eng begrenzen). Die Grenzen decken die eigenen
    // ARGON_*-Konstanten klar ab, lassen fuer kuenftige, bewusste
    // Erhoehungen der Default-Parameter aber Spielraum.
    if m_cost > ARGON_M_COST_MAX || t_cost > ARGON_T_COST_MAX || lanes > ARGON_LANES_MAX {
        return Err(CryptoError::BadKeyFile);
    }

    let passphrase_norm = normalize_passphrase(passphrase)?;

    let mut kek = SecureBuf::with_capacity(KEY_LEN);
    kek.fill_to_capacity();
    derive_kek(
        passphrase_norm.as_slice(),
        salt,
        m_cost,
        t_cost,
        lanes,
        kek.as_mut_slice(),
    )?;
    drop(passphrase_norm);

    let cipher =
        ChaCha20Poly1305::new_from_slice(kek.as_slice()).map_err(|_| CryptoError::Internal)?;
    drop(kek);

    // Ciphertext in gesperrten Speicher kopieren und dort in place entschluesseln
    let mut plain = SecureBuf::from_slice(ct);
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(nonce_bytes),
            header,
            plain.as_mut_slice(),
            Tag::from_slice(tag),
        )
        .map_err(|_| CryptoError::BadPassphrase)?;

    let mut cursor = plain.as_slice();
    let kem_dk = take_u32_prefixed_secure(&mut cursor).ok_or(CryptoError::BadKeyFile)?;
    let p384_sk = take_u32_prefixed_secure(&mut cursor).ok_or(CryptoError::BadKeyFile)?;
    Ok((kem_dk, p384_sk))
}

// ---------------------------------------------------------------------------
// Verschluesseln
// ---------------------------------------------------------------------------

pub fn encrypt_stream<R: Read, W: Write>(
    recipient_public_blob: &[u8],
    input: &mut R,
    output: &mut W,
) -> Result<()> {
    let mut cursor = recipient_public_blob;
    if take_exact(&mut cursor, 4).ok_or(CryptoError::BadKeyFile)? != MAGIC_PUB {
        return Err(CryptoError::BadKeyFile);
    }
    let kem_ek_bytes = take_u32_prefixed(&mut cursor).ok_or(CryptoError::BadKeyFile)?;
    let p384_pk_bytes = take_u32_prefixed(&mut cursor).ok_or(CryptoError::BadKeyFile)?;
    // Audit HC-15: keine ueberzaehligen Bytes nach den beiden erwarteten
    // Feldern akzeptieren - eine anghaengte Nutzlast waere sonst ein stiller
    // blinder Fleck (wird geparst, aber nie geprueft).
    if !cursor.is_empty() {
        return Err(CryptoError::BadKeyFile);
    }
    let binding = recipient_binding(kem_ek_bytes, p384_pk_bytes);

    let encoded = Encoded::<<MlKem1024 as KemCore>::EncapsulationKey>::try_from(kem_ek_bytes)
        .map_err(|_| CryptoError::BadKeyFile)?;
    let kem_ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&encoded);
    let p384_pk = P384Public::from_sec1_bytes(p384_pk_bytes).map_err(|_| CryptoError::BadKeyFile)?;

    let mut rng = OsRng;
    let (kem_ct, mut kem_shared) = kem_ek
        .encapsulate(&mut rng)
        .map_err(|_| CryptoError::Internal)?;
    let kem_shared_secure = SecureBuf::from_slice(&kem_shared);
    {
        let view: &mut [u8] = kem_shared.as_mut();
        view.zeroize();
    }

    let eph_sk = P384Secret::random(&mut rng);
    let eph_pk_bytes = eph_sk.public_key().to_sec1_bytes();
    let ecdh = diffie_hellman(eph_sk.to_nonzero_scalar(), p384_pk.as_affine());
    let ecdh_secure = SecureBuf::from_slice(ecdh.raw_secret_bytes());
    drop(ecdh);
    drop(eph_sk);

    let mut base_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut base_nonce);

    let mut header = Vec::with_capacity(4 + 8 + kem_ct.len() + eph_pk_bytes.len() + NONCE_LEN);
    header.extend_from_slice(MAGIC_CT);
    push_u32_prefixed(&mut header, &kem_ct);
    push_u32_prefixed(&mut header, &eph_pk_bytes);
    header.extend_from_slice(&base_nonce);

    let mut session_key = SecureBuf::with_capacity(KEY_LEN);
    session_key.fill_to_capacity();
    derive_session_key(
        kem_shared_secure.as_slice(),
        ecdh_secure.as_slice(),
        &header,
        &binding,
        session_key.as_mut_slice(),
    )?;
    drop(kem_shared_secure);
    drop(ecdh_secure);

    let cipher = ChaCha20Poly1305::new_from_slice(session_key.as_slice())
        .map_err(|_| CryptoError::Internal)?;
    drop(session_key);

    output.write_all(&header)?;

    // Zwei gesperrte Chunk-Puffer: `cur` wird verarbeitet, `look` ist der
    // Vorgriff, der entscheidet, ob `cur` der letzte Chunk ist.
    let mut cur = SecureBuf::with_capacity(CHUNK_SIZE);
    let mut look = SecureBuf::with_capacity(CHUNK_SIZE);
    fill_chunk(input, &mut cur)?;

    let mut counter: u64 = 0;
    loop {
        fill_chunk(input, &mut look)?;
        let last = look.len() == 0;
        let aad = chunk_aad(counter, last);
        let nonce = counter_nonce(&base_nonce, counter);

        let plain_len = cur.len();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, cur.as_mut_slice())
            .map_err(|_| CryptoError::Internal)?;

        output.write_all(&(plain_len as u32).to_le_bytes())?;
        output.write_all(cur.as_slice())?; // enthaelt jetzt Ciphertext
        output.write_all(&tag)?;
        cur.clear();

        if last {
            break;
        }
        std::mem::swap(&mut cur, &mut look);
        counter += 1;
    }
    output.flush()?;
    base_nonce.zeroize();
    Ok(())
}

// ---------------------------------------------------------------------------
// Entschluesseln
// ---------------------------------------------------------------------------

pub fn decrypt_stream<R: Read, W: Write>(
    encrypted_private_blob: &[u8],
    passphrase: &SecureBuf,
    input: &mut R,
    output: &mut W,
) -> Result<()> {
    // Audit HC-09: den Container-Header ZUERST lesen und strukturell pruefen
    // (billig - kein Argon2), und erst DANACH die teure, passphrasengeschuetzte
    // Schluesseldatei oeffnen. Eine offensichtlich kaputte/fremde Datei kostet
    // so keinen vollen Argon2-Lauf mehr und verlangt nicht erst eine Passphrase.
    let mut header = Vec::with_capacity(4 + 8 + 1568 + 97 + NONCE_LEN);
    let magic = read_exact_vec(input, 4).map_err(|_| CryptoError::BadContainer)?;
    if magic != MAGIC_CT {
        return Err(CryptoError::BadContainer);
    }
    header.extend_from_slice(&magic);
    let kem_ct_bytes = read_u32_prefixed(input, &mut header, 4096)?;
    let eph_pk_bytes = read_u32_prefixed(input, &mut header, 256)?;
    let base_nonce_v = read_exact_vec(input, NONCE_LEN).map_err(|_| CryptoError::BadContainer)?;
    header.extend_from_slice(&base_nonce_v);
    let mut base_nonce = [0u8; NONCE_LEN];
    base_nonce.copy_from_slice(&base_nonce_v);
    let kem_ct = Ciphertext::<MlKem1024>::try_from(kem_ct_bytes.as_slice())
        .map_err(|_| CryptoError::BadContainer)?;
    let eph_pk = P384Public::from_sec1_bytes(&eph_pk_bytes).map_err(|_| CryptoError::BadContainer)?;

    // Erst jetzt der teure, passphrasengeschuetzte Teil.
    let (kem_dk_bytes, p384_sk_bytes) = open_private_blob(encrypted_private_blob, passphrase)?;

    let dk_encoded =
        Encoded::<<MlKem1024 as KemCore>::DecapsulationKey>::try_from(kem_dk_bytes.as_slice())
            .map_err(|_| CryptoError::BadKeyFile)?;
    let kem_dk = <MlKem1024 as KemCore>::DecapsulationKey::from_bytes(&dk_encoded);
    drop(kem_dk_bytes);

    let p384_sk =
        P384Secret::from_slice(p384_sk_bytes.as_slice()).map_err(|_| CryptoError::BadKeyFile)?;
    drop(p384_sk_bytes);

    // Audit HC-12: dieselbe Empfaenger-Bindung wie beim Verschluesseln, hier
    // aus dem EIGENEN privaten Schluessel abgeleitet statt aus einer
    // mitgelieferten `.hpub`-Datei - muss byteidentisch zu der Bindung sein,
    // die die Gegenseite aus der Original-`.hpub` berechnet hat, sonst
    // scheitert die Sitzungsschluessel-Ableitung (und damit der AEAD-Tag).
    let own_kem_ek_bytes = kem_dk.encapsulation_key().as_bytes();
    let own_p384_pk_bytes = p384_sk.public_key().to_sec1_bytes();
    let binding = recipient_binding(&own_kem_ek_bytes, &own_p384_pk_bytes);

    let mut kem_shared = kem_dk
        .decapsulate(&kem_ct)
        .map_err(|_| CryptoError::BadContainer)?;
    let kem_shared_secure = SecureBuf::from_slice(&kem_shared);
    {
        let view: &mut [u8] = kem_shared.as_mut();
        view.zeroize();
    }

    let ecdh = diffie_hellman(p384_sk.to_nonzero_scalar(), eph_pk.as_affine());
    let ecdh_secure = SecureBuf::from_slice(ecdh.raw_secret_bytes());
    drop(ecdh);
    drop(p384_sk);

    let mut session_key = SecureBuf::with_capacity(KEY_LEN);
    session_key.fill_to_capacity();
    derive_session_key(
        kem_shared_secure.as_slice(),
        ecdh_secure.as_slice(),
        &header,
        &binding,
        session_key.as_mut_slice(),
    )?;
    drop(kem_shared_secure);
    drop(ecdh_secure);

    let cipher = ChaCha20Poly1305::new_from_slice(session_key.as_slice())
        .map_err(|_| CryptoError::Internal)?;
    drop(session_key);

    let mut buf = SecureBuf::with_capacity(CHUNK_SIZE);
    let mut next_len = read_opt_u32(input)?;
    let mut counter: u64 = 0;
    loop {
        let n = next_len.ok_or(CryptoError::BadContainer)? as usize;
        if n > CHUNK_SIZE {
            return Err(CryptoError::BadContainer);
        }
        buf.clear();
        buf.fill_to_capacity();
        input
            .read_exact(&mut buf.as_mut_slice()[..n])
            .map_err(|_| CryptoError::BadContainer)?;
        buf.truncate_wiped(n);
        let tag = read_exact_vec(input, TAG_LEN).map_err(|_| CryptoError::BadContainer)?;

        // Vorgriff: gibt es noch einen Chunk? Nur so ist das last_flag bekannt,
        // und nur so faellt eine Kuerzung der Datei auf.
        next_len = read_opt_u32(input)?;
        let last = next_len.is_none();

        let aad = chunk_aad(counter, last);
        let nonce = counter_nonce(&base_nonce, counter);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &aad,
                buf.as_mut_slice(),
                Tag::from_slice(&tag),
            )
            .map_err(|_| CryptoError::BadContainer)?;

        output.write_all(buf.as_slice())?;
        buf.clear();
        if last {
            break;
        }
        counter += 1;
    }
    output.flush()?;
    base_nonce.zeroize();
    Ok(())
}

// ---------------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------------

fn derive_session_key(
    kem_shared: &[u8],
    ecdh_shared: &[u8],
    header: &[u8],
    recipient_binding: &[u8; 32],
    out: &mut [u8],
) -> Result<()> {
    let mut ikm = SecureBuf::with_capacity(kem_shared.len() + ecdh_shared.len());
    ikm.push_bytes(kem_shared);
    ikm.push_bytes(ecdh_shared);

    let mut info = Vec::with_capacity(14 + header.len() + recipient_binding.len());
    info.extend_from_slice(b"hybridcrypt-v3");
    info.extend_from_slice(header);
    info.extend_from_slice(recipient_binding);

    let hk = Hkdf::<Sha256>::new(None, ikm.as_slice());
    hk.expand(&info, out).map_err(|_| CryptoError::Internal)
    // `ikm` wird hier genullt und entsperrt (Drop)
}

fn chunk_aad(counter: u64, last: bool) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[..8].copy_from_slice(&counter.to_le_bytes());
    aad[8] = u8::from(last);
    aad
}

fn counter_nonce(base: &[u8; NONCE_LEN], counter: u64) -> [u8; NONCE_LEN] {
    let mut n = *base;
    let c = counter.to_le_bytes();
    for i in 0..8 {
        n[NONCE_LEN - 8 + i] ^= c[i];
    }
    n
}

/// Liest bis zu `CHUNK_SIZE` Bytes in den gesperrten Puffer.
/// Laenge 0 bedeutet: Eingabe ist zu Ende.
///
/// Audit HC-15: ein durch ein Signal unterbrochener Lesevorgang
/// (`ErrorKind::Interrupted`) wird wiederholt statt als Fehler nach aussen
/// gegeben - das ist der in `std::io` selbst dokumentierte, erwartete Umgang
/// mit EINTR und kein Sonderfall unseres Codes.
fn fill_chunk<R: Read>(input: &mut R, buf: &mut SecureBuf) -> Result<()> {
    buf.clear();
    buf.fill_to_capacity();
    let mut total = 0usize;
    {
        let window = &mut buf.as_mut_slice()[..CHUNK_SIZE];
        while total < CHUNK_SIZE {
            match input.read(&mut window[total..]) {
                Ok(0) => break,
                Ok(m) => total += m,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
    buf.truncate_wiped(total);
    Ok(())
}

fn push_u32_prefixed(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

fn take_exact<'a>(cursor: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if cursor.len() < n {
        return None;
    }
    let (a, b) = cursor.split_at(n);
    *cursor = b;
    Some(a)
}

fn take_u32_prefixed<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len_bytes = take_exact(cursor, 4)?;
    let len = u32::from_le_bytes(len_bytes.try_into().ok()?) as usize;
    take_exact(cursor, len)
}

/// Wie `take_u32_prefixed`, kopiert das Ergebnis aber in gesperrten Speicher
/// (fuer die privaten Schluesselteile).
fn take_u32_prefixed_secure(cursor: &mut &[u8]) -> Option<SecureBuf> {
    let slice = take_u32_prefixed(cursor)?;
    Some(SecureBuf::from_slice(slice))
}

fn read_exact_vec<R: Read>(r: &mut R, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Liest ein laengenpraefixiertes, oeffentliches Feld und haengt Praefix und
/// Inhalt zusaetzlich an `header_echo` an (fuer die Header-Bindung).
fn read_u32_prefixed<R: Read>(
    r: &mut R,
    header_echo: &mut Vec<u8>,
    max: usize,
) -> Result<Vec<u8>> {
    let len_bytes = read_exact_vec(r, 4).map_err(|_| CryptoError::BadContainer)?;
    let len = u32::from_le_bytes(len_bytes.as_slice().try_into().unwrap()) as usize;
    if len > max {
        return Err(CryptoError::BadContainer);
    }
    let data = read_exact_vec(r, len).map_err(|_| CryptoError::BadContainer)?;
    header_echo.extend_from_slice(&len_bytes);
    header_echo.extend_from_slice(&data);
    Ok(data)
}

/// Liest 4 Bytes; `None` bei sauberem Dateiende, Fehler bei halbem Feld.
fn read_opt_u32<R: Read>(r: &mut R) -> Result<Option<u32>> {
    let mut buf = [0u8; 4];
    let mut total = 0usize;
    while total < 4 {
        match r.read(&mut buf[total..]) {
            Ok(0) => {
                if total == 0 {
                    return Ok(None);
                }
                return Err(CryptoError::BadContainer);
            }
            Ok(m) => total += m,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(CryptoError::Io),
        }
    }
    Ok(Some(u32::from_le_bytes(buf)))
}
