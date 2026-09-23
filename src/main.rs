mod filepick;
mod gui;
mod hardening;
mod hybrid;
mod proc;
mod secure;
mod worker;

use hardening::Role;

fn main() {
    // Die Rolle steht vor allem anderen fest, weil die Haertung davon abhaengt
    // (mlockall nur im Worker - siehe hardening.rs).
    let is_worker = std::env::args_os().any(|a| a == "--worker");

    // ALLERERSTES: haerten, bevor irgendein Puffer angelegt wird.
    hardening::harden_process(if is_worker { Role::Worker } else { Role::Gui });

    if is_worker {
        // Kryptografie-Rolle: kein Fenster, kein Netzwerk, nur Deskriptoren.
        worker::run();
    }

    if let Err(e) = gui::run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
