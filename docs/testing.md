# Test riproducibili

Eseguire i comandi dalla radice in PowerShell. Per la compilazione nativa servono Rust MSVC e Windows SDK; se il repository usa il toolchain locale, il wrapper `npm run tauri` lo configura automaticamente.

```powershell
npm ci
npm run build
npm run tauri -- build --bundles nsis
```

L'installer NSIS si trova in `src-tauri/target/release/bundle/nsis`. Questi comandi **compilano** il pacchetto, non lo installano e non registrano il servizio. Per compilare/verificare il motore con un Cargo nel PATH:

```powershell
cargo test --manifest-path src-tauri/Cargo.toml --release --locked --no-default-features --features yara
cargo test --manifest-path service-daemon/Cargo.toml --release --locked
cargo build --manifest-path service-daemon/Cargo.toml --release --locked
```

La prima suite usa fixture innocue e verifica hash, PE/entropia, YARA, updater, vault cifrato/ripristino, ADS Windows e watcher. La seconda riguarda configurazione, sicurezza e scheduler del servizio. Il servizio resta fermo e non viene registrato da questi test.

Per provare la GUI nativa senza installer:

```powershell
npm run tauri -- dev
```

Nella finestra avviare Quick Scan su file di prova; scegliere una cartella piccola per Custom Scan, poi interrompere/pausare. Verificare che contatori errori e incompletezza siano visibili se un file non è leggibile. Provare quarantena e ripristino **solo con un file di prova sacrificabile**, verificando prima e dopo SHA-256 con `Get-FileHash`. La cartella debug è separata dal vault Release. Il file EICAR è un test standard ma può essere intercettato da altri antivirus del PC; i test automatizzati non richiedono di disabilitarli. Non eseguire campioni malware reali.

La prova dell'installer va fatta su una VM Windows pulita: account standard, setup con UAC, avvio dalla scorciatoia, tray, azione Explorer `--scan`, disinstallazione e verifica che il vault resti intatto. Ripetere su Windows 10 e 11. Misurare CPU/RAM a riposo e durante scansioni grandi; non è stato dimostrato l'obiettivo di 45 MB per la GUI WebView2. Il pacchetto attuale è non firmato e il database minacce è di autotest: non distribuirlo come protezione completa.
