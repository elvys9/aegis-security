# Aegis Security

Applicazione desktop antimalware **sperimentale** per Windows 10/11 x64. Il client Tauri v2/React esegue scanner statico Rust, monitoraggio user-mode di cartelle selezionate, quarantena cifrata e aggiornamenti di definizioni verificati. Il pacchetto corrente è una **prerelease non firmata** e non costituisce una protezione antivirus certificata.

## Avvio e build

Prerequisiti: Node.js/npm, Rust stable MSVC, Windows SDK e WebView2. Dalla radice del progetto, in PowerShell:

```powershell
npm ci
npm run tauri -- dev
```

La build di sviluppo usa `%LOCALAPPDATA%\AegisSecurity-Dev`. Per creare l'installer NSIS:

```powershell
npm run tauri -- build --bundles nsis
```

L'output è in `src-tauri/target/release/bundle/nsis/`. Installare il pacchetto prima di aprire la build Release: il setup prepara le ACL di `%ProgramData%\AegisSecurity`. Il programma si avvia come utente standard; non eseguirlo con «Esegui come amministratore». La chiusura della finestra la nasconde nella tray; scegliere «Esci» dal menu della tray per terminare il monitoraggio.

Per la prova manuale usare **Scansione rapida**, **Scansione completa** o scegliere un file/cartella per la scansione personalizzata. Il monitoraggio controlla Downloads, Desktop e TEMP mentre l'app è in esecuzione. Il primo database include soltanto la firma di test EICAR e una regola YARA di autotest: l'assenza di un rilevamento non prova che un file sia sicuro.

## Struttura

| Directory | Scopo |
|---|---|
| `src/` | Interfaccia React, comandi ed eventi Tauri, CSS/Tailwind |
| `src-tauri/` | Motore Rust, parser PE, YARA, watcher, vault, updater e app desktop |
| `service-daemon/` | Scanner schedulato Windows SCM opzionale; installazione amministrativa separata |
| `signatures/` | Database iniziale, regole e configurazione del feed firmato |
| `installer/` | Hook NSIS, provisioning del vault e wrapper di build |
| `docs/` | Architettura, test, distribuzione e audit |
| `archive/` | Copia verificata del precedente prototipo C++/WPF |

`node_modules/`, `dist/`, `.tools/` e i `target/` Cargo sono output locali rigenerabili, esclusi da Git.

## Stato dei componenti

Lo scanner calcola SHA-256/MD5 in streaming, entropia globale e sezioni PE, rileva sezioni W+X ed esegue le regole YARA-X incluse. Le euristiche sono **indizi** e richiedono revisione. Il worker pool manuale è limitato a 1–4 thread; file non leggibili e analisi incomplete vengono conteggiati. La quarantena Windows usa AES-256-GCM a blocchi con chiave protetta da DPAPI, verifica del contenitore prima della rimozione dell'originale e ripristino senza sovrascrittura. La cancellazione fisica su SSD non è garantibile dalla sovrascrittura applicativa.

Il servizio SYSTEM è costruibile e testato, ma non è incluso né avviato dall'installer e non comunica con la GUI. Il monitoraggio della GUI non blocca un file prima dell'esecuzione. Driver minifilter/WFP, anti-tampering kernel, ML ONNX, scansione della memoria dei processi e linking/remediation di persistenze non sono implementati. Il feed HTTPS/Ed25519 resta disabilitato finché endpoint e chiave pubblica non vengono forniti e verificati. Su macOS/Linux il vault conserva l'originale: non considerarlo isolamento effettivo.

Consultare [architettura](docs/architecture.md), [test](docs/testing.md), [audit](docs/workspace-audit.md) e [distribuzione](docs/distribution.md) prima di qualsiasi rilascio.
