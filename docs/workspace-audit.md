# Audit e pulizia del workspace

L'albero precedente C++/WPF/React dimostrativo è stato archiviato in `archive/pre-tauri-source.zip`: 47 file sorgente/documentazione confrontati tramite SHA-256 prima della rimozione. Sono stati rimossi dalla radice `gui-client/`, `core-service/`, `kernel-drivers/`, `shared-ipc/`, il vecchio `CMakeLists.txt`, `docs/gui-implementation-plan.md` e `build/` generata. Sono stati sostituiti README, documentazione CMake e task VS Code non più applicabili. Non sono stati cancellati test o dati utente del vault.

```text
.
├── .vscode/             task Tauri dev/build
├── archive/             copia verificata del prototipo precedente
├── docs/                architettura, test, distribuzione, audit
├── installer/           hook NSIS, provisioning ACL, script build
├── service-daemon/      servizio SCM opzionale e test
├── signatures/          definizioni iniziali di autotest
├── src/                 GUI React/Tailwind
├── src-tauri/           backend Rust e configurazione Tauri v2
├── index.html
├── package-lock.json
├── package.json
└── vite.config.js
```

`.tools/`, `node_modules/`, `dist/` e i `target/` sono output locali ignorati; restano durante compilazione/test perché servono al ciclo di sviluppo. Il progetto non è un repository Git in questa directory, quindi `git status` non è disponibile.

> [Self-Check] Nessun parser PE, YARA o operazione di scansione è spostato nel renderer. Lo scanner limita worker e code; il servizio privilegiato è separato e non viene installato implicitamente. Il vault è autenticato e non apre/esegue i file isolati dalla GUI. I limiti di sicurezza e le funzioni mancanti sono descritti senza dichiararle implementate.
