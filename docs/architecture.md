# Architettura corrente e percorso EPP/EDR

Il prodotto corrente è un'applicazione Tauri **user-mode**, avviata come utente standard. La modularità è ispirata alla categoria EPP/EDR; non incorpora componenti Malwarebytes né driver certificati. Su Windows l'installer richiede UAC soltanto per il setup. Il servizio SCM opzionale è indipendente e non è la controparte privilegiata dei comandi GUI.

```text
Utente standard
┌─────────────────────────────────────────────────────────────┐
│ React/WebView2 ── invoke/eventi Tauri ── Rust app.rs         │
│ Dashboard, scanner live, quarantena, stato watcher/update    │
└────────────────────────────────┬────────────────────────────┘
                                 │ comandi con parametri validati
              ┌──────────────────┴─────────────────────────────┐
              │ coordinatore scansione + pool 1–4 worker        │
              │ WalkDir → SHA-256/MD5 → PE/entropia → YARA-X     │
              │ findings + contatori errori/copertura incompleta│
              └───────────┬──────────────────────┬──────────────┘
                          │                      │
                notify Downloads/           Vault AES-256-GCM
                Desktop/TEMP → alert         DPAPI + ACL SID utente
                          │                      │
                          └──── definizioni in memoria ◀── HTTPS
                                      Ed25519 verificato (non configurato)

Confine amministrativo separato
┌──────────────────────────────────────────────────────────────┐
│ Servizio SCM opzionale LocalSystem: scansioni schedulate,     │
│ watcher user-mode, log protetto. Nessun IPC con la GUI.       │
└──────────────────────────────────────────────────────────────┘

Ring 0: nessun driver installato o implementato in questo albero.
```

| Componente | Privilegio | API/librerie | CPU/RAM e limiti | Errori |
|---|---|---|---|---|
| GUI Tauri/React | Utente standard | Tauri invoke/events, dialog, tray, WebView2 | WebView2 va misurato su target; nessuna promessa <45 MB | Comandi asincroni, stato degradato visibile |
| Scanner | Utente standard | WalkDir, Read, SHA-256, MD5, parser PE, YARA-X | 1–4 worker; stream 64 KiB per file, code limitate | Accessi negati conteggiati; risultato incompleto distinto |
| Watcher | Utente standard | notify/ReadDirectoryChangesW | Un worker; debounce/coda bounded | Eventi persi e analisi incomplete esposti |
| Vault | Utente standard | AES-256-GCM, DPAPI, ACL NTFS, handle Windows | Chunk da 1 MiB; un'operazione per volta | Autenticazione, no-clobber e fail-closed |
| Updater | Utente standard | HTTPS rustls, Ed25519, swap definizioni | Periodico solo se configurato; dimensione download limitata | Firma/versione/expiry obbligatorie; cache verificata |
| Servizio opzionale | LocalSystem | SCM, notify, scanner condiviso | 1–4 worker; queue e log con limite | Errori su log, directory e ACL stretti |
| Driver minifilter/WFP | Ring 0, futuro | FltMgr, WFP, callbacks | Non misurabile: assente | Nessuna pretesa di enforcement kernel |

## Pipeline attuale

1. Enumerazione senza seguire symlink/reparse, esclusione di file speciali e directory dati.
2. Lettura a blocchi, SHA-256 e MD5, istogramma globale; confronto con le definizioni hash.
3. Parsing PE conservativo, entropia delle sezioni, W+X ed euristiche.
4. Regole YARA-X locali. Le regole incluse sono limitate all'autotest.
5. Un risultato sospetto viene mostrato all'utente; nessuna quarantena automatica. L'utente può isolarlo, ripristinarlo o eliminare il contenitore cifrato.

Il progetto **non** verifica Authenticode, non implementa Bloom filter, ONNX, analisi comportamentale/ransomware, linking di autorun o blocco pre-esecuzione. Il servizio non riceve comandi da Tauri. L'analisi di file leggibili è opportunistica; file mutati o bloccati possono produrre errori/incompletezza. La scansione rapida considera cartelle ad alto rischio e immagini su disco dei processi attivi, non la memoria dei processi.

> [Self-Check] La GUI rimane senza privilegi elevati e il parsing opera fuori dal kernel. I comandi lunghi usano thread dedicati; la scansione ha pool e code limitati, gli eventi progresso sono emessi al massimo ogni 50 ms. Il vault autentica e rilegge il contenitore prima di tentare la rimozione del file sorgente su Windows. Questo non prova assenza di race su ogni filesystem né protezione da un amministratore ostile.

## Roadmap in quattro fasi

| Fase | Stato e uscita richiesta |
|---|---|
| 1. Scanner statico | Implementato in Rust, testato con hash, PE, entropia, YARA, errori e fixture innocue. Allargare corpus/fuzzing e benchmark prima del rilascio. |
| 2. Desktop user-mode | Tauri, tray, watcher e installer NSIS implementati. Richiesti test su Windows 10/11 puliti, upgrade/disinstallazione, accessibilità, misure CPU/RAM, firma codice. |
| 3. Servizio e remediation | Servizio SCM opzionale costruito, ma non integrato nel setup/GUI. Servono broker IPC autenticato, autorizzazione, worker isolati, journal e bonifica di persistenze, con test di rollback. |
| 4. Protezione kernel | Progettare minifilter/WFP observe-only e poi enforcement. Richiesti WDK/HLK, Driver Verifier, HVCI, firma Microsoft, pilota e recovery; nessun artefatto Ring 0 è distribuito oggi. |

Qualunque distribuzione pubblica richiede prima un feed di firme reale firmato, revisione indipendente, test su hardware/VM supportati e firma del codice. EV/attestation/WHQL non sono ottenuti da questa build.
