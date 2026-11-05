import React, { useEffect, useRef, useState } from 'react';
import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';
import { open, confirm } from '@tauri-apps/plugin-dialog';
import { enable, disable, isEnabled } from '@tauri-apps/plugin-autostart';
import { ShieldCheck, ShieldAlert, LayoutDashboard, ScanLine, Archive, Terminal, Activity, Play, Pause, Square, FolderOpen, FileSearch, Database, RotateCcw, Trash2, CircleAlert, X, Download } from 'lucide-react';

const native = isTauri();
const NAV = [['dashboard','Command Center',LayoutDashboard],['scanner','Cascade Scanner Live',ScanLine],['quarantine','Quarantena',Archive],['inspector','Motore & impostazioni',Terminal]];
const num = value => new Intl.NumberFormat('it-IT').format(Math.round(value || 0));
const labels = { idle:'Pronto per la scansione', running:'Analisi in corso', paused:'Scansione in pausa', done:'Scansione completata', cancelled:'Scansione interrotta' };
function Panel({ title, icon: Icon, children, action }) { return <section className="panel"><div className="panel-heading"><h2>{Icon && <Icon size={18}/>} {title}</h2>{action}</div><div className="panel-body">{children}</div></section>; }
function Badge({ children, tone = '' }) { return <span className={`badge ${tone}`}>{children}</span>; }
function Metric({ label, value, suffix }) { return <div className="metric"><span>{label}</span><strong>{value ?? '—'}<small>{suffix}</small></strong></div>; }

export default function App() {
  const [view,setView] = useState('dashboard');
  const [status,setStatus] = useState(null);
  const [scan,setScan] = useState(null);
  const [findings,setFindings] = useState([]);
  const [vault,setVault] = useState([]);
  const [logs,setLogs] = useState([]);
  const [notice,setNotice] = useState('');
  const [pending,setPending] = useState(false);
  const [autostart,setAutostart] = useState(null);
  const [dragging,setDragging] = useState(false);
  const gate = useRef(false);
  const currentScan = useRef(null);
  currentScan.current = scan;
  const busy = scan?.status === 'running' || scan?.status === 'paused';
  const ready = native && !!status && !pending;
  function log(message) { setLogs(old => [...old.slice(-199), { time:new Date().toLocaleTimeString('it-IT'), message }]); }
  function addFinding(finding) { setFindings(old => [finding,...old.filter(item => item.id !== finding.id)]); }
  async function run(action) {
    if (!native || gate.current) return;
    gate.current = true; setPending(true);
    try { await action(); } catch(error) { const message = String(error); setNotice(message); log(message); }
    finally { gate.current = false; setPending(false); }
  }
  async function refresh() {
    const responses = await Promise.allSettled([invoke('get_status'),invoke('get_scan_snapshot'),invoke('get_findings'),invoke('list_quarantine')]);
    const setters = [setStatus,setScan,setFindings,setVault];
    responses.forEach((result,index) => { if(result.status==='fulfilled') setters[index](result.value); });
    const errors = responses.filter(result => result.status==='rejected').map(result => String(result.reason));
    if(errors.length) { setNotice(`Dati parziali: ${errors.join('; ')}`); log(`Aggiornamento parziale: ${errors.join('; ')}`); }
  }
  async function start(mode,paths = []) {
    if (['running','paused'].includes(currentScan.current?.status)) { setNotice('Interrompi la scansione corrente prima di avviarne un’altra.'); return; }
    await invoke('start_scan',{mode,paths});
    setView('scanner'); setScan(await invoke('get_scan_snapshot')); log(`Scansione ${mode} avviata.`);
  }
  useEffect(() => {
    if (!native) return;
    let disposed = false;
    const cleanup = [];
    async function subscribe(promise) { const unlisten = await promise; if (disposed) unlisten(); else cleanup.push(unlisten); }
    async function init() {
      try {
        await Promise.all([
          subscribe(listen('scan-progress',({payload}) => { if (!disposed) setScan(payload); })),
          subscribe(listen('scan-finding',({payload}) => { if (!disposed) addFinding(payload); })),
          subscribe(listen('watcher-alert',({payload}) => { if (!disposed) { addFinding(payload); log(`Monitoraggio: ${payload.path}`); } })),
          subscribe(listen('engine-status',({payload}) => { if (!disposed) setStatus(payload); })),
          subscribe(listen('scan-error',({payload}) => { if (!disposed) {setNotice(String(payload));log(String(payload));} })),
          subscribe(getCurrentWebviewWindow().onDragDropEvent(({payload}) => {
            if (disposed) return;
            setDragging(payload.type === 'over' || payload.type === 'enter');
            if (payload.type === 'drop') run(() => start('custom',payload.paths));
          })),
        ]);
        if (!disposed) { await refresh(); log('Motore nativo connesso.'); }
        try { const enabled = await isEnabled(); if (!disposed) setAutostart(enabled); } catch(error) { if (!disposed) log(`Avvio automatico non disponibile: ${error}`); }
      } catch(error) { if (!disposed) { setNotice(String(error)); log(`Connessione al motore: ${error}`); } }
    }
    init(); return () => { disposed = true; cleanup.forEach(fn => fn()); };
  },[]);
  async function pick(directory) { const result = await open({directory,multiple:true,title:directory?'Seleziona cartelle da analizzare':'Seleziona file da analizzare'}); if (result) await start('custom',Array.isArray(result)?result:[result]); }
  async function isolate(item) { await invoke('quarantine_file',{findingId:item.id}); await refresh(); setNotice('File trasferito in quarantena. Verifica lo stato del contenitore.'); }
  async function vaultAction(item,restore) {
    const accepted = await confirm(restore ? `Ripristinare il file nel percorso originale? Potrebbe contenere codice dannoso.\n${item.original_path}` : `Eliminare definitivamente il contenuto in quarantena?\n${item.original_path}`,{title:restore?'Ripristina file':'Elimina definitivamente',kind:'warning'});
    if (!accepted) return;
    const result = await invoke(restore?'restore_quarantine':'delete_quarantine',{id:item.id});
    await refresh(); setNotice(restore?`File ripristinato: ${result}`:'Contenuto in quarantena eliminato.');
  }
  function scanButtons() { return <div className="actions"><button className="primary" disabled={!ready || busy} onClick={() => run(() => start('quick'))}><Play/>Quick Scan</button><button disabled={!ready || busy} onClick={() => run(() => start('full'))}><ScanLine/>Full System Scan</button><button disabled={!ready || busy} onClick={() => run(() => pick(false))}><FileSearch/>Seleziona file</button><button disabled={!ready || busy} onClick={() => run(() => pick(true))}><FolderOpen/>Seleziona cartella</button></div>; }
  function results() { return <Panel title="Evidenze di analisi" icon={ShieldAlert} action={<Badge>{findings.length} rilevamenti</Badge>}>
    {!findings.length ? <div className="empty"><ShieldCheck size={28}/><h3>{status?'Nessun rilevamento disponibile':'In attesa del motore'}</h3><p>{status?'I risultati delle scansioni e del monitoraggio compariranno qui.':'Avvia l’app desktop per analizzare file reali.'}</p></div> : <div className="table-wrap"><table><thead><tr><th>File / percorso</th><th>Analisi</th><th>Gravità</th><th>Azione</th></tr></thead><tbody>{findings.map(item => <tr key={item.id}><td><strong>{item.name}</strong><code>{item.path}</code><details><summary>Impronte del file</summary><code>SHA-256: {item.sha256}</code><code>MD5: {item.md5}</code></details></td><td>{item.verdict === 'malicious'?'Firma dannosa':'Sospetto'}<span className="secondary">Entropia: {Number(item.entropy).toFixed(2)}</span>{item.anomalies.map((a,i) => <span className="secondary" key={i}>{a}</span>)}{item.coverage?.map((warning,i) => <span className="secondary amber-text" key={`coverage-${i}`}>{warning}</span>)}</td><td><Badge tone={item.severity === 'Alta'?'red':'amber'}>{item.severity}</Badge></td><td><button disabled={!ready} onClick={() => run(() => isolate(item))}><Archive/>Isola file</button></td></tr>)}</tbody></table></div>}
  </Panel>; }
  return <div className="app"><aside><div className="brand"><ShieldCheck size={32}/><div><strong>Aegis Security</strong><span>Endpoint security</span></div></div><nav aria-label="Navigazione principale">{NAV.map(([id,title,Icon]) => <button key={id} aria-current={view===id?'page':undefined} onClick={() => setView(id)}><Icon size={18}/>{title}</button>)}</nav><div className="sidebar-foot"><Badge tone={status?'green':'amber'}>{status?'Motore locale':'Motore non disponibile'}</Badge><p>Analisi file e monitoraggio<br/>in spazio utente.</p><span>{status?`v${status.version}`:'Desktop Windows · Tauri'}</span></div></aside>
    <div className="workspace"><header><div><span className={status?'green-text':'amber-text'}>{status?'Motore nativo connesso':native?'Connessione al motore…':'Anteprima browser · motore nativo non disponibile'}</span><p>{status?`${status.workers} worker · monitoraggio ${status.watcher_enabled?'attivo':'disattivato'}`:'Le azioni sui file sono disponibili nell’app desktop.'}</p></div><button disabled={!native || pending} onClick={() => run(refresh)}><RotateCcw/>Aggiorna stato</button></header>
    <main><div className="page-heading"><div><h1>{NAV.find(item => item[0]===view)[1]}</h1><p>{view==='dashboard'?'Stato del motore, scansioni e file da verificare.':view==='scanner'?'Analisi locale dei file con aggiornamenti dal motore.':view==='quarantine'?'Gestisci i file conservati nel contenitore locale.':'Configurazione e diagnostica del motore locale.'}</p></div><Badge tone={busy?'amber':''}>{scan?labels[scan.status]:'Non connesso'}</Badge></div>
    {status?.warnings?.map((warning,i) => <div className="warning" key={i}><CircleAlert size={18}/>{warning}</div>)}
    {view==='dashboard' && <><div className="dashboard-grid"><Panel title="Stato del sistema" icon={ShieldCheck}><div className="system-status"><ShieldCheck size={46}/><div><h3>{status?'Motore disponibile':'Motore non disponibile'}</h3><p>{status?.watcher_enabled?'Monitoraggio delle modifiche ai file attivo.':'Monitoraggio delle modifiche ai file disattivato.'}</p></div></div><div className="setting"><div><strong>Monitoraggio file</strong><p>Analizza i file modificati nelle cartelle configurate.</p></div><button role="switch" aria-checked={!!status?.watcher_enabled} disabled={!ready} onClick={() => run(async () => { await invoke('set_watcher',{enabled:!status.watcher_enabled}); await refresh(); })}>{status?.watcher_enabled?'Attivo':'Disattivato'}</button></div><p className="muted">Le rilevazioni richiedono revisione. Il monitoraggio segnala i file e non blocca l’esecuzione.</p></Panel><Panel title="Scansione on-demand" icon={ScanLine}><p className="intro">Controlla i file locali con il motore di analisi.</p>{scanButtons()}<div className="metrics compact"><Metric label="File analizzati" value={scan?num(scan.files):null}/><Metric label="Ultimo stato" value={scan?labels[scan.status]:null}/></div></Panel><Panel title="Rilevamenti & quarantena" icon={Archive}><div className="metrics"><Metric label="Da verificare" value={status?num(findings.length):null}/><Metric label="Contenitori locali" value={status?num(vault.length):null}/></div><button className="wide" onClick={() => setView('quarantine')}><Archive/>Gestisci quarantena</button></Panel><Panel title="Database delle firme" icon={Database}><div className="metrics"><Metric label="Versione definizioni" value={status?String(status.definitions_version):null}/></div><p className="muted">{status?.update_configured?'Sorgente aggiornamenti configurata.':'Nessuna sorgente aggiornamenti configurata.'}</p><button disabled={!ready || !status?.update_configured} onClick={() => run(async () => { const r = await invoke('check_updates'); setNotice(r.message); await refresh(); })}><Download/>Verifica aggiornamenti</button></Panel></div>{results()}</>}
    {view==='scanner' && <>{scanButtons()}<div className={`drop-zone ${dragging?'dragging':''}`}><FolderOpen size={22}/><span>{native?'Trascina qui file o cartelle per una scansione personalizzata.':'Il trascinamento dei file è disponibile nell’app desktop.'}</span></div><Panel title={scan?labels[scan.status]:'Motore non disponibile'} icon={ScanLine} action={<div className="actions"><button disabled={!ready || !busy} onClick={() => run(async () => { await invoke('pause_scan',{paused:scan.status!=='paused'}); setScan(await invoke('get_scan_snapshot')); })}>{scan?.status==='paused'?<Play/>:<Pause/>}{scan?.status==='paused'?'Riprendi':'Pausa'}</button><button disabled={!ready || !busy} onClick={() => run(async () => { await invoke('cancel_scan'); setScan(await invoke('get_scan_snapshot')); })}><Square/>Interrompi</button></div>}><div className="metrics"><Metric label="File analizzati" value={scan?num(scan.files):null}/><Metric label="Velocità corrente" value={scan?num(scan.rate):null} suffix=" file/s"/><Metric label="Rilevamenti" value={scan?num(scan.found):null}/><Metric label="Errori di lettura" value={scan?num(scan.errors):null}/><Metric label="Analisi incomplete" value={scan?num(scan.incomplete):null}/></div>{busy && <div className={`progress ${scan.status==='paused'?'paused':''}`} role="progressbar" aria-label="Scansione in corso; totale file non determinato"><span/></div>}<code className="scan-path">{scan?.path || 'Nessun file in analisi'}</code><p className="muted">Il totale dei file viene scoperto durante la scansione; non è disponibile una percentuale attendibile.</p></Panel>{results()}</>}
    {view==='quarantine' && <><div className="warning"><Archive size={18}/><span>I file vengono conservati localmente. Il ripristino restituisce il file al percorso originale.</span></div>{!vault.length?<Panel title="Quarantena" icon={Archive}><div className="empty"><Archive size={32}/><h3>{status?'La quarantena è vuota':'Quarantena non disponibile'}</h3><p>{status?'Isola un rilevamento dalla pagina delle scansioni.':'Connetti il motore desktop per leggere i contenitori locali.'}</p></div></Panel>:vault.map(item => <Panel key={item.id} title={item.original_path.split(/[\\/]/).pop() || item.id} icon={Archive} action={<Badge tone={item.status==='held'?'green':'amber'}>{item.status==='held'?'In quarantena':item.status==='damaged'?'Contenitore danneggiato':'Originale ancora presente'}</Badge>}><code>{item.original_path}</code><p className="muted">{item.reason} · {num(item.size)} byte · {item.created_at}</p><details><summary>SHA-256</summary><code>{item.sha256}</code></details>{item.status==='original_retained' && <p className="amber-text">La copia originale non è stata rimossa: il file non è isolato completamente.</p>}<div className="actions"><button disabled={!ready || item.status === 'damaged'} onClick={() => run(() => vaultAction(item,true))}><RotateCcw/>Ripristina</button><button className="danger" disabled={!ready} onClick={() => run(() => vaultAction(item,false))}><Trash2/>Elimina definitivamente</button></div></Panel>)}</>}
    {view==='inspector' && <div className="dashboard-grid"><Panel title="Impostazioni desktop" icon={Activity}><div className="setting"><div><strong>Avvio con Windows</strong><p>Avvia Static Guard all’accesso dell’utente.</p></div><button role="switch" aria-checked={autostart===true} disabled={!ready || autostart===null} onClick={() => run(async () => { await (autostart?disable():enable()); setAutostart(await isEnabled()); })}>{autostart===null?'Non disponibile':autostart?'Attivo':'Disattivato'}</button></div><h3>Archivio locale</h3><code>{status?.vault_path || 'Non disponibile'}</code><p className="muted">Il motore opera con i permessi dell’utente corrente. File non accessibili sono segnalati come errori di lettura.</p></Panel><Panel title="Eventi della sessione" icon={Terminal}><div className="event-log" role="log" tabIndex={0}>{logs.length?logs.map((entry,i) => <p key={i}><time>{entry.time}</time> {entry.message}</p>):<p>Nessun evento ricevuto.</p>}</div></Panel></div>}
    </main></div>{notice && <div className="notice" role="status"><CircleAlert size={20}/><p>{notice}</p><button aria-label="Chiudi notifica" onClick={() => setNotice('')}><X/></button></div>}</div>;
}
