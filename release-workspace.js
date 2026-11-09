/* Local release review. No reports or saved decisions leave this browser. */
(() => {
  'use strict';
  const KEY = 'vulntrack.release-workspace.v1';
  const root = document.getElementById('releaseWorkspace');
  const dialog = document.getElementById('releaseDialog');
  const colors = ['#87c900', '#e1369a', '#00a9e6', '#aa88ed'];
  const severity = ['Critical', 'High', 'Medium', 'Low', 'None'];
  const reviewPolicy = {id:'vulntrack-product-review-v2',name:'Product vulnerability review',
    basis:'Local policy informed by FIRST CVSS, NIST SSDF RV.2 and CISA VEX; not a certification or a numeric CVE allowance.',
    rules:['Open KEV-listed findings or confirmed product exploitability block at every severity.',
      'Confirmed affected Critical/High findings block unless a documented, unexpired risk acceptance applies.',
      'Unknown applicability, investigation or expired acceptance requires review.',
      'Other affected findings and accepted risks remain open with a warning; they are not fixed.',
      'Passed means no open findings in the supplied report, not authorization to ship.'],
    sources:[['FIRST CVSS: severity is not risk','https://www.first.org/cvss/v3.1/user-guide'],['NIST SSDF: risk analysis and response (RV.2)','https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf'],['CISA VEX: product-specific impact evidence','https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf']]};
  const palette = ['#ff4965', '#ff8b36', '#f6c34e', '#66b573', '#72798b'];
  let db = { version: 1, portfolios: [], scans: [] };
  let selected = '', view = 'components', range = 12, metric = 'severity', compare = [];
  let query = '', findingFilter = 'open', sort = 'cves', descending = true;
  let storageFailed = false, loadFailed = false;
  let pendingReport = null, pendingReportName = '';
  let busy = false, findingLimit = 200;
  let ready;
  let writeQueue = Promise.resolve();
  let database;
  function openDatabase() {
    if (!database) database = new Promise((resolve,reject) => {
      const request = indexedDB.open('vulntrack-release-workspace',1);
      request.onupgradeneeded = () => request.result.createObjectStore('workspace');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
      request.onblocked = () => reject(new Error('Close other VulnTrack tabs and reload to finish opening storage.'));
    });
    return database;
  }
  async function storeWorkspace(value) {
    const connection = await openDatabase();
    await new Promise((resolve,reject) => {
      const transaction = connection.transaction('workspace','readwrite');
      transaction.objectStore('workspace').put(value,'current');
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error || new Error('Storage transaction aborted'));
    });
  }
  function removeSamples(value) {
    const fake = scan => scan.demo || scan.report?.vulntrack?.demo || (scan.report?.package || []).some(p => normalizePackageIssues(p).some(f => String(f.id || '').startsWith('DEMO-')));
    const scans = value.scans.filter(scan => !fake(scan));
    const portfolios = value.portfolios.map(group => {
      if (!group.demo) return group;
      const products = group.products.filter(product => scans.some(scan => scan.productId === product.id)).map(product => ({...product,name:scans.find(scan => scan.productId === product.id).name,description:''}));
      return {...group,name:'Imported reports',owner:'',description:'',demo:false,products};
    }).filter(group => !group.demo && (group.products.length || !value.portfolios.find(original => original.id === group.id)?.demo));
    return {...value,portfolios,scans};
  }
  async function initialize() {
    root.innerHTML = '<div class="rw-note">Loading saved workspace…</div>';
    try {
      let saved;
      if (typeof indexedDB !== 'undefined') {
        const connection = await openDatabase();
        saved = await new Promise((resolve,reject) => {
          const request = connection.transaction('workspace','readonly').objectStore('workspace').get('current');
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        });
      }
      saved ||= JSON.parse(localStorage.getItem(KEY));
      if(saved && !validWorkspace(saved))throw new Error("Saved workspace has an invalid structure; restore a valid backup.");
      if (validWorkspace(saved)) {
        db = removeSamples(saved);
        if (typeof indexedDB !== 'undefined') { await storeWorkspace(db); localStorage.removeItem(KEY); }
      }
    } catch { storageFailed=true;loadFailed=true;toast('Saved workspace could not be loaded. Reload before editing, or export a backup before continuing.'); }
    portfolio();
  }
  const e = value => esc(value);
  const id = () => {
    if (crypto.randomUUID) return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
    return [...bytes].map((v,i)=>([4,6,8,10].includes(i)?'-':'')+v.toString(16).padStart(2,'0')).join('');
  };
  const versionKey = value => String(value || '').replace(/^\d+[_:]/,'');
  function coverage(open,field,present,positive,label) {
    const known = open.filter(present), unknown = open.length-known.length, count = known.filter(positive).length;
    if (!open.length) return {value:'0',detail:'No open findings',count:0,unknown:0};
    if (!known.length) return {value:label,detail:field,count:0,unknown};
    return {value:String(count),detail:unknown ? `${known.length} assessed · ${unknown} unknown` : `All ${known.length} open findings assessed`,count,unknown};
  }
  function metricValues(st) {
    if(st.reportPresent===false)return ['ACTIVELY EXPLOITED','FIX AVAILABLE','CRA-RELEVANT (OPEN)','ALREADY FIXED (REPORT / VEX)'].map(label=>[label,{value:'Not assessed',detail:'No CVE report imported'}]);
    return [
      ['ACTIVELY EXPLOITED',coverage(st.open,'KEV data is not in this report',f=>typeof f.kev==='boolean',f=>f.kev,'Not provided')],
      ['FIX AVAILABLE',coverage(st.open,'Fix-version evidence is not in this report',f=>Boolean(f.fix) || typeof f.fix_available==='boolean',f=>Boolean(f.fix) || f.fix_available===true,'Not provided')],
      ['CRA-RELEVANT (OPEN)',coverage(st.open,'Assess product relevance during triage',f=>typeof f.cra==='boolean',f=>f.cra,'Not assessed')],
      ['ALREADY FIXED (REPORT / VEX)',{value:String(st.fixed),detail:'Reported patched or explicitly reviewed fixed'}]
    ];
  }
  function matchComponent(bom,p) {
    return (bom?.components || []).filter(c=>c.name===p.name && (!p.version || !c.version || versionKey(c.version)===versionKey(p.version))).sort((a,b)=>(a.recordKind==='reference')-(b.recordKind==='reference'))[0];
  }
  const key = f => JSON.stringify([f.pkg, f.cve]);
  const current = () => db.scans.find(s => s.id === selected);
  const packages = s => s.report?.package || [];
  const metadata = s => s.report?.vulntrack || {};
  const stamp = s => Number.isFinite(Date.parse(s.date)) ? new Date(s.date).toISOString().slice(0, 10) : 'Undated';
  const siblings = s => db.scans.filter(x => x.productId === s.productId && x.stream === s.stream).sort((a,b) => Date.parse(a.date) - Date.parse(b.date) || a.order - b.order);
  const productFor = s => db.portfolios.flatMap(g => g.products).find(p => p.id === s.productId);
  const groupFor = s => db.portfolios.find(g => g.products.some(p => p.id === s.productId));
  function toast(message) {
    if (dialog.open) {
      let error = document.getElementById('rwDialogMessage');
      if (!error) { error = document.createElement('div'); error.id='rwDialogMessage'; error.className='rw-note rw-danger'; error.setAttribute('role','alert'); dialog.querySelector('.rw-dialog-body').prepend(error); }
      error.textContent=message; return;
    }
    let el = document.getElementById('releaseToast');
    if (!el) { el = document.createElement('div'); el.id = 'releaseToast'; el.className = 'rw-toast'; el.setAttribute('role', 'status'); document.body.append(el); }
    el.textContent = message; el.hidden = false;
    clearTimeout(toast.timer); toast.timer = setTimeout(() => { el.hidden = true; }, 7000);
  }
  function save() {
    if(loadFailed){toast('Saved workspace failed to load. Reload before saving to avoid overwriting existing data.');return Promise.resolve();}
    let snapshot;
    try { snapshot=structuredClone(db); } catch { storageFailed=true;toast('Changes could not be saved. Export your workspace before closing.');return Promise.resolve(); }
    writeQueue = writeQueue.then(async () => {
      try {
        if (typeof indexedDB !== 'undefined') { await storeWorkspace(snapshot); localStorage.removeItem(KEY); }
        else localStorage.setItem(KEY,JSON.stringify(snapshot));
        storageFailed = false;
      } catch { storageFailed = true; toast('Browser storage is unavailable. Changes are in memory only. Export the workspace before closing.'); }
    });
    return writeQueue;
  }
  function validWorkspace(data) {
    if (data?.version !== 1 || !Array.isArray(data.portfolios) || !Array.isArray(data.scans)) return false;
    const ids = new Set(), products = new Set();
    const unique = x => typeof x === 'string' && x.length > 0 && !ids.has(x) && (ids.add(x), true);
    for (const g of data.portfolios) {
      if (!unique(g.id) || typeof g.name !== 'string' || !Array.isArray(g.products)) return false;
      for (const p of g.products) { if (!unique(p.id) || typeof p.name !== 'string') return false; products.add(p.id); }
    }
    for (const s of data.scans) {
      if (!unique(s.id) || !products.has(s.productId) || !['Released', 'Nightly', 'Unassigned'].includes(s.stream) || !Number.isFinite(Date.parse(s.date)) || !(validReport(s.report) || (s.report===null && validSbom(s.sbom)))) return false;
      if (typeof s.name !== 'string' || (s.columns && (!Array.isArray(s.columns) || !s.columns.every(c => ['name','version','recipe','layer','cves','severity','review','fix'].includes(c))))) return false;
      if (s.sbom && !validSbom(s.sbom))return false;
      if (s.reviews && (typeof s.reviews !== 'object' || Array.isArray(s.reviews))) return false;
      for (const [k,r] of Object.entries(s.reviews || {})) {
        try { const parts = JSON.parse(k); if (!Array.isArray(parts) || parts.length !== 2) return false; } catch { return false; }
        if(r?.acceptance && !validAcceptance(r.acceptance))return false;
        if(r?.exploitability && !['unknown','exploitable'].includes(r.exploitability))return false;
        if (!r || !['unknown','affected','fixed','not_affected','under_investigation'].includes(r.vex) || typeof r.rationale !== 'string' || !r.rationale.trim()) return false;
      }
    }
    return true;
  }
  function validSbom(bom) {
    return Boolean(bom && Array.isArray(bom.components) && bom.components.length && Array.isArray(bom.relations) && bom.components.every(c=>c && typeof c.id==='string' && typeof c.name==='string') && bom.relations.every(r=>r && typeof r.from==='string' && typeof r.to==='string'));
  }
  function validReport(report) {
    return report && Array.isArray(report.package) && report.package.every(p => p && typeof p === 'object' && typeof p.name === 'string' && (p.issue == null || typeof p.issue==='object') && (p.issues == null || typeof p.issues==='object') && normalizePackageIssues(p).every(f => f && typeof f === 'object' && (f.id == null || typeof f.id === 'string')));
  }
  function facts(s) {
    return packages(s).flatMap(p => normalizePackageIssues(p).map(f => {
      const decision = s.reviews?.[JSON.stringify([p.name, f.id ?? 'UNKNOWN'])];
      const vex = decision?.vex || f.vex || (f.status === 'Patched' ? 'fixed' : 'unknown');
      return { ...f, pkg:p.name, version:p.version || '', layer:p.layer || '', cve:f.id ?? 'UNKNOWN', sev:severityFrom(f), score:toNum(f.scorev3)>0?f.scorev3:f.scorev2, vex,
        acceptance:decision?.acceptance || null, exploitability:decision?.exploitability || f.exploitability || 'unknown', review:decision ? 'reviewed' : 'unreviewed', rationale:decision?.rationale || '', cra:decision && Object.hasOwn(decision,'cra') ? decision.cra : f.cra_relevant,
        open:!['fixed', 'not_affected'].includes(vex), kev:typeof f.kev === 'boolean' ? f.kev : null, fix:typeof f.fixed_version === 'string' ? f.fixed_version : '' };
    }));
  }
  function validDate(value) {
    return typeof value==='string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0,10)===value;
  }
  function validAcceptance(a) {
    return a && typeof a.owner==='string' && a.owner.trim().length>0 && typeof a.controls==='string' && a.controls.trim().length>0 && validDate(a.until);
  }
  function disposition(f, now=new Date()) {
    if(!f.open)return 'closed';
    // KEV is a conservative review blocker until product non-impact is evidenced.
    if(f.kev===true || f.exploitability==='exploitable')return 'blocker';
    const affected=f.vex==='affected', accepted=affected && validAcceptance(f.acceptance) && f.acceptance.until>=now.toISOString().slice(0,10);
    if(affected && ['Critical','High'].includes(f.sev) && !accepted)return 'blocker';
    if(!affected || (!accepted && f.sev==='None') || (f.acceptance && !accepted))return 'review';
    return accepted?'accepted':'action';
  }
  function dispositionLabel(f) {
    const d=disposition(f);
    return ({blocker:f.kev===true?'KEV: resolve impact':f.exploitability==='exploitable'?'Product exploitable':'Confirmed high risk',review:f.acceptance?'Acceptance expired / invalid':'Review required',accepted:'Risk accepted (open)',action:'Action required',closed:'Closed by assessment'})[d];
  }
  function stats(s, close = []) {
    const all = facts(s), open = all.filter(f => f.open && !close.includes(key(f)));
    const counts = Object.fromEntries(severity.map(v => [v, open.filter(f => f.sev === v).length]));
    const criticalHigh = counts.Critical + counts.High;
    const blockers=open.filter(f=>disposition(f)==='blocker'), triage=open.filter(f=>disposition(f)==='review'), accepted=open.filter(f=>disposition(f)==='accepted');
    const expired=open.filter(f=>f.acceptance && (!validAcceptance(f.acceptance) || f.acceptance.until<new Date().toISOString().slice(0,10)));
    const gate = !packages(s).length ? 'unknown' : blockers.length ? 'blocked' : triage.length ? 'review' : open.length ? 'warning' : 'passed';
    return { reportPresent:Boolean(s.report), all, open, counts, criticalHigh, gate, blockers, triage, accepted, expired, cra:open.filter(f => f.cra === true).length, craUnknown:open.some(f => typeof f.cra !== 'boolean'), fixed:all.filter(f => f.vex === 'fixed').length };
  }
  const gateLabel=gate=>gate==='review'?'REVIEW REQUIRED':gate==='unknown'?'NOT ASSESSED':gate.toUpperCase();
  const gateColor=gate=>({passed:'#66b573',warning:'#e4b844',review:'#83a9ff',unknown:'#72798b',blocked:'#da3d58'})[gate];
  function policySummary(st) {
    if(!st.reportPresent)return 'SBOM inventory is available. Import the matching CVE report to assess vulnerabilities; an SBOM does not establish zero CVEs.';
    if(st.gate==='unknown')return 'No component data supplied; review cannot be evaluated.';
    if(!st.open.length)return 'No open findings in this imported report. This is not a shipment or compliance approval.';
    return `${st.gate==='review'?'Assessment incomplete. ':''}${st.blockers.length.toLocaleString()} identified blockers · ${st.triage.length.toLocaleString()} need product assessment · ${st.accepted.length.toLocaleString()} accepted risks (still open) · ${st.counts.Critical.toLocaleString()} Critical + ${st.counts.High.toLocaleString()} High = ${st.criticalHigh.toLocaleString()} combined open matches${st.expired.length?` · ${st.expired.length} expired/invalid acceptances`:''}.`;
  }
  function policyHelp() {
    modal('Product vulnerability review policy',`<p class="rw-description">${e(reviewPolicy.basis)} There is no universal safe number of Critical, High, Medium or Low CVEs.</p><ol class="rw-description">${reviewPolicy.rules.map(rule=>`<li>${e(rule)}</li>`).join('')}</ol><p class="rw-description">KEV absence and missing exploit data do not demonstrate safety. A product impact assessment needs configuration, exposure, reachable-code and mitigation evidence. Penetration testing may provide evidence; importing a CVE report does not perform a penetration test. Risk acceptance cannot waive applicable legal or contractual obligations. This local browser records the named approver; it does not authenticate approval authority.</p><h3>Sources</h3>${reviewPolicy.sources.map(([label,url])=>`<p><a href="${url}" target="_blank" rel="noopener noreferrer">${e(label)}</a></p>`).join('')}`);
  }
  function badge(gate, detail = '') {
    if (gate === 'passed') return '<span class="rw-pass">✓ passed</span>';
    return `<span class="rw-gate ${gate}">${gate === 'blocked' ? '✗' : gate === 'warning' ? '!' : '—'} ${gateLabel(gate)}${detail ? `<small>${e(detail)}</small>` : ''}</span>`;
  }
  function gateBox(gate) { return `<span class="rw-gate ${gate}">${gate === 'blocked' ? '✗' : gate === 'warning' ? '!' : gate === 'passed' ? '✓' : '—'} ${gateLabel(gate)}</span>`; }
  function worst(gates) { return ['blocked', 'review', 'unknown', 'warning', 'passed'].find(v => gates.includes(v)) || 'unknown'; }
  function craText(scans) {
    if(scans.some(s=>!s.report))return 'not assessed';
    const results = scans.map(s => stats(s));
    const count=results.reduce((n,s)=>n+s.cra,0), unknown=results.some(s=>s.craUnknown);
    return unknown ? (count ? `${count} known · incomplete` : 'not assessed') : String(count);
  }
  function latest(productId) {
    return ['Nightly', 'Released', 'Unassigned'].map(stream => db.scans.filter(s => s.productId === productId && s.stream === stream).sort((a,b) => Date.parse(b.date) - Date.parse(a.date) || b.order - a.order)[0]).filter(Boolean);
  }
  const icon = () => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="5" r="2"/><circle cx="5" cy="18" r="2"/><circle cx="19" cy="18" r="2"/><path d="M12 7v4m0 0-7 5m7-5 7 5"/></svg>';
  function spark(s) {
    const scans = siblings(s).filter(x=>x.report); if (!s.report || scans.length < 2) return '';
    const max = Math.max(1, ...scans.map(x => stats(x).open.length));
    const points = scans.map((x,i) => `${i * 168 / (scans.length - 1)},${26 - stats(x).open.length / max * 24}`).join(' ');
    const change = stats(scans[0]).open.length - stats(scans.at(-1)).open.length;
    return `<div class="rw-spark"><svg viewBox="0 0 170 30" aria-label="Open findings trend"><polygon points="0,28 ${points} 168,28" fill="#ee8636" opacity=".85"/>${scans.map((x,i) => `<circle cx="${i * 168 / (scans.length - 1)}" cy="29" r="2" fill="${gateColor(stats(x).gate)}"/>`).join('')}</svg><span style="color:${change >= 0 ? 'var(--good)' : 'var(--bad)'}">${change >= 0 ? '▼' : '▲'} ${Math.abs(change)} since ${stamp(scans[0]).slice(5).replace('-', '/')}</span></div>`;
  }
  function portfolio() {
    selected = ''; document.body.classList.remove('rw-in-scan');
    const subtitle=document.querySelector('.h-sub');if(subtitle)subtitle.textContent='Local product portfolios and build vulnerability reviews';
    root.innerHTML = `<div class="rw-toolbar"><h1>Product portfolios</h1><button class="btn rw-primary" data-action="import">+ Import build</button><span class="rw-muted rw-small">Local workspace</span><button class="btn" data-action="local-report">Load cve-summary.json from this folder</button><button class="btn" data-action="backup">Export workspace</button><button class="btn" data-action="restore">Import workspace</button><button class="btn" data-action="group">+ portfolio</button></div>${storageFailed ? '<div class="rw-note rw-danger">Changes are in memory only. Export your workspace before closing.</div>' : ''}${db.portfolios.length ? db.portfolios.map((g,gi) => {
      const scans = g.products.flatMap(p => latest(p.id)), gGate = worst(scans.map(s => stats(s).gate));
      const failing = g.products.filter(p => latest(p.id).some(s => stats(s).gate === gGate)).length;
      return `<div class="rw-portfolio" style="--group-color:${colors[gi % colors.length]}"><div class="rw-group"><div class="rw-row"><button class="rw-toggle" data-action="collapse-group" data-id="${e(g.id)}" aria-label="Toggle ${e(g.name)}" aria-expanded="${!g.collapsed}">${g.collapsed ? '▸' : '▾'}</button><div class="rw-icon">${icon()}</div><div class="rw-grow"><h2>${e(g.name)}</h2><span class="rw-muted">· ${e(g.description || 'Product security portfolio')} &nbsp; owner: ${e(g.owner || 'Unassigned')}</span><div class="rw-tags"><span class="rw-pill">${g.products.length} products</span><span class="rw-pill">${scans.length} images</span><span class="rw-pill">CRA-relevant open ${craText(scans)}</span></div></div><div>${badge(gGate, `${failing} of ${g.products.length} products`)}<div class="rw-links"><button class="rw-link" data-action="product" data-id="${e(g.id)}">+ product</button><button class="rw-link" data-action="group" data-id="${e(g.id)}">edit</button></div></div></div></div>${g.collapsed ? '' : g.products.map(p => {
        const images = latest(p.id), gate = worst(images.map(s => stats(s).gate));
        return `<div class="rw-product"><div class="rw-row"><button class="rw-toggle" data-action="collapse-product" data-id="${e(p.id)}" aria-label="Toggle ${e(p.name)}" aria-expanded="${!p.collapsed}">${p.collapsed ? '▸' : '▾'}</button><div class="rw-grow"><h3>${e(p.name)}</h3><span class="rw-muted">· ${e(p.description || '')}</span><div class="rw-tags"><span class="rw-pill">${images.length} images</span><span class="rw-pill">CRA-relevant open ${craText(images)}</span></div></div><div>${badge(gate, `${images.filter(s => stats(s).gate === gate).length} of ${images.length} streams`)}<div class="rw-links"><button class="rw-link" data-action="import" data-id="${e(p.id)}">+ scan</button><button class="rw-link" data-action="edit-product" data-id="${e(p.id)}">edit</button></div></div></div></div>${p.collapsed ? '' : images.map(s => {
          const st = stats(s), history = siblings(s);
          return `<div class="rw-image"><div class="rw-row"><div class="rw-grow"><span class="rw-stream ${s.stream.toLowerCase()}">${s.stream.toUpperCase()}</span><button class="rw-open" data-action="scan" data-id="${e(s.id)}">${e(s.release || s.name)}</button><span class="rw-muted"> · build ${s.buildDateKnown === false ? 'not supplied (imported ' + e(stamp(s)) + ')' : e(stamp(s))}</span> <span class="rw-pill">latest</span>${history.length > 1 ? ` <button class="rw-link" data-action="history" data-id="${e(s.id)}">▸ ${history.length - 1} older</button>` : ''}<div class="rw-tags"><span class="rw-pill">${s.report?`${packages(s).length} CVE recipes`:`${s.sbom.components.length.toLocaleString()} SBOM records`}</span><span class="rw-pill">${s.report?`${st.open.length} open findings`:'CVE report not imported'}</span>${s.sbom?`<button class="rw-pill rw-asset-link" data-action="open-inventory" data-id="${e(s.id)}">SBOM · ${s.sbom.components.length.toLocaleString()} records</button>`:''}<span class="rw-pill ${st.cra ? 'cra' : ''}">CRA-relevant open ${craText([s])}</span></div>${s.stream === 'Released' ? spark(s) : ''}</div>${badge(st.gate)}</div></div>`;
        }).join('')}`;
      }).join('')}</div>`;
    }).join('') : `<div class="rw-empty"><h2>A clear view of every product and release</h2><p>Group products into portfolios, track Nightly and Released images,<br>and review findings, release gates, components, and scan history locally.</p><button class="btn rw-primary" data-action="import">Import your first build</button> <button class="btn" data-action="local-report">Load cve-summary.json from this folder</button><p class="rw-small">Start with an SBOM, a CVE report, or both. Files stay together under the same build.</p></div>`}`;
  }
  function openScan(scanId, tab = 'overview') {
    selected = scanId; view = tab; query = ''; compare = []; setTab('releases'); renderScan();
    window.scrollTo({top:0});
  }
  function renderScan() {
    const s = current(); if (!s) { portfolio(); return; }
    const st = stats(s), scans = siblings(s), meta = metadata(s), product = productFor(s), group = groupFor(s);
    document.body.classList.add('rw-in-scan');
    const subtitle=document.querySelector('.h-sub');if(subtitle)subtitle.textContent=s.report?`${packages(s).length} CVE recipes · ${st.all.length.toLocaleString()} findings · ${s.sbom?`${s.sbom.components.length.toLocaleString()} SBOM records`:'SBOM not imported'}`:`${s.sbom.components.length.toLocaleString()} SBOM records · CVE report not imported`;
    root.innerHTML = `<div class="rw-scan-head"><div class="rw-row"><div class="rw-grow"><span class="rw-stream ${s.stream.toLowerCase()}">${e(s.stream.toUpperCase())}</span><strong class="rw-scan-title">${e(s.name)}</strong></div><div class="rw-actions"><button class="btn" data-action="rescan">Import new scan</button>${s.report?'<button class="btn" data-action="vex-import">Import VEX</button>':'<button class="btn rw-primary" data-action="attach-cve">Add CVE report</button>'}<button class="btn" data-action="scan-meta">Edit metadata</button><button class="btn" data-action="evidence">Download evidence</button><button class="btn rw-danger" data-action="delete-scan">Delete scan</button></div></div><div class="rw-breadcrumb"><button class="rw-link" data-action="portfolio">${e(group?.name)} / ${e(product?.name)}</button> <span class="rw-muted"> &nbsp; scan (${scans.length} in ${e(s.stream)}): </span><select id="rwScanSelect" aria-label="Select scan">${scans.map((x,i) => `<option value="${e(x.id)}" ${x.id === s.id ? 'selected' : ''}>${stamp(x)} · ${e(x.release || x.name)}${i === scans.length - 1 ? ' (latest)' : ''}</option>`).join('')}</select></div><details class="rw-build-details" ${view==='sbom'?'':'open'}><summary>Build metadata · ${e(s.release || 'Release not supplied')} · ${e(s.machine || 'Machine not supplied')}</summary><div class="rw-metadata">${[['STREAM',s.stream],['RUNTIME',`Yocto ${s.release || '—'} · ${s.machine || '—'}`],['YOCTO RELEASE',s.release],['MACHINE',s.machine],['DISTRO',s.distro],['PIPELINE',s.pipeline],['COMMIT',s.commit],['BUILD TIME',s.buildDateKnown === false ? 'Not supplied' : stamp(s)],['REPORT SCOPE',s.reportScope || 'Unspecified']].map(([label,value]) => `<div><label>${label}</label><span>${e(value || '—')}</span></div>`).join('')}</div><div class="rw-metadata"><div><label>LAYER REVISIONS</label><span>${e(s.layers || 'Not supplied')}</span></div></div></details></div>
      <div class="rw-banner ${st.gate}" ${view==='sbom'?'hidden':''}><div class="rw-verdict-icon">${st.gate === 'blocked' ? '✗' : st.gate === 'passed' ? '✓' : '!'}</div><div><strong>${s.report?gateLabel(st.gate):'VULNERABILITIES NOT ASSESSED'}</strong><span class="rw-muted"> · Product vulnerability review · policy v2</span><p>${s.report?`${packages(s).length} reported recipes · ${st.all.length} raw findings · ${st.fixed} already fixed (report / VEX)`:`${s.sbom.components.length.toLocaleString()} SBOM records imported · No CVE report supplied`}</p><p class="rw-rule">${e(policySummary(st))} <button class="rw-link" data-action="policy">Policy &amp; sources</button> ${s.report?'<button class="rw-link" data-action="priority-findings">→ show findings</button>':'<button class="btn rw-primary" data-action="attach-cve">Add matching CVE report</button>'}</p></div></div>
      ${storageFailed ? '<div class="rw-note rw-danger">Changes are in memory only. Export this workspace before closing.</div>' : ''}
      <div class="rw-artifact-status">${s.sbom?`<button class="rw-asset-link" data-action="view" data-id="sbom">✓ SBOM inventory · ${s.sbom.components.length.toLocaleString()} records</button>`:'<button class="rw-asset-link" data-action="attach-sbom">+ Add SBOM inventory</button>'}${s.report?`<button class="rw-asset-link" data-action="view" data-id="findings">✓ CVE report · ${st.all.length.toLocaleString()} findings</button>`:'<button class="rw-asset-link" data-action="attach-cve">+ Add CVE report</button>'}</div>
      <div class="rw-metrics" ${s.report && view!=='sbom'?'':'hidden'}>${metricValues(st).map(([label,m])=>`<div class="rw-metric"><label>${label}</label><b class="${/^Not /.test(m.value)?'rw-unavailable':''}">${e(m.value)}</b><span class="rw-muted rw-small">${e(m.detail)}</span></div>`).join('')}</div>
      <nav class="rw-subtabs" aria-label="Scan views">${[['overview','Overview'],['sbom',`SBOM inventory${s.sbom?' · '+s.sbom.components.length.toLocaleString():' · Not imported'}`],['findings',s.report?`CVE findings · ${st.open.length}/${st.all.length}`:'CVE findings · Not imported'],['components',s.report?`CVE recipes · ${packages(s).length}`:'CVE recipes · Not imported'],['upgrades','Upgrade preview'],['delta','Delta'],['history','History'],['evidence','Evidence']].map(([tab,label]) => `<button data-action="view" data-id="${tab}" class="${view === tab ? 'active' : ''}" aria-current="${view === tab ? 'page' : 'false'}">${label}</button>`).join('')}</nav><div class="rw-content" id="rwContent"></div>`;
    renderContent();
  }
  function sevPill(value, score = '') { return value === 'None' ? '<span class="rw-muted">unscored / none</span>' : `<span class="rw-severity ${value.toLowerCase()}">${value.toLowerCase()}${score ? ` ${e(score)}` : ''}</span>`; }
  function reviewPill(f) { return `<span class="rw-label ${f.vex === 'not_affected' || f.vex === 'fixed' ? 'safe' : f.review === 'reviewed' ? 'info' : ''}">${f.vex === 'not_affected' ? 'not affected' : f.vex === 'fixed' ? 'fixed' : f.review}</span>`; }
  function table(headers, body) { return `<div class="rw-tablewrap"><table class="rw-table"><thead><tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr></thead><tbody>${body || `<tr><td colspan="${headers.length}">No matching records.</td></tr>`}</tbody></table></div>`; }
  function renderContent() {
    const s = current(), st = stats(s), el = document.getElementById('rwContent');
    if(!s.report && ['findings','components','upgrades','history','delta'].includes(view)){el.innerHTML='<div class="rw-empty"><h2>No CVE report imported</h2><p>The SBOM shows components, licenses and dependencies. Vulnerability findings need the matching CVE report.<br>Add it to this build; you do not need to re-upload the SBOM.</p><button class="btn rw-primary" data-action="attach-cve">Add matching CVE report</button> <button class="btn" data-action="view" data-id="sbom">Explore SBOM inventory</button></div>';return;}
    if (view === 'overview') renderOverview();
    else if (view === 'sbom') renderScanSbom();
    else if (view === 'components') {
      el.innerHTML = `<div class="rw-filter"><input id="rwSearch" aria-label="Search components" placeholder="Search components, recipe or layer…" value="${e(query)}"><button class="rw-link" data-action="columns">Columns…</button></div><div id="rwResults"></div>`; renderComponents();
    } else if (view === 'findings') {
      el.innerHTML = `<div class="rw-filter"><input id="rwSearch" aria-label="Search findings" placeholder="Search CVE, component or description…" value="${e(query)}"><select id="rwFindingFilter" aria-label="Finding status"><option value="open">Open findings</option><option value="blocker">Blocking findings</option><option value="review">Needs product assessment</option><option value="accepted">Accepted risks (open)</option><option value="action">Other action required</option><option value="all">All findings</option><option value="fixed">Fixed / not affected</option><option value="cra">CRA-relevant open</option></select></div><div id="rwResults"></div>`;
      document.getElementById('rwFindingFilter').value = findingFilter; renderFindings();
    } else if (view === 'history') renderHistory();
    else if (view === 'upgrades') renderUpgrades();
    else if (view === 'delta') renderDelta();
    else el.innerHTML = `<div class="rw-box"><h3>REVIEW EVIDENCE</h3><p class="rw-description">Snapshot: ${e(s.name)} · ${stamp(s)} · ${e(s.stream)}. Evidence includes the original report, build metadata, review decisions with rationale and timestamps, attached SBOM relationships, and the evaluated release gate.</p><button class="btn" data-action="evidence">Download evidence JSON</button> <button class="btn" data-action="vex-export">Export OpenVEX</button> <button class="btn" data-action="backup">Export complete workspace</button></div><div class="rw-box"><h3>ACTIVE REVIEW POLICY</h3><p class="rw-description">${e(policySummary(st))}</p><ol class="rw-description">${reviewPolicy.rules.map(rule=>`<li>${e(rule)}</li>`).join('')}</ol><button class="btn" data-action="policy">Policy &amp; sources</button><p class="rw-description">${e(reviewPolicy.id)} · ${e(reviewPolicy.basis)}</p></div><div class="rw-box"><h3>ATTACHED SBOM</h3><p class="rw-description">${s.sbom ? `${s.sbom.components.length} components · ${s.sbom.relations.length} relationships · ${e(s.sbom.source || '')}` : 'No SBOM attached to this scan. Attach an SBOM in this scan’s SBOM tab or include it when importing the build.'}</p><button class="btn" data-action="attach-sbom">Choose or replace SBOM</button></div><div class="rw-box"><h3>CURRENT ASSESSMENTS</h3><p class="rw-description">${(s.reviewEvents || []).length} recorded review changes included in Evidence JSON. Earlier assessments saved before change history was introduced are retained as current values.</p>${table(['Component / CVE','VEX status','CRA relevant','Risk acceptance','Rationale','Reviewed at'], Object.entries(s.reviews || {}).map(([k,r]) => `<tr><td>${e(JSON.parse(k).join(' / '))}</td><td>${e(r.vex)}</td><td>${typeof r.cra === 'boolean' ? r.cra ? 'Yes' : 'No' : 'Unknown'}</td><td>${r.acceptance?`${e(r.acceptance.owner)} · until ${e(r.acceptance.until)} (UTC)<br>${e(r.acceptance.controls)}`:'None'}</td><td>${e(r.rationale)}</td><td>${e(r.at || '—')}</td></tr>`).join(''))}</div>`;
  }
  function renderComponents() {
    const s = current(), fs = facts(s), q = query.toLowerCase(), grouped = new Map();
    for (const f of fs) { if (!grouped.has(f.pkg)) grouped.set(f.pkg,[]); grouped.get(f.pkg).push(f); }
    const items = packages(s).map((p,index) => {
      const findings = grouped.get(p.name) || [], open = findings.filter(f => f.open);
      return { p, index, findings, open, worst:severity.find(v => findings.some(f => f.sev === v)) || 'None' };
    }).filter(x => [x.p.name,x.p.version,x.p.layer,x.p.recipe].join(' ').toLowerCase().includes(q));
    const values = x => sort === 'cves' ? x.findings.length : sort === 'severity' ? 5 - severity.indexOf(x.worst) : String(x.p[sort] || '');
    items.sort((a,b) => (typeof values(a) === 'number' ? values(a) - values(b) : values(a).localeCompare(values(b))) * (descending ? -1 : 1));
    const columns = current().columns || ['name','version','recipe','layer','cves','severity','review','fix'];
    const labels = {name:'Component',version:'Version',recipe:'Recipe',layer:'Layer',cves:'CVEs',severity:'Severity',review:'Review',fix:'Top fix hint'};
    document.getElementById('rwResults').innerHTML = table(columns.map(c => `<button class="rw-sort" data-action="sort" data-id="${c}">${labels[c]}${sort === c ? descending ? ' ▾' : ' ▴' : ''}</button>`), items.map(x => {
      const cells = {name:e(x.p.name),version:e(x.p.version || '—'),recipe:e(x.p.recipe || x.p.name),layer:e(x.p.layer || '—'),cves:x.findings.length,severity:x.findings.length ? sevPill(x.worst) : '—',review:!x.findings.length ? '—' : !x.open.length ? '<span class="rw-label safe">not affected / fixed</span>' : x.open.some(f => f.review === 'unreviewed') ? '<span class="rw-label">unreviewed</span>' : '<span class="rw-label info">reviewed</span>',fix:x.open.some(f => f.fix) ? `<span class="rw-label safe">${e(x.open.find(f => f.fix).fix)} update available</span>` : ''};
      return `<tr data-component="${x.index}" tabindex="0" role="button" aria-label="Inspect ${e(x.p.name)}">${columns.map(c => `<td class="${['name','version','recipe'].includes(c) ? 'mono' : ''}">${cells[c]}</td>`).join('')}</tr>`;
    }).join(''));
  }
  function renderFindings() {
    const fs = facts(current()).filter(f => (findingFilter === 'all' || findingFilter === 'fixed' ? findingFilter === 'all' || !f.open : f.open && (findingFilter !== 'cra' || f.cra === true) && (!['blocker','review','accepted','action'].includes(findingFilter) || disposition(f)===findingFilter)) && [f.cve,f.pkg,f.summary].join(' ').toLowerCase().includes(query.toLowerCase()));
    document.getElementById('rwResults').innerHTML = `<p class="rw-description">Showing ${Math.min(fs.length,findingLimit).toLocaleString()} of ${fs.length.toLocaleString()} matching findings</p>` + table(['CVE','Component','Severity','VEX','KEV','Disposition','CRA relevant'], fs.slice(0,findingLimit).map(f => `<tr data-finding="${e(key(f))}" tabindex="0" role="button"><td class="mono">${e(f.cve)}</td><td class="mono">${e(f.pkg)}</td><td>${sevPill(f.sev,f.score)}</td><td><span class="rw-label unknown">${e(f.vex)}</span></td><td>${f.kev ? '<span class="rw-label">CISA KEV</span>' : `<span class="rw-label unknown">${f.kev===false?'Not listed':'Not provided'}</span>`}</td><td>${reviewPill(f)}<div class="rw-disposition">${e(dispositionLabel(f))}</div></td><td>${typeof f.cra === 'boolean' ? f.cra ? 'Yes' : 'No' : 'Unknown'}</td></tr>`).join('')) + (fs.length>findingLimit?'<p><button class="btn" data-action="more-findings">Load 200 more findings</button></p>':'');
  }
  function buildFiles(s) {
    const st=stats(s);
    return `<section class="rw-build-files" aria-label="Files in this build"><div class="rw-box"><h3>CVE REPORT · ${s.report?'IMPORTED':'NOT IMPORTED'}</h3><p class="rw-file-name">${e(s.report?s.sourceName || 'Imported Yocto report':'Add a report to assess vulnerabilities')}</p><p class="rw-description">${s.report?`${packages(s).length} reported recipes · ${st.all.length.toLocaleString()} finding records · ${st.open.length.toLocaleString()} open`:'No vulnerability assessment has been imported. The SBOM alone is an inventory.'}</p><button class="btn ${s.report?'':'rw-primary'}" data-action="${s.report?'view':'attach-cve'}" ${s.report?'data-id="findings"':''}>${s.report?'Open CVE findings':'Add matching CVE report'}</button></div><div class="rw-box"><h3>SBOM INVENTORY · ${s.sbom?'IMPORTED':'NOT IMPORTED'}</h3><p class="rw-file-name">${e(s.sbom?.source || 'Add component, license and dependency evidence')}</p><p class="rw-description">${s.sbom?`${s.sbom.components.length.toLocaleString()} component records · ${s.sbom.relations.filter(r=>r.type==='DEPENDS_ON').length.toLocaleString()} runtime dependency links`:'No SBOM is attached to this build. CVE recipe records do not replace an SBOM inventory.'}</p><button class="btn rw-primary" data-action="${s.sbom?'view':'attach-sbom'}" ${s.sbom?'data-id="sbom"':''}>${s.sbom?'Explore SBOM inventory':'Add SBOM inventory'}</button></div></section>`;
  }
  function inventorySummary(s) {
    if(!s.sbom)return '';
    const bom=s.sbom, licenses=new Set(bom.components.flatMap(c=>c.licenses || []));
    return `<div class="rw-box"><div class="rw-toolbar"><h3>SBOM INVENTORY AT A GLANCE</h3><button class="rw-link" data-action="view" data-id="sbom">View full inventory →</button></div><p class="rw-description">${bom.components.length.toLocaleString()} component records · ${licenses.size} distinct license expressions · ${bom.relations.filter(r=>r.type==='DEPENDS_ON').length.toLocaleString()} runtime dependency links</p>${table(['Component','Version','License'],bom.components.slice(0,5).map(c=>`<tr data-bom-id="${e(c.id)}" tabindex="0" role="button"><td>${e(c.name)}</td><td>${e(c.version || 'Not provided')}</td><td>${e((c.licenses || []).join(', ') || 'Not provided')}</td></tr>`).join(''))}</div>`;
  }
  function renderOverview() {
    const s=current(), st=stats(s), statusCounts={};
    if(!s.report){document.getElementById('rwContent').innerHTML=buildFiles(s)+inventorySummary(s);return;}
    for(const f of st.all) statusCounts[f.status || 'Unknown']=(statusCounts[f.status || 'Unknown'] || 0)+1;
    const ranks={blocker:0,review:1,action:2,accepted:3,closed:4};
    const top=[...st.open].sort((a,b)=>ranks[disposition(a)]-ranks[disposition(b)] || severity.indexOf(a.sev)-severity.indexOf(b.sev)).slice(0,12);
    document.getElementById('rwContent').innerHTML=buildFiles(s)+inventorySummary(s)+`<div class="rw-overview"><div class="rw-box"><h3>BUILD SUMMARY</h3><p>${packages(s).length} reported recipes · ${new Set(st.all.map(f=>f.cve)).size.toLocaleString()} unique CVEs · ${st.open.length.toLocaleString()} open finding records</p><p class="rw-description">${Object.entries(statusCounts).map(([label,n])=>`${e(label)}: ${n.toLocaleString()}`).join(' · ')}</p><p class="rw-description">${e(s.reportScope || 'Unspecified')} report. Recipe counts can differ from installed binary-package counts in the SBOM. ${s.buildDateKnown===false?'Build date was not supplied; history uses the import date.':''}</p></div><div class="rw-box"><h3>OPEN BY SEVERITY</h3><div class="rw-tags">${severity.map(v=>`<span class="rw-pill">${sevPill(v)} ${st.counts[v]}</span>`).join('')}</div><p class="rw-description">${st.all.filter(f=>f.review==='reviewed').length} explicitly reviewed · ${st.all.filter(f=>f.review==='unreviewed').length} unreviewed</p><button class="btn" data-action="findings">Review findings</button></div></div><div class="rw-box"><h3>PRIORITY OPEN FINDINGS</h3>${table(['CVE','Component','Severity','Disposition'],top.map(f=>`<tr data-finding="${e(key(f))}" tabindex="0" role="button"><td>${e(f.cve)}</td><td>${e(f.pkg)}</td><td>${sevPill(f.sev)}</td><td>${e(dispositionLabel(f))}</td></tr>`).join(''))}</div><div class="rw-box"><h3>REPORT EXPORTS</h3><p class="rw-description">HTML/PDF/Markdown exports contain the original Yocto report. Evidence JSON includes saved review decisions and the current policy result.</p><div class="rw-tags">${['html','pdf','md','json'].map(format=>`<button class="btn" data-action="report-export" data-id="${format}">${format.toUpperCase()}</button>`).join('')}<button class="btn" data-action="evidence">Evidence JSON</button></div></div>`;
  }
  function renderScanSbom() {
    const s=current(), bom=s.sbom, q=query.toLowerCase();
    if(!bom) { document.getElementById('rwContent').innerHTML='<div class="rw-empty"><h2>Add the SBOM for this build</h2><p>Choose SPDX or CycloneDX JSON, multiple SPDX documents, or a complete .spdx.tar bundle.<br>The inventory stays attached to this build after reloading.</p><button class="btn rw-primary" data-action="attach-sbom">Choose SBOM</button></div>'; return; }
    const list=bom.components.filter(c=>[c.name,c.version,c.supplier,(c.licenses || []).join(' ')].join(' ').toLowerCase().includes(q));
    const referenceOnly=bom.components.filter(c=>c.recordKind==='reference').length;
    const integrity=bom.integrity, licenses=new Set(bom.components.flatMap(c=>c.licenses || [])), runtime=bom.relations.filter(r=>r.type==='DEPENDS_ON').length;
    const hasProblems=Boolean(integrity?.mismatches.length || integrity?.missing.length);
    const status=integrity?.missing.length?`Incomplete · ${integrity.missing.length.toLocaleString()} unresolved document references`:integrity?`${integrity.checked.toLocaleString()} checksums checked · ${integrity.mismatches.length} mismatches`:'Checksums not checked';
    document.getElementById('rwContent').innerHTML=`<div class="rw-toolbar"><h1>SBOM inventory · ${bom.components.length.toLocaleString()} component records</h1><button class="btn" data-action="attach-sbom">Replace SBOM</button></div><div class="rw-tags"><span class="rw-pill">${!licenses.size && referenceOnly?'License metadata not loaded':`${licenses.size} license expressions`}</span><span class="rw-pill">${!runtime && integrity?.missing.length?'Dependency data incomplete':`${runtime.toLocaleString()} runtime dependency links`}</span><span class="rw-pill">${e(bom.format || 'SBOM')}</span></div><p class="rw-file-name">${e(bom.source || 'Imported SBOM')} · ${(bom.documents || []).length.toLocaleString()} SPDX/SBOM documents loaded</p>${referenceOnly?`<p class="rw-description rw-danger">${(bom.components.length-referenceOnly).toLocaleString()} full component records · ${referenceOnly.toLocaleString()} reference-only records awaiting metadata</p>`:''}<details class="rw-sbom-evidence"><summary class="${hasProblems?'rw-danger':''}">File details &amp; integrity · ${e(status)}</summary><div class="rw-note">${(bom.documents || []).length} source documents. ${integrity?`${integrity.checked.toLocaleString()} external checksums checked${integrity.unchecked?` · ${integrity.unchecked} unchecked`:''}`:'Source-document checksums were not checked.'}${integrity?.mismatches.length?`<p>Checksum mismatch details:</p>${integrity.mismatches.map(v=>`<p>${e(v)}</p>`).join('')}`:''}</div></details>${integrity?.missing.length?'<div class="rw-note rw-danger">This SPDX file references documents that were not uploaded. Import the matching complete .spdx.tar bundle to load their component metadata.</div>':''}<p class="rw-description">Select a component for metadata and runtime dependencies. The inventory can include build tools as well as shipped packages. ${s.report?'Open CVE findings for vulnerability reviews.':'No CVE report imported; vulnerabilities are not assessed.'}</p><div class="rw-filter"><input id="rwSearch" aria-label="Search SBOM" value="${e(query)}" placeholder="Search component, version, supplier or license…"></div><p class="rw-muted rw-small">Showing ${Math.min(list.length,200)} of ${list.length.toLocaleString()} matching records. Search to narrow the list.</p>${table(['Component','Version','License','Supplier','Record'],list.slice(0,200).map(c=>`<tr data-bom-id="${e(c.id)}" role="button" tabindex="0"><td class="mono">${e(c.name)}</td><td>${e(c.version || 'Not provided')}</td><td>${e((c.licenses || []).join(', ') || 'Not provided')}</td><td>${e(c.supplier || 'Not provided')}</td><td>${e(c.recordKind || 'component')}</td></tr>`).join(''))}`;
  }
  function sbomDetail(cid) {
    const s=current(), c=s.sbom?.components.find(c=>c.id===cid); if(!c)return;
    modal(e(c.name),`<div class="rw-box"><h3>COMPONENT METADATA</h3><p class="rw-description">Version: ${e(c.version || 'Not provided')}<br>Supplier: ${e(c.supplier || 'Not provided')}<br>License: ${e((c.licenses || []).join(', ') || 'Not provided')}<br>Source document: ${e(c.sourceDocument || 'Not provided')}</p></div><div class="rw-box"><h3>RUNTIME DEPENDENCIES</h3>${graph(s,c)}</div>${c.files?.length?`<div class="rw-box"><h3>INSTALLED FILES (${c.files.length})</h3>${table(['Path','Checksums'],c.files.slice(0,200).map(f=>`<tr><td>${e(f.path || f.name || f.fileName || '—')}</td><td>${e(JSON.stringify(f.checksums || []))}</td></tr>`).join(''))}</div>`:''}`);
  }
  function sbomIntegrity(objects) {
    const documents=new Map(objects.filter(d=>d.documentNamespace).map(d=>[d.documentNamespace,d]));
    const result={checked:0,unchecked:0,mismatches:[],missing:[]};
    for(const obj of objects) for(const ref of obj.externalDocumentRefs || []) {
      const target=documents.get(ref.spdxDocument), source=obj._sourceName || obj.name || 'SPDX document';
      if(!target){result.missing.push(`${source}: ${ref.externalDocumentId}`);continue;}
      if(ref.checksum?.algorithm==='SHA1' && target._sourceSha1){result.checked++; if(ref.checksum.checksumValue.toLowerCase()!==target._sourceSha1)result.mismatches.push(`${source}: ${ref.externalDocumentId}`);}
      else result.unchecked++;
    }
    return result;
  }
  async function readAttachedSbom(files) {
    if(!files.length)return null;
    const objects=[];
    for(const file of files) objects.push(...await loadSbomObjectsFromFile(file));
    const parsed=buildSbomFromObjects(objects);
    if(!parsed.components?.length)throw new Error('No supported components found in this SBOM. Choose the complete SPDX bundle, not its index alone.');
    return {format:parsed.format,source:files.map(f=>f.name).join(', '),components:parsed.components,relations:parsed.relations || [],documents:parsed.documents || [],integrity:sbomIntegrity(objects),normalizerVersion:2};
  }
  function modal(title, content, subtitle = '') {
    if (dialog.open) dialog.close();
    dialog.innerHTML = `<div class="rw-dialog-header"><div><h2>${title}</h2><span class="rw-muted rw-small">${subtitle}</span></div><button class="btn" data-action="close" aria-label="Close dialog">×</button></div><div class="rw-dialog-body">${content}</div>`;
    dialog.showModal();
  }
  function graph(s,p) {
    const bom=s.sbom;
    if(!bom?.components?.length)return '<p class="rw-description">Attach a matching SBOM in this scan’s SBOM tab to explain dependencies.</p>';
    const original=matchComponent(bom,p); if(!original)return '<p class="rw-description">No matching name/version was found in the attached SBOM.</p>';
    const relations=bom.relations.filter(r=>['DEPENDS_ON','DYNAMIC_LINK','STATIC_LINK'].includes(r.type));
    const ins=new Map(),outs=new Map();
    for(const r of relations){if(!ins.has(r.to))ins.set(r.to,[]);ins.get(r.to).push(r.from);if(!outs.has(r.from))outs.set(r.from,[]);outs.get(r.from).push(r.to);}
    let component=original;
    if(!ins.has(component.id)&&!outs.has(component.id)) {
      const produced=bom.relations.filter(r=>r.type==='GENERATED_FROM'&&r.to===original.id).map(r=>bom.components.find(c=>c.id===r.from)).filter(Boolean);
      produced.sort((a,b)=>((ins.get(b.id)?.length||0)+(outs.get(b.id)?.length||0))-((ins.get(a.id)?.length||0)+(outs.get(a.id)?.length||0)));
      if(produced[0])component=produced[0];
    }
    if(!ins.has(component.id)&&!outs.has(component.id))return '<p class="rw-description">The attached SBOM provides no runtime dependency edges for this component. Build dependencies are kept separate. Reimport older attachments to enable Kirkstone runtime relationship support.</p>';
    const seen=new Set([component.id]), roots=new Set(), queue=[...(ins.get(component.id)||[])];
    for(let i=0;i<queue.length;i++){const node=queue[i];if(seen.has(node))continue;seen.add(node);const parents=ins.get(node)||[];if(!parents.length)roots.add(node);else queue.push(...parents);}
    const ancestorRoots=[...roots], left=(ancestorRoots.length?ancestorRoots:[...new Set(ins.get(component.id)||[])]).slice(0,12), right=[...new Set(outs.get(component.id)||[])].slice(0,12);
    const lookup=cid=>bom.components.find(c=>c.id===cid)||{name:cid,version:''};
    const height=Math.max(160,Math.max(left.length,right.length)*46+32);
    const box=(cid,x,y,color)=>{const c=lookup(cid);return `<g><title>${e(c.name)} ${e(c.version || '')}</title><rect x="${x}" y="${y}" width="175" height="32" rx="4" fill="${cid===component.id?'#1d2742':'#171a23'}" stroke="${color}"/><text x="${x+9}" y="${y+13}">${e(String(c.name).slice(0,25))}</text><text class="version" x="${x+9}" y="${y+26}">${e(c.version || '')}</text></g>`;};
    return `<p class="rw-description">${component.id!==original.id?`Recipe ${e(original.name)} maps to binary package <b>${e(component.name)}</b>. `:''}Arrows point from a package to its runtime dependency. Dashed arrows summarize transitive paths. Build dependencies are excluded.</p><div class="rw-graph"><svg viewBox="0 0 900 ${height}" role="img" aria-label="Runtime dependency graph for ${e(component.name)}"><defs><marker id="rwArrow" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#414858"/></marker></defs>${left.map((cid,i)=>`<path d="M200 ${41+i*46} C230 ${41+i*46},230 41,265 41" fill="none" stroke="#414858" ${!(ins.get(component.id)||[]).includes(cid)?'stroke-dasharray="4 4"':''} marker-end="url(#rwArrow)"/>${box(cid,25,25+i*46,'#719c73')}`).join('')}${right.map((cid,i)=>`<path d="M440 41 C475 41,475 ${41+i*46},510 ${41+i*46}" fill="none" stroke="#414858" marker-end="url(#rwArrow)"/>${box(cid,510,25+i*46,'#303644')}`).join('')}${box(component.id,265,25,'#83a9ff')}</svg></div><p class="rw-description">${ancestorRoots.length?'Ancestor packages':left.length?'Direct dependents (dependency cycle has no terminal root)':'Runtime dependents recorded'}: ${left.map(cid=>e(lookup(cid).name)).join(', ') || 'None'}. Showing up to 12 nodes per side.</p>`;
  }
  function componentDetail(index) {
    const s = current(), p = packages(s)[index]; if (!p) return;
    const fs = facts(s).filter(f => f.pkg === p.name);
    modal(`<span class="mono">${e(p.name)}</span> <span class="rw-muted rw-small">${e(p.version || '')} · ${e(p.recipe || p.name)} · ${e(p.layer || '')}</span>`, `<div class="rw-box"><h3>WHY IS THIS COMPONENT HERE?</h3>${graph(s,p)}</div><div class="rw-box"><h3>CVES IN THIS COMPONENT</h3>${table(['CVE','Severity','VEX','KEV','Review'],fs.slice(0,200).map(f => `<tr data-finding="${e(key(f))}" tabindex="0" role="button"><td class="mono">${e(f.cve)}</td><td>${sevPill(f.sev,f.score)}</td><td><span class="rw-label unknown">${e(f.vex)}</span></td><td><span class="rw-label unknown">${f.kev ? 'CISA KEV' : f.kev===false?'Not listed':'Not provided'}</span></td><td>${reviewPill(f)}</td></tr>`).join(''))}<p class="rw-description">Showing ${Math.min(fs.length,200)} of ${fs.length} findings. Click any CVE to open the full triage detail.</p><button class="btn" data-action="component-findings" data-id="${e(p.name)}">View all component findings</button></div>`, `${fs.length} CVE against this component · ${fs.filter(f => f.review === 'unreviewed').length} unreviewed · ${fs.some(f=>typeof f.cra!=='boolean')?'CRA relevance not fully assessed':`${fs.filter(f=>f.cra===true).length} CRA-relevant`}`);
  }
  function findingDetail(findingKey) {
    const f = facts(current()).find(x => key(x) === findingKey); if (!f) return;
    modal(`${e(f.cve)} <span class="rw-muted rw-small">${e(f.pkg)} ${e(f.version)}</span>`, `<div class="rw-box"><h3>FINDING</h3>${sevPill(f.sev,f.score)} <span class="rw-label unknown">Yocto: ${e(f.status || 'unknown')}</span><p class="rw-description">${e(f.summary || 'No description supplied in the imported report.')}</p>${/^https?:\/\//i.test(f.link || '')?`<p><a href="${e(f.link)}" target="_blank" rel="noopener noreferrer">Open vulnerability reference</a></p>`:''}<p class="rw-description">Fix version: ${e(f.fix || 'Not supplied')} · KEV status: ${f.kev ? 'Listed in CISA KEV' : f.kev===false?'Not listed':'Not provided'}</p></div><form id="rwReviewForm" class="rw-form"><input type="hidden" name="findingKey" value="${e(findingKey)}"><label>VEX assessment<select name="vex">${['unknown','affected','not_affected','fixed','under_investigation'].map(v => `<option ${f.vex === v ? 'selected' : ''}>${v}</option>`).join('')}</select></label><label>CRA relevance<select name="cra"><option value="unknown">Not assessed</option><option value="true" ${f.cra === true ? 'selected' : ''}>Relevant</option><option value="false" ${f.cra === false ? 'selected' : ''}>Not relevant</option></select></label><label>Product exploitability<select name="exploitability"><option value="unknown">Not established</option><option value="exploitable" ${f.exploitability==='exploitable'?'selected':''}>Confirmed exploitable in this product</option></select></label><label>Risk response<select name="riskResponse"><option value="remediate">Investigate / remediate</option><option value="accept" ${f.acceptance?'selected':''}>Record temporary risk acceptance</option></select></label><fieldset id="rwAcceptance" class="wide rw-form" ${f.acceptance?'':'hidden disabled'}><legend>Temporary risk acceptance (only when selected)</legend><p class="rw-description wide">Use only for confirmed affected findings. Requires a named accountable approver, expiry and mitigation evidence. The CVE stays open. The recorded name is self-declared; approval authority is verified outside this local browser. KEV-listed or confirmed exploitable findings remain blocked under this policy.</p>${input('riskOwner','Approver / accountable owner',f.acceptance?.owner || '')}${input('riskUntil','Acceptance expiry (UTC date)',f.acceptance?.until || '',false,'date')}<label class="wide">Mitigations / compensating controls<textarea name="riskControls">${e(f.acceptance?.controls || '')}</textarea></label></fieldset><label class="wide">Review rationale (required)<textarea name="rationale" required maxlength="10000" placeholder="Describe evidence, exposure, patch validation or why the product is not affected.">${e(f.rationale)}</textarea></label><div class="rw-form-actions"><button class="btn" type="button" data-action="close">Cancel</button><button class="btn" type="submit">Save review</button></div></form>`);
  }
  function reviewDecision(f,values,now=new Date()) {
    const rationale=String(values.rationale || '').trim();
    if(!rationale)throw new Error('A review rationale is required.');
    if(!['unknown','affected','fixed','not_affected','under_investigation'].includes(values.vex))throw new Error('Choose a valid VEX assessment.');
    const exploitability=values.exploitability || 'unknown';
    if(!['unknown','exploitable'].includes(exploitability))throw new Error('Choose a valid exploitability assessment.');
    if(exploitability==='exploitable' && values.vex!=='affected')throw new Error('Confirmed exploitable findings must have an affected VEX assessment.');
    const decision={vex:values.vex,exploitability,cra:values.cra==='unknown'?null:values.cra==='true',rationale,at:now.toISOString()};
    if(values.riskResponse==='accept') {
      const acceptance={owner:String(values.riskOwner || '').trim(),until:values.riskUntil,controls:String(values.riskControls || '').trim()};
      if(values.vex!=='affected')throw new Error('Assess the finding as affected before accepting residual risk.');
      if(f.kev===true || exploitability==='exploitable')throw new Error('This policy does not permit acceptance to bypass KEV or confirmed product exploitability blockers.');
      if(!validAcceptance(acceptance) || acceptance.until<now.toISOString().slice(0,10))throw new Error('Risk acceptance requires an approver, mitigation evidence and a valid expiry on or after today (UTC).');
      decision.acceptance=acceptance;
    }
    return decision;
  }
  function recordReview(s,findingKey,decision) {
    s.reviews ||= {};s.reviewEvents ||= [];
    s.reviewEvents.push({findingKey,previous:s.reviews[findingKey] || null,decision:structuredClone(decision)});
    s.reviews[findingKey]=decision;
  }
  function renderHistory() {
    const s = current(), all = siblings(s).filter(x=>x.report), scans = range ? all.slice(-range) : all;
    const top = Math.max(1,...scans.map(x => metric === 'cra' ? stats(x).cra : stats(x).open.length));
    const ceiling = Math.max(4,Math.ceil(top / 4) * 4), width = 1080, plotHeight = 215, chartBottom = 258;
    document.getElementById('rwContent').innerHTML = `<div class="rw-filter"><span class="rw-muted">Range</span><div class="rw-segments">${[[12,'last 12'],[24,'last 24'],[0,'all']].map(([n,label]) => `<button data-action="range" data-id="${n}" class="${range === n ? 'active' : ''}">${label}</button>`).join('')}</div><span class="rw-muted">Metric</span><div class="rw-segments"><button data-action="metric" data-id="severity" class="${metric === 'severity' ? 'active' : ''}">Open by severity</button><button data-action="metric" data-id="cra" class="${metric === 'cra' ? 'active' : ''}">CRA-relevant open</button></div><span class="rw-muted rw-small" style="margin-left:auto">${scans.length} of ${all.length} scans</span></div><div class="rw-chart"><svg viewBox="0 0 ${width} 330" role="group" aria-label="Open findings across scan history">${Array.from({length:5},(_,i) => { const y = chartBottom - i * plotHeight / 4; return `<line x1="50" x2="1060" y1="${y}" y2="${y}" stroke="#252a36"/><text x="22" y="${y + 4}">${ceiling * i / 4}</text>`; }).join('')}${scans.map((x,i) => {
      const st = stats(x), xPos = 50 + (i + .5) * 1010 / scans.length, bw = Math.min(48,600 / scans.length);
      let y = chartBottom;
      const bars = (metric === 'cra' ? [{n:st.cra,color:'#f6c34e'}] : [...severity].reverse().map(v => ({n:st.counts[v],color:palette[severity.indexOf(v)]}))).map(({n,color}) => { const h = n / ceiling * plotHeight; y -= h; return n ? `<rect x="${xPos - bw / 2}" y="${y}" width="${bw}" height="${h}" fill="${color}" stroke="#171a23"/>` : ''; }).join('');
      return `<g class="rw-bar" data-action="compare" data-id="${e(x.id)}" role="button" tabindex="0" aria-label="Scan ${i + 1}, ${stamp(x)}, ${st.open.length} open, ${st.gate}"><title>${stamp(x)} · ${st.open.length} open · ${st.gate}</title><rect x="${xPos - Math.max(bw,28) / 2 - 5}" y="16" width="${Math.max(bw,28) + 10}" height="300" fill="transparent"/>${bars}${compare.includes(x.id) || x.id === selected ? `<rect x="${xPos - bw / 2 - 4}" y="${y - 4}" width="${bw + 8}" height="${Math.max(chartBottom - y,1) + 8}" fill="none" stroke="#83a9ff" rx="4"/>` : ''}<text x="${xPos}" y="${y - 10}" text-anchor="middle">${metric === 'cra' ? st.cra : st.open.length}</text><text x="${xPos}" y="278" text-anchor="middle">${stamp(x).slice(5).replace('-', '/')}</text><text x="${xPos}" y="292" text-anchor="middle">#${all.indexOf(x) + 1}</text><rect x="${xPos - bw / 2}" y="306" width="${bw}" height="8" rx="2" fill="${gateColor(st.gate)}"/>${x.event ? `<line x1="${xPos}" x2="${xPos}" y1="30" y2="${Math.max(44,y - 20)}" stroke="#83a9ff" stroke-dasharray="3 4"/><circle cx="${xPos}" cy="30" r="5" fill="#83a9ff"/>` : ''}</g>`;
    }).join('')}<text x="12" y="314">Gate</text></svg></div><div class="rw-legend">${(metric === 'cra' ? ['CRA-relevant'] : severity.slice(0,4)).map((v,i) => `<span><i class="rw-key" style="background:${metric === 'cra' ? '#f6c34e' : palette[i]}"></i>${v}</span>`).join('')}<span><i class="rw-key" style="background:#83a9ff;border-radius:50%"></i>Event</span><span><i class="rw-key" style="background:#66b573"></i>Gate verdict</span></div>${scans.filter(x => x.event).map(x => `<div class="rw-event"><button class="rw-link" data-action="scan" data-id="${e(x.id)}">● &nbsp; #${all.indexOf(x) + 1}</button><span class="rw-muted">${stamp(x).slice(5).replace('-', '/')}</span> &nbsp; ${e(x.event)}</div>`).join('')}<div class="rw-note">${compare.length === 1 ? `Scan #${all.findIndex(x => x.id === compare[0]) + 1} selected — click a second one to compare.` : 'Review status is recalculated with the current policy and current UTC date, including acceptance expiry. Select two scan bars to compare findings. Click an event to inspect that scan.'}${metric === 'cra' && scans.some(x => stats(x).craUnknown) ? ' Unknown CRA relevance is excluded from the bar counts.' : ''}</div>`;
  }
  function deltaData(a,b) {
    if(!a.report || !b.report)throw new Error('Both builds need CVE reports before their findings can be compared.');
    const fa = facts(a), fb = facts(b), ma = new Map(fa.map(f => [key(f),f])), mb = new Map(fb.map(f => [key(f),f]));
    return [...new Set([...ma.keys(),...mb.keys()])].map(k => { const old = ma.get(k), next = mb.get(k); return { f:next || old, change:!old ? 'Added' : !next ? 'Removed from report' : old.open && !next.open ? 'Closed' : !old.open && next.open ? 'Reopened' : old.vex !== next.vex || old.sev !== next.sev || old.version !== next.version ? 'Changed' : '' }; }).filter(x => x.change);
  }
  function renderDelta() {
    const s = current(), scans = siblings(s).filter(x=>x.report), a = db.scans.find(x => x.id === compare[0]) || scans[Math.max(0, scans.indexOf(s) - 1)], b = db.scans.find(x => x.id === compare[1]) || s;
    document.getElementById('rwContent').innerHTML = scans.length < 2 ? '<div class="rw-note">Import another scan in this product and stream to compare releases.</div>' : `<div class="rw-filter"><label>From <select id="rwDeltaFrom" aria-label="Compare from">${scans.map(x => `<option value="${e(x.id)}" ${x.id === a.id ? 'selected' : ''}>${stamp(x)} · ${e(x.release || x.name)}</option>`).join('')}</select></label><span>→</span><label>To <select id="rwDeltaTo" aria-label="Compare to">${scans.map(x => `<option value="${e(x.id)}" ${x.id === b.id ? 'selected' : ''}>${stamp(x)} · ${e(x.release || x.name)}</option>`).join('')}</select></label></div><div class="rw-current">${gateBox(stats(a).gate)} → ${gateBox(stats(b).gate)}<span class="rw-muted">${stats(a).open.length} → ${stats(b).open.length} open findings</span></div>${table(['Change','CVE','Component','Version','Severity'],deltaData(a,b).map(({f,change}) => `<tr><td>${e(change)}</td><td>${e(f.cve)}</td><td>${e(f.pkg)}</td><td>${e(f.version)}</td><td>${sevPill(f.sev)}</td></tr>`).join(''))}<div class="rw-note">A finding removed from a report is not proof of a fix. Delta compares package/CVE identities, versions, severity and VEX assessment.</div>`;
  }
  function scenarios(s) {
    const supplied = metadata(s).upgrade_scenarios;
    if (!Array.isArray(supplied)) return [];
    return supplied.filter(x => x && typeof x.title === 'string' && Array.isArray(x.fixes)).map((x,i,all) => {
      const fixes = x.cumulative ? all.slice(0,i + 1).flatMap(v => v.fixes) : x.fixes;
      const close = stats(s).open.filter(f => fixes.some(v => v && v.package === f.pkg && v.cve === f.cve)).map(key);
      return { ...x, close:[...new Set(close)] };
    });
  }
  function renderUpgrades() {
    const s = current(), st = stats(s), paths = scenarios(s);
    document.getElementById('rwContent').innerHTML = `<p class="rw-description" style="margin-top:0">What happens to the Gate verdict if you take each Yocto upgrade path? Each scenario re-runs the active policy with the would-be-fixed findings treated as closed. Baseline upgrades can be cumulative — they include everything reachable via lower upgrade steps.</p><div class="rw-current"><span class="rw-muted">Current gate</span>${gateBox(st.gate)}<span class="rw-muted"> · Product vulnerability review · policy v2</span><span class="rw-muted rw-small" style="float:right">${st.blockers.length} blockers · ${st.triage.length} need assessment</span></div>${paths.map(path => {
      const after = stats(s,path.close), improves = ['unknown','blocked','review','warning','passed'].indexOf(after.gate) > ['unknown','blocked','review','warning','passed'].indexOf(st.gate);
      return `<details class="rw-scenario ${after.gate}"><summary><div class="rw-grow"><b>${e(path.title)}</b><p>${path.close.length} open finding${path.close.length === 1 ? '' : 's'} would close</p></div>${gateBox(st.gate)}<span class="rw-muted">→</span>${gateBox(after.gate)}<span class="rw-muted rw-small">${improves ? 'improves' : 'unchanged'}</span></summary><p>${e(path.evidence || 'User-supplied upgrade scenario; validate patches and runtime behavior before shipment.')}</p>${table(['Component','CVE','Current severity'],stats(s).open.filter(f => path.close.includes(key(f))).map(f => `<tr><td>${e(f.pkg)}</td><td>${e(f.cve)}</td><td>${sevPill(f.sev)}</td></tr>`).join(''))}</details>`;
    }).join('') || '<div class="rw-note">No upgrade evidence supplied. Add scenarios with exact package/CVE pairs; VulnTrack does not infer fixes from a newer release name.</div>'}<button class="btn" data-action="scenario">Edit upgrade scenarios</button><div class="rw-note">Preview only. These scenarios do not modify scan findings or mark vulnerabilities fixed.</div>`;
  }
  const input = (name,label,value = '',wide = false,type = 'text',required = false) => `<label class="${wide ? 'wide' : ''}">${label}<input name="${name}" type="${type}" value="${e(value)}" ${required ? 'required' : ''} maxlength="1000"></label>`;
  const actions = () => '<div class="rw-form-actions"><button class="btn" type="button" data-action="close">Cancel</button><button class="btn" type="submit">Save</button></div>';
  function editGroup(gid) {
    const g = db.portfolios.find(x => x.id === gid);
    modal(g ? 'Edit portfolio' : 'Create portfolio',`<form id="rwGroupForm" class="rw-form"><input type="hidden" name="id" value="${e(gid || '')}">${input('name','Portfolio name',g?.name || '',true,'text',true)}${input('description','Description',g?.description || '')}${input('owner','Owner / team',g?.owner || '')}${actions()}</form>`);
  }
  function editProduct(gid,pid) {
    const p = db.portfolios.flatMap(g => g.products).find(x => x.id === pid);
    modal(p ? 'Edit product' : 'Add product',`<form id="rwProductForm" class="rw-form"><input type="hidden" name="groupId" value="${e(gid || '')}"><input type="hidden" name="id" value="${e(pid || '')}">${input('name','Product name',p?.name || '',true,'text',true)}${input('description','Description',p?.description || '',true)}${actions()}</form>`);
  }
  function importDialog(pid, rescan=false, newGroup=false, groupId='') {
    pendingReport=null;pendingReportName='';
    const s=rescan?current():null;
    const group=db.portfolios.find(g=>g.products.some(p=>p.id===(pid || s?.productId))) || db.portfolios.find(g=>g.id===groupId) || db.portfolios.at(-1);
    const gid=newGroup?'__new__':group?.id || '__new__';
    const productId=pid || s?.productId || (groupId?'__new__':group?.products[0]?.id) || '__new__';
    modal('Import build',`<form id="rwImportForm" class="rw-form"><p class="rw-description wide">Select or create a portfolio and product, then upload an SBOM, a CVE report, or both for this build. At least one file is required. Everything is saved together.</p><label>Portfolio<select name="groupId" id="rwImportGroup">${db.portfolios.map(g=>`<option value="${e(g.id)}" ${g.id===gid?'selected':''}>${e(g.name)}</option>`).join('')}<option value="__new__" ${gid==='__new__'?'selected':''}>+ Create new portfolio</option></select></label><label>Product<select name="productId" id="rwImportProduct"></select></label><fieldset id="rwNewGroup" class="rw-form wide"><legend>New portfolio</legend>${input('portfolioName','Portfolio name','',false,'text',true)}${input('portfolioDescription','Portfolio description')}${input('portfolioOwner','Owner / team')}</fieldset><fieldset id="rwNewProduct" class="rw-form wide"><legend>New product</legend>${input('productName','Product name','',false,'text',true)}${input('productDescription','Product description')}</fieldset>${input('name','Image / build name',s?.name || '',false,'text',true)}<label>Stream<select name="stream">${['Unassigned','Nightly','Released'].map(v=>`<option ${s?.stream===v?'selected':''}>${v}</option>`).join('')}</select></label><div class="wide rw-upload-files"><label>SBOM inventory<input type="file" name="sbom" aria-label="SBOM inventory" accept=".json,.tar,.zst,.tar.zst,.tar.gz,.tgz" multiple><span class="rw-description">Components, licenses and dependencies. SPDX / CycloneDX JSON or complete tar bundle.</span></label><label>CVE report JSON<input type="file" name="report" aria-label="CVE report JSON" accept=".json,application/json"><span class="rw-description">Vulnerability findings and patch status. Use the matching Yocto image report.</span></label></div><details class="wide rw-advanced"><summary>Build metadata (optional)</summary><div class="rw-form"><label class="wide">Yocto testdata JSON (optional)<input type="file" name="buildMetadata" accept=".json,application/json"></label>${input('release','Yocto release',s?.release || '')}${input('machine','Machine',s?.machine || '')}${input('date','Build date','',false,'date')}${input('distro','Distro',s?.distro || '')}<label>Report scope<select name="reportScope"><option>Unspecified</option><option>Image-specific</option><option>Build-wide</option></select></label></div></details><div id="rwImportStatus" class="rw-note wide" role="status" hidden></div><div class="rw-form-actions"><button class="btn" type="button" data-action="close">Cancel</button><button class="btn rw-primary" type="submit">Import build</button></div></form>`);
    updateImportFields(true,productId);
  }
  function updateImportFields(resetProduct=false, selectedProduct='__new__') {
    const groupSelect=document.getElementById('rwImportGroup'), productSelect=document.getElementById('rwImportProduct');
    const group=db.portfolios.find(g=>g.id===groupSelect.value);
    if(resetProduct)productSelect.innerHTML=`${(group?.products || []).map(p=>`<option value="${e(p.id)}" ${p.id===selectedProduct?'selected':''}>${e(p.name)}</option>`).join('')}<option value="__new__" ${selectedProduct==='__new__' || !group?.products.some(p=>p.id===selectedProduct)?'selected':''}>+ Create new product</option>`;
    for(const [field,show] of [['rwNewGroup',groupSelect.value==='__new__'],['rwNewProduct',productSelect.value==='__new__']]){const el=document.getElementById(field);el.hidden=!show;el.disabled=!show;}
  }
  function buildMetadataFields(meta) {
    const build=String(meta.BUILDNAME || '');
    return {release:meta.LAYERSERIES_CORENAMES || meta.yocto_release || '',machine:meta.MACHINE || meta.machine || '',distro:meta.DISTRO || meta.distro || '',name:meta.IMAGE_BASENAME || meta.IMAGE_NAME || meta.image || '',date:/^\d{14}$/.test(build)?`${build.slice(0,4)}-${build.slice(4,6)}-${build.slice(6,8)}`:''};
  }
  function commitImport(report,fields,attached=null) {
    if(report!==null && !validReport(report))throw new Error('Expected a valid Yocto CVE report.');
    if(attached && !validSbom(attached))throw new Error('Invalid SBOM inventory.');
    if(!report && !attached)throw new Error('Choose a CVE report, an SBOM, or both.');
    if(!String(fields.name || '').trim())throw new Error('Image / build name is required.');
    if(fields.stream && !['Released','Nightly','Unassigned'].includes(fields.stream))throw new Error('Choose a valid stream.');
    if(fields.date && !Number.isFinite(Date.parse(fields.date)))throw new Error('Choose a valid build date.');
    let group=db.portfolios.find(g=>g.id===fields.groupId), newGroup;
    if(!group){if(fields.groupId && fields.groupId!=='__new__')throw new Error('Selected portfolio no longer exists.');const name=String(fields.portfolioName || '').trim();if(!name)throw new Error('Portfolio name is required.');group=db.portfolios.find(g=>g.name.toLowerCase()===name.toLowerCase());if(!group)group=newGroup={id:id(),name,description:fields.portfolioDescription || '',owner:fields.portfolioOwner || '',products:[]};}
    let product=group.products.find(p=>p.id===fields.productId),newProduct;
    if(!product){if(fields.productId && fields.productId!=='__new__')throw new Error('Selected product does not belong to this portfolio.');const name=String(fields.productName || '').trim();if(!name)throw new Error('Product name is required.');product=group.products.find(p=>p.name.toLowerCase()===name.toLowerCase());if(!product)product=newProduct={id:id(),name,description:fields.productDescription || ''};}
    const clean=Object.fromEntries(['name','stream','release','machine','date','distro','reportScope','sourceName'].filter(k=>typeof fields[k]==='string').map(k=>[k,fields[k]]));
    const scan=newScan(report,{...clean,productId:product.id}); if(attached)scan.sbom=attached;
    if(newGroup)db.portfolios.push(newGroup); if(newProduct)group.products.push(newProduct); db.scans.push(scan);
    return scan;
  }
  function editScan() {
    const s = current();
    modal('Edit scan metadata',`<form id="rwScanMetaForm" class="rw-form">${input('name','Image name',s.name,false,'text',true)}<label>Stream<select name="stream"><option ${s.stream === 'Unassigned' ? 'selected' : ''}>Unassigned</option><option ${s.stream === 'Released' ? 'selected' : ''}>Released</option><option ${s.stream === 'Nightly' ? 'selected' : ''}>Nightly</option></select></label>${[['release','Yocto release'],['machine','Machine'],['distro','Distro'],['pipeline','Pipeline'],['commit','Commit'],['layers','Layer revisions'],['event','History event']].map(([k,label]) => input(k,label,s[k] || '')).join('')}<label>Report scope<select name="reportScope">${['Unspecified','Image-specific','Build-wide'].map(v=>`<option ${s.reportScope===v?'selected':''}>${v}</option>`).join('')}</select></label>${input('date','Build date (optional)',s.buildDateKnown === false ? '' : stamp(s),false,'date',false)}${actions()}</form>`);
  }
  function evidence() { const s = current(); downloadText(`vulntrack-${s.name.replace(/[^a-z0-9_-]/gi,'_')}-evidence.json`,JSON.stringify({schema:'vulntrack-evidence-v1',exportedAt:new Date().toISOString(),policy:reviewPolicy,portfolio:groupFor(s)?.name,product:productFor(s)?.name,scan:s,evaluation:stats(s)},null,2),'application/json'); }
  function newScan(report, fields = {}) {
    if (report!==null && !validReport(report)) throw new Error('Expected a Yocto report with package: [{ name, version, issue }]; every issue must be an object.');
    fields = Object.fromEntries(Object.entries(fields).map(([k,v]) => [k,typeof v === 'string' ? v.trim() : v]).filter(([,v]) => v !== ''));
    const meta = report?.vulntrack || {};
    if(meta.build_time && !Number.isFinite(Date.parse(meta.build_time)))throw new Error('Invalid build_time in report metadata.');
    return { id:id(), productId:fields.productId, stream:fields.stream || 'Unassigned', name:fields.name || meta.image || 'Imported image', release:fields.release || meta.yocto_release || '',machine:fields.machine || meta.machine || '', distro:meta.distro || '',pipeline:meta.pipeline || '',commit:meta.commit || '',layers:meta.layers || '',event:meta.event || '',date:fields.date || meta.build_time || new Date().toISOString(),buildDateKnown:Boolean(fields.date || meta.build_time),importedAt:new Date().toISOString(),order:db.scans.reduce((n,s)=>Math.max(n,s.order || 0),0)+1,report,reviews:{}, ...fields };
  }
  function attachReport(s,report,filename) {
    if(!validReport(report))throw new Error('Choose a valid Yocto CVE report JSON.');
    if(s.report)throw new Error('A CVE report is already attached. Import a new scan to preserve the existing review.');
    s.report=report;s.sourceName=filename;
  }
  function readFile(accept, handler) {
    const file = document.createElement('input'); file.type = 'file'; file.accept = accept;
    file.hidden = true; document.body.append(file);
    file.addEventListener('change',async () => { try { if (file.files[0]) await handler(JSON.parse((await file.files[0].text()).replace(/^\uFEFF/,'')),file.files[0].name); } catch (err) { toast(err.message || 'Invalid JSON file.'); } finally { file.remove(); } });
    file.addEventListener('cancel',() => file.remove()); file.click();
  }
  function readFileList(accept,handler) {
    const input=document.createElement('input');input.type='file';input.accept=accept;input.multiple=true;input.hidden=true;document.body.append(input);
    input.addEventListener('change',async()=>{try{if(input.files.length)await handler([...input.files]);}catch(err){toast(err.message || 'Could not attach SBOM.');}finally{input.remove();}});
    input.addEventListener('cancel',()=>input.remove());input.click();
  }
  function importVex(doc) {
    if (!Array.isArray(doc?.statements)) throw new Error('Expected OpenVEX statements.');
    const fs = facts(current()), decisions = []; let invalid = 0;
    for (const statement of doc.statements) {
      const cve = statement.vulnerability?.name || statement.vulnerability?.['@id'];
      const products = (statement.products || []).map(p => p['@id']);
      const rationale = statement.impact_statement || statement.action_statement || statement.justification || '';
      if (!['affected','not_affected','fixed','under_investigation'].includes(statement.status) || !String(rationale).trim()) { invalid++; continue; }
      for (const f of fs) {
        const purl = `pkg:generic/${encodeURIComponent(f.pkg)}@${encodeURIComponent(f.version)}`;
        if (f.cve === cve && products.includes(purl)) decisions.push({key:key(f),vex:statement.status,rationale:String(rationale),at:new Date().toISOString()});
      }
    }
    if (!decisions.length) throw new Error('No matching assessments. Match exact pkg:generic/name@version product identifiers and supply an impact/action statement or justification.');
    modal('Review imported VEX',`<p class="rw-description">${decisions.length} matching assessment(s); ${invalid} invalid statement(s) skipped. Apply only after verifying the evidence.</p>${table(['Package / CVE','Assessment','Rationale'],decisions.map(d => `<tr><td>${e(JSON.parse(d.key).join(' / '))}</td><td>${e(d.vex)}</td><td>${e(d.rationale)}</td></tr>`).join(''))}<div class="rw-form-actions"><button class="btn" data-action="close">Cancel</button><button class="btn" id="rwApplyVex">Apply ${decisions.length} assessments</button></div>`);
    document.getElementById('rwApplyVex').onclick = () => { const s = current(); s.reviews ||= {}; for (const d of decisions) {const previous=s.reviews[d.key] || {};recordReview(s,d.key,{cra:previous.cra ?? null,vex:d.vex,rationale:d.rationale,at:d.at});} save(); dialog.close(); renderScan(); };
  }
  function exportVex() {
    const s = current();
    const statements = facts(s).filter(f => f.review === 'reviewed' && f.vex !== 'unknown').map(f => ({vulnerability:{name:f.cve},products:[{'@id':`pkg:generic/${encodeURIComponent(f.pkg)}@${encodeURIComponent(f.version)}`}],status:f.vex,...(f.vex === 'not_affected' ? {impact_statement:f.rationale} : f.vex === 'affected' ? {action_statement:f.rationale} : {impact_statement:f.rationale}),timestamp:s.reviews[key(f)].at}));
    downloadText('vulntrack.openvex.json',JSON.stringify({'@context':'https://openvex.dev/ns/v0.2.0','@id':`urn:uuid:${id()}`,author:'VulnTrack local review',timestamp:new Date().toISOString(),version:1,statements},null,2),'application/json');
  }
  async function perform(action, targetId) {
    await ready;
    const s = current();
    if (action === 'portfolio') portfolio();
    else if (action === 'group') targetId ? editGroup(targetId) : importDialog(null,false,true);
    else if (action === 'product') importDialog(null,false,false,targetId);
    else if (action === 'edit-product') editProduct(null,targetId);
    else if (action === 'local-report') {
      const response = await fetch('cve-summary.json',{cache:'no-store'});
      if (!response.ok) throw new Error('Could not read cve-summary.json from this folder. Use Import scan and choose the file instead.');
      const report = await response.json();
      if (!validReport(report)) throw new Error('Expected a valid Yocto cve-summary.json report.');
      prepareReport(report,'cve-summary.json');
    }
    else if (action === 'collapse-group') { const g = db.portfolios.find(g => g.id === targetId); g.collapsed = !g.collapsed; save(); portfolio(); }
    else if (action === 'collapse-product') { const p = db.portfolios.flatMap(g => g.products).find(p => p.id === targetId); p.collapsed = !p.collapsed; save(); portfolio(); }
    else if (action === 'scan' || action === 'history') openScan(targetId,action === 'history' ? 'history' : 'overview');
    else if (action === 'view' || action === 'findings') { view = action === 'findings' ? 'findings' : targetId; renderScan(); }
    else if (action === 'import' || action === 'rescan') importDialog(targetId,action === 'rescan');
    else if (action === 'scan-meta') editScan();
    else if (action === 'close') dialog.close();
    else if (action === 'backup') downloadText('vulntrack-workspace.json',JSON.stringify(db,null,2),'application/json');
    else if (action === 'restore') readFile('.json',data => {
      if (!validWorkspace(data)) throw new Error('Invalid workspace backup. Nothing was changed.');
      modal('Restore workspace',`<p class="rw-description">Replace this browser workspace with ${data.portfolios.length} portfolio(s) and ${data.scans.length} scan(s)? Export your current workspace first if you need to keep it.</p><div class="rw-form-actions"><button class="btn" data-action="close">Cancel</button><button class="btn" id="rwRestore">Restore workspace</button></div>`);
      document.getElementById('rwRestore').onclick = async () => { db = removeSamples(data); await save(); dialog.close(); portfolio(); };
    });
    else if (action === 'open-inventory')openScan(targetId,'sbom');
    else if (action === 'attach-cve') {
      readFile('.json',async(report,filename)=>{if(!validReport(report))throw new Error('Choose a valid Yocto CVE report JSON.');if(current()?.id!==s.id)throw new Error('Reopen the intended build before adding its CVE report.');attachReport(s,report,filename);await save();view='overview';query='';renderScan();});
    }
    else if (action === 'policy') policyHelp();
    else if (action === 'priority-findings') {view='findings';query='';findingLimit=200;findingFilter=s?stats(s).blockers.length?'blocker':stats(s).triage.length?'review':'open':'open';renderScan();}
    else if (action === 'evidence') evidence();
    else if (action === 'vex-import') {if(!s.report)throw new Error('Add a CVE report before importing VEX assessments.');readFile('.json',importVex);}
    else if (action === 'vex-export') exportVex();
    else if (action === 'delete-scan') {
      modal('Delete scan',`<p>Delete ${e(s.name)} (${stamp(s)}) and its local review decisions?</p><div class="rw-form-actions"><button class="btn" data-action="close">Cancel</button><button class="btn rw-danger" id="rwDelete">Delete this scan</button></div>`);
      document.getElementById('rwDelete').onclick = () => { db.scans = db.scans.filter(x => x.id !== s.id); save(); dialog.close(); portfolio(); };
    } else if (action === 'attach-sbom') {
      readFileList('.json,.tar,.zst,.tar.zst,.tar.gz,.tgz',async files=>{const attached=await readAttachedSbom(files);if(current()?.id!==s.id)throw new Error('Reopen the intended scan before attaching its SBOM.');s.sbom=attached;await save();view='sbom';query='';renderScan();});
    } else if (action === 'report-export') { if(!s.report)throw new Error('No CVE report to export.');buildFromYocto(s.report); setTab('releases'); window.VulnTrackReportExporter.exportReport(targetId,{yocto:s.report,rows,pkgIndex}); }
    else if (action === 'component-findings') { dialog.close();query=targetId;view='findings';findingFilter='all';findingLimit=200;renderScan(); }
    else if (action === 'more-findings') { findingLimit+=200;renderFindings(); }
    else if (action === 'range') { range = Number(targetId); renderHistory(); }
    else if (action === 'metric') { metric = targetId; renderHistory(); }
    else if (action === 'compare') { compare = compare.length === 1 ? [compare[0],targetId] : [targetId]; if (compare.length === 2) { view = 'delta'; renderScan(); } else renderHistory(); }
    else if (action === 'sort') { descending = sort === targetId ? !descending : targetId === 'cves' || targetId === 'severity'; sort = targetId; renderComponents(); }
    else if (action === 'columns') modal('Visible component columns',`<form id="rwColumnsForm" class="rw-form">${[['name','Component'],['version','Version'],['recipe','Recipe'],['layer','Layer'],['cves','CVEs'],['severity','Severity'],['review','Review'],['fix','Top fix hint']].map(([v,label]) => `<label><span><input type="checkbox" name="column" value="${v}" ${(s.columns || ['name','version','recipe','layer','cves','severity','review','fix']).includes(v) ? 'checked' : ''} ${v === 'name' ? 'disabled' : ''}> ${label}</span></label>`).join('')}${actions()}</form>`);
    else if (action === 'scenario') modal('Upgrade scenarios',`<form id="rwScenarioForm" class="rw-form"><p class="rw-description wide">Provide explicit package/CVE pairs covered by each upgrade. Set cumulative to true to include fixes from earlier scenarios. Preview changes only the hypothetical gate.</p><label class="wide">Scenarios JSON<textarea name="scenarios" required style="min-height:250px" class="mono">${e(JSON.stringify(metadata(s).upgrade_scenarios || [],null,2))}</textarea></label>${actions()}</form>`);
  }
  function click(event) {
    const action = event.target.closest('[data-action]');
    if (action) { perform(action.dataset.action,action.dataset.id).catch(err => toast(err.message)); return; }
    const component = event.target.closest('[data-component]'); if (component) componentDetail(Number(component.dataset.component));
    const bomRow=event.target.closest('[data-bom-id]');if(bomRow)sbomDetail(bomRow.dataset.bomId);
    const finding = event.target.closest('[data-finding]'); if (finding) findingDetail(finding.dataset.finding);
  }
  root.addEventListener('click',click); dialog.addEventListener('click',click);
  for (const area of [root,dialog]) area.addEventListener('keydown',event => {
    if (['Enter',' '].includes(event.key) && event.target.matches('tr[data-component],tr[data-finding],tr[data-bom-id],g[data-action]')) { event.preventDefault(); event.target.dispatchEvent(new MouseEvent('click',{bubbles:true})); }
  });
  root.addEventListener('input',event => { if (event.target.id === 'rwSearch') { query = event.target.value; findingLimit=200; view === 'components' ? renderComponents() : view==='sbom' ? renderScanSbom() : renderFindings(); if(view==='sbom'){const input=document.getElementById('rwSearch');input.focus();input.setSelectionRange(query.length,query.length);} } });
  root.addEventListener('change',event => {
    const t = event.target;
    if (t.id === 'rwScanSelect') { selected = t.value; compare = []; renderScan(); }
    if (t.id === 'rwFindingFilter') { findingFilter = t.value; findingLimit=200; renderFindings(); }
    if (t.id === 'rwDeltaFrom' || t.id === 'rwDeltaTo') { compare = [document.getElementById('rwDeltaFrom').value,document.getElementById('rwDeltaTo').value]; renderDelta(); }
  });
  dialog.addEventListener('change',event=>{
    if(event.target.name==='riskResponse'){const fields=document.getElementById('rwAcceptance');fields.hidden=event.target.value!=='accept';fields.disabled=fields.hidden;}
    if(event.target.id==='rwImportGroup')updateImportFields(true);
    if(event.target.id==='rwImportProduct')updateImportFields();
    if(['report','sbom'].includes(event.target.name) && event.target.files?.[0]){const input=dialog.querySelector('[name="name"]');if(!input.value)input.value=event.target.files[0].name.replace(/(?:\.rootfs)?\.json$|\.spdx\.(?:tar(?:\.(?:gz|zst))?|json)$|\.tar(?:\.(?:gz|zst))?$/i,'');}
  });
  dialog.addEventListener('submit',async event => {
    event.preventDefault(); if(busy)return; const form = event.target, formId = form.getAttribute('id'), data = new FormData(form), v = Object.fromEntries(data), s = current();
    if(loadFailed){toast('Reload to recover the saved workspace before making changes.');return;}
    busy=true; const submit=form.querySelector?.('[type="submit"]');if(submit)submit.disabled=true;
    try {
      if (formId === 'rwGroupForm') {
        if (!v.name.trim()) throw new Error('Portfolio name is required.');
        const g = db.portfolios.find(x => x.id === v.id); if (g) Object.assign(g,{name:v.name.trim(),description:v.description,owner:v.owner}); else db.portfolios.push({id:id(),name:v.name.trim(),description:v.description,owner:v.owner,products:[]});
      } else if (formId === 'rwProductForm') {
        if (!v.name.trim()) throw new Error('Product name is required.');
        const p = db.portfolios.flatMap(g => g.products).find(x => x.id === v.id); if (p) Object.assign(p,{name:v.name.trim(),description:v.description}); else db.portfolios.find(g => g.id === v.groupId).products.push({id:id(),name:v.name.trim(),description:v.description});
      } else if (formId === 'rwImportForm') {
        const status=document.getElementById('rwImportStatus');status.hidden=false;status.textContent='Reading and validating build files…';await nextPaint();
        const file=data.get('report'),report=pendingReport || (file?.size?JSON.parse((await file.text()).replace(/^\uFEFF/,'')):null);
        if(report!==null && !validReport(report))throw new Error('Invalid Yocto CVE report.');
        const metadataFile=data.get('buildMetadata');
        if(metadataFile?.size){const metadata=buildMetadataFields(JSON.parse(await metadataFile.text()));for(const [k,value]of Object.entries(metadata))if(!v[k])v[k]=value;}
        const attached=await readAttachedSbom(data.getAll('sbom').filter(file=>file?.size));
        const imported=commitImport(report,{...v,sourceName:pendingReport?pendingReportName:report?file.name:''},attached);
        selected=imported.id;view=attached?'sbom':'overview';query='';compare=[];
      } else if (formId === 'rwScanMetaForm') { if (!v.name.trim()) throw new Error('Image name is required.'); Object.assign(s,{...v,date:v.date || s.importedAt || s.date,buildDateKnown:Boolean(v.date)}); }
      else if (formId === 'rwReviewForm') {
        const finding=facts(s).find(f=>key(f)===v.findingKey);if(!finding)throw new Error('Finding no longer exists.');
        recordReview(s,v.findingKey,reviewDecision(finding,v));
      } else if (formId === 'rwColumnsForm') s.columns = ['name',...data.getAll('column').filter(c => c !== 'name')];
      else if (formId === 'rwScenarioForm') {
        const paths = JSON.parse(v.scenarios);
        if (!Array.isArray(paths) || paths.some(x => !x || typeof x.title !== 'string' || !Array.isArray(x.fixes) || x.fixes.some(f => !f || typeof f.package !== 'string' || typeof f.cve !== 'string'))) throw new Error('Each scenario requires title and fixes: [{package, cve}].');
        s.report.vulntrack ||= {}; s.report.vulntrack.upgrade_scenarios = paths;
      }
      await save(); pendingReport = null; dialog.close(); if (selected) { setTab('releases'); renderScan(); } else portfolio();
    } catch (err) { toast(err.message || 'Unable to save changes.'); } finally {busy=false;if(submit)submit.disabled=false;}
  });
  async function prepareReport(report,filename) {
    await ready;
    if (!validReport(report)) throw new Error('Expected a valid Yocto cve-summary.json report.');
    importDialog(); pendingReport = report; pendingReportName=filename;
    const fileInput = dialog.querySelector('[name="report"]');
    fileInput.required = false; fileInput.closest('label').hidden = true;
    const note = document.createElement('div'); note.className = 'rw-note wide';
    note.textContent = `Loaded ${filename}: ${report.package.length} reported components. Enter your actual product and image/build metadata below; missing fields remain unknown. This can be a build-wide report containing native tools, rather than a shipped-image inventory.`;
    document.getElementById('rwImportForm').prepend(note);
    const nameInput=dialog.querySelector('[name="name"]');if(!nameInput.value)nameInput.value=filename.replace(/(?:\.rootfs)?\.json$/i,'');
  }
  function resetWorkspace() {
    db = {version:1,portfolios:[],scans:[]}; selected = ''; compare = []; query = ''; pendingReport = null;
    if (dialog.open) dialog.close();
    save(); portfolio(); setTab('releases');
  }
  document.getElementById('resetBtn').addEventListener('click',resetWorkspace);
  document.getElementById('rwImportScan').onclick = async () => {await ready;importDialog();};
  document.querySelector('[data-page="releases"]').addEventListener('click',portfolio);
  document.querySelector('[data-page="releases"]').addEventListener('keydown',event => { if (event.key === 'Enter' || event.key === ' ') portfolio(); });
  document.querySelectorAll('.tab:not([data-page="releases"])').forEach(tab => {
    const syncAnalysis = () => { const s = current(); if (s?.report && yocto !== s.report) { buildFromYocto(s.report); document.getElementById('reportTitle').textContent = `VulnTrack · ${s.name}`; } };
    tab.addEventListener('click',syncAnalysis);
    tab.addEventListener('keydown',event => { if (event.key === 'Enter' || event.key === ' ') syncAnalysis(); });
  });
  window.VulnTrackWorkspace = {
    capture:prepareReport,
    // Pure calculations are also used by the standalone regression check.
    facts, stats, deltaData, validWorkspace, scenarios, removeSamples, metricValues, versionKey, matchComponent, sbomIntegrity, commitImport, buildMetadataFields, validSbom, attachReport, disposition, reviewDecision, validAcceptance, policy:reviewPolicy
  };
  function refreshAtUtcMidnight() {
    const next=new Date();next.setUTCHours(24,0,0,50);
    setTimeout(()=>{selected?renderScan():portfolio();refreshAtUtcMidnight();},next.getTime()-Date.now());
  }
  ready=initialize();
  refreshAtUtcMidnight();
})();
