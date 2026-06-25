(function(){
  "use strict";

  const SEVERITIES = ["Critical", "High", "Medium", "Low", "None"];
  const REPO_URL = "https://github.com/prashantdivate/VulnTrack";
  const MAINTAINER = "Prashant Divate";
  const REPORT_TITLE = "VulnTrack Vulnerability Assessment";

  function esc(s){
    return String(s ?? "").replace(/[&<>"]/g, c=>({
      "&":"&amp;",
      "<":"&lt;",
      ">":"&gt;",
      '"':"&quot;"
    }[c]));
  }

  function toNum(x){
    const n = Number(String(x ?? "").trim());
    return Number.isFinite(n) ? n : 0;
  }

  function downloadText(filename, text, type="text/plain;charset=utf-8"){
    const blob = new Blob([text], {type});
    downloadBlob(filename, blob);
  }

  function downloadBlob(filename, blob){
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function pdfSafeText(s){
    return String(s ?? "")
      .replace(/[^\x20-\x7E]/g, " ")
      .replace(/\\/g, "\\\\")
      .replace(/\(/g, "\\(")
      .replace(/\)/g, "\\)")
      .trim();
  }

  function hexToRgb(hex){
    const clean = String(hex).replace("#", "");
    return [
      parseInt(clean.slice(0, 2), 16) / 255,
      parseInt(clean.slice(2, 4), 16) / 255,
      parseInt(clean.slice(4, 6), 16) / 255
    ];
  }

  function truncateText(s, max){
    const text = String(s ?? "");
    return text.length > max ? text.slice(0, Math.max(0, max - 3)) + "..." : text;
  }

  function wrapText(s, maxChars, maxLines=3){
    const words = String(s ?? "").replace(/\s+/g, " ").trim().split(" ").filter(Boolean);
    const lines = [];
    let line = "";
    for (const word of words){
      const next = line ? `${line} ${word}` : word;
      if (next.length > maxChars && line){
        lines.push(line);
        line = word;
      } else {
        line = next;
      }
      if (lines.length === maxLines) break;
    }
    if (line && lines.length < maxLines) lines.push(line);
    if (words.length && lines.join(" ").length < words.join(" ").length && lines.length){
      lines[lines.length - 1] = truncateText(lines[lines.length - 1], Math.max(3, maxChars));
    }
    return lines.length ? lines : ["-"];
  }

  class PdfPage {
    constructor(width, height){
      this.width = width;
      this.height = height;
      this.parts = [];
    }

    y(top){
      return this.height - top;
    }

    color(hex, stroke=false){
      const [r,g,b] = hexToRgb(hex);
      this.parts.push(`${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} ${stroke ? "RG" : "rg"}`);
    }

    rect(x, y, w, h, fill="#ffffff"){
      this.color(fill);
      this.parts.push(`${x.toFixed(2)} ${(this.y(y) - h).toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re f`);
    }

    strokedRect(x, y, w, h, fill="#ffffff", stroke="#dfe5ef"){
      this.color(fill);
      this.parts.push(`${x.toFixed(2)} ${(this.y(y) - h).toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re f`);
      this.color(stroke, true);
      this.parts.push(`0.75 w ${x.toFixed(2)} ${(this.y(y) - h).toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re S`);
    }

    text(x, y, text, size=10, color="#172033", bold=false){
      this.color(color);
      this.parts.push(`BT /F1 ${size} Tf ${bold ? "0.20 Tc" : "0 Tc"} ${x.toFixed(2)} ${this.y(y).toFixed(2)} Td (${pdfSafeText(text)}) Tj ET`);
    }

    line(x1, y1, x2, y2, color="#dfe5ef", width=0.75){
      this.color(color, true);
      this.parts.push(`${width} w ${x1.toFixed(2)} ${this.y(y1).toFixed(2)} m ${x2.toFixed(2)} ${this.y(y2).toFixed(2)} l S`);
    }

    polygon(points, fill){
      if (points.length < 3) return;
      this.color(fill);
      const [first, ...rest] = points;
      const body = rest.map(([x,y])=>`${x.toFixed(2)} ${this.y(y).toFixed(2)} l`).join(" ");
      this.parts.push(`${first[0].toFixed(2)} ${this.y(first[1]).toFixed(2)} m ${body} h f`);
    }

    stream(){
      return this.parts.join("\n");
    }
  }

  class PdfDoc {
    constructor(){
      this.width = 612;
      this.height = 792;
      this.pages = [];
    }

    addPage(){
      const page = new PdfPage(this.width, this.height);
      this.pages.push(page);
      return page;
    }

    build(){
      const objects = [];
      objects[1] = "<< /Type /Catalog /Pages 2 0 R >>";
      objects[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";

      const kids = [];
      this.pages.forEach((page, index)=>{
        const pageObj = 4 + index * 2;
        const contentObj = pageObj + 1;
        kids.push(`${pageObj} 0 R`);
        const stream = page.stream();
        objects[pageObj] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${this.width} ${this.height}] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentObj} 0 R >>`;
        objects[contentObj] = `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`;
      });
      objects[2] = `<< /Type /Pages /Kids [${kids.join(" ")}] /Count ${this.pages.length} >>`;

      let pdf = "%PDF-1.4\n";
      const offsets = [0];
      for (let i = 1; i < objects.length; i++){
        offsets[i] = pdf.length;
        pdf += `${i} 0 obj\n${objects[i]}\nendobj\n`;
      }
      const xref = pdf.length;
      pdf += `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
      for (let i = 1; i < objects.length; i++){
        pdf += `${String(offsets[i]).padStart(10, "0")} 00000 n \n`;
      }
      pdf += `trailer\n<< /Size ${objects.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
      return new Blob([pdf], {type:"application/pdf"});
    }
  }

  function fileBase(){
    return `vulntrack-vulnerability-report-${new Date().toISOString().slice(0,19).replace(/[:T]/g, "-")}`;
  }

  function severityColor(sev){
    switch(sev){
      case "Critical": return "#ff5878";
      case "High": return "#ffaa50";
      case "Medium": return "#78c8ff";
      case "Low": return "#8cffb4";
      default: return "#b8c0cc";
    }
  }

  function scoreColor(score){
    const s = toNum(score);
    if (s >= 9) return "#dc2626";
    if (s >= 7) return "#ea580c";
    if (s >= 4) return "#d97706";
    if (s > 0) return "#16a34a";
    return "#64748b";
  }

  function scoreLabel(score){
    const s = toNum(score);
    return s ? s.toFixed(1) : "-";
  }

  function scorePill(score){
    const label = scoreLabel(score);
    return `<span class="scorePill" style="background:${scoreColor(score)}">${esc(label)}</span>`;
  }

  function htmlIcon(type){
    const paths = {
      shield: `<path d="M12 3l7 3v5c0 4.5-2.8 8.4-7 10-4.2-1.6-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-5"/>`,
      package: `<path d="M21 8l-9-5-9 5 9 5 9-5z"/><path d="M3 8v8l9 5 9-5V8"/><path d="M12 13v8"/>`,
      stack: `<path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 12l9 5 9-5"/><path d="M3 16l9 5 9-5"/>`,
      issue: `<path d="M12 3l8 4v5c0 4-3 7.5-8 9-5-1.5-8-5-8-9V7l8-4z"/><path d="M12 8v5"/><path d="M12 16h.01"/>`,
      eye: `<path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6z"/><circle cx="12" cy="12" r="3"/>`
    };
    return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[type] || paths.shield}</svg>`;
  }

  function severityRank(sev){
    return {Critical:4, High:3, Medium:2, Low:1, None:0}[sev] ?? 0;
  }

  function rowRiskScore(r){
    return severityRank(r.sev) * 100 + Math.max(toNum(r.scorev3), toNum(r.scorev2));
  }

  function worstPackageStatus(p){
    if (p.unpatched) return "Unpatched";
    if (p.ignored) return "Ignored";
    if (p.patched) return "Patched";
    return "-";
  }

  function topRiskRows(rows, limit=12){
    return [...rows].sort((a,b)=>rowRiskScore(b)-rowRiskScore(a)).slice(0, limit);
  }

  function topRiskPackages(pkgIndex, limit=12){
    const rank = (p)=>(
      p.sevCounts.Critical * 100000 +
      p.sevCounts.High * 10000 +
      p.sevCounts.Medium * 1000 +
      p.total
    );
    return [...pkgIndex].sort((a,b)=>rank(b)-rank(a)).slice(0, limit);
  }

  function rankedPackages(pkgIndex){
    const rank = (p)=>(
      p.sevCounts.Critical * 100000 +
      p.sevCounts.High * 10000 +
      p.sevCounts.Medium * 1000 +
      p.total
    );
    return [...pkgIndex].sort((a,b)=>rank(b)-rank(a));
  }

  function rankedIssues(rows){
    return [...rows].sort((a,b)=>rowRiskScore(b)-rowRiskScore(a));
  }

  function reportStats(yocto, rows){
    const statusLabels = ["Unpatched", "Ignored", "Patched"];
    const severityCounts = Object.fromEntries(SEVERITIES.map(k=>[k, 0]));
    const statusCounts = Object.fromEntries(statusLabels.map(k=>[k, 0]));
    const vectorCounts = {};
    let maxCvss3 = 0;
    let maxCvss2 = 0;

    for (const r of rows){
      severityCounts[r.sev] = (severityCounts[r.sev] || 0) + 1;
      if (r.status in statusCounts) statusCounts[r.status]++;
      const s3 = toNum(r.scorev3);
      const s2 = toNum(r.scorev2);
      if (s3 > maxCvss3) maxCvss3 = s3;
      if (s2 > maxCvss2) maxCvss2 = s2;
      if (r.vector) vectorCounts[r.vector] = (vectorCounts[r.vector] || 0) + 1;
    }

    return {
      generatedAt: new Date().toISOString(),
      schemaVersion: yocto?.version ?? "-",
      packageCount: yocto?.package?.length || 0,
      affectedPackages: new Set(rows.map(r=>r.pkg)).size,
      totalIssues: rows.length,
      uniqueCves: new Set(rows.map(r=>r.cve)).size,
      openIssues: rows.filter(r=>r.status === "Unpatched" || r.status === "Ignored").length,
      maxCvss3,
      maxCvss2,
      commonVector: Object.entries(vectorCounts).sort((a,b)=>b[1]-a[1])[0]?.[0] || "-",
      severityCounts,
      statusCounts
    };
  }

  function riskPosture(stats){
    if ((stats.severityCounts.Critical || 0) > 0 || (stats.statusCounts.Unpatched || 0) > 0) return "Action Required";
    if ((stats.severityCounts.High || 0) > 0 || (stats.statusCounts.Ignored || 0) > 0) return "Needs Review";
    if (stats.totalIssues > 0) return "Monitored";
    return "No CVEs Reported";
  }

  function executiveSummary(stats){
    if (!stats.totalIssues){
      return "The uploaded Yocto CVE report was parsed successfully and no CVE issues were found in the provided data. Continue validating build coverage and regenerate this report after layer or recipe changes.";
    }
    return `The report identifies ${stats.totalIssues.toLocaleString()} CVE issue records across ${stats.affectedPackages.toLocaleString()} affected packages, including ${(stats.severityCounts.Critical || 0).toLocaleString()} critical and ${(stats.severityCounts.High || 0).toLocaleString()} high severity findings. ${stats.openIssues.toLocaleString()} findings are currently unpatched or ignored and should be reviewed before release.`;
  }

  function recommendedActions(stats){
    const actions = [];
    if ((stats.severityCounts.Critical || 0) > 0) actions.push("Prioritize Critical findings for immediate triage and patch validation.");
    if ((stats.statusCounts.Unpatched || 0) > 0) actions.push("Resolve Unpatched issues through recipe upgrades or backported patches, then rerun Yocto CVE checks.");
    if ((stats.statusCounts.Ignored || 0) > 0) actions.push("Review Ignored findings and ensure each exception has a documented, approved justification.");
    actions.push("Confirm affected packages are included in the deployed image and reachable at runtime.");
    actions.push("Rebuild and regenerate this report after remediation to verify status changes.");
    return actions.slice(0, 5);
  }

  function htmlBarChart(items, color="#78c8ff"){
    const max = Math.max(1, ...items.map(x=>x.value));
    const height = Math.max(150, items.length * 30 + 28);
    const rowsSvg = items.map((item, i)=>{
      const y = 22 + i * 30;
      const width = Math.round((item.value / max) * 310);
      const label = String(item.label || "-").length > 30 ? String(item.label).slice(0, 29) + "..." : String(item.label || "-");
      return `
        <text x="12" y="${y + 14}" fill="#c7d2e6" font-size="11">${esc(label)}</text>
        <rect x="160" y="${y}" width="310" height="16" rx="8" fill="#172033"></rect>
        <rect x="160" y="${y}" width="${width}" height="16" rx="8" fill="${color}"></rect>
        <text x="482" y="${y + 13}" fill="#f5f7fb" font-size="11" font-weight="700">${item.value}</text>
      `;
    }).join("");
    return `<svg class="reportSvg" viewBox="0 0 530 ${height}" role="img" aria-label="Bar chart">${rowsSvg}</svg>`;
  }

  function conicForCounts(counts, labels){
    const total = labels.reduce((sum, label)=>sum + (counts[label] || 0), 0);
    if (!total) return "#2a3448";
    let cursor = 0;
    return `conic-gradient(${labels.map(label=>{
      const start = cursor;
      const end = cursor + ((counts[label] || 0) / total) * 100;
      cursor = end;
      return `${severityColor(label)} ${start.toFixed(2)}% ${end.toFixed(2)}%`;
    }).join(", ")})`;
  }

  function mdBar(value, max){
    const size = max ? Math.max(0, Math.round((value / max) * 24)) : 0;
    return "#".repeat(size) || "-";
  }

  function buildHtmlReport(ctx){
    const { yocto, rows, pkgIndex } = ctx;
    const stats = reportStats(yocto, rows);
    const issueRows = rankedIssues(rows);
    const packageRows = rankedPackages(pkgIndex);
    const topRows = issueRows.slice(0, 12);
    const topPkgs = packageRows.slice(0, 10);
    const remediationRows = issueRows.filter(r=>r.status === "Unpatched" || r.status === "Ignored").slice(0, 10);
    const pkgChartItems = topPkgs.slice(0, 8).map(p=>({label:p.name, value:p.total}));
    const sevChartItems = SEVERITIES.map(label=>({label, value:stats.severityCounts[label] || 0}));
    const statusChartItems = ["Unpatched","Ignored","Patched"].map(label=>({label, value:stats.statusCounts[label] || 0}));
    const posture = riskPosture(stats);
    const summary = executiveSummary(stats);
    const actionItems = recommendedActions(stats);

    const cveTable = topRows.length ? topRows.map(r=>`
      <tr>
        <td><strong>${esc(r.cve)}</strong></td>
        <td><span class="pill" style="border-color:${severityColor(r.sev)}66;color:${severityColor(r.sev)}">${esc(r.sev)}</span></td>
        <td>${esc(r.pkg)}</td>
        <td>${esc(r.status || "-")}</td>
        <td>${scorePill(Math.max(toNum(r.scorev3), toNum(r.scorev2)))}</td>
        <td>${esc(r.summary || "-")}</td>
      </tr>
    `).join("") : `<tr><td colspan="6">No CVE issues found in the parsed JSON.</td></tr>`;

    const pkgTable = topPkgs.length ? topPkgs.map(p=>`
      <tr>
        <td><strong>${esc(p.name)}</strong></td>
        <td>${esc(p.version || "-")}</td>
        <td>${esc(p.layer || "-")}</td>
        <td>${p.total}</td>
        <td>${p.sevCounts.Critical}</td>
        <td>${p.sevCounts.High}</td>
        <td>${esc(worstPackageStatus(p))}</td>
      </tr>
    `).join("") : `<tr><td colspan="7">No affected packages found.</td></tr>`;

    const remediationTable = remediationRows.length ? remediationRows.map(r=>`
      <tr>
        <td><strong>${esc(r.cve)}</strong></td>
        <td>${esc(r.pkg)}</td>
        <td>${esc(r.pkgVersion || "-")}</td>
        <td>${esc(r.layer || "-")}</td>
        <td>${esc(r.status || "-")}</td>
        <td>${esc(r.summary || "-")}</td>
      </tr>
    `).join("") : `<tr><td colspan="6">No unpatched or ignored issues found.</td></tr>`;

    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${REPORT_TITLE}</title>
  <style>
    :root{color-scheme:light;--ink:#111827;--muted:#667085;--line:#e4e7ec;--soft:#f8fafc;--brand:#101828;--accent:#2563eb}
    *{box-sizing:border-box}
    body{margin:0;font-family:Segoe UI,Arial,sans-serif;color:var(--ink);background:#eef2f7}
    .shell{max-width:1180px;margin:0 auto;padding:30px}
    header{position:relative;overflow:hidden;background:linear-gradient(120deg,#ffffff 0%,#f8fbff 66%,#eef5ff 100%);border:1px solid #cfe0f7;border-radius:6px;padding:24px 28px;box-shadow:0 8px 24px rgba(37,99,235,.07)}
    .hero{display:grid;grid-template-columns:54px 1fr;gap:16px;align-items:center;position:relative;z-index:1}
    .heroIcon{width:44px;height:44px;border-radius:50%;background:linear-gradient(180deg,#3b82f6,#1d4ed8);display:grid;place-items:center;box-shadow:0 10px 18px rgba(37,99,235,.22)}
    .heroIcon svg{width:27px;height:27px;fill:none;stroke:#fff;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}
    .heroWatermark{position:absolute;right:48px;top:18px;width:112px;height:112px;opacity:.13;color:#2563eb}
    .heroWatermark svg{width:100%;height:100%;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
    .heroWatermark:after{content:"";position:absolute;inset:-12px;background:radial-gradient(#2563eb 1px,transparent 1px);background-size:9px 9px;opacity:.38;transform:translate(34px,-4px)}
    .eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:#2563eb;font-weight:900}
    h1{margin:5px 0 0;font-size:30px;letter-spacing:.1px;color:#101828}
    h2{margin:0 0 14px;font-size:18px;color:#101828}
    h3{margin:0 0 10px;font-size:14px;color:#344054}
    .sub{margin-top:8px;color:#475467;font-size:12px;line-height:1.45;display:flex;gap:14px;flex-wrap:wrap}
    .subItem{display:inline-flex;align-items:center;gap:5px}
    .subItem svg{width:12px;height:12px;fill:none;stroke:#667085;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
    .section{margin-top:18px}
    .kpis{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin:10px 0 18px 0}
    .kpi,.card{background:white;border:1px solid var(--line);border-radius:8px;padding:16px;box-shadow:0 8px 20px rgba(16,24,40,.05)}
    .kpi{display:grid;grid-template-columns:34px 1fr;gap:12px;align-items:center;min-height:72px}
    .kpiIcon{width:30px;height:30px;border-radius:8px;display:grid;place-items:center}
    .kpiIcon svg{width:18px;height:18px;fill:none;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}
    .kpiIcon.pkg{background:#eff6ff;color:#2563eb}.kpiIcon.pkg svg{stroke:#2563eb}
    .kpiIcon.aff{background:#ecfdf3;color:#16a34a}.kpiIcon.aff svg{stroke:#16a34a}
    .kpiIcon.issue{background:#fff7ed;color:#f97316}.kpiIcon.issue svg{stroke:#f97316}
    .kpiIcon.open{background:#f5f3ff;color:#7c3aed}.kpiIcon.open svg{stroke:#7c3aed}
    .kpiIcon.risk{background:#eef2ff;color:#4f46e5}.kpiIcon.risk svg{stroke:#4f46e5}
    .kpi .label{font-size:11px;color:var(--muted);font-weight:800;text-transform:uppercase;letter-spacing:.06em}
    .kpi .value{font-size:26px;font-weight:900;margin-top:8px;color:#101828}
    .kpi .hint{margin-top:4px;font-size:11px;color:var(--muted)}
    .summaryGrid{display:grid;grid-template-columns:1.2fr .8fr;gap:16px}
    .summaryText{font-size:14px;line-height:1.58;color:#344054}
    .actionsList{margin:0;padding-left:18px;color:#344054;font-size:13px;line-height:1.55}
    .actionsList li{margin:7px 0}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:18px 0}
    .donutWrap{display:flex;align-items:center;gap:22px;min-height:190px}
    .donut{width:176px;height:176px;border-radius:50%;background:var(--chart);position:relative;flex:0 0 auto;border:1px solid var(--line)}
    .donut:after{content:"";position:absolute;inset:42px;background:white;border-radius:50%;box-shadow:inset 0 0 0 1px var(--line)}
    .legend{display:grid;gap:8px;font-size:13px}
    .legendRow{display:flex;align-items:center;gap:8px}
    .swatch{width:11px;height:11px;border-radius:3px}
    .reportSvg{width:100%;height:auto;border:1px solid var(--line);border-radius:8px;background:#111827}
    .tableWrap{overflow:auto;border:1px solid var(--line);border-radius:8px;background:white}
    table{width:100%;border-collapse:collapse;background:white}
    th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:12px}
    th{background:#f8fafc;color:#475467;font-size:11px;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap}
    tr:nth-child(even) td{background:#fcfcfd}
    .pill{display:inline-flex;border:1px solid;border-radius:999px;padding:3px 8px;font-weight:800;background:#fff}
    .scorePill{display:inline-flex;min-width:42px;justify-content:center;border-radius:999px;padding:4px 9px;color:#fff;font-weight:900;font-size:11px}
    .note{color:var(--muted);font-size:12px;line-height:1.5}
    .posture{display:inline-flex;align-items:center;border:1px solid #bfdbfe;background:#eff6ff;color:#1d4ed8;border-radius:999px;padding:5px 10px;font-size:12px;font-weight:900}
    .toc{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}
    .toc span{font-size:11px;font-weight:800;color:#475467;background:#f8fafc;border:1px solid var(--line);border-radius:999px;padding:6px 10px}
    .break{break-inside:avoid}
    @media (max-width:900px){.kpis,.grid,.summaryGrid,.hero{grid-template-columns:1fr}.heroWatermark{display:none}.shell{padding:14px}}
    @media print{body{background:white}.shell{max-width:none;padding:0}.card,.kpi,header{box-shadow:none}}
  </style>
</head>
<body>
  <div class="shell">
    <header>
      <div class="heroWatermark">${htmlIcon("shield")}</div>
      <div class="hero">
        <div class="heroIcon">${htmlIcon("shield")}</div>
        <div>
          <div class="eyebrow">Yocto CVE Assessment</div>
          <h1>${REPORT_TITLE}</h1>
          <div class="sub">
            <span class="subItem">${htmlIcon("package")} Generated ${esc(new Date(stats.generatedAt).toLocaleString())} from Yocto cve-summary.json. Schema ${esc(stats.schemaVersion)}.</span>
          </div>
          <div class="sub">
            <span class="subItem">${htmlIcon("stack")} Repository: <a href="${REPO_URL}" style="color:#2563eb">${REPO_URL}</a></span>
            <span class="subItem">${htmlIcon("eye")} Maintainer: ${esc(MAINTAINER)}</span>
          </div>
        </div>
      </div>
    </header>
    <div class="toc"><span>Executive Summary</span><span>Risk Distribution</span><span>Priority Findings</span><span>Remediation Focus</span></div>
    <section class="kpis">
      <div class="kpi"><span class="kpiIcon pkg">${htmlIcon("package")}</span><div><div class="label">Packages</div><div class="value">${stats.packageCount.toLocaleString()}</div></div></div>
      <div class="kpi"><span class="kpiIcon aff">${htmlIcon("stack")}</span><div><div class="label">Affected Packages</div><div class="value">${stats.affectedPackages.toLocaleString()}</div></div></div>
      <div class="kpi"><span class="kpiIcon issue">${htmlIcon("issue")}</span><div><div class="label">CVE Issues</div><div class="value">${stats.totalIssues.toLocaleString()}</div></div></div>
      <div class="kpi"><span class="kpiIcon open">${htmlIcon("eye")}</span><div><div class="label">Open / Ignored</div><div class="value">${stats.openIssues.toLocaleString()}</div></div></div>
      <div class="kpi"><span class="kpiIcon risk">${htmlIcon("shield")}</span><div><div class="label">Risk Posture</div><div class="value" style="font-size:18px">${esc(posture)}</div><div class="hint">Derived from severity and status</div></div></div>
    </section>
    <section class="section summaryGrid">
      <article class="card break"><h2>Executive Summary</h2><p class="summaryText">${esc(summary)}</p><span class="posture">${esc(posture)}</span></article>
      <article class="card break"><h2>Recommended Actions</h2><ul class="actionsList">${actionItems.map(item=>`<li>${esc(item)}</li>`).join("")}</ul></article>
    </section>
    <section class="grid">
      <article class="card break"><h2>Severity Infographic</h2><div class="donutWrap"><div class="donut" style="--chart:${conicForCounts(stats.severityCounts, SEVERITIES)}"></div><div class="legend">${SEVERITIES.map(label=>`<div class="legendRow"><span class="swatch" style="background:${severityColor(label)}"></span><strong>${label}</strong> ${stats.severityCounts[label] || 0}</div>`).join("")}</div></div></article>
      <article class="card break"><h2>Status Graph</h2>${htmlBarChart(statusChartItems, "#22c55e")}</article>
      <article class="card break"><h2>Severity Graph</h2>${htmlBarChart(sevChartItems, "#78c8ff")}</article>
      <article class="card break"><h2>Most Vulnerable Packages</h2>${htmlBarChart(pkgChartItems, "#ffaa50")}</article>
    </section>
    <section class="card break"><h2>Risk Snapshot</h2><p class="note">Highest CVSS v3: <strong>${stats.maxCvss3 ? stats.maxCvss3.toFixed(1) : "-"}</strong>. Highest CVSS v2: <strong>${stats.maxCvss2 ? stats.maxCvss2.toFixed(1) : "-"}</strong>. Most common vector: <strong>${esc(stats.commonVector)}</strong>.</p></section>
    <section class="card break"><h2>Top CVEs By Priority</h2><div class="tableWrap"><table><thead><tr><th>CVE</th><th>Severity</th><th>Package</th><th>Status</th><th>CVSS</th><th>Summary</th></tr></thead><tbody>${cveTable}</tbody></table></div></section>
    <section class="card break"><h2>Package Risk Summary</h2><div class="tableWrap"><table><thead><tr><th>Package</th><th>Version</th><th>Layer</th><th>Issues</th><th>Critical</th><th>High</th><th>Worst Status</th></tr></thead><tbody>${pkgTable}</tbody></table></div></section>
    <section class="card break"><h2>Remediation Focus</h2><p class="note">Prioritize Critical and High issues that are Unpatched or Ignored, then validate whether the vulnerable code is shipped and reachable in the final image.</p><div class="tableWrap"><table><thead><tr><th>CVE</th><th>Package</th><th>Version</th><th>Layer</th><th>Status</th><th>Summary</th></tr></thead><tbody>${remediationTable}</tbody></table></div></section>
    <section class="card break"><h2>Report Scope</h2><p class="note">This export intentionally summarizes the highest-risk packages and CVEs. Use the interactive dashboard tabs or JSON/CSV exports for exhaustive row-level exploration.</p></section>
  </div>
</body>
</html>`;
  }

  function buildMarkdownReport(ctx){
    const { yocto, rows, pkgIndex } = ctx;
    const stats = reportStats(yocto, rows);
    const issueRows = rankedIssues(rows);
    const packageRows = rankedPackages(pkgIndex);
    const maxSev = Math.max(1, ...SEVERITIES.map(k=>stats.severityCounts[k] || 0));
    const maxStatus = Math.max(1, ...Object.values(stats.statusCounts));
    const posture = riskPosture(stats);
    const summary = executiveSummary(stats);
    const actions = recommendedActions(stats);
    const lines = [
      "# VulnTrack Vulnerability Report",
      "",
      `Generated: ${stats.generatedAt}`,
      `Schema version: ${stats.schemaVersion}`,
      `Repository: ${REPO_URL}`,
      `Maintainer: ${MAINTAINER}`,
      `Risk posture: ${posture}`,
      "",
      "## Executive Summary",
      "",
      summary,
      "",
      "## Recommended Actions",
      "",
      ...actions.map(action=>`- ${action}`),
      "",
      "## Summary",
      "",
      "| Metric | Value |",
      "| --- | ---: |",
      `| Packages | ${stats.packageCount} |`,
      `| Affected packages | ${stats.affectedPackages} |`,
      `| CVE issues | ${stats.totalIssues} |`,
      `| Unique CVEs | ${stats.uniqueCves} |`,
      `| Open / ignored | ${stats.openIssues} |`,
      `| Highest CVSS v3 | ${stats.maxCvss3 ? stats.maxCvss3.toFixed(1) : "-"} |`,
      "",
      "## Severity Graph",
      ""
    ];
    for (const label of SEVERITIES) lines.push(`- ${label}: ${mdBar(stats.severityCounts[label] || 0, maxSev)} ${stats.severityCounts[label] || 0}`);
    lines.push("", "## Status Graph", "");
    for (const label of ["Unpatched","Ignored","Patched"]) lines.push(`- ${label}: ${mdBar(stats.statusCounts[label] || 0, maxStatus)} ${stats.statusCounts[label] || 0}`);
    lines.push("", "## Top CVEs By Priority", "", "| CVE | Severity | Package | Version | Status | CVSS | Summary |", "| --- | --- | --- | --- | --- | ---: | --- |");
    for (const r of issueRows.slice(0, 20)){
      const score = Math.max(toNum(r.scorev3), toNum(r.scorev2));
      lines.push(`| ${r.cve} | ${r.sev} | ${r.pkg} | ${r.pkgVersion || "-"} | ${r.status || "-"} | ${score || "-"} | ${String(r.summary || "-").replace(/\|/g, "\\|")} |`);
    }
    lines.push("", "## Top Packages", "", "| Package | Version | Layer | Issues | Critical | High | Worst Status |", "| --- | --- | --- | ---: | ---: | ---: | --- |");
    for (const p of packageRows.slice(0, 20)){
      lines.push(`| ${p.name} | ${p.version || "-"} | ${p.layer || "-"} | ${p.total} | ${p.sevCounts.Critical} | ${p.sevCounts.High} | ${worstPackageStatus(p)} |`);
    }
    lines.push("", "## Remediation Notes", "", "- Prioritize Critical and High issues that are Unpatched or Ignored.", "- Confirm whether each vulnerable package is shipped in the final image and reachable at runtime.", "- Prefer package or recipe upgrades; backport patches when upgrades are risky.", "- Re-run Yocto CVE checks after fixes and keep ignored CVEs justified.");
    lines.push("", "## Report Scope", "", "This export intentionally summarizes the highest-risk packages and CVEs. Use the interactive dashboard tabs or JSON/CSV exports for exhaustive row-level exploration.");
    return lines.join("\n");
  }

  function buildJsonSummary(ctx){
    const { yocto, rows, pkgIndex } = ctx;
    return JSON.stringify({
      tool: "VulnTrack",
      report: reportStats(yocto, rows),
      topCves: topRiskRows(rows, 25),
      topPackages: topRiskPackages(pkgIndex, 25).map(p=>({...p, worstStatus: worstPackageStatus(p)})),
      issues: rows
    }, null, 2);
  }

  function drawCard(page, x, y, w, h, title){
    page.strokedRect(x, y, w, h, "#ffffff", "#dfe5ef");
    page.text(x + 12, y + 22, title, 13, "#08152c", true);
  }

  function drawWrappedText(page, x, y, text, maxChars, options={}){
    const size = options.size ?? 8.5;
    const color = options.color ?? "#344054";
    const lineH = options.lineH ?? 11;
    const maxLines = options.maxLines ?? 5;
    const lines = wrapText(text, maxChars, maxLines);
    lines.forEach((line, i)=>page.text(x, y + i * lineH, line, size, color, options.bold ?? false));
    return y + lines.length * lineH;
  }

  function drawPdfSectionTitle(page, y, title, subtitle=""){
    page.text(42, y, title, 17, "#08152c", true);
    if (subtitle) page.text(42, y + 17, subtitle, 8.5, "#667085");
  }

  function shieldPoints(cx, cy, scale=1){
    return [
      [cx, cy - 18 * scale],
      [cx + 16 * scale, cy - 11 * scale],
      [cx + 13 * scale, cy + 10 * scale],
      [cx, cy + 22 * scale],
      [cx - 13 * scale, cy + 10 * scale],
      [cx - 16 * scale, cy - 11 * scale]
    ];
  }

  function drawShieldIcon(page, cx, cy, scale=1, fill="#2563eb", stroke="#ffffff"){
    page.polygon(shieldPoints(cx, cy, scale), fill);
    page.line(cx - 6 * scale, cy, cx - 1 * scale, cy + 5 * scale, stroke, 1.5);
    page.line(cx - 1 * scale, cy + 5 * scale, cx + 8 * scale, cy - 7 * scale, stroke, 1.5);
  }

  function drawKpiIcon(page, x, y, color, type){
    page.rect(x, y, 24, 24, "#f8fafc");
    page.strokedRect(x, y, 24, 24, "#f8fafc", "#e4e7ec");
    if (type === "shield"){
      drawShieldIcon(page, x + 12, y + 12, .42, color, "#ffffff");
    } else if (type === "eye"){
      page.line(x + 6, y + 12, x + 12, y + 7, color, 1.1);
      page.line(x + 12, y + 7, x + 18, y + 12, color, 1.1);
      page.line(x + 18, y + 12, x + 12, y + 17, color, 1.1);
      page.line(x + 12, y + 17, x + 6, y + 12, color, 1.1);
      page.rect(x + 10, y + 10, 4, 4, color);
    } else {
      page.rect(x + 8, y + 8, 8, 8, color);
      page.line(x + 8, y + 8, x + 12, y + 5, color, 1.1);
      page.line(x + 16, y + 8, x + 12, y + 5, color, 1.1);
      page.line(x + 16, y + 16, x + 12, y + 19, color, 1.1);
      page.line(x + 8, y + 16, x + 12, y + 19, color, 1.1);
    }
  }

  function drawPdfScorePill(page, x, y, score){
    const label = scoreLabel(score);
    const fill = scoreColor(score);
    page.rect(x, y - 10, 34, 14, fill);
    page.text(x + 8, y, label, 7.2, "#ffffff", true);
  }

  function drawPriorityCards(page, rows, startY){
    const cardW = 255;
    const cardH = 76;
    rows.slice(0, 6).forEach((r, i)=>{
      const col = i % 2;
      const row = Math.floor(i / 2);
      const x = 42 + col * 273;
      const y = startY + row * 88;
      const score = Math.max(toNum(r.scorev3), toNum(r.scorev2));
      page.strokedRect(x, y, cardW, cardH, "#ffffff", "#dfe5ef");
      page.text(x + 12, y + 20, r.cve, 10, "#101828", true);
      drawPdfScorePill(page, x + cardW - 50, y + 20, score);
      page.text(x + 12, y + 38, `${r.sev} / ${r.status || "-"}`, 8, severityColor(r.sev), true);
      page.text(x + 12, y + 53, truncateText(r.pkg, 32), 7.8, "#475467");
      drawWrappedText(page, x + 12, y + 67, r.summary || "-", 44, {size:6.6, lineH:8, maxLines:1});
    });
  }

  function drawDonut(page, cx, cy, outer, inner, counts){
    const total = SEVERITIES.reduce((sum, sev)=>sum + (counts[sev] || 0), 0);
    if (!total){
      page.polygon(circlePoints(cx, cy, outer), "#b8c0cc");
      page.polygon(circlePoints(cx, cy, inner), "#ffffff");
      return;
    }

    let start = -90;
    for (const sev of SEVERITIES){
      const value = counts[sev] || 0;
      if (!value) continue;
      const span = (value / total) * 360;
      const end = start + span;
      const pts = sectorPoints(cx, cy, outer, inner, start, end);
      page.polygon(pts, severityColor(sev));
      start = end;
    }
  }

  function circlePoints(cx, cy, r){
    const points = [];
    for (let a = 0; a < 360; a += 8){
      const rad = (a * Math.PI) / 180;
      points.push([cx + Math.cos(rad) * r, cy + Math.sin(rad) * r]);
    }
    return points;
  }

  function sectorPoints(cx, cy, outer, inner, startDeg, endDeg){
    const points = [];
    const step = Math.max(3, Math.min(8, (endDeg - startDeg) / 8));
    for (let a = startDeg; a <= endDeg; a += step){
      const rad = (a * Math.PI) / 180;
      points.push([cx + Math.cos(rad) * outer, cy + Math.sin(rad) * outer]);
    }
    const endRad = (endDeg * Math.PI) / 180;
    points.push([cx + Math.cos(endRad) * outer, cy + Math.sin(endRad) * outer]);
    for (let a = endDeg; a >= startDeg; a -= step){
      const rad = (a * Math.PI) / 180;
      points.push([cx + Math.cos(rad) * inner, cy + Math.sin(rad) * inner]);
    }
    const startRad = (startDeg * Math.PI) / 180;
    points.push([cx + Math.cos(startRad) * inner, cy + Math.sin(startRad) * inner]);
    return points;
  }

  function drawBarChart(page, x, y, w, h, title, items, color){
    drawCard(page, x, y, w, h, title);
    const chartX = x + 12;
    const chartY = y + 42;
    const chartW = w - 24;
    const rowH = Math.min(21, Math.max(14, (h - 58) / Math.max(1, items.length)));
    const labelW = Math.min(82, chartW * 0.30);
    const valueW = 42;
    const barW = Math.max(24, chartW - labelW - valueW - 22);
    const max = Math.max(1, ...items.map(item=>item.value || 0));
    page.rect(chartX, chartY - 7, chartW, h - 50, "#0b1220");

    items.forEach((item, i)=>{
      const rowY = chartY + i * rowH;
      const barX = chartX + labelW + 8;
      const barY = rowY + 2;
      const fillW = Math.max(2, ((item.value || 0) / max) * barW);
      page.text(chartX + 6, rowY + 13, truncateText(item.label, 14), 6.8, "#f6f8ff");
      page.rect(barX, barY, barW, 8, "#18233a");
      if (item.value) page.rect(barX, barY, fillW, 8, color);
      page.text(chartX + chartW - valueW + 4, rowY + 12, String(item.value || 0), 6.8, "#f6f8ff", true);
    });
  }

  function drawSeverityCard(page, x, y, w, h, stats){
    drawCard(page, x, y, w, h, "Severity Infographic");
    drawDonut(page, x + 78, y + 102, 48, 25, stats.severityCounts);
    SEVERITIES.forEach((sev, i)=>{
      const ly = y + 58 + i * 17;
      page.rect(x + 150, ly - 8, 8, 8, severityColor(sev));
      page.text(x + 165, ly, sev, 8.5, "#08152c", true);
      page.text(x + 220, ly, String(stats.severityCounts[sev] || 0), 8.5, "#08152c");
    });
  }

  function drawKpis(page, stats){
    const kpis = [
      ["Packages", stats.packageCount, "#2563eb", "box"],
      ["Affected Packages", stats.affectedPackages, "#16a34a", "box"],
      ["CVE Issues", stats.totalIssues, "#f97316", "shield"],
      ["Open / Ignored", stats.openIssues, "#7c3aed", "eye"]
    ];
    kpis.forEach(([label, value, color, type], i)=>{
      const x = 42 + i * 132;
      page.strokedRect(x, 150, 120, 58, "#ffffff", "#d9e2ef");
      drawKpiIcon(page, x + 10, 167, color, type);
      page.text(x + 44, 175, label.toUpperCase(), 6.9, "#475467", true);
      page.text(x + 44, 198, Number(value).toLocaleString(), 17, "#08152c", true);
    });
  }

  function drawTableHeader(page, y, columns, x=42, w=528){
    page.rect(x, y, w, 18, "#f1f5fb");
    let cx = x + 6;
    columns.forEach(col=>{
      page.text(cx, y + 12, col.label, 7.2, "#42526b", true);
      cx += col.w;
    });
  }

  function drawTableRow(page, y, columns, values, fill, options={}){
    const x = options.x ?? 42;
    const w = options.w ?? 528;
    const rowH = options.rowH ?? 28;
    const fontSize = options.fontSize ?? 7.1;
    const lineH = options.lineH ?? 8.5;
    if (fill) page.rect(x, y, w, rowH, fill);
    let cx = x + 6;
    columns.forEach((col, i)=>{
      const lines = wrapText(values[i], Math.floor(col.w / 4.1), col.lines || 1);
      lines.forEach((line, li)=>page.text(cx, y + 11 + li * lineH, line, fontSize, "#172033"));
      cx += col.w;
    });
    page.line(x, y + rowH, x + w, y + rowH, "#e8edf5", 0.5);
  }

  function addPaginatedTable(pdf, title, subtitle, columns, rows, mapper, options={}){
    let page = pdf.addPage();
    page.rect(0, 0, 612, 792, "#ffffff");
    let y = 42;
    const rowH = options.rowH ?? 22;
    const fontSize = options.fontSize ?? 6.8;
    const lineH = options.lineH ?? 8;

    const drawTitle = ()=>{
      page.text(42, y, title, 17, "#08152c", true);
      y += 20;
      if (subtitle){
        page.text(42, y, subtitle, 8.5, "#5b6578");
        y += 18;
      }
      drawTableHeader(page, y, columns);
      y += 18;
    };

    drawTitle();
    if (!rows.length){
      page.text(48, y + 16, "No rows found.", 9, "#5b6578");
      return;
    }

    rows.forEach((row, i)=>{
      if (y > 742 - rowH){
        page = pdf.addPage();
        page.rect(0, 0, 612, 792, "#ffffff");
        y = 42;
        drawTitle();
      }
      drawTableRow(page, y, columns, mapper(row), i % 2 ? "#fbfcfe" : "", {rowH, fontSize, lineH});
      y += rowH;
    });
  }

  function buildPdfReport(ctx){
    const { yocto, rows, pkgIndex } = ctx;
    const stats = reportStats(yocto, rows);
    const issueRows = rankedIssues(rows);
    const packageRows = rankedPackages(pkgIndex);
    const topRows = issueRows.slice(0, 18);
    const topPkgs = packageRows.slice(0, 14);
    const remediationRows = topRiskRows(rows, 40).filter(r=>r.status === "Unpatched" || r.status === "Ignored").slice(0, 18);
    const statusItems = ["Unpatched","Ignored","Patched"].map(label=>({label, value:stats.statusCounts[label] || 0}));
    const sevItems = SEVERITIES.map(label=>({label, value:stats.severityCounts[label] || 0}));
    const pkgItems = topPkgs.slice(0, 10).map(p=>({label:p.name, value:p.total}));
    const posture = riskPosture(stats);
    const summary = executiveSummary(stats);
    const actions = recommendedActions(stats);

    const pdf = new PdfDoc();
    let page = pdf.addPage();
    page.rect(0, 0, 612, 792, "#ffffff");
    page.rect(0, 0, 612, 18, "#2563eb");
    page.strokedRect(42, 42, 528, 92, "#f8fbff", "#cfe0f7");
    drawShieldIcon(page, 66, 82, .95, "#2563eb", "#ffffff");
    page.text(96, 64, "YOCTO CVE ASSESSMENT", 7.5, "#2563eb", true);
    page.text(96, 86, REPORT_TITLE, 18, "#101828", true);
    page.text(96, 108, `Generated ${new Date(stats.generatedAt).toLocaleString()} from Yocto cve-summary.json. Schema ${stats.schemaVersion}.`, 7.2, "#475467");
    page.text(96, 123, `Repository: ${REPO_URL}    Maintainer: ${MAINTAINER}`, 7.2, "#475467");
    drawShieldIcon(page, 505, 84, 1.55, "#eaf2ff", "#c6dbff");
    drawKpis(page, stats);

    drawCard(page, 42, 224, 528, 92, "Executive Summary");
    drawWrappedText(page, 58, 262, summary, 94, {size:8.4, lineH:10.5, maxLines:4});
    page.rect(432, 248, 112, 18, "#eff6ff");
    page.text(441, 261, posture, 8, "#1d4ed8", true);

    drawPdfSectionTitle(page, 344, "Risk Distribution", "Severity, status, and package concentration at a glance.");
    drawSeverityCard(page, 42, 382, 255, 144, stats);
    drawBarChart(page, 315, 382, 255, 144, "Status Graph", statusItems, "#22c55e");
    drawBarChart(page, 42, 548, 255, 154, "Severity Graph", sevItems, "#78c8ff");
    drawBarChart(page, 315, 548, 255, 154, "Most Vulnerable Packages", pkgItems.slice(0, 7), "#ffaa50");

    page = pdf.addPage();
    page.rect(0, 0, 612, 792, "#ffffff");
    drawPdfSectionTitle(page, 46, "Priority Findings", "Top findings with CVSS score badges and remediation-oriented context.");
    drawPriorityCards(page, topRows, 86);
    drawCard(page, 42, 370, 528, 124, "Recommended Actions");
    actions.forEach((action, i)=>{
      const ay = 410 + i * 18;
      page.rect(58, ay - 9, 8, 8, i < 2 ? "#2563eb" : "#94a3b8");
      drawWrappedText(page, 74, ay, action, 86, {size:8.2, lineH:10, maxLines:1});
    });

    drawPdfSectionTitle(page, 540, "Top CVEs By Priority", "Highest-priority findings by severity and CVSS score.");
    let y = 580;
    const cveCols = [
      {label:"CVE", w:76},
      {label:"Severity", w:55},
      {label:"Package", w:104},
      {label:"Status", w:58},
      {label:"CVSS", w:38},
      {label:"Summary", w:190, lines:2}
    ];
    drawTableHeader(page, y, cveCols);
    y += 18;
    if (topRows.length){
      topRows.forEach((r, i)=>{
        if (y > 720){
          page = pdf.addPage();
          page.rect(0, 0, 612, 792, "#ffffff");
          y = 42;
          drawTableHeader(page, y, cveCols);
          y += 18;
        }
        const score = Math.max(toNum(r.scorev3), toNum(r.scorev2));
        drawTableRow(page, y, cveCols, [r.cve, r.sev, r.pkg, r.status || "-", score || "-", r.summary || "-"], i % 2 ? "#fbfcfe" : "");
        y += 28;
      });
    } else {
      page.text(48, y + 16, "No CVE issues found in the parsed JSON.", 9, "#5b6578");
      y += 34;
    }

    y += 24;
    if (y > 620){
      page = pdf.addPage();
      page.rect(0, 0, 612, 792, "#ffffff");
      y = 42;
    }
    page.text(42, y, "Package Risk Summary", 17, "#08152c", true);
    y += 20;
    const pkgCols = [
      {label:"Package", w:145},
      {label:"Version", w:58},
      {label:"Layer", w:115},
      {label:"Issues", w:44},
      {label:"Critical", w:48},
      {label:"High", w:38},
      {label:"Worst Status", w:80}
    ];
    drawTableHeader(page, y, pkgCols);
    y += 18;
    topPkgs.forEach((p, i)=>{
      if (y > 720){
        page = pdf.addPage();
        page.rect(0, 0, 612, 792, "#ffffff");
        y = 42;
        drawTableHeader(page, y, pkgCols);
        y += 18;
      }
      drawTableRow(page, y, pkgCols, [p.name, p.version || "-", p.layer || "-", p.total, p.sevCounts.Critical, p.sevCounts.High, worstPackageStatus(p)], i % 2 ? "#fbfcfe" : "");
      y += 28;
    });

    page = pdf.addPage();
    page.rect(0, 0, 612, 792, "#ffffff");
    page.text(42, 46, "Remediation Focus", 17, "#08152c", true);
    page.text(42, 66, "Prioritize Critical and High issues that are Unpatched or Ignored, then validate runtime exposure.", 9, "#5b6578");
    y = 90;
    const remCols = [
      {label:"CVE", w:80},
      {label:"Package", w:128},
      {label:"Version", w:58},
      {label:"Layer", w:110},
      {label:"Status", w:62},
      {label:"Summary", w:90, lines:2}
    ];
    drawTableHeader(page, y, remCols);
    y += 18;
    if (remediationRows.length){
      remediationRows.forEach((r, i)=>{
        if (y > 720){
          page = pdf.addPage();
          page.rect(0, 0, 612, 792, "#ffffff");
          y = 42;
          drawTableHeader(page, y, remCols);
          y += 18;
        }
        drawTableRow(page, y, remCols, [r.cve, r.pkg, r.pkgVersion || "-", r.layer || "-", r.status || "-", r.summary || "-"], i % 2 ? "#fbfcfe" : "");
        y += 28;
      });
    } else {
      page.text(48, y + 16, "No unpatched or ignored issues found.", 9, "#5b6578");
    }

    page = pdf.addPage();
    page.rect(0, 0, 612, 792, "#ffffff");
    drawPdfSectionTitle(page, 46, "Report Scope", "This export is optimized for review and decision-making.");
    drawWrappedText(page, 42, 92, "The PDF report intentionally includes curated high-risk findings, package concentration, remediation focus, and distribution summaries. The interactive dashboard remains the system of record for complete filtering, drilling into every package, and inspecting every issue row.", 100, {size:9, lineH:12, maxLines:6});
    drawWrappedText(page, 42, 180, "Use JSON or CSV exports when a complete machine-readable evidence package is required for automation, ticket import, or archival.", 100, {size:9, lineH:12, maxLines:3});

    return pdf.build();
  }

  function exportReport(format, ctx){
    if (!ctx?.yocto || !Array.isArray(ctx.yocto.package)){
      alert("Load a valid Yocto cve-summary.json before exporting a report.");
      return;
    }

    const base = fileBase();
    if (format === "html"){
      downloadText(`${base}.html`, buildHtmlReport(ctx), "text/html;charset=utf-8");
    } else if (format === "md"){
      downloadText(`${base}.md`, buildMarkdownReport(ctx), "text/markdown;charset=utf-8");
    } else if (format === "json"){
      downloadText(`${base}.json`, buildJsonSummary(ctx), "application/json;charset=utf-8");
    } else if (format === "pdf"){
      downloadBlob(`${base}.pdf`, buildPdfReport(ctx));
    }
  }

  window.VulnTrackReportExporter = { exportReport };
})();
