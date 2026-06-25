(function(){
  "use strict";

  const SEVERITIES = ["Critical", "High", "Medium", "Low", "None"];
  const REPO_URL = "https://github.com/prashantdivate/VulnTrack";
  const MAINTAINER = "Prashant Divate";

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
    const topRows = issueRows.slice(0, 15);
    const topPkgs = packageRows.slice(0, 12);
    const remediationRows = topRiskRows(rows, 30).filter(r=>r.status === "Unpatched" || r.status === "Ignored").slice(0, 12);
    const pkgChartItems = topPkgs.map(p=>({label:p.name, value:p.total}));
    const sevChartItems = SEVERITIES.map(label=>({label, value:stats.severityCounts[label] || 0}));
    const statusChartItems = ["Unpatched","Ignored","Patched"].map(label=>({label, value:stats.statusCounts[label] || 0}));

    const cveTable = topRows.length ? topRows.map(r=>`
      <tr>
        <td><strong>${esc(r.cve)}</strong></td>
        <td><span class="pill" style="border-color:${severityColor(r.sev)}66;color:${severityColor(r.sev)}">${esc(r.sev)}</span></td>
        <td>${esc(r.pkg)}</td>
        <td>${esc(r.status || "-")}</td>
        <td>${esc(Math.max(toNum(r.scorev3), toNum(r.scorev2)) || "-")}</td>
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

    const packagesTabTable = packageRows.length ? packageRows.map(p=>`
      <tr>
        <td><strong>${esc(p.name)}</strong></td>
        <td>${esc(p.version || "-")}</td>
        <td>${esc(p.layer || "-")}</td>
        <td>${p.total}</td>
        <td>${p.sevCounts.Critical}</td>
        <td>${p.sevCounts.High}</td>
        <td>${p.sevCounts.Medium}</td>
        <td>${p.sevCounts.Low}</td>
        <td>${p.patched}</td>
        <td>${p.unpatched}</td>
        <td>${p.ignored}</td>
      </tr>
    `).join("") : `<tr><td colspan="11">No package rows found.</td></tr>`;

    const issuesTabTable = issueRows.length ? issueRows.map(r=>`
      <tr>
        <td><strong>${esc(r.cve)}</strong></td>
        <td><span class="pill" style="border-color:${severityColor(r.sev)}66;color:${severityColor(r.sev)}">${esc(r.sev)}</span></td>
        <td>${esc(r.pkg)}</td>
        <td>${esc(r.pkgVersion || "-")}</td>
        <td>${esc(r.status || "-")}</td>
        <td>${esc(Math.max(toNum(r.scorev3), toNum(r.scorev2)) || "-")}</td>
        <td>${esc(r.summary || "-")}</td>
      </tr>
    `).join("") : `<tr><td colspan="7">No CVE issues found.</td></tr>`;

    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VulnTrack Vulnerability Report</title>
  <style>
    :root{color-scheme:light;--ink:#172033;--muted:#5b6578;--line:#dfe5ef}
    *{box-sizing:border-box}
    body{margin:0;font-family:Segoe UI,Arial,sans-serif;color:var(--ink);background:#eef3fa}
    .shell{max-width:1180px;margin:0 auto;padding:28px}
    header{background:#0b1220;color:#f6f8ff;border-radius:18px;padding:26px;box-shadow:0 18px 44px rgba(20,32,54,.16)}
    h1{margin:0;font-size:30px;letter-spacing:.2px}
    h2{margin:0 0 14px;font-size:18px}
    .sub{margin-top:8px;color:#c7d2e6;font-size:13px}
    .kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:18px 0}
    .kpi,.card{background:white;border:1px solid var(--line);border-radius:14px;padding:16px;box-shadow:0 10px 24px rgba(20,32,54,.08)}
    .kpi .label{font-size:12px;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.04em}
    .kpi .value{font-size:28px;font-weight:900;margin-top:8px}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:18px 0}
    .donutWrap{display:flex;align-items:center;gap:18px}
    .donut{width:168px;height:168px;border-radius:50%;background:var(--chart);position:relative;flex:0 0 auto}
    .donut:after{content:"";position:absolute;inset:34px;background:white;border-radius:50%;box-shadow:inset 0 0 0 1px var(--line)}
    .legend{display:grid;gap:8px;font-size:13px}
    .legendRow{display:flex;align-items:center;gap:8px}
    .swatch{width:12px;height:12px;border-radius:4px}
    .reportSvg{width:100%;height:auto;border:1px solid var(--line);border-radius:12px;background:#0f1728}
    table{width:100%;border-collapse:collapse;background:white;border:1px solid var(--line);border-radius:12px;overflow:hidden}
    th,td{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:12px}
    th{background:#f1f5fb;color:#42526b;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
    .pill{display:inline-flex;border:1px solid;border-radius:999px;padding:3px 8px;font-weight:800}
    .note{color:var(--muted);font-size:12px;line-height:1.5}
    .break{break-inside:avoid}
    @media (max-width:800px){.kpis,.grid{grid-template-columns:1fr}.shell{padding:14px}}
    @media print{body{background:white}.shell{max-width:none;padding:0}.card,.kpi,header{box-shadow:none}}
  </style>
</head>
<body>
  <div class="shell">
    <header>
      <h1>VulnTrack Vulnerability Report</h1>
      <div class="sub">Generated ${esc(new Date(stats.generatedAt).toLocaleString())} from Yocto cve-summary.json. Schema ${esc(stats.schemaVersion)}.</div>
      <div class="sub">Repository: <a href="${REPO_URL}" style="color:#cfe0ff">${REPO_URL}</a> &nbsp; Maintainer: ${esc(MAINTAINER)}</div>
    </header>
    <section class="kpis">
      <div class="kpi"><div class="label">Packages</div><div class="value">${stats.packageCount.toLocaleString()}</div></div>
      <div class="kpi"><div class="label">Affected Packages</div><div class="value">${stats.affectedPackages.toLocaleString()}</div></div>
      <div class="kpi"><div class="label">CVE Issues</div><div class="value">${stats.totalIssues.toLocaleString()}</div></div>
      <div class="kpi"><div class="label">Open / Ignored</div><div class="value">${stats.openIssues.toLocaleString()}</div></div>
    </section>
    <section class="grid">
      <article class="card break"><h2>Severity Infographic</h2><div class="donutWrap"><div class="donut" style="--chart:${conicForCounts(stats.severityCounts, SEVERITIES)}"></div><div class="legend">${SEVERITIES.map(label=>`<div class="legendRow"><span class="swatch" style="background:${severityColor(label)}"></span><strong>${label}</strong> ${stats.severityCounts[label] || 0}</div>`).join("")}</div></div></article>
      <article class="card break"><h2>Status Graph</h2>${htmlBarChart(statusChartItems, "#22c55e")}</article>
      <article class="card break"><h2>Severity Graph</h2>${htmlBarChart(sevChartItems, "#78c8ff")}</article>
      <article class="card break"><h2>Most Vulnerable Packages</h2>${htmlBarChart(pkgChartItems, "#ffaa50")}</article>
    </section>
    <section class="card break"><h2>Risk Snapshot</h2><p class="note">Highest CVSS v3: <strong>${stats.maxCvss3 ? stats.maxCvss3.toFixed(1) : "-"}</strong>. Highest CVSS v2: <strong>${stats.maxCvss2 ? stats.maxCvss2.toFixed(1) : "-"}</strong>. Most common vector: <strong>${esc(stats.commonVector)}</strong>.</p></section>
    <section class="card break"><h2>Top CVEs By Priority</h2><table><thead><tr><th>CVE</th><th>Severity</th><th>Package</th><th>Status</th><th>CVSS</th><th>Summary</th></tr></thead><tbody>${cveTable}</tbody></table></section>
    <section class="card break"><h2>Package Risk Summary</h2><table><thead><tr><th>Package</th><th>Version</th><th>Layer</th><th>Issues</th><th>Critical</th><th>High</th><th>Worst Status</th></tr></thead><tbody>${pkgTable}</tbody></table></section>
    <section class="card break"><h2>Remediation Focus</h2><p class="note">Prioritize Critical and High issues that are Unpatched or Ignored, then validate whether the vulnerable code is shipped and reachable in the final image.</p><table><thead><tr><th>CVE</th><th>Package</th><th>Version</th><th>Layer</th><th>Status</th><th>Summary</th></tr></thead><tbody>${remediationTable}</tbody></table></section>
    <section class="card break"><h2>Packages Tab Output</h2><p class="note">Full package list from the dashboard Packages tab, sorted by risk and issue count.</p><table><thead><tr><th>Package</th><th>Version</th><th>Layer</th><th>Issues</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Patched</th><th>Unpatched</th><th>Ignored</th></tr></thead><tbody>${packagesTabTable}</tbody></table></section>
    <section class="card break"><h2>Issues Tab Output</h2><p class="note">Full CVE issue list from the dashboard Issues tab, sorted by severity and CVSS score.</p><table><thead><tr><th>CVE</th><th>Severity</th><th>Package</th><th>Version</th><th>Status</th><th>CVSS</th><th>Summary</th></tr></thead><tbody>${issuesTabTable}</tbody></table></section>
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
    const lines = [
      "# VulnTrack Vulnerability Report",
      "",
      `Generated: ${stats.generatedAt}`,
      `Schema version: ${stats.schemaVersion}`,
      `Repository: ${REPO_URL}`,
      `Maintainer: ${MAINTAINER}`,
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
    lines.push("", "## Packages Tab Output", "", "| Package | Version | Layer | Issues | Critical | High | Medium | Low | Patched | Unpatched | Ignored |", "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    for (const p of packageRows){
      lines.push(`| ${p.name} | ${p.version || "-"} | ${p.layer || "-"} | ${p.total} | ${p.sevCounts.Critical} | ${p.sevCounts.High} | ${p.sevCounts.Medium} | ${p.sevCounts.Low} | ${p.patched} | ${p.unpatched} | ${p.ignored} |`);
    }
    lines.push("", "## Issues Tab Output", "", "| CVE | Severity | Package | Version | Status | CVSS | Summary |", "| --- | --- | --- | --- | --- | ---: | --- |");
    for (const r of issueRows){
      const score = Math.max(toNum(r.scorev3), toNum(r.scorev2));
      lines.push(`| ${r.cve} | ${r.sev} | ${r.pkg} | ${r.pkgVersion || "-"} | ${r.status || "-"} | ${score || "-"} | ${String(r.summary || "-").replace(/\|/g, "\\|")} |`);
    }
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
      ["Packages", stats.packageCount],
      ["Affected Packages", stats.affectedPackages],
      ["CVE Issues", stats.totalIssues],
      ["Open / Ignored", stats.openIssues]
    ];
    kpis.forEach(([label, value], i)=>{
      const x = 42 + i * 132;
      page.strokedRect(x, 158, 120, 54, "#ffffff", "#dfe5ef");
      page.text(x + 10, 180, label.toUpperCase(), 7.5, "#42526b", true);
      page.text(x + 10, 202, Number(value).toLocaleString(), 18, "#08152c", true);
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

    const pdf = new PdfDoc();
    let page = pdf.addPage();
    page.rect(0, 0, 612, 792, "#eef3fa");
    page.rect(42, 42, 528, 74, "#0b1220");
    page.text(58, 78, "VulnTrack Vulnerability Report", 22, "#ffffff", true);
    page.text(58, 99, `Generated ${new Date(stats.generatedAt).toLocaleString()} from Yocto cve-summary.json. Schema ${stats.schemaVersion}.`, 9, "#c7d2e6");
    page.text(58, 112, `Repository: ${REPO_URL}    Maintainer: ${MAINTAINER}`, 8, "#c7d2e6");
    drawKpis(page, stats);
    drawSeverityCard(page, 42, 230, 255, 154, stats);
    drawBarChart(page, 315, 230, 255, 154, "Status Graph", statusItems, "#22c55e");
    drawBarChart(page, 42, 402, 255, 154, "Severity Graph", sevItems, "#78c8ff");
    drawBarChart(page, 315, 402, 255, 154, "Most Vulnerable Packages", pkgItems, "#ffaa50");

    drawCard(page, 42, 574, 528, 86, "Risk Snapshot");
    page.text(58, 612, `Highest CVSS v3: ${stats.maxCvss3 ? stats.maxCvss3.toFixed(1) : "-"}    Highest CVSS v2: ${stats.maxCvss2 ? stats.maxCvss2.toFixed(1) : "-"}`, 10, "#172033", true);
    page.text(58, 632, `Most common vector: ${stats.commonVector}`, 9, "#5b6578");
    page.text(58, 650, "Yocto JSON does not include EPSS/KEV/exploit intelligence by default.", 9, "#5b6578");

    page = pdf.addPage();
    page.rect(0, 0, 612, 792, "#ffffff");
    page.text(42, 46, "Top CVEs By Priority", 17, "#08152c", true);
    let y = 66;
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

    const allPkgCols = [
      {label:"Package", w:122},
      {label:"Version", w:52},
      {label:"Layer", w:92},
      {label:"Issues", w:36},
      {label:"Crit", w:32},
      {label:"High", w:32},
      {label:"Med", w:32},
      {label:"Low", w:32},
      {label:"Patch", w:36},
      {label:"Unpatch", w:44},
      {label:"Ign", w:24}
    ];
    addPaginatedTable(
      pdf,
      "Packages Tab Output",
      `Full package list from the dashboard Packages tab (${packageRows.length.toLocaleString()} rows), sorted by risk and issue count.`,
      allPkgCols,
      packageRows,
      p=>[p.name, p.version || "-", p.layer || "-", p.total, p.sevCounts.Critical, p.sevCounts.High, p.sevCounts.Medium, p.sevCounts.Low, p.patched, p.unpatched, p.ignored],
      {rowH:18, fontSize:6.3, lineH:7.2}
    );

    const allIssueCols = [
      {label:"CVE", w:76},
      {label:"Sev", w:42},
      {label:"Package", w:112},
      {label:"Version", w:54},
      {label:"Status", w:58},
      {label:"CVSS", w:34},
      {label:"Summary", w:152, lines:2}
    ];
    addPaginatedTable(
      pdf,
      "Issues Tab Output",
      `Full CVE issue list from the dashboard Issues tab (${issueRows.length.toLocaleString()} rows), sorted by severity and CVSS score.`,
      allIssueCols,
      issueRows,
      r=>[r.cve, r.sev, r.pkg, r.pkgVersion || "-", r.status || "-", Math.max(toNum(r.scorev3), toNum(r.scorev2)) || "-", r.summary || "-"],
      {rowH:24, fontSize:6.2, lineH:7.2}
    );

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
