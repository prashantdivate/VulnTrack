<p align="center">
  <img src="readme-assets/logo/vulntrack-banner.png" width="100%" alt="VulnTrack">
</p>

<p align="center">
<a
  <img src="https://img.shields.io/github/deployments/prashantdivate/VulnTrack/github-pages?label=GitHub%20Pages&logo=github" />
  <img src="https://img.shields.io/website?url=https%3A%2F%2Fprashantdivate.github.io%2FVulnTrack%2F&label=Website&logo=googlechrome" />
  <img src="https://img.shields.io/badge/Yocto-Compatible-blue?logo=yoctoproject" />
  <img src="https://img.shields.io/badge/Client--Side-Only-success" />
  <img src="https://img.shields.io/github/last-commit/prashantdivate/VulnTrack" />
</a>
</p>

# VulnTrack — Yocto CVE Dashboard

VulnTrack is a lightweight, browser-based dashboard for visualizing Yocto
`cve-summary.json` reports.  
It runs entirely on the client side using HTML, CSS, and JavaScript — no backend, no server, no data upload.

Inspired by GTI-style vulnerability intelligence dashboards and designed specifically for Yocto-based systems.

---
## Features and Support

- [x] Yocto build CVE analysis
- [x] SBOM analysis, Supports modern SPDX 3.0.1
- [ ] Allow customozation for security and license profiles of SBOM

---
## Demo

### Summary Dashboard
<img src="readme-assets/screenshots/summary.png" alt="Summary View" width="100%">

### Issues View
<img src="readme-assets/screenshots/issues.png" alt="Issues View" width="100%">

### CVE View
<img src="readme-assets/screenshots/cve-view.png" alt="CVE View" width="100%">

---

## How to Run Locally

### Option 1: Open Directly
Open index.html directly in your browser.

### Option 2: Run a Local Server (Recommended)

```bash
python3 -m http.server 8080
```

Then open http://localhost:8080

---

## How to Use

1. Generate Yocto CVE data (cve-summary.json)
2. Open the VulnTrack dashboard
3. Click Choose JSON
4. Select your cve-summary.json file
5. Explore Summary, Packages, Issues, and other tabs
6. Click CVEs for details
7. Export CSV if needed
8. To analyze the SBOM generated from yocto build
9. Click on SBOM option from the tabs
10. Click on choose SBOM
11. Upload the json file and click on individual component for more details

---

## Notes & Limitations

Yocto CVE JSON does not include EPSS, KEV, exploit intelligence, or ATT&CK mappings.
These can be added later via enrichment or external APIs.

---

## Intended Audience

Embedded Linux developers, Yocto maintainers, security engineers, and cybersecurity analysts.

---

## License

Internal/personal usage. Could you please update if open-sourcing?
