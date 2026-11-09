# Release workspace — real Yocto reports

The dashboard contains no sample portfolios or sample scan generator. Previously saved reference samples are removed on load; actual imported reports are preserved. All displayed findings, counts, history points and dependency edges come from imported evidence.

## Load your report

Click **Import build**. In one window, select or create the portfolio (for example your MadOS family) and product (the device/image you track), name the build, and choose its SBOM, its CVE report, or both. At least one valid artifact is required. A CVE report is not required to import an SBOM. One **Import build** saves them together. Existing portfolios/products can be reused for later scans. Build metadata is optional and expands in the same window; you can also attach Yocto image testdata JSON to populate known MACHINE, DISTRO, image, release and BUILDNAME date fields. Other testdata variables are not retained.

When serving this repository locally, **Load cve-summary.json from this folder** opens the same form with that report already loaded. Prefer the image-specific `.rootfs.json` when reviewing a shipped image. **+ portfolio**, **+ product**, and **+ scan** open the same combined import window at the corresponding level. Existing names, descriptions and owners can be changed with **edit**.

Portfolios is the only top-level view. Each scan contains Overview, SBOM inventory, CVE findings, CVE recipes, Upgrade preview, Delta, History, and Evidence. The names distinguish the CVE report’s recipe records from the SBOM’s component records. Overview shows two file cards with their actual filenames, counts and direct open/add actions, plus an SBOM component/license preview. The build header and portfolio rows also link directly to an attached inventory. SBOM imports open the inventory immediately. Overview includes CVE report exports when a CVE report is present. Findings progressively loads 200 records at a time; filters/search apply to the full report.

No report is transmitted to a service. Loading from the folder requires HTTP serving; when opening the HTML file directly, use the file picker instead. Missing build date, machine, release, pipeline and layer revisions are not invented. History uses the import date when no build date is supplied and labels this distinction.

For an SBOM-only build, the CVE report is stored as absent, not as a fabricated empty report. Vulnerability status is “Not assessed”; finding counts and fix/KEV/CRA cards are not presented as zero. Selecting CVE-dependent views explains what is missing. Use **Add matching CVE report** to attach it to this same build later, preserving the SBOM. CVE history and delta exclude SBOM-only snapshots, so an absent report cannot be presented as removed or remediated vulnerabilities. An existing CVE report is not overwritten by this action; import a new scan to preserve earlier reviews.

The SBOM inventory shows component versions, licenses, suppliers and runtime dependency links. Select a row for its metadata and dependency graph. CVE metrics are kept out of the inventory view so component data remains prominent; build metadata can be expanded. A top-level SPDX JSON may only reference the component documents. Missing documents are identified with instructions to upload the complete matching `.spdx.tar` bundle. A standalone SPDX index without component documents is rejected with an explanation.

Snapshots and reviews are stored in browser IndexedDB to support reports larger than localStorage's typical limit. Export workspace provides a portable backup. Your browser origin/profile controls which workspace is loaded.

**Reset all data** clears the loaded analysis and saved portfolios, scans, attached SBOMs and reviews for the current browser origin. It does not remove the original report files. Reload waits for storage to load, and old localStorage workspaces are migrated to IndexedDB after sample records are removed.

## What cve-summary.json provides

Package names, versions, layers, CVE identifiers, summaries, CVSS scores/vectors, patch statuses and reference links. A build-wide summary can include native build tools; it must not be presented as proof that every listed package ships in a device. Prefer the matching image-specific CVE JSON for a shipped-image review.

The vulnerability review uses `vulntrack-product-review-v2`. It replaces the former blanket “all Critical/High CVEs must be zero” rule. Raw CVE counts and severity are retained. They are not proof that every matched vulnerability is exploitable in the shipped product.

- **Blocked:** an open KEV-listed finding (pending supported product non-impact assessment), confirmed product exploitability at any severity, or a confirmed affected Critical/High finding without valid risk acceptance.
- **Review required:** unresolved applicability, investigation, an unscored affected finding, or expired/invalid acceptance where no stronger blocking rule applies. Unknown evidence is not clearance.
- **Warning:** other confirmed affected findings and valid accepted risks. They remain open and actionable. This is not a shipment approval.
- **Passed:** components are present and the supplied report has no open findings. This does not certify the product, test coverage or legal compliance.
- **Unknown:** no component records are supplied.

Open a finding to record VEX assessment, product exploitability, CRA relevance and rationale. “Affected” confirms product applicability; do not use it merely because a version matcher found a CVE. Use configuration, build options, reachable-code analysis, exposure, vendor advisories and, where appropriate, actual security testing as evidence. “Not affected” and “fixed” require supporting rationale. An `Ignored` Yocto status alone does not close a finding.

Temporary risk acceptance requires confirmed affected status, rationale, an accountable approver, mitigation/control evidence and an expiry date. It remains valid through that UTC date and is re-evaluated on views/reloads and at UTC midnight. Critical/High findings block again when acceptance expires; lower-severity expired acceptances need review. KEV-listed or confirmed product-exploitable findings cannot bypass blocking through acceptance in this local policy. Choose “Investigate / remediate” to remove an acceptance. The named approver is a local record, not an authenticated sign-off; approval authority must be verified through your organization's process. Risk acceptance cannot waive legal, regulatory, safety or contractual duties.

Each new review and VEX import records the previous and new decision in `reviewEvents`, included in Evidence JSON and workspace backups. Existing assessments made before this change are preserved; no past change history is invented. VEX import replaces any previous acceptance, requiring deliberate reassessment. OpenVEX exports preserve `affected` status for accepted risks; acceptance is not an OpenVEX fixed status. History gates are recomputed using the current policy/date, rather than pretending to be immutable historical release approvals.

### Basis and limits of the policy

The sources below describe prioritization and evidence requirements; they do **not** prescribe these exact application gate rules or a universal permitted number of Critical/High CVEs. This is VulnTrack's documented default policy, informed by that guidance. It is not an implementation of the full CISA SSVC decision tree or an EPSS scoring service.

- [FIRST CVSS v3.1 User Guide, §2.1](https://www.first.org/cvss/v3.1/user-guide): base severity is not a complete risk assessment; product environment and threat context matter.
- [NIST SP 800-218 SSDF, RV.2.1 and RV.2.2, printed pages 17–18](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf): analyze risk and plan remediation or another documented risk response, including acceptance where appropriate.
- [CISA SSVC guide](https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf): prioritization includes exploitation and mission/safety impact; CVSS alone does not capture that context.
- [CISA Minimum Requirements for VEX](https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf): supports product-specific affected, not-affected, fixed and under-investigation assessments with evidence.
- [FIRST EPSS](https://www.first.org/epss/using-epss): exploitation probability is an additional input, not a complete product-risk score. EPSS is not currently fetched by VulnTrack.
- [EU CRA, Regulation (EU) 2024/2847, Annex I Part I(2)(a)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng): addresses known exploitable vulnerabilities, rather than establishing a CVE-count quota. Applicability and conformity obligations require separate assessment; this browser does not determine compliance.

No product penetration test or runtime reachability test is performed by importing these artifacts. No exposure, exploitability, mitigations, KEV values or approvals are fabricated. CVSS v2 fallback scores use High (not Critical) for scores >=7; v3 scores retain the Critical category.

## Additional evidence

- **Installed components, licenses and dependency graph:** matching image SPDX SBOM. Choose the matching complete bundle during Import build, or choose/replace it directly in the scan's SBOM tab. It persists with that scan after reload. Kirkstone runtime dependency direction and document namespaces are resolved from source evidence. Recipe-to-binary links and epoch-prefixed versions are matched; build dependencies are excluded from the runtime graph. External source checksums are verified for tar documents when WebCrypto is available; mismatches and missing documents remain visible. Full bundles are preferable to a top-level index with unresolved external references. If native zstd decoding is unsupported, decompress to .tar first.
- **Image-only package scope:** the image-specific CVE JSON and matching .manifest file. The manifest is useful to verify shipped package scope; it is not currently a separate upload type in VulnTrack.
- **History and Delta:** multiple real CVE reports for the same product/stream, retaining their actual build dates.
- **Build metadata:** actual image name, MACHINE, DISTRO, Yocto release, build date, pipeline and source/layer revisions, entered through Edit metadata. Buildhistory output is useful evidence for recording changes; it is not parsed automatically.
- **CRA relevance and not-affected decisions:** an explicit product security review; these cannot be determined from CVSS alone. Record a rationale in the finding review form.
- **CISA KEV/exploit maturity and fixed versions/upgrade previews:** external intelligence or verified patch/version evidence. Ordinary Yocto CVE JSON does not supply these fields. **Not provided** means the report has no KEV or fix-version evidence. **Not assessed** means CRA relevance has not been explicitly reviewed. Partial evidence displays its unknown count. Zero appears only when all open findings are assessed or there are no open findings. Upgrade previews do not rebuild Yocto or query an online fix index.

## Yocto configuration

The user's existing configuration enables CVE checking and SPDX generation:

```conf
INHERIT += " cve-check create-spdx "
CVE_SOCKET_TIMEOUT = "180"
include conf/distro/include/cve-extra-exclusions.inc
```

No additional setting is needed just to load the existing JSON. For the matching SPDX output, look under tmp/deploy/images/<MACHINE>/ and tmp/deploy/spdx/. Exact files and SPDX versions vary by Yocto release. SPDX_PRETTY = "1" is optional for readability; source/package archives are not needed just to display a dependency graph. Keep the existing exclusions include only if it belongs to your branch's intended CVE policy; Ignored findings need contextual review.

## Optional enrichment format

The original report can remain unchanged. If exporting verified enrichment yourself, use top-level vulntrack metadata (image, yocto_release, machine, distro, pipeline, commit, layers, event). Per-finding optional fields are cra_relevant (boolean), kev (boolean), fixed_version (string) and vex (assessment). Never insert estimates as facts.

Top-level vulntrack.upgrade_scenarios is an array of objects with title, fixes: [{package, cve}], evidence and optional cumulative: true. Cumulative scenarios include exact package/CVE fixes from earlier scenarios. The UI's Edit upgrade scenarios accepts this array. Preview changes only the hypothetical gate.

Import VEX accepts OpenVEX statements with exact vulnerability names and products[].@id matching pkg:generic/<encoded-package>@<encoded-version>. A supported assessment and nonempty impact/action statement or justification are required. Matching assessments are previewed before applying. Export OpenVEX includes saved reviews and timestamps.

## Validation

Run node tests/release-workspace.test.cjs. To additionally check your actual report, pass its path as the first argument. No test packages are required; any small in-memory unit-test inputs are isolated from the dashboard and are never saved or displayed.
