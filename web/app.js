/**
 * ShadowTrace Web Hub - Main Application Controller
 * Offline-first, privacy-guaranteed client-side forensics and distribution portal.
 */
(function() {
  'use strict';

  // State
  var state = {
    currentTab: 'direct-checks',
    os: 'unknown',
    usbDevice: null
  };

  // DOM Helpers
  function $(id) { return document.getElementById(id); }
  function $$(selector) { return document.querySelectorAll(selector); }

  // 1. Tab Switching
  function setupTabs() {
    $$('.tab-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var tabId = btn.getAttribute('data-tab');
        switchTab(tabId);
      });
    });
  }

  function switchTab(tabId) {
    state.currentTab = tabId;
    $$('.tab-btn').forEach(function(btn) {
      btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
    });
    $$('.tab-content').forEach(function(content) {
      content.classList.toggle('active', content.id === tabId);
    });
  }

  // 2. OS Auto-Detection
  function detectOS() {
    var ua = navigator.userAgent || "";
    var platform = navigator.platform || "";
    var os = "unknown";

    if (/Windows/i.test(ua)) {
      os = "windows";
    } else if (/Macintosh|MacIntel|MacPPC|Mac68K/i.test(ua)) {
      // Differentiate Apple Silicon vs Intel
      var isAppleSilicon = (navigator.maxTouchPoints > 2) || (/Macintosh/.test(ua) && !/Intel/.test(ua));
      os = isAppleSilicon ? "macos-arm" : "macos-intel";
    } else if (/Android/i.test(ua)) {
      os = "android";
    } else if (/iPhone|iPad|iPod/i.test(ua)) {
      os = "ios";
    } else if (/Linux/i.test(ua) || /X11/i.test(platform)) {
      os = "linux";
    }

    state.os = os;

    // Highlight recommended card in download hub
    var cardId = null;
    var osLabel = "Your System";
    if (os === "windows") {
      cardId = "card-windows";
      osLabel = "Windows (64-bit)";
    } else if (os === "macos-arm") {
      cardId = "card-mac-arm";
      osLabel = "macOS (Apple Silicon M1/M2/M3/M4)";
    } else if (os === "macos-intel") {
      cardId = "card-mac-intel";
      osLabel = "macOS (Intel)";
    } else if (os === "linux") {
      cardId = "card-linux";
      osLabel = "Linux (x64)";
    } else if (os === "android") {
      cardId = "card-android";
      osLabel = "Android Device";
    } else if (os === "ios") {
      cardId = "card-ios";
      osLabel = "Apple iOS Device";
    }

    if (cardId && $(cardId)) {
      $(cardId).classList.add("recommended");
      var recBadge = $(cardId).querySelector(".platform-tag");
      if (recBadge) recBadge.textContent = "RECOMMENDED FOR YOU";
    }

    var osBanner = $("detected-os-text");
    if (osBanner) {
      osBanner.textContent = "Detected: " + osLabel;
    }
  }

  // 3. WebUSB Android Live Check & Automatic Package Scanner
  function setupWebUsb() {
    var btnConnect = $("btn-usb-connect");
    var term = $("usb-terminal");
    var auditResults = $("usb-audit-results");
    var pasteAuditBtn = $("btn-paste-audit");
    var pasteInput = $("paste-adb-dump");

    var currentScanResult = null;
    var activeFilter = "all";

    function log(msg) {
      if (term) {
        term.textContent += "[" + new Date().toLocaleTimeString() + "] " + msg + "\n";
        term.scrollTop = term.scrollHeight;
      }
    }

    function renderPackageList(packages, filter, searchTerm) {
      var container = $("pkg-list-container");
      if (!container) return;

      var termLower = (searchTerm || "").toLowerCase().trim();
      var filtered = packages.filter(function(p) {
        if (filter === "sideloaded" && (!p.isSideloaded || p.isUninstalled)) return false;
        if (filter === "accessibility" && !p.hasAccessibility) return false;
        if (filter === "threats" && !p.isKnownThreat) return false;
        if (filter === "uninstalled" && !p.isUninstalled) return false;
        if (termLower && p.name.toLowerCase().indexOf(termLower) === -1 && p.installer.toLowerCase().indexOf(termLower) === -1) {
          return false;
        }
        return true;
      });

      if (filtered.length === 0) {
        container.innerHTML = '<p style="font-size:0.84rem; color:var(--dim); padding:10px;">No third-party packages matched this filter.</p>';
        return;
      }

      var html = "";
      filtered.forEach(function(pkg) {
        var cardClass = "pkg-card";
        if (pkg.isKnownThreat) cardClass += " threat";
        else if (pkg.isSideloaded && pkg.hasAccessibility) cardClass += " sideload-acc";
        else if (pkg.isUninstalled) cardClass += " remnant";

        html += '<div class="' + cardClass + '">';
        html += '  <div class="pkg-header-row">';
        html += '    <span class="pkg-name">' + escapeHtml(pkg.name) + '</span>';
        html += '    <div class="pkg-badges">';
        if (pkg.isKnownThreat) {
          html += '    <span class="badge-tag threat">&#9888; KNOWN SPYWARE</span>';
        }
        if (pkg.hasAccessibility) {
          html += '    <span class="badge-tag screenread">&#128065; SCREEN-READING ACCESS</span>';
        }
        if (pkg.hasDeviceAdmin) {
          html += '    <span class="badge-tag screenread">&#128737; DEVICE ADMIN</span>';
        }
        if (pkg.isUninstalled) {
          html += '    <span class="badge-tag remnant">&#128465; UNINSTALLED REMNANT</span>';
        } else if (pkg.isSideloaded) {
          html += '    <span class="badge-tag sideload">&#9888; SIDELOADED (' + escapeHtml(pkg.installer) + ')</span>';
        } else {
          html += '    <span class="badge-tag playstore">&check; ' + escapeHtml(pkg.installer) + '</span>';
        }
        html += '    </div>';
        html += '  </div>';
        if (pkg.path) {
          html += '  <div class="pkg-path">' + escapeHtml(pkg.path) + '</div>';
        }
        if (pkg.threat) {
          html += '  <div style="font-size:0.78rem; color:var(--bad); font-weight:600;">Threat: ' + escapeHtml(pkg.threat) + '</div>';
        }
        html += '</div>';
      });

      container.innerHTML = html;
    }

    function downloadReportFile(content, filename, mimeType) {
      var blob = new Blob([content], { type: mimeType || 'text/html;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    function buildForensicReportHtml(res) {
      var dateObj = new Date(res.timestamp || Date.now());
      var dateUtc = dateObj.toUTCString();
      var dateLocal = dateObj.toLocaleString();
      var safeModel = escapeHtml(res.model || "Android Device");
      var randId = Math.floor(1000 + Math.random() * 9000);
      var refId = "ST-AND-" + dateObj.getFullYear() +
        String(dateObj.getMonth() + 1).padStart(2, "0") +
        String(dateObj.getDate()).padStart(2, "0") + "-" + randId;

      var verdictTitle = "NO KNOWN MERCENARY SPYWARE IDENTIFIED";
      var verdictClass = "clean";
      var verdictDesc = "Analyzed " + res.packagesTotal + " third-party application(s), device properties, and security permissions. Zero indicators matched documented commercial mercenary spyware databases (Pegasus, Predator, Candiru, FinSpy).";

      if (res.level === "known-threat") {
        verdictTitle = "CRITICAL: DOCUMENTED SPYWARE IDENTIFIERS DETECTED";
        verdictClass = "bad";
        verdictDesc = "Found " + res.hits.length + " indicator(s) matching documented commercial mercenary spyware or stalkerware signatures.";
      } else if (res.level === "worth-a-look") {
        verdictTitle = "WORTH A CLOSER LOOK: SUSPICIOUS CONFIGURATIONS DETECTED";
        verdictClass = "warn";
        verdictDesc = "No known spyware matched, but " + res.leads.length + " security settings, sideloads, or elevated permissions require review.";
      }

      var html = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n';
      html += '<title>ShadowTrace Forensic Audit - ' + safeModel + ' (' + refId + ')</title>\n';
      html += '<style>\n';
      html += ':root { --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; --mono: "SFMono-Regular", Consolas, Menlo, monospace; }\n';
      html += '@page { size: A4; margin: 12mm 15mm 15mm 15mm; }\n';
      html += 'body { font-family: var(--font); color: #0f172a; background: #f8fafc; line-height: 1.5; margin: 0; padding: 24px; font-size: 13px; }\n';
      html += '.report-sheet { max-width: 920px; margin: 0 auto; background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 36px 40px; box-shadow: 0 4px 10px rgba(0,0,0,0.06); }\n';
      html += '.toolbar { max-width: 920px; margin: 0 auto 16px auto; display: flex; gap: 10px; justify-content: flex-end; }\n';
      html += '.btn-action { background: #0f172a; color: #fff; border: none; padding: 9px 18px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; }\n';
      html += '.btn-action.secondary { background: #e2e8f0; color: #1e293b; }\n';
      html += '.btn-action:hover { opacity: 0.9; }\n';
      html += '.header { border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: flex-start; }\n';
      html += '.brand-title { font-size: 22px; font-weight: 800; color: #0f172a; margin: 0 0 4px 0; letter-spacing: 0.5px; }\n';
      html += '.brand-sub { font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 700; letter-spacing: 1px; }\n';
      html += '.meta-pill { text-align: right; font-family: var(--mono); font-size: 11px; color: #475569; }\n';
      html += '.meta-pill strong { color: #0f172a; font-size: 12px; }\n';
      html += '.verdict-box { border-radius: 8px; padding: 16px 20px; margin: 20px 0; border: 1px solid; border-left-width: 6px; }\n';
      html += '.verdict-box.clean { background: #f0fdf4; border-color: #86efac; border-left-color: #22c55e; color: #15803d; }\n';
      html += '.verdict-box.warn { background: #fffbeb; border-color: #fde68a; border-left-color: #f59e0b; color: #b45309; }\n';
      html += '.verdict-box.bad { background: #fef2f2; border-color: #fca5a5; border-left-color: #ef4444; color: #b91c1c; }\n';
      html += '.verdict-box h2 { margin: 0 0 6px 0; font-size: 16px; font-weight: 800; letter-spacing: 0.3px; }\n';
      html += '.verdict-box p { margin: 0; font-size: 12.5px; color: #334155; line-height: 1.45; }\n';
      html += '.verdict-doctrine { margin-top: 8px; font-style: italic; font-size: 11.5px; color: #64748b; border-top: 1px dashed rgba(0,0,0,0.12); padding-top: 6px; }\n';
      html += 'h3.sec-title { font-size: 14px; font-weight: 700; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin: 28px 0 12px 0; text-transform: uppercase; letter-spacing: 0.5px; }\n';
      html += '.meta-grid { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 12px; }\n';
      html += '.meta-grid th, .meta-grid td { border: 1px solid #e2e8f0; padding: 7px 10px; text-align: left; }\n';
      html += '.meta-grid th { background: #f8fafc; color: #475569; width: 22%; font-weight: 600; }\n';
      html += '.meta-grid td { color: #0f172a; }\n';
      html += '.finding-box { border-left: 4px solid #ef4444; background: #fff1f2; border-radius: 4px; padding: 10px 14px; margin-bottom: 10px; font-size: 12px; }\n';
      html += '.finding-box.lead { border-left-color: #f59e0b; background: #fffbeb; }\n';
      html += '.finding-box strong { color: #0f172a; display: block; margin-bottom: 2px; }\n';
      html += '.table-container { width: 100%; overflow-x: auto; margin-top: 10px; }\n';
      html += 'table.pkg-table { width: 100%; border-collapse: collapse; font-size: 11px; margin-bottom: 24px; }\n';
      html += 'table.pkg-table th, table.pkg-table td { border: 1px solid #cbd5e1; padding: 6px 8px; text-align: left; vertical-align: top; }\n';
      html += 'table.pkg-table th { background: #f1f5f9; color: #334155; font-weight: 700; }\n';
      html += 'table.pkg-table tr:nth-child(even) { background: #f8fafc; }\n';
      html += '.tag { display: inline-block; padding: 2px 5px; border-radius: 3px; font-size: 9.5px; font-family: var(--mono); font-weight: 600; white-space: nowrap; margin-right: 3px; }\n';
      html += '.tag-play { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }\n';
      html += '.tag-side { background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }\n';
      html += '.tag-threat { background: #ef4444; color: #fff; font-weight: 700; }\n';
      html += '.tag-acc { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }\n';
      html += '.tag-remnant { background: #e2e8f0; color: #475569; border: 1px solid #cbd5e1; }\n';
      html += '.code-font { font-family: var(--mono); word-break: break-all; font-size: 10.5px; }\n';
      html += '.footer-section { border-top: 1px solid #cbd5e1; margin-top: 36px; padding-top: 16px; font-size: 11px; color: #64748b; display: flex; justify-content: space-between; align-items: flex-end; }\n';
      html += '@media print {\n';
      html += '  body { background: #fff !important; padding: 0 !important; }\n';
      html += '  .toolbar { display: none !important; }\n';
      html += '  .report-sheet { border: none !important; box-shadow: none !important; padding: 0 !important; max-width: 100% !important; }\n';
      html += '  thead { display: table-header-group; }\n';
      html += '  tr { page-break-inside: avoid; }\n';
      html += '}\n';
      html += '</style>\n</head>\n<body>\n';

      // Toolbar
      html += '<div class="toolbar">\n';
      html += '  <button class="btn-action" onclick="window.print()">&#128424; Print to PDF / Paper</button>\n';
      html += '  <button class="btn-action secondary" onclick="downloadReportSource()">&#128229; Save Offline HTML File</button>\n';
      html += '</div>\n';

      html += '<div class="report-sheet">\n';

      // Header
      html += '  <div class="header">\n';
      html += '    <div class="title-group">\n';
      html += '      <div class="brand-title">SHADOWTRACE FORENSIC TRIAGE REPORT</div>\n';
      html += '      <div class="brand-sub">DIGITAL FORENSIC ASSESSMENT &middot; MOBILE DEVICE AUDIT</div>\n';
      html += '    </div>\n';
      html += '    <div class="meta-pill">\n';
      html += '      <div>REPORT ID: <strong>' + refId + '</strong></div>\n';
      html += '      <div>DATE: ' + dateLocal + '</div>\n';
      html += '      <div>CLASSIFICATION: <strong>CONFIDENTIAL / PRIVILEGED</strong></div>\n';
      html += '    </div>\n';
      html += '  </div>\n';

      // Executive Verdict
      html += '  <div class="verdict-box ' + verdictClass + '">\n';
      html += '    <h2>' + verdictTitle + '</h2>\n';
      html += '    <p>' + escapeHtml(verdictDesc) + '</p>\n';
      html += '    <div class="verdict-doctrine"><strong>Doctrine D1 Enforcement:</strong> "No known indicators were found in the places that can be checked. This is not a clean bill of health."</div>\n';
      html += '  </div>\n';

      // Device Hardware & Firmware Posture
      html += '  <h3 class="sec-title">1. Device Telemetry &amp; Security Posture</h3>\n';
      html += '  <table class="meta-grid">\n';
      html += '    <tr><th>Device Model</th><td>' + safeModel + '</td><th>Operating System</th><td>Android ' + escapeHtml(res.androidVersion || "Unknown") + '</td></tr>\n';
      html += '    <tr><th>Security Patch Level</th><td>' + escapeHtml(res.securityPatch || "Unknown") + '</td><th>Verified Boot Status</th><td>' + escapeHtml(res.verifiedBoot || "Unknown") + '</td></tr>\n';
      html += '    <tr><th>Total 3rd-Party Packages</th><td>' + res.packagesTotal + '</td><th>Sideloaded Applications</th><td>' + res.sideloadedCount + '</td></tr>\n';
      html += '    <tr><th>Device Administrators</th><td>' + res.deviceAdmins.length + ' registered</td><th>Accessibility Services</th><td>' + res.accessibility.length + ' active listeners</td></tr>\n';
      html += '    <tr><th>Uninstalled Remnants</th><td>' + res.uninstalledCount + ' found</td><th>Acquisition Channel</th><td>Live USB Protocol Stream (Strict Read-Only)</td></tr>\n';
      html += '  </table>\n';

      // Findings & Hits
      if (res.hits && res.hits.length > 0) {
        html += '  <h3 class="sec-title" style="color:#ef4444;">2. Actionable Spyware Indicators (' + res.hits.length + ' Detected)</h3>\n';
        res.hits.forEach(function(hit) {
          html += '  <div class="finding-box">\n';
          html += '    <strong>Threat: ' + escapeHtml(hit.threat) + ' &mdash; Package: ' + escapeHtml(hit.package) + '</strong>\n';
          html += '    <div>' + escapeHtml(hit.details) + '</div>\n';
          html += '  </div>\n';
        });
      }

      // Leads & Permissions
      if (res.leads && res.leads.length > 0) {
        html += '  <h3 class="sec-title">3. Security Findings &amp; High-Risk Privileges (' + res.leads.length + ' Items)</h3>\n';
        res.leads.forEach(function(lead) {
          html += '  <div class="finding-box lead">\n';
          html += '    <strong>' + escapeHtml(lead.title) + '</strong>\n';
          html += '    <div>' + escapeHtml(lead.details) + '</div>\n';
          html += '  </div>\n';
        });
      }

      // Active Accessibility Services
      if (res.accessibility && res.accessibility.length > 0) {
        html += '  <h3 class="sec-title">4. Active Accessibility Services (Keystroke &amp; Screen Listeners)</h3>\n';
        html += '  <table class="meta-grid">\n';
        html += '    <tr><th>Service Component</th><th>Granted App</th></tr>\n';
        res.accessibility.forEach(function(acc) {
          var comp = acc.split("/");
          html += '    <tr><td class="code-font">' + escapeHtml(acc) + '</td><td>' + escapeHtml(comp[0]) + '</td></tr>\n';
        });
        html += '  </table>\n';
      }

      // Full Application Inventory Table
      html += '  <h3 class="sec-title">5. Comprehensive Third-Party Application Inventory (' + res.allPackages.length + ' Total)</h3>\n';
      html += '  <p style="font-size:11.5px; color:#64748b; margin:0 0 10px 0;">Complete list of third-party user applications enumerated from device storage via package manager:</p>\n';
      html += '  <div class="table-container">\n';
      html += '    <table class="pkg-table">\n';
      html += '      <thead>\n';
      html += '        <tr>\n';
      html += '          <th style="width:30px;">#</th>\n';
      html += '          <th>Package Identifier</th>\n';
      html += '          <th>Installer Source</th>\n';
      html += '          <th>APK Location on Storage</th>\n';
      html += '          <th>Status / Elevated Powers</th>\n';
      html += '        </tr>\n';
      html += '      </thead>\n';
      html += '      <tbody>\n';

      res.allPackages.forEach(function(pkg, idx) {
        html += '        <tr>\n';
        html += '          <td>' + (idx + 1) + '</td>\n';
        html += '          <td class="code-font"><strong>' + escapeHtml(pkg.name) + '</strong></td>\n';
        html += '          <td>';
        if (pkg.isSideloaded && !pkg.isUninstalled) {
          html += '<span class="tag tag-side">Sideloaded</span>';
        } else if (pkg.isUninstalled) {
          html += '<span class="tag tag-remnant">Remnant</span>';
        } else {
          html += '<span class="tag tag-play">' + escapeHtml(pkg.installer) + '</span>';
        }
        html += '</td>\n';
        html += '          <td class="code-font" style="color:#64748b;">' + escapeHtml(pkg.path || "N/A") + '</td>\n';
        html += '          <td>';
        if (pkg.isKnownThreat) {
          html += '<span class="tag tag-threat">&#9888; ' + escapeHtml(pkg.threat) + '</span> ';
        }
        if (pkg.hasAccessibility) {
          html += '<span class="tag tag-acc">&#128065; Screen-Reader</span> ';
        }
        if (pkg.hasDeviceAdmin) {
          html += '<span class="tag tag-acc">&#128737; Device Admin</span> ';
        }
        if (!pkg.isKnownThreat && !pkg.hasAccessibility && !pkg.hasDeviceAdmin && !pkg.isUninstalled) {
          html += '<span style="color:#16a34a; font-size:11px;">Clean</span>';
        }
        html += '</td>\n';
        html += '        </tr>\n';
      });

      html += '      </tbody>\n';
      html += '    </table>\n';
      html += '  </div>\n';

      // Forensic Integrity Footer
      html += '  <div class="footer-section">\n';
      html += '    <div>\n';
      html += '      <strong>ShadowTrace Toolkit v3.0.2</strong> &middot; Digital Forensic &amp; Spyware Triage Engine<br>\n';
      html += '      Repository: <a href="https://github.com/manilreddy1/ShadowTrace" target="_blank">https://github.com/manilreddy1/ShadowTrace</a><br>\n';
      html += '      Generated locally in offline browser memory &middot; Zero network egress verified.\n';
      html += '    </div>\n';
      html += '    <div style="text-align:right;">\n';
      html += '      EXAMINER VERIFICATION: ___________________________<br>\n';
      html += '      TIMESTAMP (UTC): ' + dateUtc + '\n';
      html += '    </div>\n';
      html += '  </div>\n';

      html += '</div>\n'; // close .report-sheet

      // Script to support offline download from the report toolbar
      html += '<script>\n';
      html += 'function downloadReportSource() {\n';
      html += '  var blob = new Blob([document.documentElement.outerHTML], { type: "text/html;charset=utf-8" });\n';
      html += '  var url = URL.createObjectURL(blob);\n';
      html += '  var a = document.createElement("a");\n';
      html += '  a.href = url;\n';
      html += '  a.download = "shadowtrace-report-' + refId + '.html";\n';
      html += '  document.body.appendChild(a);\n';
      html += '  a.click();\n';
      html += '  document.body.removeChild(a);\n';
      html += '  URL.revokeObjectURL(url);\n';
      html += '}\n';
      html += '</scr' + 'ipt>\n';

      html += '</body>\n</html>';
      return html;
    }

    function renderAuditVerdict(res) {
      if (!auditResults) return;
      currentScanResult = res;
      var html = "";

      if (res.level === "known-threat") {
        html += '<div class="verdict-banner bad">';
        html += '<h3>CRITICAL: Known Spyware Indicators Found</h3>';
        html += '<p>Identified ' + res.hits.length + ' package(s) matching documented mercenary spyware / stalkerware lists.</p>';
        html += '</div>';
      } else if (res.level === "worth-a-look") {
        html += '<div class="verdict-banner warn">';
        html += '<h3>Worth a Closer Look</h3>';
        html += '<p>No known malware matches, but ' + res.leads.length + ' security setting(s) or permissions require review.</p>';
        html += '</div>';
      } else {
        html += '<div class="verdict-banner clean">';
        html += '<h3>No Known Threats Found</h3>';
        html += '<p>Checked ' + res.packagesTotal + ' third-party package(s) and device settings. None match known published spyware lists.</p>';
        html += '</div>';
      }

      // Forensic Report Actions
      html += '<div class="report-actions">';
      html += '  <button id="btn-print-report" class="btn btn-primary btn-sm">&#128424; View &amp; Print Detailed Report (PDF)</button>';
      html += '  <button id="btn-download-html" class="btn btn-sm" style="background:var(--panel2);">&#128229; Download Report (.html)</button>';
      html += '  <button id="btn-export-json" class="btn btn-sm" style="background:var(--panel2);">&#128190; Export Raw Data (.json)</button>';
      html += '</div>';

      // Device Security Posture Dashboard
      html += '<div class="device-dashboard">';
      html += '  <div class="device-stat"><span class="stat-label">Device Model</span><span class="stat-val">' + escapeHtml(res.model || "Android Device") + '</span></div>';
      html += '  <div class="device-stat"><span class="stat-label">Android OS</span><span class="stat-val">Android ' + escapeHtml(res.androidVersion || "Unknown") + '</span></div>';

      var patchClass = "ok";
      if (res.securityPatch && res.securityPatch !== "Unknown") {
        var pYear = parseInt(res.securityPatch.split("-")[0], 10);
        if (pYear < 2024) patchClass = "bad";
        else if (pYear < 2025) patchClass = "warn";
      }
      html += '  <div class="device-stat"><span class="stat-label">Security Patch</span><span class="stat-val ' + patchClass + '">' + escapeHtml(res.securityPatch || "Unknown") + '</span></div>';

      var bootClass = (res.verifiedBoot && res.verifiedBoot.toLowerCase() === "green") ? "ok" : "warn";
      html += '  <div class="device-stat"><span class="stat-label">Verified Boot</span><span class="stat-val ' + bootClass + '">' + escapeHtml(res.verifiedBoot || "Unknown") + '</span></div>';
      html += '  <div class="device-stat"><span class="stat-label">Device Admins</span><span class="stat-val">' + res.deviceAdmins.length + ' active</span></div>';
      html += '  <div class="device-stat"><span class="stat-label">Accessibility Services</span><span class="stat-val">' + res.accessibility.length + ' active</span></div>';
      html += '</div>';

      // Render hits
      if (res.hits.length > 0) {
        html += '<h4 style="margin: 14px 0 8px; color: var(--bad);">Actionable Findings:</h4>';
        res.hits.forEach(function(h) {
          html += '<div class="finding-item threat">';
          html += '<span class="finding-title">' + escapeHtml(h.package) + '</span>';
          html += '<span class="finding-sub">' + escapeHtml(h.threat) + ' &middot; ' + escapeHtml(h.details) + '</span>';
          html += '</div>';
        });
      }

      // Render leads
      if (res.leads.length > 0) {
        html += '<h4 style="margin: 14px 0 8px; color: var(--warn);">Leads & Device Settings:</h4>';
        res.leads.forEach(function(l) {
          html += '<div class="finding-item ' + (l.severity === "worth-a-look" ? "threat" : "clean") + '">';
          html += '<span class="finding-title">' + escapeHtml(l.title) + '</span>';
          html += '<span class="finding-sub">' + escapeHtml(l.details) + '</span>';
          html += '</div>';
        });
      }

      // Render Third-Party Packages Explorer
      html += '<div class="pkg-explorer">';
      html += '  <h3><span>Installed Third-Party Applications (' + res.packagesTotal + ' Found)</span>';
      html += '    <span style="font-size:0.78rem; font-family:var(--mono); color:var(--dim); font-weight:normal;">' + res.sideloadedCount + ' sideloaded</span>';
      html += '  </h3>';
      html += '  <p style="font-size:0.84rem; color:var(--dim); margin:0 0 10px;">Every third-party app installed on the device, categorized by origin, accessibility screen-reading privileges, and threat matching:</p>';
      
      html += '  <input type="text" id="pkg-search-input" placeholder="Search third-party packages by name or store..." style="margin-bottom:8px;">';

      var threatsCount = res.hits.length;
      var accCount = res.allPackages.filter(function(p) { return p.hasAccessibility; }).length;

      html += '  <div class="pkg-filters">';
      html += '    <button class="filter-chip active" data-filter="all">All Packages (' + res.packagesTotal + ')</button>';
      html += '    <button class="filter-chip" data-filter="sideloaded">Sideloaded (' + res.sideloadedCount + ')</button>';
      html += '    <button class="filter-chip" data-filter="accessibility">Screen-Reading (' + accCount + ')</button>';
      if (res.uninstalledCount > 0) {
        html += '    <button class="filter-chip" data-filter="uninstalled">Remnants (' + res.uninstalledCount + ')</button>';
      }
      if (threatsCount > 0) {
        html += '    <button class="filter-chip" data-filter="threats" style="color:var(--bad);">Threats (' + threatsCount + ')</button>';
      }
      html += '  </div>';

      html += '  <div id="pkg-list-container" class="pkg-list"></div>';
      html += '</div>';

      auditResults.innerHTML = html;

      // Initial render of package list
      renderPackageList(res.allPackages, "all", "");

      // Setup View/Print Detailed Report
      var btnPrint = $("btn-print-report");
      if (btnPrint) {
        btnPrint.addEventListener('click', function() {
          var reportHtml = buildForensicReportHtml(res);
          var win = window.open('', '_blank');
          if (win) {
            win.document.open();
            win.document.write(reportHtml);
            win.document.close();
            setTimeout(function() {
              win.focus();
            }, 300);
          } else {
            // Popup blocker fallback: download directly
            var dateStr = new Date().toISOString().slice(0, 10);
            var safeModel = (res.model || "device").replace(/[^a-zA-Z0-9_-]/g, "_");
            downloadReportFile(reportHtml, "shadowtrace-forensic-report-" + safeModel + "-" + dateStr + ".html", "text/html;charset=utf-8");
          }
        });
      }

      // Setup Download HTML Report
      var btnDownloadHtml = $("btn-download-html");
      if (btnDownloadHtml) {
        btnDownloadHtml.addEventListener('click', function() {
          var reportHtml = buildForensicReportHtml(res);
          var dateStr = new Date().toISOString().slice(0, 10);
          var safeModel = (res.model || "device").replace(/[^a-zA-Z0-9_-]/g, "_");
          downloadReportFile(reportHtml, "shadowtrace-forensic-report-" + safeModel + "-" + dateStr + ".html", "text/html;charset=utf-8");
        });
      }

      // Setup Export Raw JSON
      var btnExport = $("btn-export-json");
      if (btnExport) {
        btnExport.addEventListener('click', function() {
          var reportData = {
            toolkit: "ShadowTrace Toolkit",
            version: "3.0.2",
            auditType: "Android USB Device Telemetry",
            timestamp: res.timestamp,
            verdict: res.level,
            device: {
              model: res.model,
              androidVersion: res.androidVersion,
              securityPatch: res.securityPatch,
              verifiedBoot: res.verifiedBoot
            },
            summary: {
              packagesTotal: res.packagesTotal,
              sideloadedCount: res.sideloadedCount,
              uninstalledCount: res.uninstalledCount,
              accessibilityServicesCount: res.accessibility.length,
              deviceAdminsCount: res.deviceAdmins.length,
              knownThreatHits: res.hits.length,
              leadsCount: res.leads.length
            },
            findings: {
              hits: res.hits,
              leads: res.leads
            },
            packages: res.allPackages,
            deviceAdmins: res.deviceAdmins,
            accessibilityServices: res.accessibility,
            rawProperties: res.properties
          };

          var dateStr = new Date().toISOString().slice(0, 10);
          var safeModel = (res.model || "device").replace(/[^a-zA-Z0-9_-]/g, "_");
          downloadReportFile(JSON.stringify(reportData, null, 2), "shadowtrace-android-audit-" + safeModel + "-" + dateStr + ".json", "application/json");
        });
      }

      // Setup filter chip click listeners
      var chips = auditResults.querySelectorAll('.filter-chip');
      chips.forEach(function(chip) {
        chip.addEventListener('click', function() {
          chips.forEach(function(c) { c.classList.remove('active'); });
          chip.classList.add('active');
          activeFilter = chip.getAttribute('data-filter');
          var searchVal = $("pkg-search-input") ? $("pkg-search-input").value : "";
          renderPackageList(res.allPackages, activeFilter, searchVal);
        });
      });

      // Setup live search
      var searchInput = $("pkg-search-input");
      if (searchInput) {
        searchInput.addEventListener('input', function() {
          renderPackageList(res.allPackages, activeFilter, searchInput.value);
        });
      }

      auditResults.scrollIntoView({ behavior: 'smooth' });
    }

    if (btnConnect) {
      btnConnect.addEventListener('click', async function() {
        term.textContent = "";
        $("usb-status-text").textContent = "Starting automatic Android scan...";
        log("Initiating automatic scan for all third-party Android packages...");

        try {
          // Automatic scan tries local bridge first, then WebUSB
          var result = await window.WebUsbAdb.runAutoScan(
            function(msg) { log(msg); },
            function(status) { $("usb-status-text").textContent = status; },
            false
          );

          log("Parsed " + result.packagesTotal + " third-party packages (" + result.sideloadedCount + " sideloaded).");
          renderAuditVerdict(result);
          log("Automatic scan complete.");

        } catch (err) {
          log("Scan Note: " + err.message);
          $("usb-status-text").textContent = "Scan paused: " + err.message;
          alert("Android scan paused:\n" + err.message + "\n\nMake sure your phone is connected via USB with 'USB debugging' enabled in Developer options.");
        }
      });
    }

    var btnWebUsbRaw = $("btn-webusb-raw");
    if (btnWebUsbRaw) {
      btnWebUsbRaw.addEventListener('click', async function() {
        term.textContent = "";
        $("usb-status-text").textContent = "Connecting via WebUSB...";
        log("Opening direct WebUSB connection...");

        try {
          var result = await window.WebUsbAdb.runAutoScan(
            function(msg) { log(msg); },
            function(status) { $("usb-status-text").textContent = status; },
            true
          );

          log("Parsed " + result.packagesTotal + " third-party packages.");
          renderAuditVerdict(result);
          log("WebUSB scan complete.");

        } catch (err) {
          log("WebUSB Note: " + err.message);
          $("usb-status-text").textContent = "WebUSB error: " + err.message;
          alert("WebUSB note:\n" + err.message);
        }
      });
    }

    if (pasteAuditBtn && pasteInput) {
      pasteAuditBtn.addEventListener('click', function() {
        var text = pasteInput.value.trim();
        if (!text) {
          alert("Please paste package list lines (e.g. from 'adb shell pm list packages -3 -f -i') or device properties.");
          return;
        }
        var result = window.WebUsbAdb.auditAndroidData(text);
        renderAuditVerdict(result);
      });
    }
  }

  // 4. Client-Side Hash Verifier (Web Crypto API)
  function setupHashVerifier() {
    var drop = $("drop-hash-verifier");
    var fileInput = $("file-hash-input");
    var resultBox = $("hash-verify-result");

    // Official release fingerprints
    var OFFICIAL_HASHES = {
      "shadowtrace-toolkit-windows-x64.exe": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "shadowtrace-toolkit-macos-apple-silicon.dmg": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "shadowtrace-toolkit-macos-intel.dmg": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "shadowtrace-toolkit-linux-x64.tar.gz": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    };

    if (!drop) return;

    drop.addEventListener('click', function() {
      if (fileInput) fileInput.click();
    });

    drop.addEventListener('dragover', function(e) {
      e.preventDefault();
      drop.classList.add('dragover');
    });

    drop.addEventListener('dragleave', function() {
      drop.classList.remove('dragover');
    });

    drop.addEventListener('drop', function(e) {
      e.preventDefault();
      drop.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        verifyFile(e.dataTransfer.files[0]);
      }
    });

    if (fileInput) {
      fileInput.addEventListener('change', function() {
        if (fileInput.files && fileInput.files[0]) {
          verifyFile(fileInput.files[0]);
        }
      });
    }

    async function verifyFile(file) {
      resultBox.innerHTML = '<p style="color: var(--dim);"><span class="badge-seal"><span class="dot"></span></span> Calculating SHA-256 in local browser memory (' + (file.size / 1e6).toFixed(1) + ' MB)...</p>';
      
      var reader = new FileReader();
      reader.onload = async function(evt) {
        try {
          var buffer = evt.target.result;
          var digest = await crypto.subtle.digest("SHA-256", buffer);
          var hashHex = Array.from(new Uint8Array(digest))
            .map(function(b) { return b.toString(16).padStart(2, '0'); })
            .join('');

          var html = '<div class="verdict-banner clean" style="margin-top:14px;">';
          html += '<h3>Fingerprint Computed Offline</h3>';
          html += '<p><strong>File:</strong> ' + escapeHtml(file.name) + ' (' + file.size.toLocaleString() + ' bytes)</p>';
          html += '<p><strong>SHA-256:</strong> <code style="word-break:break-all;">' + hashHex + '</code></p>';
          html += '<p style="font-size:0.84rem; color: var(--ok); margin-top:8px;">&check; The file was analyzed 100% in local memory. Never sent over the internet.</p>';
          html += '</div>';

          resultBox.innerHTML = html;
        } catch (err) {
          resultBox.innerHTML = '<div class="verdict-banner bad"><p>Could not compute hash: ' + escapeHtml(err.message) + '</p></div>';
        }
      };
      reader.readAsArrayBuffer(file);
    }
  }

  // 5. Offline Threat & Link Inspector
  function setupThreatInspector() {
    var btnCheck = $("btn-check-ioc");
    var inputQuery = $("ioc-query-input");
    var resultBox = $("ioc-result-box");

    if (!btnCheck || !inputQuery) return;

    btnCheck.addEventListener('click', function() {
      var query = inputQuery.value.trim().toLowerCase();
      if (!query) {
        alert("Please enter a domain, URL, IP address or package identifier.");
        return;
      }

      // Strip protocols and paths if a URL was pasted
      var cleanQuery = query.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];

      var iocs = window.SHADOWTRACE_IOCS || { domains: [], ips: [], packages: [], hashes: [] };
      var found = [];

      // Check domains
      iocs.domains.forEach(function(d) {
        if (cleanQuery === d.value.toLowerCase() || cleanQuery.endsWith("." + d.value.toLowerCase())) {
          found.push({ type: "Domain Indicator", value: d.value, threat: d.threat });
        }
      });

      // Check IPs
      iocs.ips.forEach(function(ip) {
        if (cleanQuery === ip.value) {
          found.push({ type: "IP Address Indicator", value: ip.value, threat: ip.threat });
        }
      });

      // Check Packages
      iocs.packages.forEach(function(pkg) {
        if (cleanQuery === pkg.value.toLowerCase()) {
          found.push({ type: "Android Package Indicator", value: pkg.value, threat: pkg.threat });
        }
      });

      if (found.length > 0) {
        var html = '<div class="verdict-banner bad">';
        html += '<h3>ALERT: Matched Published Spyware Indicator</h3>';
        html += '<p>The target matches documented infrastructure or artifacts:</p>';
        found.forEach(function(item) {
          html += '<div class="finding-item threat">';
          html += '<span class="finding-title">' + escapeHtml(item.value) + ' (' + escapeHtml(item.type) + ')</span>';
          html += '<span class="finding-sub">Attributed Threat: ' + escapeHtml(item.threat) + '</span>';
          html += '</div>';
        });
        html += '<p style="color:var(--bad); font-weight:600; font-size:0.86rem; margin-top:8px;">DO NOT connect to, click, or browse this destination. Seek expert helpline guidance.</p>';
        html += '</div>';
        resultBox.innerHTML = html;
      } else {
        var cleanHtml = '<div class="verdict-banner clean">';
        cleanHtml += '<h3>No Known Mercenary Spyware Match</h3>';
        cleanHtml += '<p><code>' + escapeHtml(cleanQuery) + '</code> was not found on the published mercenary threat lists.</p>';
        cleanHtml += '<p style="font-size:0.82rem; color:var(--dim);">Note: A clean result is not proof of safety against brand-new, zero-day infrastructure.</p>';
        cleanHtml += '</div>';
        resultBox.innerHTML = cleanHtml;
      }
    });
  }

  // 6. Utility Functions
  function escapeHtml(str) {
    if (!str) return '';
    return str.toString()
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // 7. PWA Service Worker Registration
  function registerServiceWorker() {
    if ('serviceWorker' in navigator && (window.location.protocol === 'https:' || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
      navigator.serviceWorker.register('./sw.js').then(function(reg) {
        console.log("ShadowTrace PWA Offline Service Worker Registered:", reg.scope);
      }).catch(function(err) {
        console.log("Service Worker registration skipped:", err);
      });
    }
  }

  // Initialize
  document.addEventListener('DOMContentLoaded', function() {
    setupTabs();
    detectOS();
    setupWebUsb();
    setupHashVerifier();
    setupThreatInspector();
    registerServiceWorker();
  });

})();

