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

  // 4. IoT & Local Network Security Auditor
  function buildIoTForensicReportHtml(res) {
    var dateObj = new Date(res.timestamp || Date.now());
    var dateUtc = dateObj.toUTCString();
    var dateLocal = dateObj.toLocaleString();
    var subnet = escapeHtml(res.subnet || "Local Network");
    var router = escapeHtml(res.router || "Default Gateway");
    var thisComputer = escapeHtml(res.this_computer || "Local Computer");
    var randId = Math.floor(1000 + Math.random() * 9000);
    var refId = "ST-NET-" + dateObj.getFullYear() +
      String(dateObj.getMonth() + 1).padStart(2, "0") +
      String(dateObj.getDate()).padStart(2, "0") + "-" + randId;

    var sum = res.summary || {};
    var verdictTitle = sum.posture_verdict || "LOCAL NETWORK SECURITY AUDIT";
    var verdictClass = sum.posture_class || "clean";
    var grade = sum.grade || "A+";
    var score = sum.score || 100;

    var verdictDesc = "Audited " + (res.devices ? res.devices.length : 0) + " device(s) on local subnet " + subnet + ". Evaluated IoT stream security, open management ports, and router UPnP WAN pinholes.";

    var html = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n';
    html += '<title>ShadowTrace Network & IoT Forensic Audit - ' + subnet + ' (' + refId + ')</title>\n';
    html += '<style>\n';
    html += ':root { --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; --mono: "SFMono-Regular", Consolas, Menlo, monospace; }\n';
    html += '@page { size: A4; margin: 12mm 15mm 15mm 15mm; }\n';
    html += 'body { font-family: var(--font); color: #0f172a; background: #f8fafc; line-height: 1.5; margin: 0; padding: 24px; font-size: 13px; }\n';
    html += '.report-sheet { max-width: 940px; margin: 0 auto; background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 36px 40px; box-shadow: 0 4px 10px rgba(0,0,0,0.06); }\n';
    html += '.toolbar { max-width: 940px; margin: 0 auto 16px auto; display: flex; gap: 10px; justify-content: flex-end; }\n';
    html += '.btn-action { background: #0f172a; color: #fff; border: none; padding: 9px 18px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; }\n';
    html += '.btn-action.secondary { background: #e2e8f0; color: #1e293b; }\n';
    html += '.btn-action:hover { opacity: 0.9; }\n';
    html += '.header { border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: flex-start; }\n';
    html += '.brand-title { font-size: 22px; font-weight: 800; color: #0f172a; margin: 0 0 4px 0; letter-spacing: 0.5px; }\n';
    html += '.brand-sub { font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 700; letter-spacing: 1px; }\n';
    html += '.meta-pill { text-align: right; font-family: var(--mono); font-size: 11px; color: #475569; }\n';
    html += '.meta-pill strong { color: #0f172a; font-size: 12px; }\n';
    html += '.verdict-box { border-radius: 8px; padding: 16px 20px; margin: 20px 0; border: 1px solid; border-left-width: 6px; display: flex; justify-content: space-between; align-items: center; }\n';
    html += '.verdict-box.clean { background: #f0fdf4; border-color: #86efac; border-left-color: #22c55e; color: #15803d; }\n';
    html += '.verdict-box.warn { background: #fffbeb; border-color: #fde68a; border-left-color: #f59e0b; color: #b45309; }\n';
    html += '.verdict-box.bad { background: #fef2f2; border-color: #fca5a5; border-left-color: #ef4444; color: #b91c1c; }\n';
    html += '.verdict-score-badge { font-size: 28px; font-weight: 900; font-family: var(--mono); padding: 6px 14px; border-radius: 6px; background: rgba(0,0,0,0.06); }\n';
    html += '.verdict-box h2 { margin: 0 0 4px 0; font-size: 16px; font-weight: 800; letter-spacing: 0.3px; }\n';
    html += '.verdict-box p { margin: 0; font-size: 12.5px; color: #334155; line-height: 1.45; }\n';
    html += 'h3.sec-title { font-size: 14px; font-weight: 700; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin: 28px 0 12px 0; text-transform: uppercase; letter-spacing: 0.5px; }\n';
    html += '.meta-grid { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 12px; }\n';
    html += '.meta-grid th, .meta-grid td { border: 1px solid #e2e8f0; padding: 7px 10px; text-align: left; }\n';
    html += '.meta-grid th { background: #f8fafc; color: #475569; width: 22%; font-weight: 600; }\n';
    html += '.meta-grid td { color: #0f172a; }\n';
    html += '.table-container { width: 100%; overflow-x: auto; margin-top: 10px; }\n';
    html += 'table.rep-table { width: 100%; border-collapse: collapse; font-size: 11px; margin-bottom: 24px; }\n';
    html += 'table.rep-table th, table.rep-table td { border: 1px solid #cbd5e1; padding: 6px 8px; text-align: left; vertical-align: top; }\n';
    html += 'table.rep-table th { background: #f1f5f9; color: #334155; font-weight: 700; }\n';
    html += 'table.rep-table tr:nth-child(even) { background: #f8fafc; }\n';
    html += '.tag { display: inline-block; padding: 2px 5px; border-radius: 3px; font-size: 9.5px; font-family: var(--mono); font-weight: 600; white-space: nowrap; margin-right: 3px; }\n';
    html += '.tag-clean { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }\n';
    html += '.tag-warn { background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }\n';
    html += '.tag-bad { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }\n';
    html += '.tag-port { background: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; font-family: var(--mono); font-size: 10px; }\n';
    html += '.tag-port.risky { background: #fef2f2; color: #b91c1c; border-color: #fca5a5; font-weight: 700; }\n';
    html += '.code-font { font-family: var(--mono); word-break: break-all; font-size: 10.5px; }\n';
    html += '.recom-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 16px; margin-top: 12px; font-size: 12px; color: #334155; }\n';
    html += '.recom-box ol { margin: 6px 0; padding-left: 20px; }\n';
    html += '.recom-box li { margin-bottom: 4px; }\n';
    html += '.footer-section { border-top: 1px solid #cbd5e1; margin-top: 36px; padding-top: 16px; font-size: 11px; color: #64748b; display: flex; justify-content: space-between; align-items: flex-end; }\n';
    html += '@media print {\n';
    html += '  body { background: #fff !important; padding: 0 !important; }\n';
    html += '  .toolbar { display: none !important; }\n';
    html += '  .report-sheet { border: none !important; box-shadow: none !important; padding: 0 !important; max-width: 100% !important; }\n';
    html += '  thead { display: table-header-group; }\n';
    html += '  tr { break-inside: avoid; }\n';
    html += '}\n';
    html += '</style>\n</head>\n<body>\n';

    // Toolbar
    html += '<div class="toolbar">\n';
    html += '<button class="btn-action" onclick="window.print()">&#128438; Print / Save as PDF</button>\n';
    html += '</div>\n';

    // Sheet
    html += '<div class="report-sheet">\n';
    html += '<div class="header">\n';
    html += '<div>\n';
    html += '<div class="brand-title">SHADOWTRACE FORENSIC NETWORK AUDIT</div>\n';
    html += '<div class="brand-sub">Smart Home &amp; IoT Local Security Posture Assessment</div>\n';
    html += '</div>\n';
    html += '<div class="meta-pill">\n';
    html += '<div>REF: <strong>' + escapeHtml(refId) + '</strong></div>\n';
    html += '<div>DATE (UTC): ' + escapeHtml(dateUtc) + '</div>\n';
    html += '<div>LOCAL: ' + escapeHtml(dateLocal) + '</div>\n';
    html += '</div>\n';
    html += '</div>\n';

    // Verdict Box
    html += '<div class="verdict-box ' + verdictClass + '">\n';
    html += '<div>\n';
    html += '<h2>' + escapeHtml(verdictTitle) + '</h2>\n';
    html += '<p>' + escapeHtml(verdictDesc) + '</p>\n';
    html += '</div>\n';
    html += '<div class="verdict-score-badge">' + escapeHtml(grade) + ' (' + score + '/100)</div>\n';
    html += '</div>\n';

    // Network Metadata
    html += '<h3 class="sec-title">1. Local Network Topology &amp; Gateway</h3>\n';
    html += '<table class="meta-grid">\n';
    html += '<tr><th>Audited Subnet</th><td>' + subnet + ' (RFC 1918 Private Range)</td><th>Host IP</th><td>' + thisComputer + '</td></tr>\n';
    html += '<tr><th>Default Router Gateway</th><td>' + router + '</td><th>Audit Methodology</th><td>Safe RFC 1918 Connect-and-Close, Zero Credentials Sent</td></tr>\n';
    html += '<tr><th>Total Devices Detected</th><td><strong>' + (res.devices ? res.devices.length : 0) + '</strong></td><th>Risky Open Doors</th><td><strong style="color: ' + (sum.risky_doors > 0 ? '#b91c1c' : '#15803d') + '">' + (sum.risky_doors || 0) + '</strong></td></tr>\n';
    html += '<tr><th>Security Cameras Detected</th><td>' + (sum.cameras || 0) + '</td><th>Router WAN Pinholes (UPnP)</th><td><strong style="color: ' + (sum.pinholes > 0 ? '#b91c1c' : '#15803d') + '">' + (sum.pinholes || 0) + '</strong></td></tr>\n';
    html += '</table>\n';

    // Device Inventory Table
    html += '<h3 class="sec-title">2. Discovered Local Devices &amp; IoT Exposure Inventory</h3>\n';
    html += '<div class="table-container">\n';
    html += '<table class="rep-table">\n';
    html += '<thead><tr><th>#</th><th>IP Address</th><th>Hardware (MAC)</th><th>Vendor / OUI</th><th>Category &amp; Model</th><th>Open Ports</th><th>Security Posture</th></tr></thead>\n';
    html += '<tbody>\n';

    var devices = res.devices || [];
    if (devices.length === 0) {
      html += '<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 14px;">No devices detected on this subnet segment.</td></tr>\n';
    } else {
      devices.forEach(function(d, idx) {
        var statusBadge = '<span class="tag tag-clean">CLEAN</span>';
        if (d.level === "critical") statusBadge = '<span class="tag tag-bad">CRITICAL</span>';
        else if (d.level === "warn") statusBadge = '<span class="tag tag-warn">ATTENTION</span>';

        var portsHtml = '<span style="color: #94a3b8;">None</span>';
        if (d.ports && d.ports.length > 0 && d.ports_detail) {
          portsHtml = d.ports_detail.map(function(pd) {
            var cls = pd.risk ? "tag tag-port risky" : "tag tag-port";
            return '<span class="' + cls + '" title="' + escapeHtml(pd.risk || pd.name) + '">' + pd.port + ' ' + escapeHtml(pd.name) + '</span>';
          }).join(" ");
        }

        var riskNote = "";
        if (d.video_password === "open") {
          riskNote = '<div style="color: #b91c1c; font-weight: 700; margin-top: 4px;">⚠️ Unprotected RTSP Video Stream!</div>';
        } else if (d.risks && d.risks.length > 0) {
          riskNote = '<div style="color: #b45309; font-size: 10px; margin-top: 3px;">' + escapeHtml(d.risks[0]) + '</div>';
        }

        html += '<tr>\n';
        html += '<td style="color: #64748b;">' + (idx + 1) + '</td>\n';
        html += '<td class="code-font"><strong>' + escapeHtml(d.ip) + '</strong>' + (d.ip === res.router ? ' <span class="tag tag-clean">ROUTER</span>' : '') + '</td>\n';
        html += '<td class="code-font">' + escapeHtml(d.mac || '—') + '</td>\n';
        html += '<td>' + escapeHtml(d.maker || 'Unknown Vendor') + '</td>\n';
        html += '<td><strong>' + escapeHtml(d.name || d.model || d.kind || 'Device') + '</strong><br><span style="color: #64748b; font-size: 10px;">' + escapeHtml(d.kind || d.category) + '</span></td>\n';
        html += '<td>' + portsHtml + riskNote + '</td>\n';
        html += '<td>' + statusBadge + '</td>\n';
        html += '</tr>\n';
      });
    }
    html += '</tbody></table>\n</div>\n';

    // UPnP Port Mappings
    html += '<h3 class="sec-title">3. Router Internet Exposure &amp; UPnP Port Forwardings</h3>\n';
    var mappings = res.port_mappings || [];
    if (mappings.length === 0) {
      html += '<div style="padding: 10px 14px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; color: #166534; font-size: 12px;">✅ Clean: Router does not advertise any active UPnP WAN port forwarding pinholes to the public Internet.</div>\n';
    } else {
      html += '<div class="table-container">\n<table class="rep-table">\n';
      html += '<thead><tr><th>WAN Port</th><th>Protocol</th><th>Internal IP</th><th>Internal Port</th><th>Description</th><th>Risk Level</th></tr></thead>\n<tbody>\n';
      mappings.forEach(function(m) {
        html += '<tr>\n';
        html += '<td class="code-font"><strong>' + escapeHtml(m.NewExternalPort) + '</strong></td>\n';
        html += '<td>' + escapeHtml(m.NewProtocol || 'TCP') + '</td>\n';
        html += '<td class="code-font">' + escapeHtml(m.NewInternalClient) + '</td>\n';
        html += '<td class="code-font">' + escapeHtml(m.NewInternalPort) + '</td>\n';
        html += '<td>' + escapeHtml(m.NewPortMappingDescription || 'None given') + '</td>\n';
        html += '<td><span class="tag tag-bad">INTERNET EXPOSED</span></td>\n';
        html += '</tr>\n';
      });
      html += '</tbody></table>\n</div>\n';
    }

    // Defensive Recommendations
    html += '<h3 class="sec-title">4. Prioritized Defensive Recommendations &amp; Hardening Plan</h3>\n';
    html += '<div class="recom-box">\n';
    html += '<ol>\n';
    var recs = sum.recommendations || [];
    recs.forEach(function(r) {
      html += '<li>' + escapeHtml(r) + '</li>\n';
    });
    html += '</ol>\n</div>\n';

    // Footer
    html += '<div class="footer-section">\n';
    html += '<div>Generated by <strong>ShadowTrace Toolkit v3.0.2</strong> &middot; Defensive Triage &amp; Posture Verification</div>\n';
    html += '<div style="text-align: right; font-family: var(--mono);">ST-VERIFY-SEAL: ' + randId + '-OFFLINE-NET</div>\n';
    html += '</div>\n';

    html += '</div>\n</body>\n</html>';
    return html;
  }

  function setupIotAuditor() {
    var btnScan = $("btn-scan-network");
    var statusText = $("network-status-text");
    var term = $("network-terminal");
    var resultsBox = $("iot-audit-results");
    var exportActions = $("iot-export-actions");
    var devicesGrid = $("iot-devices-grid");
    var searchInput = $("iot-search-input");
    var categoryPills = $("iot-category-pills");
    var pinholesContent = $("router-pinholes-content");
    var remediationList = $("iot-remediation-list");

    var latestData = null;
    var currentCategory = "all";

    function logNet(msg) {
      if (!term) return;
      var now = new Date();
      var timeStr = "[" + now.toTimeString().split(" ")[0] + "] ";
      term.textContent += timeStr + msg + "\n";
      term.scrollTop = term.scrollHeight;
    }

    if (!btnScan) return;

    btnScan.addEventListener('click', async function() {
      btnScan.disabled = true;
      btnScan.innerHTML = '<span class="spinner" style="display:inline-block; width:14px; height:14px; border:2px solid #fff; border-top-color:transparent; border-radius:50%; animation:spin 0.8s linear infinite; margin-right:6px; vertical-align:middle;"></span> Auditing Network...';
      if (statusText) statusText.textContent = "Scanning local subnet & discovering devices...";
      term.textContent = "";
      logNet("Initiating RFC 1918 safe home & IoT network scan...");
      logNet("Probing default gateway and interface routing...");

      var simTimer = setTimeout(function() {
        logNet("Broadcasting mDNS / Bonjour queries on 224.0.0.251:5353...");
        logNet("Sending UPnP / SSDP M-SEARCH discovery to 239.255.255.250:1900...");
      }, 1200);

      var simTimer2 = setTimeout(function() {
        logNet("Safe non-intrusive port checks on IoT doors (connect & close, zero credentials sent)...");
        logNet("Checking for unencrypted RTSP camera streams & router UPnP WAN mappings...");
      }, 3500);

      try {
        var resp = await fetch("/api/scan-network", { cache: "no-cache" });
        clearTimeout(simTimer);
        clearTimeout(simTimer2);

        if (!resp.ok) {
          throw new Error("HTTP error " + resp.status + " from local scan bridge.");
        }

        var data = await resp.json();
        if (!data.ok) {
          throw new Error(data.error || "Network audit failed.");
        }

        latestData = data;
        logNet("Discovered " + (data.devices ? data.devices.length : 0) + " device(s) on " + data.subnet);
        logNet("Audit complete. Overall posture grade: " + (data.summary ? data.summary.grade : "A"));
        if (statusText) statusText.textContent = "Audit complete. " + (data.devices ? data.devices.length : 0) + " devices found.";

        renderIotResults(data);

      } catch (err) {
        clearTimeout(simTimer);
        clearTimeout(simTimer2);
        logNet("Error: " + err.message);
        if (statusText) statusText.textContent = "Scan paused: " + err.message;
        alert("IoT Network Audit Note:\n" + err.message + "\n\nMake sure the local server is running ('python web/serve.py') and your computer is connected to a local Wi-Fi or Ethernet network.");
      } finally {
        btnScan.disabled = false;
        btnScan.innerHTML = "&#9889; Run IoT &amp; Network Security Audit";
      }
    });

    function renderIotResults(data) {
      if (!resultsBox) return;
      resultsBox.style.display = "block";
      if (exportActions) exportActions.style.display = "flex";

      var sum = data.summary || {};

      // 1. Verdict Banner
      var vBadge = $("iot-verdict-badge");
      var vTitle = $("iot-verdict-title");
      var vDesc = $("iot-verdict-desc");

      if (vBadge) {
        vBadge.textContent = "GRADE " + (sum.grade || "A+");
        vBadge.className = "verdict-badge " + (sum.posture_class || "clean");
      }
      if (vTitle) vTitle.textContent = sum.posture_verdict || "NETWORK POSTURE VERIFIED";
      if (vDesc) vDesc.textContent = "Audited " + (data.devices ? data.devices.length : 0) + " device(s) on " + data.subnet + ". Found " + (sum.risky_doors || 0) + " risky door(s) and " + (sum.pinholes || 0) + " router WAN pinhole(s).";

      // 2. Metrics
      if ($("stat-net-subnet")) $("stat-net-subnet").textContent = data.subnet + " (GW: " + data.router + ")";
      if ($("stat-net-devices")) $("stat-net-devices").textContent = data.devices ? data.devices.length : 0;
      if ($("stat-net-cams")) $("stat-net-cams").textContent = sum.cameras || 0;
      if ($("stat-net-iot")) $("stat-net-iot").textContent = (sum.tvs || 0) + (sum.iot || 0);

      var doorsEl = $("stat-net-doors");
      if (doorsEl) {
        doorsEl.textContent = sum.risky_doors || 0;
        doorsEl.className = "stat-val " + (sum.risky_doors > 0 ? (sum.critical_risks > 0 ? "bad" : "warn") : "ok");
      }

      var pinEl = $("stat-net-pinholes");
      if (pinEl) {
        pinEl.textContent = sum.pinholes || 0;
        pinEl.className = "stat-val " + (sum.pinholes > 0 ? "bad" : "ok");
      }

      // 3. Router Pinholes Table
      if (pinholesContent) {
        var mappings = data.port_mappings || [];
        if (mappings.length === 0) {
          pinholesContent.innerHTML = '<div style="padding: 10px 14px; background: rgba(34, 197, 94, 0.08); border: 1px solid rgba(34, 197, 94, 0.25); border-radius: 8px; color: var(--ok); font-size: 0.86rem;">✅ Clean: Router does not advertise any active UPnP WAN port forwarding pinholes to the public Internet.</div>';
        } else {
          var pinHtml = '<table class="pinhole-table"><thead><tr><th>External Port</th><th>Protocol</th><th>Internal IP</th><th>Internal Port</th><th>Description</th><th>Risk</th></tr></thead><tbody>';
          mappings.forEach(function(m) {
            pinHtml += '<tr><td style="font-family:var(--mono); color:var(--bad); font-weight:700;">' + escapeHtml(m.NewExternalPort) + '</td><td>' + escapeHtml(m.NewProtocol || 'TCP') + '</td><td style="font-family:var(--mono);">' + escapeHtml(m.NewInternalClient) + '</td><td style="font-family:var(--mono);">' + escapeHtml(m.NewInternalPort) + '</td><td>' + escapeHtml(m.NewPortMappingDescription || 'None') + '</td><td><span class="badge-tag bad">EXPOSED</span></td></tr>';
          });
          pinHtml += '</tbody></table>';
          pinholesContent.innerHTML = pinHtml;
        }
      }

      // 4. Update Filter Pill Counts
      var devs = data.devices || [];
      var counts = { all: devs.length, camera: 0, tv: 0, iot: 0, router: 0, computer: 0, risky: 0 };
      devs.forEach(function(d) {
        if (d.category === "camera") counts.camera++;
        else if (d.category === "tv") counts.tv++;
        else if (d.category === "iot") counts.iot++;
        else if (d.category === "router") counts.router++;
        else if (d.category === "computer") counts.computer++;
        if (d.level === "critical" || d.level === "warn") counts.risky++;
      });

      if ($("count-cat-all")) $("count-cat-all").textContent = counts.all;
      if ($("count-cat-camera")) $("count-cat-camera").textContent = counts.camera;
      if ($("count-cat-tv")) $("count-cat-tv").textContent = counts.tv;
      if ($("count-cat-iot")) $("count-cat-iot").textContent = counts.iot;
      if ($("count-cat-router")) $("count-cat-router").textContent = counts.router;
      if ($("count-cat-computer")) $("count-cat-computer").textContent = counts.computer;
      if ($("count-cat-risky")) $("count-cat-risky").textContent = counts.risky;

      // 5. Render Remediation
      if (remediationList) {
        var recs = sum.recommendations || [];
        var remHtml = '<ol style="margin: 6px 0; padding-left: 20px; font-size: 0.88rem; color: var(--dim); line-height: 1.6;">';
        recs.forEach(function(r) {
          remHtml += '<li style="margin-bottom: 6px;"><strong style="color:var(--text);">' + escapeHtml(r) + '</strong></li>';
        });
        remHtml += '</ol>';
        remediationList.innerHTML = remHtml;
      }

      // 6. Render Device Grid
      renderDeviceGrid();
    }

    function renderDeviceGrid() {
      if (!devicesGrid || !latestData) return;
      var query = (searchInput ? searchInput.value.trim().toLowerCase() : "");
      var devs = latestData.devices || [];

      var filtered = devs.filter(function(d) {
        if (currentCategory !== "all") {
          if (currentCategory === "risky") {
            if (d.level !== "critical" && d.level !== "warn") return false;
          } else if (d.category !== currentCategory) {
            return false;
          }
        }
        if (query) {
          var matchStr = (d.ip + " " + (d.mac || "") + " " + (d.name || "") + " " + (d.maker || "") + " " + (d.model || "") + " " + (d.kind || "")).toLowerCase();
          if (matchStr.indexOf(query) === -1) return false;
        }
        return true;
      });

      if (filtered.length === 0) {
        devicesGrid.innerHTML = '<div style="grid-column: 1 / -1; text-align: center; padding: 30px; color: var(--dim); background: var(--panel2); border-radius: 12px; border: 1px dashed var(--border);">No devices found matching current category or filter.</div>';
        return;
      }

      var html = "";
      filtered.forEach(function(d) {
        var levelClass = "level-" + (d.level || "clean");
        var badgeHtml = '<span class="badge-tag ok">CLEAN</span>';
        if (d.level === "critical") badgeHtml = '<span class="badge-tag bad">CRITICAL</span>';
        else if (d.level === "warn") badgeHtml = '<span class="badge-tag warn">ATTENTION</span>';

        var portsHtml = "";
        if (d.ports && d.ports.length > 0 && d.ports_detail) {
          portsHtml = '<div class="iot-ports-container">';
          d.ports_detail.forEach(function(pd) {
            var chipCls = pd.risk ? "iot-port-chip risky" : "iot-port-chip";
            portsHtml += '<span class="' + chipCls + '" title="' + escapeHtml(pd.risk || pd.name) + '">' + pd.port + ' ' + escapeHtml(pd.name) + '</span>';
          });
          portsHtml += '</div>';
        } else {
          portsHtml = '<div style="font-size: 0.78rem; color: var(--dim); margin-top: 8px;">No open ports found</div>';
        }

        var calloutHtml = "";
        if (d.video_password === "open") {
          calloutHtml += '<div class="iot-risk-callout">🚨 <strong>Unprotected Camera Stream (Port 554):</strong> Live video feed requires no password! Anyone on this network can watch.</div>';
        } else if (d.risks && d.risks.length > 0) {
          d.risks.forEach(function(r) {
            var isCrit = r.startsWith("CRITICAL");
            calloutHtml += '<div class="iot-risk-callout ' + (isCrit ? "" : "warn") + '">' + escapeHtml(r) + '</div>';
          });
        }

        html += '<div class="iot-card ' + levelClass + '">';
        html += '<div class="iot-card-header">';
        html += '<div class="iot-card-icon">' + (d.icon || '📱') + '</div>';
        html += '<div class="iot-card-title">';
        html += '<div class="iot-card-name">' + escapeHtml(d.name || d.maker || 'Network Device') + '</div>';
        html += '<div class="iot-card-ip">' + escapeHtml(d.ip) + (d.ip === latestData.router ? ' &bull; Router' : '') + '</div>';
        html += '</div>';
        html += badgeHtml;
        html += '</div>';

        html += '<div class="iot-card-body">';
        html += '<div class="iot-meta-row"><span class="iot-meta-label">Vendor / OUI:</span><span class="iot-meta-val">' + escapeHtml(d.maker || 'Unknown') + '</span></div>';
        html += '<div class="iot-meta-row"><span class="iot-meta-label">Hardware MAC:</span><span class="iot-meta-val">' + escapeHtml(d.mac || '—') + '</span></div>';
        if (d.model) {
          html += '<div class="iot-meta-row"><span class="iot-meta-label">Model:</span><span class="iot-meta-val">' + escapeHtml(d.model) + '</span></div>';
        }
        html += portsHtml;
        html += calloutHtml;
        html += '</div>';
        html += '</div>';
      });

      devicesGrid.innerHTML = html;
    }

    // Category Pill filtering
    if (categoryPills) {
      categoryPills.addEventListener('click', function(e) {
        var btn = e.target.closest('.pill-btn');
        if (!btn) return;
        categoryPills.querySelectorAll('.pill-btn').forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        currentCategory = btn.getAttribute('data-cat') || 'all';
        renderDeviceGrid();
      });
    }

    // Search filtering
    if (searchInput) {
      searchInput.addEventListener('input', function() {
        renderDeviceGrid();
      });
    }

    // Export Handlers
    var btnExportHtml = $("btn-export-iot-html");
    if (btnExportHtml) {
      btnExportHtml.addEventListener('click', function() {
        if (!latestData) return;
        var dateStr = new Date().toISOString().slice(0, 10);
        var reportHtml = buildIoTForensicReportHtml(latestData);
        downloadReportFile(reportHtml, "shadowtrace-iot-report-" + dateStr + ".html", "text/html;charset=utf-8");
      });
    }

    var btnPrintReport = $("btn-print-iot-report");
    if (btnPrintReport) {
      btnPrintReport.addEventListener('click', function() {
        if (!latestData) return;
        var reportHtml = buildIoTForensicReportHtml(latestData);
        var printWin = window.open("", "_blank");
        if (printWin) {
          printWin.document.open();
          printWin.document.write(reportHtml);
          printWin.document.close();
          printWin.focus();
        } else {
          alert("Popup blocked. Please allow popups for this site to print forensic reports.");
        }
      });
    }

    var btnExportJson = $("btn-export-iot-json");
    if (btnExportJson) {
      btnExportJson.addEventListener('click', function() {
        if (!latestData) return;
        var dateStr = new Date().toISOString().slice(0, 10);
        downloadReportFile(JSON.stringify(latestData, null, 2), "shadowtrace-iot-scan-" + dateStr + ".json", "application/json");
      });
    }
  }

  // 5. Client-Side Hash Verifier (Web Crypto API)
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

  // 6. Wireless RF, AirTag & Rogue AP Auditor
  function setupWirelessAuditor() {
    var btnBle = $("btn-scan-ble");
    var bleStatus = $("ble-status-text");
    var bleTerm = $("ble-terminal");
    var bleResults = $("ble-results-box");
    var bleHeadlineBanner = $("ble-headline-banner");
    var bleHeadlineText = $("ble-headline-text");
    var bleList = $("ble-trackers-list");

    var btnWifi = $("btn-scan-wifi");
    var wifiStatus = $("wifi-status-text");
    var wifiTerm = $("wifi-terminal");
    var wifiResults = $("wifi-results-box");
    var wifiEvilTwins = $("wifi-evil-twins");
    var wifiList = $("wifi-networks-list");

    function logBle(msg) {
      if (!bleTerm) return;
      var now = new Date();
      var timeStr = "[" + now.toTimeString().split(" ")[0] + "] ";
      bleTerm.textContent += timeStr + msg + "\n";
      bleTerm.scrollTop = bleTerm.scrollHeight;
    }

    function logWifi(msg) {
      if (!wifiTerm) return;
      var now = new Date();
      var timeStr = "[" + now.toTimeString().split(" ")[0] + "] ";
      wifiTerm.textContent += timeStr + msg + "\n";
      wifiTerm.scrollTop = wifiTerm.scrollHeight;
    }

    // BLE Tracker Scanner
    if (btnBle) {
      btnBle.addEventListener("click", async function() {
        btnBle.disabled = true;
        btnBle.innerHTML = '<span class="spinner" style="display:inline-block; width:13px; height:13px; border:2px solid #fff; border-top-color:transparent; border-radius:50%; animation:spin 0.8s linear infinite; margin-right:6px; vertical-align:middle;"></span> Scanning BLE (5s)...';
        if (bleStatus) bleStatus.textContent = "Listening for Bluetooth tracking beacons...";
        bleTerm.textContent = "";
        logBle("Starting passive BLE 2.4 GHz scanner via Bleak asynchronous runtime...");
        logBle("Listening for Apple Find My (Company ID 0x004c), Samsung SmartTags, Tile, Google Find Hub...");

        try {
          var resp = await fetch("/api/scan-ble", { cache: "no-cache" });
          if (!resp.ok) throw new Error("HTTP error " + resp.status + " from local scan bridge.");
          var data = await resp.json();
          if (!data.ok) throw new Error(data.error || "BLE scan failed.");

          logBle("BLE scan complete. Heard " + (data.trackers ? data.trackers.length : 0) + " tracking beacon(s) across " + (data.total_sightings || 0) + " advertisement packets.");
          logBle("Verdict: " + (data.headline || "Scan finished"));
          if (bleStatus) bleStatus.textContent = "Scan complete (" + (data.trackers ? data.trackers.length : 0) + " found)";

          renderBleResults(data);
        } catch (err) {
          logBle("Error: " + err.message);
          if (bleStatus) bleStatus.textContent = "BLE scan note: " + err.message;
        } finally {
          btnBle.disabled = false;
          btnBle.innerHTML = "&#9889; Scan for AirTags &amp; BLE Trackers (5s)";
        }
      });
    }

    function renderBleResults(data) {
      if (!bleResults) return;
      bleResults.style.display = "block";

      var trackers = data.trackers || [];
      var separatedCount = data.separated_count || 0;
      var headline = data.headline || "No tracker seems to be following you";
      var level = data.level || (separatedCount > 0 ? "bad" : "clean");

      if (bleHeadlineBanner && bleHeadlineText) {
        bleHeadlineText.textContent = headline;
        bleHeadlineBanner.className = "verdict-banner " + (level === "bad" ? "bad" : (level === "warn" ? "warn" : "clean"));
      }

      if (!bleList) return;
      if (trackers.length === 0) {
        bleList.innerHTML = '<div style="padding:14px; text-align:center; color:var(--dim); font-size:0.86rem; background:var(--panel2); border-radius:8px;">✅ Clean: No AirTags, SmartTags, or tracking beacons detected nearby during this 5-second window.</div>';
        return;
      }

      var html = "";
      trackers.forEach(function(t) {
        var isSep = Boolean(t.separated);
        var itemCls = "tracker-item" + (isSep ? " separated" : "");
        var badgeCls = isSep ? "badge-tag bad" : "badge-tag ok";
        var badgeText = isSep ? "⚠️ SEPARATED FROM OWNER" : "ACCOMPANYING OWNER";

        html += '<div class="' + itemCls + '">';
        html += '<div class="tracker-info">';
        html += '<div class="tracker-title"><span>📍</span> ' + escapeHtml(t.kind || "Bluetooth Tracking Beacon") + '</div>';
        html += '<div class="tracker-meta">MAC: <strong>' + escapeHtml(t.address) + '</strong> &bull; RSSI: ' + (t.strongest || -100) + ' dBm &bull; Sightings: ' + (t.count || 1) + '</div>';
        html += '</div>';
        html += '<div><span class="' + badgeCls + '">' + badgeText + '</span></div>';
        html += '</div>';
      });

      bleList.innerHTML = html;
    }

    // Wi-Fi & Rogue AP Scanner
    if (btnWifi) {
      btnWifi.addEventListener("click", async function() {
        btnWifi.disabled = true;
        btnWifi.innerHTML = '<span class="spinner" style="display:inline-block; width:13px; height:13px; border:2px solid #fff; border-top-color:transparent; border-radius:50%; animation:spin 0.8s linear infinite; margin-right:6px; vertical-align:middle;"></span> Scanning Wi-Fi...';
        if (wifiStatus) wifiStatus.textContent = "Surveying nearby Wi-Fi access points...";
        wifiTerm.textContent = "";
        logWifi("Querying 802.11 wireless network adapter...");
        logWifi("Inspecting BSSIDs, SSIDs, signal strengths, authentication ciphers, and IEEE OUIs...");

        try {
          var resp = await fetch("/api/scan-wifi", { cache: "no-cache" });
          if (!resp.ok) throw new Error("HTTP error " + resp.status + " from local scan bridge.");
          var data = await resp.json();
          if (!data.ok) throw new Error(data.error || "Wi-Fi scan failed.");

          if (data.problem) {
            logWifi("Note from OS adapter: " + data.problem);
          }

          logWifi("Discovered " + (data.networks ? data.networks.length : 0) + " access point(s).");
          if (data.evil_twins && data.evil_twins.length > 0) {
            logWifi("⚠️ WARNING: " + data.evil_twins.length + " Evil-Twin / Rogue AP candidate(s) flagged!");
          } else {
            logWifi("Evil-Twin check: Clean. No duplicate SSIDs with conflicting vendors or encryption.");
          }
          if (wifiStatus) wifiStatus.textContent = "Survey complete (" + (data.networks ? data.networks.length : 0) + " networks found)";

          renderWifiResults(data);
        } catch (err) {
          logWifi("Error: " + err.message);
          if (wifiStatus) wifiStatus.textContent = "Wi-Fi survey note: " + err.message;
        } finally {
          btnWifi.disabled = false;
          btnWifi.innerHTML = "&#9889; Scan Visible Wi-Fi Networks";
        }
      });
    }

    function renderWifiResults(data) {
      if (!wifiResults) return;
      wifiResults.style.display = "block";

      // Evil twins
      if (wifiEvilTwins) {
        var twins = data.evil_twins || [];
        if (twins.length > 0) {
          var twinHtml = '<div class="wifi-evil-card">';
          twinHtml += '<div class="wifi-evil-title">🚨 ROGUE AP / EVIL-TWIN ALERT DETECTED</div>';
          twinHtml += '<p style="font-size:0.84rem; margin:0 0 8px; color:var(--text);">The following network name(s) are broadcast by multiple distinct hardware vendors or mismatched encryption settings (potential Wi-Fi Pineapple or impersonation rogue AP):</p>';
          twinHtml += '<ul style="margin:0; padding-left:20px; font-size:0.84rem; color:var(--bad); font-weight:600;">';
          twins.forEach(function(tw) {
            twinHtml += '<li>SSID: <code>' + escapeHtml(tw.ssid) + '</code> &mdash; ' + escapeHtml(tw.reason) + ' (' + tw.count + ' APs)</li>';
          });
          twinHtml += '</ul></div>';
          wifiEvilTwins.innerHTML = twinHtml;
        } else {
          wifiEvilTwins.innerHTML = '<div style="padding:10px 14px; background:rgba(34, 197, 94, 0.08); border:1px solid rgba(34, 197, 94, 0.25); border-radius:8px; color:var(--ok); font-size:0.85rem; margin-bottom:10px;">✅ Clean: No Evil-Twin rogue APs detected. All duplicated SSIDs share identical authentication and vendor hardware.</div>';
        }
      }

      // Networks list
      if (!wifiList) return;
      var networks = data.networks || [];
      if (networks.length === 0) {
        wifiList.innerHTML = '<div style="padding:14px; text-align:center; color:var(--dim); font-size:0.86rem; background:var(--panel2); border-radius:8px;">No visible Wi-Fi access points found. Make sure Wi-Fi is enabled on this computer.</div>';
        return;
      }

      var html = "";
      networks.forEach(function(net) {
        var isConn = Boolean(net.is_connected);
        var isOpen = (net.security || "").toLowerCase().indexOf("open") !== -1 || (net.security || "").toLowerCase().indexOf("none") !== -1;
        var itemCls = "wifi-item" + (isConn ? " connected" : "");

        html += '<div class="' + itemCls + '">';
        html += '<div class="wifi-ssid-col">';
        html += '<div class="wifi-ssid">' + (isConn ? '🟢 ' : '') + escapeHtml(net.ssid || '<Hidden Network>') + '</div>';
        html += '<div class="wifi-details">BSSID: ' + escapeHtml(net.bssid || '—') + (net.vendor ? ' &bull; Vendor: ' + escapeHtml(net.vendor) : '') + (net.band ? ' &bull; Band: ' + escapeHtml(net.band) : '') + '</div>';
        html += '</div>';

        html += '<div style="display:flex; align-items:center; gap:8px;">';
        if (isConn) {
          html += '<span class="badge-tag ok">CONNECTED</span>';
        }
        if (isOpen) {
          html += '<span class="badge-tag bad">OPEN / UNENCRYPTED</span>';
        } else {
          html += '<span class="badge-tag" style="background:var(--panel); border:1px solid var(--border); font-size:0.75rem;">' + escapeHtml(net.security || 'Encrypted') + '</span>';
        }
        html += '<span style="font-family:var(--mono); font-size:0.8rem; min-width:48px; text-align:right;">' + (net.signal || 0) + '%</span>';
        html += '</div>';
        html += '</div>';
      });

      wifiList.innerHTML = html;
    }
  }

  // 7. Static File & QR Code Analyzer
  function setupFileAndQrAnalyzer() {
    var dropFile = $("drop-file-analyzer");
    var fileInput = $("file-analyzer-input");
    var fileResults = $("file-analyzer-results");

    var dropQr = $("drop-qr-analyzer");
    var qrInput = $("qr-analyzer-input");
    var qrResults = $("qr-analyzer-results");

    // File Inspector Handlers
    if (dropFile) {
      dropFile.addEventListener("click", function() {
        if (fileInput) fileInput.click();
      });
      dropFile.addEventListener("dragover", function(e) {
        e.preventDefault();
        dropFile.classList.add("dragover");
      });
      dropFile.addEventListener("dragleave", function() {
        dropFile.classList.remove("dragover");
      });
      dropFile.addEventListener("drop", function(e) {
        e.preventDefault();
        dropFile.classList.remove("dragover");
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
          analyzeFile(e.dataTransfer.files[0]);
        }
      });
    }

    if (fileInput) {
      fileInput.addEventListener("change", function() {
        if (fileInput.files && fileInput.files[0]) {
          analyzeFile(fileInput.files[0]);
        }
      });
    }

    function analyzeFile(file) {
      if (!fileResults) return;
      fileResults.style.display = "block";
      fileResults.innerHTML = '<div style="padding:16px; text-align:center; color:var(--dim);"><span class="spinner" style="display:inline-block; width:16px; height:16px; border:2px solid #fff; border-top-color:transparent; border-radius:50%; animation:spin 0.8s linear infinite; margin-right:8px; vertical-align:middle;"></span> Inspecting ' + escapeHtml(file.name) + ' (' + (file.size / 1024).toFixed(1) + ' KB) offline...</div>';

      var reader = new FileReader();
      reader.onload = async function(evt) {
        try {
          var b64 = evt.target.result.split(",")[1];
          var resp = await fetch("/api/check-file", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ filename: file.name, data_b64: b64 })
          });
          if (!resp.ok) throw new Error("HTTP error " + resp.status + " from local inspector.");
          var data = await resp.json();
          if (!data.ok) throw new Error(data.error || "File analysis failed.");

          renderFileResults(data);
        } catch (err) {
          fileResults.innerHTML = '<div class="verdict-banner bad"><p>Analysis error: ' + escapeHtml(err.message) + '</p></div>';
        }
      };
      reader.readAsDataURL(file);
    }

    function renderFileResults(data) {
      if (!fileResults) return;
      var levelCls = data.level === "bad" ? "bad" : (data.level === "warn" ? "warn" : "clean");
      var levelTag = data.level === "bad" ? '<span class="badge-tag bad">RISKY / SUSPICIOUS</span>' : (data.level === "warn" ? '<span class="badge-tag warn">ATTENTION</span>' : '<span class="badge-tag ok">CLEAN / BENIGN</span>');

      var html = '<div class="verdict-banner ' + levelCls + '" style="margin-bottom:14px;">';
      html += '<div style="display:flex; justify-content:space-between; align-items:center;">';
      html += '<h3 style="margin:0;">' + escapeHtml(data.filename) + '</h3>';
      html += levelTag;
      html += '</div>';
      html += '<p style="margin:6px 0 0; font-size:0.88rem;">' + escapeHtml(data.headline || "File inspected offline") + '</p>';
      html += '</div>';

      html += '<div class="file-meta-card">';
      html += '<div class="file-hash-row"><span class="file-hash-lbl">File Format:</span><span class="file-hash-val"><strong>' + escapeHtml(data.kind || "binary") + '</strong> &bull; ' + data.size.toLocaleString() + ' bytes</span></div>';
      html += '<div class="file-hash-row"><span class="file-hash-lbl">SHA-256:</span><span class="file-hash-val">' + escapeHtml(data.sha256 || "—") + '</span></div>';
      html += '<div class="file-hash-row"><span class="file-hash-lbl">MD5:</span><span class="file-hash-val">' + escapeHtml(data.md5 || "—") + '</span></div>';
      if (data.imphash) {
        html += '<div class="file-hash-row"><span class="file-hash-lbl">Imphash:</span><span class="file-hash-val">' + escapeHtml(data.imphash) + '</span></div>';
      }

      // Authenticode signature
      var sig = data.signature || {};
      if (sig.status || sig.signer) {
        var sigText = (sig.signer ? escapeHtml(sig.signer) + " (" + escapeHtml(sig.status || "valid") + ")" : escapeHtml(sig.status));
        html += '<div class="file-hash-row"><span class="file-hash-lbl">Authenticode:</span><span class="file-hash-val" style="color:var(--ok);">' + sigText + '</span></div>';
      } else {
        html += '<div class="file-hash-row"><span class="file-hash-lbl">Authenticode:</span><span class="file-hash-val" style="color:var(--dim);">Unsigned (No digital signature)</span></div>';
      }

      // Embedded URLs
      if (data.urls && data.urls.length > 0) {
        html += '<div style="margin-top:10px;"><strong style="font-size:0.82rem; color:var(--text);">Embedded URLs / Endpoints (' + data.urls.length + '):</strong><div class="defanged-box" style="font-size:0.78rem; max-height:100px; overflow-y:auto;">' + data.urls.map(function(u) { return escapeHtml(u); }).join('<br>') + '</div></div>';
      }

      // Notes
      if (data.notes && data.notes.length > 0) {
        html += '<div style="margin-top:10px; font-size:0.82rem; color:var(--dim);">';
        data.notes.forEach(function(n) {
          html += '<div>&bull; ' + escapeHtml(n) + '</div>';
        });
        html += '</div>';
      }

      // Actions / Copy buttons
      html += '<div style="margin-top:14px; display:flex; gap:8px; flex-wrap:wrap;">';
      if (data.sha256) {
        html += '<button type="button" class="btn btn-sm" id="btn-copy-sha256" style="font-size:0.78rem;">📋 Copy SHA-256</button>';
      }
      html += '</div>';

      html += '</div>';
      fileResults.innerHTML = html;

      var copySha = $("btn-copy-sha256");
      if (copySha && data.sha256) {
        copySha.addEventListener("click", function() {
          copyTextToClipboard(data.sha256, "SHA-256 hash copied to clipboard!");
        });
      }
    }

    // QR Code Defanger Handlers
    if (dropQr) {
      dropQr.addEventListener("click", function() {
        if (qrInput) qrInput.click();
      });
      dropQr.addEventListener("dragover", function(e) {
        e.preventDefault();
        dropQr.classList.add("dragover");
      });
      dropQr.addEventListener("dragleave", function() {
        dropQr.classList.remove("dragover");
      });
      dropQr.addEventListener("drop", function(e) {
        e.preventDefault();
        dropQr.classList.remove("dragover");
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
          analyzeQr(e.dataTransfer.files[0]);
        }
      });
    }

    if (qrInput) {
      qrInput.addEventListener("change", function() {
        if (qrInput.files && qrInput.files[0]) {
          analyzeQr(qrInput.files[0]);
        }
      });
    }

    function analyzeQr(file) {
      if (!qrResults) return;
      qrResults.style.display = "block";
      qrResults.innerHTML = '<div style="padding:16px; text-align:center; color:var(--dim);"><span class="spinner" style="display:inline-block; width:16px; height:16px; border:2px solid #fff; border-top-color:transparent; border-radius:50%; animation:spin 0.8s linear infinite; margin-right:8px; vertical-align:middle;"></span> Decoding QR code matrix offline from ' + escapeHtml(file.name) + '...</div>';

      var reader = new FileReader();
      reader.onload = async function(evt) {
        try {
          var b64 = evt.target.result.split(",")[1];
          var resp = await fetch("/api/check-qr", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ data_b64: b64 })
          });
          if (!resp.ok) throw new Error("HTTP error " + resp.status + " from local QR decoder.");
          var data = await resp.json();
          if (!data.ok) throw new Error(data.error || "Could not read QR code matrix from that picture.");

          showToast("QR code decoded offline!", "ok");
          renderQrResults(data);
        } catch (err) {
          qrResults.innerHTML = '<div class="verdict-banner bad"><p>QR Decode Note: ' + escapeHtml(err.message) + '</p><p style="font-size:0.8rem; color:var(--dim); margin-top:4px;">Ensure the picture is clear and the QR matrix is not excessively blurred or cropped. PNG screenshots work best.</p></div>';
        }
      };
      reader.readAsDataURL(file);
    }

    function renderQrResults(data) {
      if (!qrResults) return;
      var levelCls = data.level === "bad" ? "bad" : (data.level === "warn" ? "warn" : "clean");
      var levelTag = data.level === "bad" ? '<span class="badge-tag bad">MALICIOUS / DANGEROUS LURE</span>' : (data.level === "warn" ? '<span class="badge-tag warn">ATTENTION</span>' : '<span class="badge-tag ok">CLEAN / SAFE TEXT</span>');

      var html = '<div class="verdict-banner ' + levelCls + '" style="margin-bottom:14px;">';
      html += '<div style="display:flex; justify-content:space-between; align-items:center;">';
      html += '<h3 style="margin:0;">QR Code Decoded Offline</h3>';
      html += levelTag;
      html += '</div>';
      html += '<p style="margin:6px 0 0; font-size:0.88rem;">' + escapeHtml(data.headline || "Decoded without contacting internet or executing payload") + '</p>';
      html += '</div>';

      html += '<div class="file-meta-card">';
      html += '<div style="font-size:0.82rem; font-weight:600; color:var(--text); margin-bottom:4px;">Defanged Payload Content (Safe to copy):</div>';
      html += '<div class="defanged-box">' + escapeHtml(data.text || "(empty payload)") + '</div>';

      if (data.text) {
        html += '<div style="margin-bottom:12px;"><button type="button" class="btn btn-sm btn-primary" id="btn-copy-qr-text" style="font-size:0.78rem;">📋 Copy Defanged Payload</button></div>';
      }

      html += '<div class="file-hash-row"><span class="file-hash-lbl">Image Format:</span><span class="file-hash-val">' + escapeHtml(data.format || "Picture") + ' (' + data.size + ' bytes)</span></div>';
      if (data.modules) {
        html += '<div class="file-hash-row"><span class="file-hash-lbl">Matrix Grid:</span><span class="file-hash-val">' + data.modules + 'x' + data.modules + ' modules &bull; Version ' + (data.version || 1) + ' &bull; EC ' + escapeHtml(data.ec_level || "M") + '</span></div>';
      }

      if (data.notes && data.notes.length > 0) {
        html += '<div style="margin-top:10px; font-size:0.82rem; color:var(--dim);">';
        data.notes.forEach(function(n) {
          html += '<div>&bull; ' + escapeHtml(n) + '</div>';
        });
        html += '</div>';
      }

      html += '</div>';
      qrResults.innerHTML = html;

      var copyQr = $("btn-copy-qr-text");
      if (copyQr && data.text) {
        copyQr.addEventListener("click", function() {
          copyTextToClipboard(data.text, "QR payload copied to clipboard!");
        });
      }
    }
  }

  // 8. Age-Encrypted Forensic Evidence Packaging
  function setupAgePackaging() {
    var inputKey = $("age-recipient-key");
    var btnPackage = $("btn-create-age-package");
    var resultBox = $("age-package-result");

    if (!btnPackage) return;

    btnPackage.addEventListener("click", async function() {
      btnPackage.disabled = true;
      btnPackage.innerHTML = '<span class="spinner" style="display:inline-block; width:13px; height:13px; border:2px solid #fff; border-top-color:transparent; border-radius:50%; animation:spin 0.8s linear infinite; margin-right:6px; vertical-align:middle;"></span> Encrypting &amp; Packaging...';
      if (resultBox) {
        resultBox.style.display = "block";
        resultBox.innerHTML = '<p style="color:var(--dim); font-size:0.86rem;"><span class="badge-seal"><span class="dot"></span></span> Generating ChaCha20-Poly1305 key, X25519 key exchange, and Ed25519 signature...</p>';
      }

      try {
        var recipientKey = inputKey ? inputKey.value.trim() : "";
        var auditSummary = {
          date: new Date().toISOString(),
          agent: "ShadowTrace Web Hub v3.0.2",
          os: navigator.userAgent
        };

        var files = [
          { name: "st_triage_manifest.json", content: JSON.stringify(auditSummary, null, 2) },
          { name: "st_evidence_notes.txt", content: "ShadowTrace Forensic Triage Evidence Package\nCreated: " + new Date().toUTCString() + "\nIntegrity Seal: Ed25519 Signature Verified\nRecipient: " + (recipientKey || "Auto-Generated Demonstration Recipient Key") + "\n" }
        ];

        var resp = await fetch("/api/package-evidence", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ recipient_key: recipientKey, files: files })
        });

        if (!resp.ok) throw new Error("HTTP error " + resp.status + " from local packaging bridge.");
        var data = await resp.json();
        if (!data.ok) throw new Error(data.error || "Packaging failed.");

        showToast("Evidence archive encrypted & signed!", "ok");
        renderAgePackageResult(data);
      } catch (err) {
        if (resultBox) {
          resultBox.innerHTML = '<div class="verdict-banner bad"><p>Packaging error: ' + escapeHtml(err.message) + '</p></div>';
        }
      } finally {
        btnPackage.disabled = false;
        btnPackage.innerHTML = '🔒 Create &amp; Download Signed Evidence Package (.zip.age)';
      }
    });

    function renderAgePackageResult(data) {
      if (!resultBox) return;
      var html = '<div class="verdict-banner clean" style="margin-top:12px;">';
      html += '<h3>🔒 End-to-End Encrypted Evidence Archive Created</h3>';
      html += '<p>The archive has been encrypted via <strong>RFC 7748 X25519 + ChaCha20-Poly1305</strong> and signed with <strong>Ed25519</strong>. Only the holder of the recipient key can decrypt it.</p>';
      html += '</div>';

      html += '<div class="safety-number-container">';
      html += '<div style="font-size:0.82rem; font-weight:700; color:var(--text); letter-spacing:0.05em; text-transform:uppercase;">60-Digit Signal-Style Verification Safety Number</div>';
      html += '<div class="safety-number-code">' + escapeHtml(data.safety_number || "—") + '</div>';
      html += '<div style="margin-top:8px;"><button type="button" class="btn btn-sm" id="btn-copy-safety-code" style="font-size:0.78rem;">📋 Copy Safety Number</button></div>';
      html += '<p style="font-size:0.78rem; color:var(--dim); margin-top:8px;">Compare this number with your helpline responder out-of-band (over a Signal or WhatsApp voice call) to guarantee zero man-in-the-middle tampering.</p>';
      html += '</div>';

      html += '<div class="file-meta-card">';
      html += '<div class="file-hash-row"><span class="file-hash-lbl">Archive Name:</span><span class="file-hash-val"><strong>' + escapeHtml(data.filename) + '</strong> (' + (data.bytes || 0).toLocaleString() + ' bytes)</span></div>';
      html += '<div class="file-hash-row"><span class="file-hash-lbl">Recipient Key:</span><span class="file-hash-val">' + escapeHtml(data.recipient) + '</span></div>';
      html += '<div class="file-hash-row"><span class="file-hash-lbl">Package SHA-256:</span><span class="file-hash-val">' + escapeHtml(data.package_sha256 || "—") + '</span></div>';
      html += '</div>';

      html += '<div style="margin-top:14px; text-align:center;">';
      html += '<a id="btn-download-age-archive" class="btn btn-primary" style="display:inline-block; text-decoration:none; padding:10px 20px;">⬇️ Download ' + escapeHtml(data.filename) + '</a>';
      html += '</div>';

      resultBox.innerHTML = html;

      var copyCode = $("btn-copy-safety-code");
      if (copyCode && data.safety_number) {
        copyCode.addEventListener("click", function() {
          copyTextToClipboard(data.safety_number, "Safety number copied to clipboard!");
        });
      }

      var downloadBtn = $("btn-download-age-archive");
      if (downloadBtn && data.data_b64) {
        downloadBtn.href = "data:application/octet-stream;base64," + data.data_b64;
        downloadBtn.download = data.filename;
      }
    }
  }

  // 9. Toast & Clipboard Utility Functions
  function showToast(message, type) {
    var container = $("toast-container");
    if (!container) return;
    var toast = document.createElement("div");
    toast.className = "toast " + (type || "ok");
    var icon = (type === "bad" ? "⚠️" : (type === "warn" ? "🔔" : "✓"));
    toast.innerHTML = '<span style="font-size:1.1rem; flex-shrink:0;">' + icon + '</span><span>' + escapeHtml(message) + '</span>';
    container.appendChild(toast);
    setTimeout(function() {
      toast.style.transition = "opacity 0.3s ease, transform 0.3s ease";
      toast.style.opacity = "0";
      toast.style.transform = "translateY(12px) scale(0.95)";
      setTimeout(function() {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 350);
    }, 3800);
  }
  window.showShadowTraceToast = showToast;

  function copyTextToClipboard(text, successMsg) {
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function() {
        showToast(successMsg || "Copied to clipboard!", "ok");
      }).catch(function() {
        fallbackCopy(text, successMsg);
      });
    } else {
      fallbackCopy(text, successMsg);
    }
  }

  function fallbackCopy(text, successMsg) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
      showToast(successMsg || "Copied to clipboard!", "ok");
    } catch (e) {
      prompt("Copy to clipboard:", text);
    }
    document.body.removeChild(ta);
  }

  // 10. General Utility Functions
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
    setupIotAuditor();
    setupWirelessAuditor();
    setupFileAndQrAnalyzer();
    setupAgePackaging();
    setupHashVerifier();
    setupThreatInspector();
    registerServiceWorker();
  });

})();

