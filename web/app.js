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
        if (filter === "sideloaded" && !p.isSideloaded) return false;
        if (filter === "accessibility" && !p.hasAccessibility) return false;
        if (filter === "threats" && !p.isKnownThreat) return false;
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
        if (pkg.isSideloaded) {
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
      if (threatsCount > 0) {
        html += '    <button class="filter-chip" data-filter="threats" style="color:var(--bad);">Threats (' + threatsCount + ')</button>';
      }
      html += '  </div>';

      html += '  <div id="pkg-list-container" class="pkg-list"></div>';
      html += '</div>';

      auditResults.innerHTML = html;

      // Initial render of package list
      renderPackageList(res.allPackages, "all", "");

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

