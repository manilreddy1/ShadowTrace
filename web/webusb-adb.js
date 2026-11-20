/**
 * ShadowTrace Toolkit - WebUSB & ADB Android Forensics Engine
 * Automatically queries connected Android devices for ALL existing third-party packages,
 * uninstalled package remnants, screen-reading accessibility permissions, device administrators,
 * and system security properties.
 *
 * Runs 100% offline in browser memory. Never transmits device data.
 */
(function(window) {
  'use strict';

  // ADB Packet Constants
  var A_CNXN = 0x4e584e43; // "CNXN"
  var A_AUTH = 0x48545541; // "AUTH"
  var A_OPEN = 0x4e45504f; // "OPEN"
  var A_OKAY = 0x59414b4f; // "OKAY"
  var A_CLSE = 0x45534c43; // "CLSE"
  var A_WRTE = 0x45545257; // "WRTE"

  var ADB_VERSION = 0x01000000;
  var MAX_PAYLOAD = 1048576;

  function buildPacket(command, arg0, arg1, data) {
    var len = data ? data.byteLength : 0;
    var crc = 0;
    if (data) {
      var u8 = new Uint8Array(data);
      for (var i = 0; i < u8.length; i++) {
        crc = (crc + u8[i]) >>> 0;
      }
    }
    var buffer = new ArrayBuffer(24 + len);
    var view = new DataView(buffer);
    view.setUint32(0, command, true);
    view.setUint32(4, arg0, true);
    view.setUint32(8, arg1, true);
    view.setUint32(12, len, true);
    view.setUint32(16, crc, true);
    view.setUint32(20, (command ^ 0xffffffff) >>> 0, true);

    if (data) {
      new Uint8Array(buffer, 24).set(new Uint8Array(data));
    }
    return buffer;
  }

  var WebUsbAdb = {
    isSupported: function() {
      return !!(navigator.usb && navigator.usb.requestDevice);
    },

    /**
     * Attempts to query connected device via local ADB server endpoint (/api/scan-android)
     * Returns parsed result if local bridge is running, else returns null.
     */
    queryLocalBridge: async function(onLog) {
      try {
        onLog("Checking local ADB bridge connection at /api/scan-android...");
        var res = await fetch("/api/scan-android?t=" + Date.now(), { cache: "no-store" });
        if (!res.ok) {
          onLog("Local bridge returned HTTP status: " + res.status);
          return null;
        }
        var data = await res.json();
        if (data && data.ok && data.raw) {
          onLog("Connected to Android device (Serial: " + (data.serial || "default") + ") via local ADB bridge!");
          return data.raw;
        } else if (data && data.error) {
          onLog("Bridge device response: " + data.error);
          throw new Error(data.error);
        }
      } catch (e) {
        onLog("Local bridge note: " + e.message);
        if (e.message && (
          e.message.indexOf("device") !== -1 ||
          e.message.indexOf("debugging") !== -1 ||
          e.message.indexOf("unauthorized") !== -1 ||
          e.message.indexOf("failed") !== -1 ||
          e.message.indexOf("timed out") !== -1
        )) {
          throw e;
        }
      }
      return null;
    },

    /**
     * Direct WebUSB connection to an Android device
     */
    connectWebUsb: async function(onLog, onStatus) {
      if (!this.isSupported()) {
        throw new Error("WebUSB is only supported in Chromium-based browsers (Chrome, Edge, Brave, Opera).");
      }

      onStatus("Requesting USB Device Selection...");
      onLog("Opening browser USB selector. Choose your connected Android phone...");

      var device = await navigator.usb.requestDevice({
        filters: [
          { classCode: 255, subclassCode: 66, protocolCode: 1 },
          { classCode: 255 }
        ]
      });

      onStatus("Device Connected: " + (device.productName || "Android Device"));
      onLog("Opened USB connection to: " + (device.productName || "Android") + " (Vendor: 0x" + device.vendorId.toString(16) + ")");

      await device.open();
      if (device.configuration === null) {
        await device.selectConfiguration(1);
      }

      // Find ADB interface (class 255, subclass 66, protocol 1)
      var iface = device.configuration.interfaces.find(function(i) {
        return i.alternates.some(function(a) { return a.interfaceClass === 255; });
      }) || device.configuration.interfaces[0];

      try {
        await device.claimInterface(iface.interfaceNumber);
      } catch (claimErr) {
        if (claimErr.name === "SecurityError" || (claimErr.message && claimErr.message.indexOf("Unable to claim interface") !== -1)) {
          throw new Error("Cannot claim USB interface directly in browser because the OS or local ADB driver has exclusive access. Please click 'Auto-Scan Android Device' to use the Local ADB Bridge instead.");
        }
        throw claimErr;
      }
      var alternate = iface.alternates[0];

      var epIn = alternate.endpoints.find(function(e) { return e.direction === 'in'; });
      var epOut = alternate.endpoints.find(function(e) { return e.direction === 'out'; });

      if (!epIn || !epOut) {
        throw new Error("Could not find bulk IN and OUT endpoints on USB interface.");
      }

      onStatus("ADB Interface Claimed.");
      onLog("Claimed USB Interface " + iface.interfaceNumber + " (In: EP" + epIn.endpointNumber + ", Out: EP" + epOut.endpointNumber + ")");

      return {
        device: device,
        epIn: epIn.endpointNumber,
        epOut: epOut.endpointNumber,

        send: async function(cmd, arg0, arg1, data) {
          var pkt = buildPacket(cmd, arg0, arg1, data);
          await device.transferOut(epOut.endpointNumber, pkt);
        },

        read: async function(length) {
          var res = await device.transferIn(epIn.endpointNumber, length || 16384);
          return res.data;
        },

        close: async function() {
          try {
            await device.releaseInterface(iface.interfaceNumber);
            await device.close();
          } catch (e) {
            console.warn(e);
          }
        }
      };
    },

    /**
     * Automatic Audit Runner: Tries Local Bridge first, then WebUSB, and executes
     * full automatic enumeration of all third-party packages.
     */
    runAutoScan: async function(onLog, onStatus, forceWebUsb) {
      if (!forceWebUsb) {
        // 1. Try local bridge (fastest, supports all browsers if serve.py is running)
        var rawBridge = await this.queryLocalBridge(onLog);
        if (rawBridge) {
          onStatus("Audit completed via local ADB bridge.");
          onLog("Successfully retrieved package telemetry and security posture via local bridge.");
          return this.auditAndroidData(rawBridge);
        }
      }

      // 2. Fall back to pure WebUSB
      onLog(forceWebUsb ? "Direct WebUSB requested..." : "Local bridge not active. Proceeding with WebUSB direct device query...");
      var usb = await this.connectWebUsb(onLog, onStatus);

      try {
        onStatus("Performing ADB Handshake...");
        onLog("Sending CNXN packet (Version 0x01000000)...");

        var hostBanner = new TextEncoder().encode("host::ShadowTrace-Hub\0");
        await usb.send(A_CNXN, ADB_VERSION, MAX_PAYLOAD, hostBanner.buffer);

        // Read response header
        var headerData = await usb.read(24);
        var view = new DataView(headerData.buffer);
        var cmd = view.getUint32(0, true);

        if (cmd === A_AUTH) {
          onStatus("Authentication Required");
          onLog("Phone requested RSA authentication. Please tap 'Always allow from this computer' on your phone screen.");
        } else if (cmd === A_CNXN) {
          onLog("Device accepted connection (already authorized)!");
        }

        // Open shell stream to query third-party packages and security posture
        var shellCmd = new TextEncoder().encode(
          "shell:pm list packages -3 -f -i; " +
          "echo '===SECTION==='; " +
          "pm list packages -u; " +
          "echo '===SECTION==='; " +
          "settings get secure enabled_accessibility_services; " +
          "echo '===SECTION==='; " +
          "getprop ro.build.version.security_patch; " +
          "getprop ro.boot.verifiedbootstate; " +
          "getprop ro.build.tags; " +
          "getprop ro.product.model\0"
        );

        onLog("Requesting shell telemetry stream: querying all third-party packages (pm list packages -3 -f -i)...");
        await usb.send(A_OPEN, 1, 0, shellCmd.buffer);

        var output = "";
        var attempts = 0;

        while (attempts < 15) {
          attempts++;
          var chunk = await usb.read(16384);
          if (!chunk || chunk.byteLength === 0) break;

          var dv = new DataView(chunk.buffer);
          if (chunk.byteLength >= 24) {
            var cCmd = dv.getUint32(0, true);
            var dLen = dv.getUint32(12, true);

            if (cCmd === A_WRTE && dLen > 0) {
              var payload = new Uint8Array(chunk.buffer, 24, Math.min(dLen, chunk.byteLength - 24));
              output += new TextDecoder().decode(payload);
              // Send OKAY acknowledge
              var remoteId = dv.getUint32(4, true);
              await usb.send(A_OKAY, 1, remoteId, null);
            } else if (cCmd === A_CLSE) {
              onLog("Stream completed (CLSE received).");
              break;
            }
          }
        }

        await usb.close();

        if (!output || output.trim().length === 0) {
          throw new Error("No telemetry output received from device. Ensure phone screen is unlocked and authorized.");
        }

        onLog("Received " + output.length + " bytes of device telemetry. Parsing packages...");
        return this.auditAndroidData(output);

      } catch (err) {
        await usb.close();
        throw err;
      }
    },

    /**
     * Comprehensive Forensic Parser & Auditor
     * Parses packages, installation paths, stores, accessibility permissions, and properties.
     */
    auditAndroidData: function(text) {
      var lines = text.split(/\r?\n/);

      var allPackages = [];
      var packagesSet = new Set();
      var uninstalledPackages = [];
      var properties = {};
      var accessibility = [];
      var deviceAdmins = [];
      var hits = [];
      var leads = [];
      var gaps = [];

      var iocs = (window.SHADOWTRACE_IOCS && window.SHADOWTRACE_IOCS.packages) || [];
      var iocMap = {};
      iocs.forEach(function(item) {
        iocMap[item.value.toLowerCase()] = item.threat;
      });

      // Split into sections if available
      var sections = text.split(/===SECTION===/);
      var pkgSection = sections[0] || text;

      // 1. Parse Third-Party Packages: pm list packages -3 -f -i
      // Format: package:/data/app/~~.../base.apk=com.example.app installer=com.android.vending
      var pkgLines = pkgSection.split(/\r?\n/);
      for (var p = 0; p < pkgLines.length; p++) {
        var pl = pkgLines[p].trim();
        if (!pl) continue;

        var m = pl.match(/^package:(.*?)=([a-zA-Z0-9_.]+)(?:\s+installer=([^\s]+))?/);
        if (m) {
          var apkPath = m[1];
          var pkgId = m[2];
          var rawInstaller = m[3] || "null";

          if (!packagesSet.has(pkgId)) {
            packagesSet.add(pkgId);

            var isGooglePlay = (rawInstaller === "com.android.vending");
            var isSamsungStore = (rawInstaller === "com.sec.android.app.samsungapps");
            var isSideloaded = (!isGooglePlay && !isSamsungStore && rawInstaller !== "com.amazon.venezia");

            var installerLabel = "Sideloaded / Unknown";
            if (isGooglePlay) installerLabel = "Google Play Store";
            else if (isSamsungStore) installerLabel = "Samsung Galaxy Store";
            else if (rawInstaller !== "null" && rawInstaller !== "") installerLabel = rawInstaller;

            allPackages.push({
              name: pkgId,
              path: apkPath,
              installer: installerLabel,
              rawInstaller: rawInstaller,
              isSideloaded: isSideloaded,
              hasAccessibility: false,
              hasDeviceAdmin: false,
              isKnownThreat: !!iocMap[pkgId.toLowerCase()],
              threat: iocMap[pkgId.toLowerCase()] || null
            });
          }
        } else {
          // Simple "package:com.foo.bar" or "Package [com.foo.bar]"
          var sMatch = pl.match(/^package:([a-zA-Z0-9_.]+)/) || pl.match(/Package\s*\[([a-zA-Z0-9_.]+)\]/);
          if (sMatch) {
            var sId = sMatch[1];
            if (!packagesSet.has(sId)) {
              packagesSet.add(sId);
              allPackages.push({
                name: sId,
                path: "",
                installer: "Unknown",
                rawInstaller: "unknown",
                isSideloaded: false,
                hasAccessibility: false,
                hasDeviceAdmin: false,
                isKnownThreat: !!iocMap[sId.toLowerCase()],
                threat: iocMap[sId.toLowerCase()] || null
              });
            }
          }
        }
      }

      // 1b. Parse Uninstalled / Remnant Packages from pm list packages -u
      var uninstalledSection = sections[1] || "";
      var uLines = uninstalledSection.split(/\r?\n/);
      for (var u = 0; u < uLines.length; u++) {
        var ul = uLines[u].trim();
        var um = ul.match(/^package:([a-zA-Z0-9_.]+)/);
        if (um) {
          var uPkg = um[1];
          if (!packagesSet.has(uPkg)) {
            packagesSet.add(uPkg);
            var isThreat = !!iocMap[uPkg.toLowerCase()];
            var uItem = {
              name: uPkg,
              path: "[Residual Uninstalled App Data]",
              installer: "Residual / Remnant",
              rawInstaller: "uninstalled",
              isSideloaded: false,
              isUninstalled: true,
              hasAccessibility: false,
              hasDeviceAdmin: false,
              isKnownThreat: isThreat,
              threat: iocMap[uPkg.toLowerCase()] || null
            };
            allPackages.push(uItem);
            uninstalledPackages.push(uItem);
            if (isThreat) {
              hits.push({
                type: "uninstalled-threat",
                package: uPkg,
                threat: uItem.threat,
                severity: "known-threat",
                details: "Previously uninstalled remnant app matches known mercenary spyware indicator."
              });
            }
          }
        }
      }

      // 2. Parse Other Sections & Lines
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i].trim();
        if (!line) continue;

        // enabled_accessibility_services
        if (line.indexOf("enabled_accessibility_services") !== -1) {
          var accVal = line.split("=")[1] || line.split(":")[1] || "";
          accVal.split(":").forEach(function(s) {
            var sClean = s.trim().replace(/^\{/, "").replace(/\}$/, "");
            if (sClean && accessibility.indexOf(sClean) === -1) {
              accessibility.push(sClean);
            }
          });
        }

        // device_policy / Device Admins
        if (line.indexOf("admin=") !== -1 || line.indexOf("Active admin:") !== -1 || line.indexOf("ComponentInfo{") !== -1) {
          var adminMatch = line.match(/ComponentInfo\{([^/]+)\//);
          if (adminMatch && deviceAdmins.indexOf(adminMatch[1]) === -1) {
            deviceAdmins.push(adminMatch[1]);
          }
        }

        // getprop: "[key]: [value]"
        var propMatch = line.match(/^\[([^\]]+)\]:\s*\[([^\]]*)\]/);
        if (propMatch) {
          properties[propMatch[1]] = propMatch[2];
        }
      }

      // Link accessibility and device admin attributes to package objects
      var accessibilityPkgMap = {};
      accessibility.forEach(function(acc) {
        var aPkg = acc.split("/")[0];
        accessibilityPkgMap[aPkg] = acc;
      });

      var adminPkgMap = {};
      deviceAdmins.forEach(function(adm) {
        adminPkgMap[adm] = true;
      });

      allPackages.forEach(function(pkg) {
        if (accessibilityPkgMap[pkg.name]) {
          pkg.hasAccessibility = true;
          pkg.accessibilityService = accessibilityPkgMap[pkg.name];
        }
        if (adminPkgMap[pkg.name]) {
          pkg.hasDeviceAdmin = true;
        }

        // Flag Actionable Findings: Known Spyware Matches
        if (pkg.isKnownThreat) {
          hits.push({
            type: "package-ioc",
            package: pkg.name,
            threat: pkg.threat,
            severity: "known-threat",
            details: "Matches published mercenary spyware / stalkerware indicator."
          });
        }

        // Flag Actionable Findings: Sideloaded App with Accessibility Powers
        if (pkg.isSideloaded && pkg.hasAccessibility) {
          leads.push({
            type: "sideload-accessibility",
            target: pkg.name,
            severity: "worth-a-look",
            title: "Sideloaded App with Screen-Reading Accessibility Powers",
            details: "App '" + pkg.name + "' was installed outside verified app stores and holds full Accessibility powers to read screen text and keystrokes."
          });
        }
      });

      // Audit System Properties
      var patchDate = properties["ro.build.version.security_patch"];
      if (patchDate) {
        var patchTime = new Date(patchDate).getTime();
        var now = new Date().getTime();
        var daysOld = Math.floor((now - patchTime) / (1000 * 60 * 60 * 24));
        if (daysOld > 180) {
          leads.push({
            type: "security-patch",
            target: patchDate,
            severity: "worth-a-look",
            title: "Outdated Security Patch (" + patchDate + ", " + daysOld + " days old)",
            details: "Device is missing security patches for known zero-day vulnerabilities."
          });
        }
      }

      var bootState = properties["ro.boot.verifiedbootstate"];
      if (bootState && bootState.toLowerCase() !== "green") {
        leads.push({
          type: "boot-state",
          target: bootState,
          severity: "worth-a-look",
          title: "Bootloader Unlocked (" + bootState + ")",
          details: "Verified boot state is '" + bootState + "'. The device chain-of-trust is compromised or running a custom image."
        });
      }

      var buildTags = properties["ro.build.tags"];
      if (buildTags && buildTags.indexOf("test-keys") !== -1) {
        leads.push({
          type: "test-keys",
          target: buildTags,
          severity: "worth-a-look",
          title: "Custom / Test-Key ROM Signature Detected",
          details: "Firmware was built with test-keys rather than official release keys."
        });
      }

      // Roll up verdict
      var level = "nothing-known";
      if (hits.length > 0) {
        level = "known-threat";
      } else if (leads.some(function(l) { return l.severity === "worth-a-look"; })) {
        level = "worth-a-look";
      }

      var devModel = properties["ro.product.model"] || properties["ro.product.device"] || "Android Device";
      var androidVer = properties["ro.build.version.release"] || "Unknown";
      var patchDate = properties["ro.build.version.security_patch"] || "Unknown";
      var bootState = properties["ro.boot.verifiedbootstate"] || properties["ro.boot.flash.locked"] || "Unknown";

      return {
        level: level,
        timestamp: new Date().toISOString(),
        packagesTotal: allPackages.length,
        allPackages: allPackages,
        sideloadedCount: allPackages.filter(function(p) { return p.isSideloaded && !p.isUninstalled; }).length,
        uninstalledCount: uninstalledPackages.length,
        uninstalledPackages: uninstalledPackages,
        model: devModel,
        androidVersion: androidVer,
        securityPatch: patchDate,
        verifiedBoot: bootState,
        properties: properties,
        accessibility: accessibility,
        deviceAdmins: deviceAdmins,
        hits: hits,
        leads: leads,
        gaps: gaps
      };
    }
  };

  window.WebUsbAdb = WebUsbAdb;
})(window);
