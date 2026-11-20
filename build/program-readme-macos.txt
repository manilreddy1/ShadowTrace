SHADOWTRACE TOOLKIT - HOW TO OPEN IT ON A MAC

1. Drag "ShadowTrace Toolkit" onto the Applications folder in this window.
2. Open Applications and double-click "ShadowTrace Toolkit".

The app is not signed by Apple (signing needs a paid account in a real
person's name, and this project is anonymous), so macOS will stop it the first
time you open it. That is expected. You only need to do this once:

3. macOS says it cannot verify the app. Click "Done" (or "OK").
4. Open System Settings > Privacy & Security. Scroll down to the message about
   "ShadowTrace Toolkit" and click "Open Anyway". Enter your password.
5. Double-click "ShadowTrace Toolkit" again and click "Open".

A window opens: choose a check and press Start check.

To let it check Safari: System Settings > Privacy & Security > Full Disk Access,
click +, choose Applications > ShadowTrace Toolkit, and turn it on.

Check the download first if you can: compare its SHA-256 with the release page,
or run  gh attestation verify <file> --repo interplains/ShadowTrace-Toolkit
Guide: https://github.com/interplains/ShadowTrace-Toolkit#readme
