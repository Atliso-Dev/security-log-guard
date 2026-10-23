# Changelog

Every release is on the [releases page](https://github.com/Atliso-Dev/security-log-guard/releases) with its zip, and on [atliso.com](https://atliso.com/tools) under Version history.

## 1.0.1 - unreleased

- Never clears the Security log unless the archive succeeded. In 1.0.0 a failed archive (full disk, no rights) was still followed by a clear, which lost the events. Now it stops, logs why and exits 1 so Intune shows the remediation failed.
- Checks the clear and the switch to overwrite as needed too, and exits 1 if either fails.
- PowerShell Gallery metadata (PSScriptInfo), ready for `Install-Script Atliso-SecurityLogGuard`.

## 1.0.0 - 2026-08-01

Initial public release. MIT licensed. Download the zip below or clone the repo. See README for usage and the linked Atliso guide.

