# NEXORA-SENTINEL — Qualification and test plan

This is the reproducible pre-release test procedure for the current v0.2.0 foundation. Passing CI is not a declaration that missing source specifications, independent hardware custody, or Android device behavior have been verified.

## 1. Automated qualification

### Windows 10 / 11 (PowerShell)

Requirements: 64-bit Python 3.11 or 3.12 and Git. From the repository root:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\qualify.ps1
```

The script creates `.venv`, installs the project and test/build tools, then runs dependency checks, Ruff, pytest, compileall, wheel build and CLI help smoke tests. It does not run autonomous actions or enable capabilities.

If Python is installed only through the Python launcher, the script also supports `py -3`.

### Linux / Debian / Android Debian

```bash
bash scripts/qualify.sh
```

On a fresh Linux system, first install Python 3.11+, venv support and pip. The qualification script creates a local `.venv` if absent. On Android Debian, run inside the Debian environment rather than plain Android shell unless Python build prerequisites are installed.

## 2. CI platform matrix

The Platform Qualification workflow runs on:
- Ubuntu latest + Python 3.11
- Ubuntu latest + Python 3.12
- Windows latest + Python 3.11
- Windows latest + Python 3.12

Each matrix job checks pip consistency, Ruff, the complete pytest suite, Python compilation, wheel build, `nexora --help`, and `nexora settings diff --help`.

GitHub's `windows-latest` is a current hosted Windows image; it is not an exact Windows 10 physical-device certification. Run the PowerShell procedure on the target Windows 10 machine before marking that platform verified.

## 3. Safe first-run smoke test

Use a disposable working copy and temporary data directory. Do not point test commands at production data or real signing keys.

```bash
nexora --help
nexora --data-dir ./tmp-test-data status
nexora --data-dir ./tmp-test-data catalog-check
nexora --data-dir ./tmp-test-data capabilities
nexora --data-dir ./tmp-test-data settings --help
```

The catalog check may report incomplete source coverage. That is expected while the original definitions are missing; do not patch the catalog with guessed definitions to make this command green.

## 4. Manual qualification checklist

Mark each item only after performing it and recording OS, Python version, commit SHA, date and result.

- [ ] Clean install on Windows 10 x64.
- [ ] Clean install on Windows 11 x64.
- [ ] Clean install on Ubuntu/Debian x64.
- [ ] Install and basic CLI smoke test inside Android Debian/Termux environment.
- [ ] Run the full pytest suite on each supported host.
- [ ] Verify settings preview never mutates either source file.
- [ ] Verify emergency-stop behavior with missing, dangling-link and inaccessible marker cases where supported.
- [ ] Verify signed backup, wrong-key rejection, tamper rejection and restore into a new empty directory.
- [ ] Verify witness chain with a separately stored public key and receipt log.
- [ ] Repeat witness verification using a genuinely separate physical device/storage account and independent operator.
- [ ] Confirm no test creates an ENABLED capability or executes a proposed tool.
- [ ] Review logs for secrets, private keys, tokens or user data.
- [ ] Verify uninstall/reinstall does not overwrite user data or signing keys.

## 5. Device and trust limitations

Remote CI cannot verify Android hardware behavior, Android storage permissions, Termux process lifecycle, device sleep behavior, or physical separation of witness custody. Those require a human operator and target devices. Never copy private signing keys into CI artifacts or commit them to the repository.

## 6. Release decision

A green CI run is necessary but not sufficient. Do not publish a stable release while any of these remain unresolved:
- Canonical capability definitions 1–84 and meta-rules 1–15 have not been recovered from the original source.
- The 264×264 interaction matrix remains unknown/unpopulated.
- Physical off-device witness verification has not been completed.
- Windows 10 and Android Debian target-device qualification has not been recorded.
- A reviewed per-setting authorization matrix and rollback policy are absent.

Use the manual checklist to record evidence. Keep unknown requirements blocked; never manufacture a passing result.
