# Operations guide

## Local install
On Debian or Android Debian, run `bash scripts/install_android_debian.sh`. Then run `.venv/bin/nexora status`.

## Verification
Run `bash scripts/run_tests.sh` from the repository root. CI performs Ruff, pytest and compileall.

## Data and recovery
Keep the data directory private and back it up while the application is stopped. Never copy private signing keys into Git, issue reports or cloud backups without encryption. Verify audit integrity before recovery. A corrupted audit log must not be silently reset.

## Approval keys
Generate a dedicated Ed25519 private key using the approval module. Enroll its public key only after an out-of-band fingerprint check. A fingerprint proves key continuity, not the identity of the human operator. Rotate by enrolling a new key, verifying it, then revoking the old fingerprint.

## Safe operating posture
Keep autonomy at L0. Scheduler, sandbox and network flags are off by default. A due job is a review item, not permission to execute. Tool proposals require separate human review. Do not enable unimplemented integrations.
