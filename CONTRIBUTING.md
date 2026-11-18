# Contributing

1. Open an issue describing the threat, expected behavior and acceptance tests.
2. Keep changes small and independently reviewable.
3. Add regression tests for every security boundary.
4. Run `bash scripts/run_tests.sh`.
5. Document data migrations, trust assumptions and rollback behavior.
6. Never weaken fail-closed defaults to make a test pass.
7. Do not add secrets, real user data, or private signing keys.
