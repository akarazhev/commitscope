# Verification and release status

**2.1.1 clean-start build — 2026-09-20. Full live acceptance has NOT passed.**

Read [the detailed clean-install report](CLEAN-INSTALL-VERIFICATION.md) and the
[raw evidence inventory](verification/clean-start/README.md).

The local suite passed **132/132** tests as a normal user with a new empty HOME
and a fresh standard-library venv. Eight actual application-fixture tests passed;
those eight are included in the total. The suite also includes explicit scanner
and Claude protocol doubles, not live service integration.

The real scanner installation failed DNS on the first download. The real native
Claude installer failed DNS as well. Neither actual scanner execution nor actual
Claude subscription/API calls is confirmed. Do not interpret more unit tests, a
valid archive, or an implementation of both auth modes as completed acceptance.

This is a complete fresh-install source distribution, not a migration or upgrade
package. Installation instructions are in [START-HERE](../START-HERE.md). It is not
an offline bundle, a fresh-OS test certificate, or a production qualification.

Current non-root results: [suite](verification/clean-start/unit-tests.txt),
[actual acceptance JSON](verification/clean-start/actual-acceptance/acceptance.json),
[native installer failure](verification/clean-start/real-claude-installer.txt).
Historical evidence is retained under `verification/legacy-v2.1/` and
`verification/legacy-v2/`; those hashes and test counts do not describe this build.
