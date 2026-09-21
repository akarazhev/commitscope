# Working on this review project

Read README.md, docs/SECURITY.md, and docs/VERIFICATION.md before using or modifying the
runner. This project is trusted orchestration, not the subject application. Never
import target Python modules or run target build/test/package-install scripts here.

Use `python3 -I tests/run_tests.py` for local regression tests. `review.py demo` is a
separate real-scanner acceptance test; `--app-only` is not a substitute for that test.
Do not fabricate scanner output or a successful Claude API call. Keep protocol doubles
confined to tests and label their evidence as synthetic.

Keep source and findings confidential. Do not send source to AI without the operator's
explicit approval. Do not use bypassPermissions, auto-apply fixes, edit original run
reports, disable failure checks to make a build pass, or treat exit 0 as merge approval.
The AI adapter uses safe mode for subscription and bare mode for API. Neither path
loads this file as model context. Keep authentication explicit; never add a fallback
between subscription and API billing or expose credentials in argv/report/log output.
