# CommitScope 2.4.1 Documents

The active Methodology is a sourced survey of international practice, checked on
2026-09-23, with qualitative comparisons and the rationale for the local CommitScope
choice. The User Guide teaches a synthetic end-to-end employee and reviewer journey
for the 2.4.1 workflow: scanners, mandatory Hunter and Verifier, protected evidence,
and a human decision. The Starter Kit 1.0 Playbook is prominently labeled **LEGACY** on its first
page and every footer. It is a concise historical reference, not the current
procedure or a reproduction of the original kit.

These active handouts were updated after the v2.4.1 release. Its immutable source
distribution still contains the previous 2.4.0 PDF editions. The legacy playbooks
remain unchanged.

| Edition | English | Russian |
|---|---|---|
| Methodology | [PDF](en/security-review-methodology-en.pdf) | [PDF](ru/security-review-methodology-ru.pdf) |
| User Guide | [PDF](en/commitscope-user-guide-en.pdf) | [PDF](ru/commitscope-user-guide-ru.pdf) |
| LEGACY Starter Kit 1.0 | [PDF](en/security-review-playbook-en-legacy.pdf) | [PDF](ru/security-review-playbook-ru-legacy.pdf) |

## Rebuild

Edit `source/content-en.json` and `source/content-ru.json` together. Active documents
use matching chapter, section, block, figure, and citation IDs; the legacy playbooks
retain explicit pages. The builder escapes text before PDF layout and
embeds the checked-in Noto Sans font; no system font or network access is needed.

Use Python 3.11-3.14 and the documentation-only dependency `reportlab==4.4.10`.
Install it in the build environment (`python3 -m pip install reportlab==4.4.10`);
it is not a CommitScope runtime dependency. Poppler (`pdfinfo`, `pdftotext`,
`pdftoppm`) is needed for full document QA. Then, from the trusted checkout:

```bash
SOURCE_DATE_EPOCH=1790035200 python3 -I scripts/build_pdfs.py
python3 -I scripts/update_checksums.py
python3 -I scripts/update_checksums.py --check
python3 -I -m unittest discover -s tests -p 'test_pdfs.py' -v
```

`--output-dir /absolute/temporary/directory` builds into a separate directory.
The default epoch is `1790035200`; an explicit `SOURCE_DATE_EPOCH` overrides it.
ReportLab invariant mode, fixed metadata, embedded fonts, A4 margins, and atomic
destination replacement make matching clean builds byte-identical with the same
Python/ReportLab/zlib environment and epoch. Rebuild with the documented epoch when
updating the checked-in PDFs. Dependency upgrades require renewed hash and visual QA.

Render **every page of all six files** with `pdftoppm -png`, inspect the images for
clipping, overlap, missing Cyrillic glyphs, readable commands, and consistent footers,
and inspect `pdftotext -layout` output. Text extraction alone does not prove layout.
The focused tests skip rendering/text checks when Poppler is absent and skip rebuild
checks when ReportLab is absent; those skips do not satisfy release-document QA.

All sources, PDFs, font/license files, and build scripts are explicit sdist inputs.
They are documentation assets rather than runtime wheel resources. `SHA256SUMS`
covers exactly `config/sdist-manifest.json` except itself. The checksum tool rejects
symlinks and `--check` does not rewrite files. After changing the sdist manifest,
refresh its existing hash in `config/resource-manifest.json` before checksumming.

These documents and offline tests do not establish live scanner/model readiness,
publish a release, or authorize source transfer. See `docs/VERIFICATION.md`.
