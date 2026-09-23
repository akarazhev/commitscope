# Bilingual Presentation Documents Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce four presentation-quality English/Russian PDF handouts: a sourced international security-review methodology and a complete CommitScope user tutorial.

**Architecture:** Keep the existing paired JSON sources and ReportLab build. Add a small validated set of semantic blocks and fixed vector diagram templates, then write paired methodology and guide content against those blocks. Chapters flow across as many readable A4 pages as needed. Rebuild tracked PDFs deterministically and verify commands, text, links, bilingual parity, page renders, package inputs, and checksums.

**Tech Stack:** Python 3.11-3.14 standard library, unittest, ReportLab 4.4.10, checked-in Noto Sans, Poppler (`pdfinfo`, `pdftotext`, `pdftoppm`), existing in-tree package builder.

**Spec:** `docs/superpowers/specs/2026-09-23-presentation-documents-design.md`

## Global Constraints

- Keep CommitScope runtime and its `v2.4.0` tag/release unchanged; submit documents in a separate PR.
- Update only the four active methodology/guide PDFs; retain both legacy playbooks and their explicit legacy labels.
- Both final editions must have matching language-neutral document, chapter, section, block, figure, and citation IDs; prose is localized. Physical page count follows readable pagination, not a target number.
- Compare approaches qualitatively against the agreed company constraints, never with invented precision or universal superiority claims.
- Use only synthetic examples; PDF generation and QA must make no Claude requests or transfer company code.
- `commitscope review` remains account-only with mandatory Semgrep, Gitleaks, Trivy, Hunter, Verifier, exact model ID, explicit upload consent, protected output, and human decision.
- Keep existing `tests/test_pdfs.py` acceptance phrases in the new guide or update tests only where equivalent EN/RU wording genuinely improves the guide; never weaken the required-stage or state assertions.
- PDF sources, generated files, scripts, fonts, and new plan/spec paths must be represented in the exact source manifest and `SHA256SUMS`; changing that manifest also changes its digest in `config/resource-manifest.json`.
- Preserve A4, the pinned ReportLab build, Noto Sans, `SOURCE_DATE_EPOCH=1790035200`, and byte-identical rebuilds in the same environment.
- The external-practice survey is dated **2026-09-23**. Treat NIST SSDF 1.1 as final and SSDF 1.2 as draft; verify other cited edition states at implementation time.

## File map

| File | Responsibility |
|---|---|
| `scripts/build_pdfs.py` | Validate source schema/pair and render text, code, tables, diagrams, callouts, captions, references, and page decorations. |
| `docs/security-review-pdfs/source/content-en.json` | English content and numbered source metadata. |
| `docs/security-review-pdfs/source/content-ru.json` | Equivalent Russian content with the same semantic IDs. |
| `docs/security-review-pdfs/{en,ru}/*.pdf` | Four rebuilt active handouts; legacy files remain byte-identical. |
| `tests/test_pdfs.py` | Source parity, invalid-input, rendering, reproducibility, metadata, and PDF-text contracts. |
| `tests/test_acceptance.py` | Current-command and corporate-review documentation contract. |
| `docs/security-review-pdfs/README.md` and `README.md` | Discoverability, dated scope, build/QA instructions. |
| `config/sdist-manifest.json`, `config/resource-manifest.json`, `SHA256SUMS` | Exact distribution inputs and digests. |

## Review Focus

1. A broken or duplicated citation/block ID must fail before writing any PDF; Task 1 adds this negative test.
2. Text containing `&`, `<`, `>` or a long Cyrillic label must render as literal readable text, not markup or a clipped diagram; Task 2 adds rendering fixtures and checks.
3. A wide comparison table must split or reflow legibly, not shrink text below 9 pt; Task 2 adds a long-cell rendering test and Task 5 visually checks every page.
4. A user following an old optional-AI/API-key/`--ref HEAD` example must not mistake partial evidence for corporate completion; Task 4 adds static and CLI-shape tests.
5. A valid-looking PDF with stale pre-release wording, missing figures, or a mismatched Russian structure must fail QA; Tasks 1, 3, 4, and 5 add checks.

---

### Task 1: Semantic Source Contract and Paired Validation

**Files:**
- Modify: `scripts/build_pdfs.py`
- Modify: `tests/test_pdfs.py`
- Modify: `config/sdist-manifest.json`, `config/resource-manifest.json`, `SHA256SUMS` only if a new tracked test/source file is added

**Interfaces:**
- Produces: `validate_source(source: dict, language: str) -> None`, `validate_pair(en: dict, ru: dict) -> None`, and `build_pair(en: dict, ru: dict, output: Path) -> None`. `build_pair` validates both documents and their parity before destination creation, then delegates to `build_document`.
- Converted chapter shape: `{"id": "m01", "title": "...", "sections": [{"id": "decision", "heading": "...", "blocks": [{"id": "claim", "type": "paragraph", "text": "...", "citations": ["S1"]}]}]}`.
- `paragraph`, `callout`, `code`, `table`, and `diagram` are the allowed active block types. `table` has `headers` and `rows`; `diagram` has `kind`, `nodes`, and optional `edges`. Figure blocks have `caption`.
- Each converted active document has a `references` array of `{id, title, url, checked}`. Existing `pages[].sections[].paragraphs`/`code` remains supported during migration and for the legacy playbook; the final active documents use the new schema.

Minimal converted fixture for the validator test:

```python
active = {
    "id": "methodology", "title": "Example", "subject": "Example", "footer": "Example",
    "references": [{"id": "S1", "title": "NIST SSDF 1.1",
                    "url": "https://csrc.nist.gov/pubs/sp/800/218/final", "checked": "2026-09-23"}],
    "chapters": [{"id": "m01", "title": "Decision", "sections": [{
        "id": "scope", "heading": "Scope", "blocks": [{"id": "claim",
        "type": "paragraph", "text": "Reviewed scope [S1].", "citations": ["S1"]}]
    }]}],
}
```

- [ ] **Step 1: Write failing validator tests.** Add `test_active_source_ids_and_citations_are_validated` and `test_english_russian_structure_must_match` to `tests/test_pdfs.py`. Wrap `active` above in `{"language": "en", "version": "2.4.0", "documents": {"methodology": active}}`; deep-copy for RU and set its language. Assert duplicate block ID, unknown citation `S9`, non-HTTPS source URL, and a missing RU section each raise `ValueError`. Assert the valid pair passes. Use `tempfile.TemporaryDirectory`, call `build_pair(en, invalid_ru, output)`, and verify `output` remains absent.
- [ ] **Step 2: Run the focused red tests.** Run `python3 -I -m unittest discover -s tests -p test_pdfs.py -k 'active_source_ids_and_citations_are_validated' -v` and the matching `-k english_russian_structure_must_match`; expect failures because validation is absent.
- [ ] **Step 3: Implement minimal validation.** Add the three functions above, enforce unique IDs within each converted document, known block types/diagram kinds, nonempty text/table rows, HTTPS reference URLs, exact citation resolution, and matching ordered ID/type trees across languages. Validate current `pages` as legacy content until Tasks 3-4 replace each active document with `chapters`; compare only page/section counts and field shape during that transition, never localized headings. Have `main()` load both JSON sources and call `build_pair`. Keep the legacy playbook and transitional pages on the old rendering path.
- [ ] **Step 4: Run green tests and regressions.** Run the two focused tests, then `python3 -I -m unittest discover -s tests -p test_pdfs.py -v`. Existing six PDFs must still rebuild byte-identically at the pinned epoch.
- [ ] **Step 5: Refresh exact digests and commit.** Run `python3 -I scripts/update_checksums.py`, then `--check`, `git diff --check`, and commit `test: validate bilingual PDF source contracts`.

### Task 2: Readable Tables, Figures, and Source References

**Files:**
- Modify: `scripts/build_pdfs.py`
- Modify: `tests/test_pdfs.py`
- Modify: `SHA256SUMS`

**Interfaces:**
- Consumes: Task 1 block schema and validators.
- Produces: `render_block(block: dict, styles: dict, references: dict) -> list` used by `build_document`; figure kinds `flow`, `boundary`, `lanes`, `cycle`, and `decision`. All figure labels come from localized JSON; coordinates come only from fixed renderer templates.
- `table` uses ReportLab `Table` with paragraph cells, repeated header, row splitting, and at least 9 pt cell text. `references` are numbered, printed as title plus full URL, and linked in the PDF.

- [ ] **Step 1: Add failing renderer tests.** In `tests/test_pdfs.py`, create a temporary converted source containing `A & B < C`, a long Russian label, 30 table rows with wrapped text, a `boundary` figure, and a citation to `https://csrc.nist.gov/pubs/sp/800/218/final`. Assert `pdftotext -layout` contains the literal text, figure number/caption, a repeated table header on split pages, and source URL; assert the PDF has no replacement glyph. Check rendering with `pdftoppm` and `pdfinfo -url` when Poppler supports those options.
- [ ] **Step 2: Run red test.** Run `python3 -I -m unittest discover -s tests -p test_pdfs.py -k semantic_blocks_render -v`; expect missing block renderer or absent table/figure text.
- [ ] **Step 3: Implement fixed block renderers.** Escape all JSON text before ReportLab markup. Use `Paragraph` cells and `Table(..., repeatRows=1, splitByRow=1)` at readable widths. Use ReportLab vector shapes or a dedicated `Flowable` for the five bounded figure kinds, with text wrapping measured before drawing; split large matrices into two four-column tables rather than compressing six criteria into one A4 portrait row. Keep captions with figures and print reference IDs plus full URLs. The dispatch must reject unknown block types rather than silently omit them:

```python
def render_block(block: dict, styles: dict, references: dict) -> list:
    renderer = {
        "paragraph": render_paragraph, "callout": render_callout,
        "code": render_code, "table": render_table, "diagram": render_diagram,
    }.get(block["type"])
    if renderer is None:
        raise ValueError(f"unsupported block type: {block['type']}")
    return renderer(block, styles, references)
```
- [ ] **Step 4: Run green tests and compare legacy.** Run the focused test and all `test_pdfs.py`; compare both legacy PDF SHA-256 values to their pre-task values. Render the synthetic page at 120 and 200 dpi and inspect the long label and table boundary.
- [ ] **Step 5: Refresh checksum and commit.** Run checksum update/check and `git diff --check`; commit `feat(docs): render sourced tables and vector diagrams`.

### Task 3: Write and Verify the Bilingual Methodology

**Files:**
- Modify: `docs/security-review-pdfs/source/content-en.json`
- Modify: `docs/security-review-pdfs/source/content-ru.json`
- Modify: `tests/test_pdfs.py`
- Modify: `docs/security-review-pdfs/{en,ru}/security-review-methodology-*.pdf`
- Modify: `SHA256SUMS`

**Interfaces:**
- Consumes: Task 1 schema, Task 2 figure/table kinds.
- Produces: ordered chapter IDs `m01` to `m08`, shared block/figure IDs, numbered reference IDs, and two methodology PDFs. Chapters may span physical pages.

- [ ] **Step 1: Verify primary sources.** Open the official publication pages for NIST SSDF 1.1 and draft status of 1.2, OWASP SAMM, OWASP ASVS 5.0, OWASP LLM01, and Anthropic Claude Code security/data usage. Record titles, editions, direct URLs, and `checked: 2026-09-23` in both content sources. Distinguish implementation facts from our inference; do not copy extended source text.
- [ ] **Step 2: Add failing methodology contract tests.** In `tests/test_pdfs.py`, assert chapter IDs `m01`-`m08`, the five required figure IDs `practice-map`, `comparison`, `trust-boundary`, `finding-lifecycle`, `rollout`, matching EN/RU structure, required source IDs, and the absence of fabricated numeric detection/cost claims. Assert both PDFs have the review date and captions in extracted text. The structural assertion can be written as:

```python
assert [chapter["id"] for chapter in en["documents"]["methodology"]["chapters"]] == [
    f"m{i:02d}" for i in range(1, 9)
]
validate_pair(en, ru)
```
- [ ] **Step 3: Run red tests.** Run `python3 -I -m unittest discover -s tests -p test_pdfs.py -k methodology -v`; expect missing pages, figures, and source references.
- [ ] **Step 4: Write both editions.** Cover executive decision, landscape, two legible comparison matrices, company-specific criteria, selected architecture and trust boundaries, finding lifecycle with a synthetic vulnerable-to-fixed example, rollout proposals, remaining risks, and cited bibliography. The matrix must contrast manual-only, scanner-only, AI-only, centralized service, and local combined review; label relative judgments as CommitScope team inference.
- [ ] **Step 5: Build and inspect.** Run `SOURCE_DATE_EPOCH=1790035200 python3 -I scripts/build_pdfs.py`; run focused tests. Extract and read both languages with `pdftotext -layout`; render each methodology page with `pdftoppm -r 120 -png` and inspect every PNG, then spot-check dense pages at 200 dpi. Revise source/layout until no clipping or unreadable table remains.
- [ ] **Step 6: Update digests and commit.** Run checksum update/check, `git diff --check`, and commit `docs: explain bilingual review methodology and choice`.

### Task 4: Write and Verify the Bilingual User Tutorial

**Files:**
- Modify: `docs/security-review-pdfs/source/content-en.json`
- Modify: `docs/security-review-pdfs/source/content-ru.json`
- Modify: `tests/test_pdfs.py`, `tests/test_acceptance.py`
- Modify: `docs/security-review-pdfs/{en,ru}/commitscope-user-guide-*.pdf`
- Modify: `SHA256SUMS`

**Interfaces:**
- Consumes: Tasks 1-2 schema and renderer, the published v2.4.0 CLI contract, existing synthetic `examples/ai-acceptance/idor` and `examples/review-policy.json`.
- Produces: ordered chapter IDs `g01` to `g09`, matching EN/RU block IDs, role diagrams, command examples, and two guide PDFs. Chapters may span physical pages.

- [ ] **Step 1: Add failing guide contract tests.** Require published-tag installation (`git+https://github.com/akarazhev/commitscope.git@v2.4.0`), `--auth account`, `--allow-code-upload`, an exact-model placeholder clearly marked for replacement, a 40-character lower-case SHA example, protected output outside the target, `verify-review`, all three exit states, and a human reviewer. Reject `--ref HEAD` in the corporate example, API-key workflow, optional Hunter/Verifier, and the stale "No public v2.4.0 tag" wording. Assert chapter IDs `g01`-`g09` and four figure IDs `roles`, `timeline`, `directory`, `decision`.
- [ ] **Step 2: Run red tests.** Run `python3 -I -m unittest discover -s tests -p test_pdfs.py -k user_guide -v` and the focused documentation tests in `tests/test_acceptance.py`; expect missing tutorial/figure/tag assertions.
- [ ] **Step 3: Write the two tutorials.** For each step include purpose, exact action/command, expected observation, and recovery. Separate scanner-only demo from explicitly consent-gated live `review`; use only bundled synthetic material. Explain account permissions, source transfer, policy and storage, report anatomy, confidential `private/`, reviewer handoff, unsigned manifest, fix/rerun, and troubleshooting. Never present a mock output as an observed live run. Use this command shape after confirming each flag against the v2.4.0 CLI, with the SHA, policy, output, and model values explicitly marked as examples to replace:

```sh
commitscope review \
  --repo /absolute/path/to/synthetic-target \
  --ref 0123456789abcdef0123456789abcdef01234567 \
  --policy /protected/review-policy.json \
  --out /protected/reviews/run-id \
  --auth account \
  --allow-code-upload \
  --model APPROVED_EXACT_MODEL_ID
commitscope verify-review --run /protected/reviews/run-id
```
- [ ] **Step 4: Validate command shape without model calls.** Compare all flags against `commitscope review --help` and `commitscope verify-review --help` from a clean installed v2.4.0 CLI. Run documented `preflight`, `doctor`, and scanner-only `demo` with approved local scanner state. For the consent-gated command, parse/validate flags and refer only to existing labeled synthetic live-acceptance evidence; do not issue new model requests.
- [ ] **Step 5: Build and inspect.** Rebuild at the pinned epoch; run focused tests. Read EN/RU `pdftotext -layout`, render every guide page at 120 dpi, inspect all pages and dense ones at 200 dpi. Fix wraps, code blocks, Cyrillic and caption placement.
- [ ] **Step 6: Update digests and commit.** Run checksum update/check, `git diff --check`, and commit `docs: teach the bilingual corporate review workflow`.

### Task 5: Complete Discoverability, Package, and Visual Acceptance

**Files:**
- Modify: `docs/security-review-pdfs/README.md`, `README.md`
- Modify: `tests/test_pdfs.py`, `tests/test_acceptance.py`
- Modify: `SHA256SUMS`
- Inspect: `config/sdist-manifest.json`, `config/resource-manifest.json`

**Interfaces:**
- Consumes: four final PDFs and paired sources from Tasks 3-4.
- Produces: discoverable handouts, complete verification evidence, and a reviewable documentation PR; no release/tag change.

- [ ] **Step 1: Add final acceptance assertions.** Check README links to all four PDFs, exact source-manifest inclusion, no pre-release wording in extracted guide text, current account-only workflow, and no change to the two legacy PDF digests. Require reproducible outputs from two fresh `build_pdfs.py --output-dir` runs at the pinned epoch.
- [ ] **Step 2: Run red tests.** Run the focused `test_pdfs.py`/`test_acceptance.py` assertions and record the missing links or contract failures.
- [ ] **Step 3: Update entry points.** Describe the methodology as the dated, sourced rationale and the guide as the step-by-step tutorial; link both language editions from `README.md` and `docs/security-review-pdfs/README.md`. State that the published v2.4.0 tag predates this documentation PR and is not rewritten.
- [ ] **Step 4: Run green and broad checks.** Run `python3 -I tests/run_tests.py`, `python3 -I scripts/update_checksums.py --check`, `git diff --check`, and two byte-compared PDF builds. Run `python3 -I scripts/build_dist.py --dist-dir /private/tmp/commitscope-presentation-dist`; inspect the sdist for four PDFs, paired JSON, Noto Sans, builder, and updated docs; install wheel and sdist in clean venvs.
- [ ] **Step 5: Final page-by-page QA.** Render every page of all four PDFs at 120 dpi and every figure/matrix/code-dense page at 200 dpi. Inspect labels, table breaks, printed citations, page numbers, links, Russian glyphs, and absence of overlap. Correct and repeat until no defects remain. Keep QA images outside the repo.
- [ ] **Step 6: Commit and review.** Refresh `SHA256SUMS`; commit `docs: publish presentation handouts in both languages`. Request an independent whole-branch review of claim accuracy, EN/RU parity, stale instructions, and release-boundary wording; fix findings with tests. Then open a separate documentation PR against `main`, without merge, tag, or release.

## Execution finish line

The branch is ready for owner review only when all four PDFs are visually checked page by page, cited claims trace to current primary sources, examples match v2.4.0, both languages have matching semantic IDs, tests/checksums/package builds pass, and an independent reviewer has no unresolved Important findings. The owner decides whether and when to merge and publish an updated documentation release.
