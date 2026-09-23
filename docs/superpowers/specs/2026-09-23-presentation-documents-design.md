# Bilingual Presentation Documents Design

**Date:** 2026-09-23
**Base:** CommitScope v2.4.0, commit `25b56d2525cd256bf5d6d236eca1bad7f548ec84`
**Audience:** mixed leadership and engineering audience

## Intent and success criteria

The owner needs four bilingual PDF handouts for a company presentation: a
security-review methodology that surveys current international practice and
explains why CommitScope is a rational choice under the company's constraints,
and a teachable CommitScope user guide. The current two-page methodology and
three-page guide are operational summaries, not these handouts. Older illustrated
PDFs describe the obsolete 2.1.1 workflow and must not be presented as current.

The opening pages must be understandable without knowing CLI syntax; later pages
must give engineers auditable reasoning and executable instructions. Both
languages must make the same substantive claims. The documents must distinguish
source-backed facts, CommitScope's implemented behavior, and our qualitative
assessment. "Most rational" means fit to the stated company constraints, not a
universal or measured superiority claim.

## Deliverables and boundaries

Update these four tracked PDFs and their paired source data in place:

- `docs/security-review-pdfs/en/security-review-methodology-en.pdf`
- `docs/security-review-pdfs/ru/security-review-methodology-ru.pdf`
- `docs/security-review-pdfs/en/commitscope-user-guide-en.pdf`
- `docs/security-review-pdfs/ru/commitscope-user-guide-ru.pdf`

Preserve the two legacy playbooks as explicitly labeled historical references.
Update the PDF builder, documentation index, checksums, and focused tests only as
needed for the new content. Do not change scanner, AI, review, verifier, policy,
or distribution runtime behavior. Do not move or rewrite the published v2.4.0
tag; the documents will be proposed in a separate PR. No new release is implied.

Use only synthetic repository examples. Do not send company code or make model
requests as part of documentation generation or PDF QA. Any live tutorial step
requiring a Claude request must be visibly opt-in and require the operator's
organization-approved source-transfer authority.

## Methodology: argument and visual story

Structure both editions in the same sequence:

1. Executive decision: the company need, selected local workflow, and limits of
   the conclusion in plain language.
2. Dated landscape of complementary practices: threat modeling and manual
   review; SAST, secret detection, SCA, IaC and dynamic testing; AI-assisted
   analysis; verification, evidence retention, and human risk ownership.
3. Comparison matrix for manual-only, scanner-only, AI-only, a centralized
   service, and the local combined workflow. Assess coverage type,
   reproducibility, confidentiality/data transfer, operating burden, cost
   drivers, and evidence auditability. Use qualitative labels and explain each;
   do not invent detection percentages or vendor price figures.
4. Explicit decision criteria drawn from the agreed company workflow: mandatory
   Claude Code account, employee-initiated local run, approved upload, protected
   directory handoff, assigned reviewer, exact commit, and macOS/glibc Linux
   support. Explain why each alternative is insufficient alone and which useful
   practices remain outside CommitScope.
5. Current implementation and trade-offs: immutable snapshot; Semgrep,
   Gitleaks, Trivy; independent Hunter and Verifier; protected raw and
   normalized evidence; `verify-review`; human decision. Show trust boundaries,
   what reaches Anthropic, and what stays local. Explain fail-closed
   `INCOMPLETE`, bounded heuristic secret screening, and unsigned manifest.
6. Evidence journey: hypothesis, verification/counterevidence, finding,
   reviewer decision, fix commit, and full re-review. A concrete synthetic
   vulnerable-to-fixed example must not imply universal model accuracy.
7. Rollout proposals and limitations: pilot measures, review ownership,
   exception handling, change control for model/scanner updates, no automatic
   merge approval or penetration-test claim.
8. Numbered sources and "checked on 2026-09-23" statement. Cite sources near
   the associated facts and distinguish stable publications from drafts.

Required diagrams: worldwide-practice map, options/criteria matrix, data flow
with trust boundaries, finding lifecycle, and rollout stages. Each diagram has a
number, caption, and text explanation so it remains intelligible without color.

Primary references to verify during writing include NIST SSDF 1.1 (final;
SSDF 1.2 is draft), OWASP SAMM, OWASP ASVS 5.0, OWASP LLM prompt-injection
guidance, and official Anthropic Claude Code security/authentication and data
handling documentation. Reference SLSA only for the bounded provenance point if
needed. Cite the exact publication/page used, not search results. The matrix's
relative judgments are our inference under the stated criteria, not claims made
by the standards.

## User guide: teach one complete journey

Provide a role-based tutorial with a manager-readable journey overview and
engineer/reviewer detail. Use the same chapter IDs in English and Russian:

1. What a completed corporate review is and is not; operator and reviewer roles.
2. Install from the already-published `v2.4.0` tag; host requirements;
   preflight, bootstrap, doctor; interpretation of failures.
3. Prepare Claude Code 2.1.259+ under the intended personal/corporate account;
   check authentication; explain exact model ID, upload authorization, and the
   account-only/no-fallback boundary.
4. Prepare a clean target and full commit ID, external approved policy, safe
   dependencies, and new protected output path. Teach what the source packet
   can contain and why heuristic screening is not permission to upload secrets.
5. First run on bundled synthetic material. Show scanner-only `demo` clearly as
   practice, then an explicitly consent-gated end-to-end `review` example.
   Commands must be checked against the released CLI and fixture structure;
   never present placeholder output as a real observed run.
6. Read `READY_FOR_HUMAN_REVIEW`, `FINDINGS_REQUIRE_TRIAGE`, and `INCOMPLETE`;
   explain normalized reports, `evidence/`, `private/`, and the separate human
   decision using a labeled synthetic example.
7. Preserve and transfer the unchanged protected directory; reviewer runs
   `verify-review`, examines evidence and limitations, and records their own
   decision with manifest hash in the company system.
8. Fix and rerun on a new commit and output directory; compare evidence without
   treating disappearance of a finding as proof of remediation.
9. Troubleshooting decision table and a concise command/exit-code reference.

Use illustrated role lanes, a one-run timeline, a directory anatomy diagram,
and a decision tree for the three exit states. For each teaching step include
the objective, command or action, expected observable result, and recovery when
it fails. No step may imply that `scan`, `ai`, or the GitHub Action alone is a
completed corporate review. Replace every stale claim that the v2.4.0 tag or
release does not exist.

## Source, layout, and rendering design

Continue using the existing `source/content-en.json`, `source/content-ru.json`,
ReportLab builder, checked-in Noto Sans font, A4 page size, and reproducible
epoch. Extend the current heading/paragraph/code schema with a small fixed set
of semantic blocks for tables, diagrams, callouts, captions, and references.
Each block and figure gets a stable language-neutral ID; the two source files
must have matching document/chapter/block and citation IDs. Text is localized,
while figure meaning and numerical claims remain equivalent. The renderer uses
fixed vector templates, not arbitrary drawing commands embedded in JSON.

Keep generous type size and space; paginate by readable units instead of
forcing a predetermined page count. Aim for a presentation-friendly methodology
and a fuller training guide, with appendices for dense reference material.
Clickable links must also print human-readable source titles and URLs. Avoid
decorative diagrams that carry no claim. Never rely on color alone to explain
roles or states.

## Verification and release handling

- Validate JSON schema, cross-language ID parity, figure/citation references,
  current version wording, and absence of obsolete API-auth/optional-AI steps.
- Smoke-test every documented command that can run without model consent in a
  disposable environment; validate the consent-gated command shape against CLI
  parsing and existing controlled acceptance evidence, labeling the distinction.
- Build twice with the pinned documentation toolchain and epoch; compare each
  corresponding PDF byte for byte and run source-manifest checksum checks.
- Run existing and focused PDF/document contract tests, including extracted
  text, metadata, required terms, links, table content, and bilingual structure.
- Render every page of all four PDFs with Poppler, visually inspect every page
  at presentation and print scale, and correct clipped text, overlaps,
  unreadable tables, missing Cyrillic glyphs, and broken page transitions.
- Preserve original legacy PDFs. Confirm the source package includes all four
  updated PDFs, source JSON, fonts, and builder inputs. Leave user worktree
  changes and `.idea/` untouched.
- Open a separate documentation PR only after review and verification. Do not
  modify the existing v2.4.0 tag or release; a later documentation release is a
  separate owner decision.

## Non-goals

No new security scanner, CLI workflow, account integration, dashboard, or
company-specific policy is proposed. No claim of production certification,
formal compliance, exhaustive secret removal, signed evidence, measured model
recall, or approval to transfer real corporate source is added by these PDFs.
