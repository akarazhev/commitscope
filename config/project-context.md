# Project security context — owner-maintained

Status: UNAPPROVED / GENERIC. Replace this text before relying on AI business-logic review.

The reviewer must not assume that this project is multi-tenant, Internet-facing, or a web service. Establish those facts from an owner-approved description. Record important assets, actors/roles, trust boundaries, deployment constraints and security invariants here. Describe existing authorization boundaries and intentional exceptions.

The bundled demonstration, and ONLY the demonstration, uses two synthetic tenants: tenant-a and tenant-b. A caller may read only invoices belonging to its tenant. A permitted same-tenant read must continue to work after remediation. Its direct function parameters are a test harness, not a real authentication system.
