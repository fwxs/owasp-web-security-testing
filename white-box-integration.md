# White-box integration: graphify + codebase-memory-mcp + WSTG skill

Code-assisted (white/grey-box) methodology for an **authorized** web app assessment. It uses two
code-graph tools to target the dynamic testing that the `owasp-web-security-testing` skill drives.

## Roles — who does what, and why

| Component | Authoritative for | Not authoritative for |
|-----------|-------------------|-----------------------|
| **codebase-memory-mcp** (directed AST/LSP graph: functions, classes, CALLS/USAGE/RESOLVED_CALLS, HTTP routes, cross-service links; semantic search; ~15 MCP tools) | Entrypoint enumeration, **directed** reachability (handler → sink), route inventory, cross-service edges | Runtime behavior, config/infra, whether a path is exploitable |
| **graphify** (multimodal knowledge graph over code+docs; edges tagged EXTRACTED / INFERRED / …; runs as a Claude Code skill / optional local MCP) | Architecture model, trust boundaries, roles/tenancy, **spec-vs-implementation** gaps, semantic "how does X work" | Reachability direction (graph is undirected); anything on an INFERRED edge without corroboration |
| **owasp-web-security-testing** skill | Test methodology, WSTG mapping, coverage checklist, risk rating, report | Discovering code structure (that's the graphs' job) |
| **Claude** | Orchestration; maintains the attack-surface inventory that bridges graphs → WSTG checklist | — |

Rule of thumb: **graphify for "what is the app and what should it enforce," codebase-memory-mcp for
"what exactly calls what," WSTG skill for "prove it and report it."** Never trust an INFERRED
graphify edge as an attack path until codebase-memory-mcp (or the code) confirms the directed call.

## The bridging artifact

`resources/attack-surface-inventory.csv` is the join table that makes this an integration rather than
three tools in a row. One row per entrypoint→sink path:

`entrypoint, method, handler, auth_required, roles, params, reachable_sinks, sink_type, trust_boundary, candidate_wstg, static_confidence, priority, dynamic_result, evidence`

- `auth_required` / `roles`: from the code — is there an authz check *on the path* to the sink?
- `sink_type`: sql | cmd | template | url-fetch | deserialize | file-path | authz-missing | redirect | ...
- `static_confidence`: `extracted` (AST-confirmed directed path) | `inferred` (graphify only — must verify)
- `candidate_wstg`: WSTG test IDs from the skill's Step-3 mapping (e.g. INPV-05 for a SQL sink)
- `dynamic_result`: filled only after the WSTG test runs against the authorized app

Rows here feed priorities into `wstg-checklist.csv`; the checklist stays the coverage source of truth.

## Workflow

### Phase 0 — Prep and trust boundary (do not skip)
- Confirm written authorization and scope (same gate as the base skill).
- **Pin the commit** you index. The graph is a snapshot; record the SHA so findings are reproducible
  and you can reason about drift from what's deployed.
- Index with both tools: `index_repository` (codebase-memory-mcp) and graphify ingest into
  `graphify-out/`. Confirm the exact MCP tool names from the server's advertised tool list
  (`/mcp` in Claude Code) before scripting calls — do not assume verb names.
- **Data-handling check.** graphify's semantic pass can send code/doc content to your AI provider
  unless you run code-only mode; codebase-memory-mcp runs a local binary and writes to agent config.
  On a client engagement, confirm this is permitted by the engagement terms before indexing their code.

### Phase 1 — Architecture orientation (graphify)
Ask architecture-level questions: frameworks, auth/session model, services and their boundaries,
where PII/payments/privileged actions live, and — critically — **what the design docs say the app
should enforce**. Output: the trust-boundary map and role/tenancy model. This replaces the guesswork
in Step 2 of `attack-vector-strategy.md`.

### Phase 2 — Entrypoint enumeration (codebase-memory-mcp)
Query the graph for all HTTP routes/handlers. This is a more complete entrypoint set than a crawler
(it includes unlinked, deprecated, and admin routes the crawler never reaches). Reconcile against
graphify: routes in docs but not code (drift) and code routes absent from docs (shadow endpoints)
are both worth a row. Write one inventory row per entrypoint.

### Phase 3 — Directed flow tracing to sinks (codebase-memory-mcp)
For each entrypoint, trace the **directed** call chain handler → sink. Use semantic search to catch
aliased sinks (search "query"/"exec"/"fetch"/"render"/"deserialize"/"eval"). Classify each sink and,
on each path, record whether an authz check is present or **absent**:

| Sink reached | Attack path | WSTG |
|--------------|-------------|------|
| SQL/ORM exec with tainted input | SQLi | INPV-05 |
| OS command / shell | Command injection | INPV-12 |
| Template render of input | SSTI / stored XSS | INPV-* / CLNT-01 |
| Server-side URL fetch of input | SSRF | INPV-19 |
| Deserialization of input | Insecure deserialization | INPV-* |
| File path built from input | Path traversal / LFI | ATHZ-01 / INPV-11 |
| Object fetched by user-supplied ID, **no authz on path** | IDOR / BOLA | ATHZ-04 |
| Privileged handler reachable by low-priv role | Privilege escalation | ATHZ-02/03 |

`authz-missing` on a path to a sensitive sink is your highest-value lead — it is exactly what a
crawler cannot see and what code-graph is uniquely good at surfacing.

### Phase 4 — Map and prioritize (WSTG skill)
Convert each path into candidate WSTG tests and rank by **static exposure × sink impact**:
1. Unauthenticated path (no authz check) → dangerous sink, crossing a trust boundary.
2. Cross-tenant/cross-user object access (IDOR/BOLA).
3. Authenticated injection/upload sinks.
4. Session/CSRF on state-changing handlers.
5. Everything else (config, transport, info leak).
Push these priorities into `wstg-checklist.csv`.

### Phase 5 — Dynamic verification (WSTG skill, authorized runtime)
The graphs produced hypotheses; now confirm each against the running app using the WSTG test's
**How to Test**. A static path can be a false positive (parameterized query the AST didn't mark safe,
framework auto-escaping, upstream WAF, dead code). Only a reproduced result against the deployed app
is a finding. Record `dynamic_result` + evidence in the inventory and `result/severity` in the
checklist. This closes the code-truth vs runtime-truth gap.

### Phase 6 — Spec-gap and chaining (graphify + WSTG skill)
Use graphify to compare intended design (docs) against implemented behavior — mismatches are often
business-logic flaws (BUSL) that no call-graph reveals (e.g. the workflow *allows* skipping a payment
step the spec says is mandatory). Then chain confirmed findings across entrypoints (see Step 6 of the
strategy doc) — a chain reaching admin or another tenant is one high/critical, not several mediums.

### Phase 7 — Coverage and report (WSTG skill)
`python3 scripts/coverage_report.py resources/wstg-checklist.csv`, rate findings with one model, and
populate `report-template.md`. Add the predicting call chain as static evidence per finding — a report
that shows both the code path and the reproduced exploit is far stronger than either alone.

## Feedback loops
- **Dynamic → static:** discovered an unlinked route or parameter at runtime? Query the graph for its
  call chain to explain and prioritize it.
- **Static → dynamic:** code routes the crawler never hit mark gaps in dynamic coverage — test them.
- **graphify INFERRED → codebase-memory-mcp:** every INFERRED edge you intend to act on gets confirmed
  as a directed EXTRACTED call (or dropped).

## Failure modes to watch
- **Snapshot drift:** the graph is at commit X; the deployed app may differ. Re-index on material
  change; never report a static-only path as confirmed.
- **Undirected/inferred over-trust (graphify):** manufactures non-existent paths. Direction and
  confidence come from codebase-memory-mcp or the code.
- **Tool-name assumptions:** bind to the server's actual advertised MCP tool names; fully-qualify them
  (`ServerName:tool_name`) to avoid tool-not-found errors.
- **Coverage illusion:** static reachability ≠ tested. A path stays `not-started` in the checklist
  until it's been dynamically verified or justified `n/a`.
