# Security Assessment Report: mcp-factorial

**Repository:** https://github.com/t4dhg/mcp-factorial
**Package:** `@t4dhg/mcp-factorial` v8.1.1
**Assessment Date:** 2026-04-16
**Assessor:** Automated multi-agent security audit (Claude)
**Scope:** Full source code, dependencies, CI/CD, authentication, destructive operations, obfuscation, and exfiltration analysis

---

## Executive Summary

This repository implements an MCP (Model Context Protocol) server that wraps the Factorial HR API, exposing HR management tools (employees, time-off, attendance, payroll, ATS, etc.) to AI assistants via the stdio transport.

**Overall Verdict: LOW-MEDIUM RISK -- No malicious intent detected.**

The codebase is clean of backdoors, data exfiltration, time bombs, and obfuscated code. All network traffic goes exclusively to `api.factorialhr.com`. Dependencies are minimal and well-known. However, there are several design-level security concerns around **ungated destructive operations**, a **trivially bypassable confirmation system**, and an **unvalidated API base URL override** that should be understood before deployment.

---

## 1. Backdoors & Data Exfiltration

| Check                                                | Result                                                                         |
| ---------------------------------------------------- | ------------------------------------------------------------------------------ |
| Outbound calls to non-Factorial domains              | **CLEAN** -- All 4 `fetch()` calls target `api.factorialhr.com` exclusively    |
| `eval()` / `new Function()` / dynamic code execution | **CLEAN** -- None found                                                        |
| `child_process` / `exec` / `spawn`                   | **CLEAN** -- None found                                                        |
| WebSocket / covert network channels                  | **CLEAN** -- None found                                                        |
| Data encoding / steganography                        | **CLEAN** -- None found                                                        |
| API key / token logging or exfiltration              | **CLEAN** -- Credentials are never logged or sent externally                   |
| CI/CD secret exfiltration                            | **CLEAN** -- Standard GitHub Actions with `CODECOV_TOKEN` and `NPM_TOKEN` only |

**Conclusion: No backdoors or exfiltration mechanisms found.**

---

## 2. Dependencies & Supply Chain

| Metric                               | Value                                                      |
| ------------------------------------ | ---------------------------------------------------------- |
| Production dependencies              | **3** (`@modelcontextprotocol/sdk`, `dotenv`, `zod`)       |
| Dev dependencies                     | **11** (eslint, prettier, typescript, vitest, husky, etc.) |
| Total transitive packages (lockfile) | **411**                                                    |
| Non-npmjs.org resolved URLs          | **0**                                                      |
| Missing integrity hashes             | **0**                                                      |
| Suspicious/typosquatting packages    | **0**                                                      |
| Malicious install scripts            | **0** (only standard `esbuild` and `fsevents` postinstall) |

### Dependency Inventory

| Package                            | Assessment                                                                                          |
| ---------------------------------- | --------------------------------------------------------------------------------------------------- |
| `@modelcontextprotocol/sdk` ^1.0.0 | SAFE -- Official Anthropic MCP SDK                                                                  |
| `dotenv` ^16.4.0                   | SAFE -- Industry standard, 30M+ weekly downloads                                                    |
| `zod` ^3.24.0                      | SAFE -- Standard schema validation, 14M+ weekly downloads                                           |
| All 11 dev dependencies            | SAFE -- All well-known packages (eslint, prettier, typescript, vitest, husky, lint-staged, codecov) |

### Minor Issues

- **LOW:** `package-lock.json` version field shows `3.0.0` while `package.json` shows `8.1.1` (stale lockfile metadata -- cosmetic only, does not affect security)
- **LOW:** `server.json` shows version `7.1.0` vs `package.json` `8.1.1` (stale)

**Conclusion: Supply chain is clean. Minimal, well-known dependencies with verified integrity.**

---

## 3. Time Bombs & Obfuscated Code

| Check                                                       | Result                                                                               |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Date-based conditional logic / triggers                     | **CLEAN** -- All `Date.now()` usage is for cache TTL, token expiry, audit timestamps |
| `eval()` / `new Function()`                                 | **CLEAN** -- None found                                                              |
| Base64 encoding (`atob`/`btoa`/`Buffer.from(...,'base64')`) | **CLEAN** -- Only `Buffer.from(arrayBuffer)` for document download (no base64)       |
| Hex-encoded strings / `String.fromCharCode`                 | **CLEAN** -- None found                                                              |
| Minified or unreadable code                                 | **CLEAN** -- All source is cleanly formatted TypeScript                              |
| Suspicious `setTimeout`/`setInterval`                       | **CLEAN** -- Only used for HTTP retry backoff and cache cleanup                      |
| Out-of-place files                                          | **CLEAN** -- All files match expected project structure                              |

**Conclusion: No time bombs, no obfuscated code, no hidden logic.**

---

## 4. Authentication & Credential Handling

### Architecture

The server supports two authentication modes:

- **API Key** (`x-api-key` header) -- for standard API calls
- **OAuth2 refresh-token grant** -- for document downloads

### Positive Findings

- OAuth2 flow is standard and correctly implemented
- Tokens stored in-memory only (no disk persistence to protect)
- API keys and tokens are never logged, even in debug mode
- Error messages reference variable names, not credential values
- `.gitignore` properly excludes `.env` files
- Stdio-only transport (no HTTP listeners, no network attack surface)
- Confirmation tokens use `crypto.randomBytes(16)` (cryptographically secure)

### Issues Found

| Severity     | Finding                                                                                                                                                                                                                                            | Location                       |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| **CRITICAL** | **`FACTORIAL_BASE_URL` allows redirecting all API traffic (including API key) to any URL with no validation.** No HTTPS enforcement, no domain restriction. An attacker who controls the environment could exfiltrate the API key.                 | `src/config.ts:104-108`        |
| **HIGH**     | **Aggressive `.env` file search includes hardcoded paths** (`~/turborepo/.env`, `~/projects/.env`). A malicious `.env` file at these paths could override API keys and base URL. These appear to be development artifacts left in production code. | `src/config.ts:65-66`          |
| **MEDIUM**   | **No HTTPS enforcement on API requests.** Default URL is HTTPS but if `FACTORIAL_BASE_URL` is set to `http://`, API keys transmit in cleartext.                                                                                                    | `src/http-client.ts`           |
| **MEDIUM**   | **Document download bypasses standard HTTP client**, using a direct `fetch()` call. While the URL is hardcoded to HTTPS (which is good), it skips retry logic and any future security middleware.                                                  | `src/api/documents.ts:178-216` |
| **MEDIUM**   | **OAuth2 variables missing from `server.json` manifest.** `FACTORIAL_OAUTH_CLIENT_ID`, `FACTORIAL_OAUTH_CLIENT_SECRET`, and `FACTORIAL_OAUTH_REFRESH_TOKEN` are not declared with `isSecret: true`, so MCP clients won't protect them.             | `server.json`                  |
| **LOW**      | **Debug logging may include API response data** (which could contain PII) when `DEBUG=true`. API keys themselves are NOT logged.                                                                                                                   | `src/http-client.ts:124,130`   |
| **LOW**      | **Rotated refresh tokens are lost on restart.** New tokens are cached in-memory only; the old token in env vars may become invalid.                                                                                                                | `src/oauth.ts:169`             |

---

## 5. Destructive API Operations

This is the area with the most significant findings. The server exposes **~50 write operations** to the Factorial HR API.

### Confirmation System Design Flaw

The server has **two** confirmation systems, but only the weaker one is active:

| System                                                         | Location                      | Status                                    | Strength                                                    |
| -------------------------------------------------------------- | ----------------------------- | ----------------------------------------- | ----------------------------------------------------------- |
| `checkConfirmation` (boolean `confirm: true` parameter)        | `src/tools/shared.ts:156-169` | **ACTIVE**                                | **WEAK** -- trivially bypassable by passing `confirm: true` |
| `ConfirmationManager` (crypto tokens, 5-min TTL, one-time use) | `src/confirmation.ts`         | **DEAD CODE** -- never imported or called | **Strong** -- proper two-phase confirmation                 |

The active system is a single boolean: if the MCP client (or LLM agent) passes `{confirm: true}`, the operation proceeds immediately. There is no multi-step flow, no token exchange, no time delay.

### Ungated DELETE Operations (No Confirmation At All)

These DELETE operations execute immediately without any safety check:

| Operation               | Endpoint                                          | Tool                                           |
| ----------------------- | ------------------------------------------------- | ---------------------------------------------- |
| Delete project task     | `DELETE /project_management/project_tasks/{id}`   | `factorial_projects(action: "delete_task")`    |
| Remove project worker   | `DELETE /project_management/project_workers/{id}` | `factorial_projects(action: "remove_worker")`  |
| Delete time record      | `DELETE /project_management/time_records/{id}`    | `factorial_projects(action: "delete_time")`    |
| Delete training session | `DELETE /trainings/sessions/{id}`                 | `factorial_training(action: "delete_session")` |
| Unenroll from training  | `DELETE /trainings/memberships/{id}`              | `factorial_training(action: "unenroll")`       |
| Archive work area       | `POST /locations/work_areas/{id}/archive`         | `factorial_work_areas(action: "archive")`      |

### Gated DELETE Operations (Confirmation Required, but Bypassable)

These require `confirm: true` but can be trivially bypassed:

| Operation          | Endpoint                                   | Impact                                     |
| ------------------ | ------------------------------------------ | ------------------------------------------ |
| Delete team        | `DELETE /teams/teams/{id}`                 | Removes team and member associations       |
| Delete location    | `DELETE /locations/locations/{id}`         | Removes location and employee associations |
| Delete project     | `DELETE /project_management/projects/{id}` | Removes project and all sub-resources      |
| Delete training    | `DELETE /trainings/trainings/{id}`         | Removes training and all enrollments       |
| Delete job posting | `DELETE /ats/job_postings/{id}`            | Removes posting and all applications       |
| Delete candidate   | `DELETE /ats/candidates/{id}`              | Permanently removes candidate record       |
| Delete application | `DELETE /ats/applications/{id}`            | Removes application                        |
| Terminate employee | `PATCH /employees/employees/{id}`          | Terminates employee, revokes access        |
| Cancel leave       | `DELETE /timeoff/leaves/{id}`              | Cancels approved leave                     |

### Other Ungated Business-Critical Actions

| Operation                        | Impact                                                        |
| -------------------------------- | ------------------------------------------------------------- |
| `approveLeave`                   | Deducts from employee's leave allowance                       |
| `advanceApplication`             | Advances candidate through hiring pipeline                    |
| All CREATE operations (16 total) | Creates employees, teams, projects, etc. without confirmation |
| All UPDATE operations (14 total) | Modifies existing records without confirmation                |

### Unimplemented Safety Features

The `OPERATION_POLICIES` in `src/write-safety.ts` defines `cooldownMs` and `maxBatchSize` fields, but **no code enforces them**. There is no rate limiting on destructive operations.

---

## 6. Environment Variable Security

| Variable                        | Documented in .env.example | Security Impact                                                |
| ------------------------------- | -------------------------- | -------------------------------------------------------------- |
| `FACTORIAL_API_KEY`             | Yes                        | Primary credential -- handled securely                         |
| `FACTORIAL_OAUTH_CLIENT_ID`     | Yes                        | OAuth credential -- handled securely                           |
| `FACTORIAL_OAUTH_CLIENT_SECRET` | Yes                        | OAuth credential -- handled securely                           |
| `FACTORIAL_OAUTH_REFRESH_TOKEN` | Yes                        | OAuth credential -- handled securely                           |
| `DEBUG`                         | Yes                        | Enables verbose stderr logging (no credential leak)            |
| `FACTORIAL_API_VERSION`         | Yes                        | API version selection -- no security impact                    |
| `FACTORIAL_TIMEOUT_MS`          | Yes                        | Request timeout -- no security impact                          |
| `FACTORIAL_MAX_RETRIES`         | Yes                        | Retry count -- no security impact                              |
| `FACTORIAL_BASE_URL`            | **No**                     | **CRITICAL** -- Can redirect all API traffic including API key |
| `ENV_FILE_PATH`                 | **No**                     | **LOW** -- Custom .env file path                               |

---

## 7. Risk Summary

### By Category

| Category               | Verdict         | Details                                                        |
| ---------------------- | --------------- | -------------------------------------------------------------- |
| Backdoors              | **CLEAN**       | No backdoors, no remote code execution vectors                 |
| Data Exfiltration      | **CLEAN**       | No external data transmission beyond Factorial API             |
| Supply Chain           | **CLEAN**       | 3 production deps, all well-known, all from npmjs.org          |
| Time Bombs             | **CLEAN**       | No date-triggered logic                                        |
| Obfuscated Code        | **CLEAN**       | All code is clean, readable TypeScript                         |
| Authentication         | **MEDIUM RISK** | Unvalidated base URL override could redirect credentials       |
| Destructive Operations | **HIGH RISK**   | 6 ungated DELETE operations; confirmation system is bypassable |
| Configuration          | **LOW RISK**    | Aggressive .env search, undocumented env vars                  |

### Critical & High Findings Summary

| #   | Severity     | Finding                                                                                      | Recommendation                                                                                          |
| --- | ------------ | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| 1   | **CRITICAL** | `FACTORIAL_BASE_URL` accepts any URL, can redirect API key to attacker                       | Validate URL scheme (HTTPS only) and optionally restrict domain; or remove this override entirely       |
| 2   | **HIGH**     | 6 DELETE operations have zero confirmation gate                                              | Add `checkConfirmation` calls and `OPERATION_POLICIES` entries for all DELETE operations                |
| 3   | **HIGH**     | Active confirmation system is trivially bypassable (`confirm: true` boolean)                 | Wire up the existing `ConfirmationManager` (crypto-token two-phase system) which is currently dead code |
| 4   | **HIGH**     | Hardcoded `.env` search paths (`~/turborepo/.env`, `~/projects/.env`)                        | Remove these development-specific fallback paths                                                        |
| 5   | **MEDIUM**   | `approveLeave` and `advanceApplication` have no confirmation despite being business-critical | Add confirmation requirements                                                                           |
| 6   | **MEDIUM**   | No rate limiting or cooldown enforcement on destructive operations                           | Implement the `cooldownMs` enforcement that is defined but not active                                   |

---

## 8. Recommendations for Deployment

### Before Running in Production

1. **Set only the minimum required environment variables.** Do NOT set `FACTORIAL_BASE_URL` -- let it default to `https://api.factorialhr.com`.
2. **Use a Factorial API key with minimal permissions.** If you only need read access, use a read-only API key. This is the single most effective mitigation for the destructive operations risk.
3. **Do NOT place `.env` files at `~/turborepo/.env` or `~/projects/.env`** -- the server will load them unexpectedly.
4. **Keep `DEBUG=false`** in production to avoid logging API response data that may contain PII.

### If Modifying the Code

1. **Validate `FACTORIAL_BASE_URL`** in `src/config.ts` -- reject non-HTTPS URLs and optionally restrict to `*.factorialhr.com`.
2. **Remove hardcoded `.env` fallback paths** (`~/turborepo/.env`, `~/projects/.env`) from `src/config.ts:65-66`.
3. **Add `checkConfirmation` to all ungated DELETE operations** in the tools layer.
4. **Consider activating the `ConfirmationManager`** (`src/confirmation.ts`) for a proper two-phase confirmation flow.
5. **Add `OPERATION_POLICIES` entries** for all missing operations.

---

## 9. Conclusion

**This codebase does not contain malicious code.** There are no backdoors, no data exfiltration, no time bombs, no obfuscated code, and no compromised dependencies. All network communication is directed to the legitimate Factorial HR API.

The primary risks are **architectural** rather than malicious:

- The confirmation system for destructive operations is weak by design (single boolean, not a crypto-token flow)
- Several DELETE operations lack any confirmation gate
- The API base URL can be overridden without validation

For a deployment on a **private network** with a **read-only or limited-permission API key**, the risk is **acceptable**. For a deployment with a full-permission API key, the destructive operations gaps should be addressed first.

---

_Report generated by multi-agent security analysis. 5 specialized agents examined: (1) backdoors & exfiltration, (2) dependencies & supply chain, (3) destructive API operations, (4) time bombs & obfuscation, (5) authentication & credential handling. Total files reviewed: 60+ source files, 411 lockfile entries, CI/CD workflows, and all configuration files._
