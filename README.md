# AuthZEN PoC

A browser-based proof-of-concept demonstrating the [AuthZEN Authorization API](https://openid.net/wg/authzen/specifications/) (OpenID Foundation) — the emerging standard for externalising authorization decisions to a Policy Decision Point (PDP).

**Live demo:** https://authzen-poc.pages.dev

## What this demonstrates

- **AuthZEN API** (`POST /access/v1/evaluation` and `/access/v1/evaluations`) — single and bulk access evaluation
- **InMemoryPDP** — glob-pattern rule matching, priority-based conflict resolution, default-deny
- **OpenFGA export** — generate an authorization model + tuples from PDP rules, playable at [play.fga.dev](https://play.fga.dev)
- **OPA/Rego export** — generate a Rego v1 policy, runnable at [play.openpolicyagent.org](https://play.openpolicyagent.org)
- **AS Bridge simulation** — how an OAuth Authorization Server calls AuthZEN during [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) Token Exchange

All authorization logic runs in-browser via WebAssembly (no server required).

## Structure

```
pkg/authzen/        Core AuthZEN types, InMemoryPDP, HTTP handler, OpenFGA/Rego export
cmd/demo-wasm/      Go WASM entry point (9 exported functions)
demo/               Static browser demo (HTML + authzen.wasm + wasm_exec.js)
scripts/            Standards tracker automation
standards-baseline.json  Tracked specifications and their revision state
```

## Development

**Prerequisites:** Go 1.26.5+, govulncheck v1.6.0

```bash
# Install pre-push hook
git config core.hooksPath .githooks
chmod +x .githooks/pre-push

# Run tests
export PATH="/opt/homebrew/bin:$PATH"
go test ./... -race

# Build WASM
GOOS=js GOARCH=wasm go build -o demo/authzen.wasm ./cmd/demo-wasm/
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" demo/wasm_exec.js
```

## Standards tracked

| Standard | Status | Check method |
|---|---|---|
| AuthZEN Authorization API 2.0 | WG draft | Page hash + GitHub |
| draft-gazitt-oauth-authzen-issuance-00 | Individual draft | IETF Datatracker |
| draft-gazitt-oauth-authzen-token-exchange-00 | Individual draft | IETF Datatracker |
| RFC 8693 Token Exchange | RFC | Manual |
| OpenFGA DSL schema 1.1 | Active | Page hash + GitHub |
| OPA Rego v1 | Active | Page hash + GitHub |

The [standards-tracker workflow](.github/workflows/standards-tracker.yml) runs daily and opens GitHub issues when revisions are detected.
