# Pinned sibling OpenAPI copies

The national APIs this system calls are published by their own
repositories. Each one is copied here unmodified as `<system>.yaml` and
pinned by one line of `SOURCE` (reconciliation M11):

```
<copy> <owner/repo> <commit> <path in that repo>
```

| Copy | Repository | Used for |
|---|---|---|
| `cisp.yaml` | rootxkit/uspace-cisp | the publication, heartbeat, reads and subscriptions; generated into `cispclient/` |
| `authority.yaml` | rootxkit/uspace-authority | the token service and its JWKS; `occurrence/v1` once the authority publishes it |
| `ussp.yaml` | rootxkit/uspace-ussp | the receiver of the degraded direct delivery |

Client types are generated from these copies, never written by hand.
`scripts/check-contracts.sh` (`make check-contracts`, CI job
`contracts`) fetches every file at its pinned commit and fails on any
difference, on a copy without a `SOURCE` line and on a line without a
copy; the same script checks the uspace-lab schemas pinned in
`../../schemas/SOURCE`. Bumping a copy is one `build:` commit that
changes the file and its line together, never inside a feature pull
request. When the uspace-lab aggregate of the national APIs is
published, it replaces these copies.
