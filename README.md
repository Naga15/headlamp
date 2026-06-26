# Tier-1 E2E screenshots for PR #5929

Captured 2026-05-24 from a local kind ×2 + Keycloak setup running the
`feat/oidc-token-broadcast` branch with `--oidc-use-token-broadcast=true`.

| File | What it shows |
|---|---|
| [01-cluster-a-after-login.png](01-cluster-a-after-login.png) | After logging into cluster-a only: DevTools shows both `headlamp-auth-cluster-a` AND `headlamp-auth-cluster-b` cookies set (the broadcast worked) |
| [02-cluster-b-no-relogin.png](02-cluster-b-no-relogin.png) | Same browser session navigated to cluster-b — accessible without re-login, broadcast cookie is honored by cluster-b's apiserver |
| [03-negative-test-mismatched-client.png](03-negative-test-mismatched-client.png) | Negative test: cluster-b reconfigured with a different `oidc-client-id`. Only `headlamp-auth-cluster-a.0` cookie set, cluster-b prompts re-login. Precondition correctly enforced. |

Branch exists only to host these images for embedding in PR #5929
comments. Not intended for merge.
