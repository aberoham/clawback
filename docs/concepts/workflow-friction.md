---
title: Workflow Friction Ranking
parent: Concepts
nav_order: 4
---

# Workflow friction ranking
{: .no_toc }

Remediation adoption depends on friction. If a secure approach adds significant daily overhead, developers will circumvent it. This ranking helps security engineers prioritize which remediations to roll out first and set realistic expectations.

---

## Ranking

Ordered from lowest to highest friction for a typical macOS developer workstation.

| Approach | Friction | Daily impact |
|----------|----------|-------------|
| Git credential helpers (osxkeychain, GCM, `gh`) | Very low | Background operation, zero daily input |
| GCP ADC (`gcloud auth application-default login`) | Low | Periodic re-auth (~1hr tokens), SDKs handle the rest |
| Trusted publishing (PyPI, npm, RubyGems) | Low (for devs) | CI-side setup; developers stop publishing locally |
| `granted`/`assume` (AWS) | Low | Exports creds to current shell, no subshell required |
| 1Password `op run --env-file` | Low-medium | Single biometric touch per session in env-file mode; medium when wrapping individual commands |
| Exec-based kubeconfig plugins (EKS, GKE, AKS) | Low-medium | <200ms per kubectl call, transparent once configured |
| `direnv` + vault integration | Medium | 1-3 second latency per directory change; compounds with multiple secrets |
| 1Password SSH agent | Medium | Touch ID per SSH connection |
| Cloud SSO login (`aws sso login`, `gcloud auth`, `az login`) | Medium | 8-90 minute token lifetimes; unexpected re-auth interrupts flow |
| `aws-vault exec` | High | Requires wrapping every command or spawning subshell; 5-minute default keychain lock exacerbates |
| macOS `security` CLI (manual Keychain) | High | Verbose shell wrappers; GUI permission dialogs interrupt automation |
| FIDO2 hardware keys (SSH) | High | Physical touch per connection, no caching, device must be present |

## Key observations

**The lowest-friction fixes are often Tier 2** ("move it into Keychain/credential store") rather than Tier 1 ("eliminate it everywhere"). This is why a tiered remediation library is valuable: it provides an acceptable path when tool support is limited or when Tier 1 requires infrastructure changes that take time to roll out.

**Friction is not uniform across contexts.** 1Password `op run` is low friction in env-file mode (one biometric touch, then a normal workflow) but medium friction when wrapping individual CLI commands. `aws-vault` is high friction by default due to its 5-minute keychain lock timeout, but tolerable if configured with `--server` mode for long-running processes.

**Some high-friction approaches are worth it.** FIDO2 hardware keys are high friction but provide the strongest SSH security guarantee available. The friction cost is justified for high-value access (production infrastructure, signing keys). For routine development SSH, the 1Password SSH agent is a better friction/security tradeoff.

## Performance benchmarks

Where latency matters (shell startup, per-command overhead):

| Tool | Typical latency |
|------|----------------|
| `security find-generic-password` (macOS Keychain) | 10-50ms |
| Exec-based kubeconfig plugins | <200ms |
| 1Password `op read` | ~1 second |
| `direnv` with vault calls | 1-3 seconds per directory |
