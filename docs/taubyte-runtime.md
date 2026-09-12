# Taubyte Runtime

InfraSeal includes a Taubyte runtime provider scaffold, but it is not a live deployment integration yet. Today, `--runtime taubyte` checks the configured runtime resolver and falls back to local execution when the YAML contains:

```yaml
runtime:
  preferred: local
  fallback: local
```

or when a command explicitly asks for Taubyte while local fallback is available:

```bash
infraseal scan --profile quick --runtime taubyte
```

The result records the runtime as `local (fallback from taubyte)`.

## Current Status

- Implemented: runtime provider interface, Taubyte provider registration, explicit unavailable status, fallback-to-local behavior, and a unit test that prevents unsupported deployment claims.
- Not implemented: Taubyte project provisioning, Dream/Tau command execution, workload packaging, sandbox artifact upload/download, log collection, and cleanup.
- Safety posture: pressing or invoking the Taubyte runtime path cannot currently deploy anything. It either falls back to local execution or returns an explicit unavailable error when no fallback is configured.

## Planned Integration

The intended flow is:

1. Detect `dream` or `tau` on `PATH`.
2. Create or select an isolated local Dream universe or configured Taubyte cloud.
3. Package the target workload and scan evidence.
4. Deploy the workload to the sandbox.
5. Run InfraSeal evaluator adapters against the sandbox endpoint and repository evidence.
6. Pull logs, response samples, and scan artifacts back into `.infraseal/reports/`.
7. Destroy or freeze the sandbox based on policy.

Taubyte's public docs describe Dream as the local cloud tool and `tau` as the project/deployment CLI. See:

- [Taubyte installation](https://tau.how/getting-started/installation/)
- [Taubyte local cloud](https://tau.how/getting-started/local-cloud/)
- [Tau CLI](https://tau.how/tools/tau-cli/)

## Future YAML Shape

```yaml
runtime:
  preferred: taubyte
  fallback: local
  taubyte:
    mode: dream
    universe: infraseal-eval
    project: support-agent-eval
    cleanup: always
```

Until those fields are implemented, keep `fallback: local` for normal development and CI.
