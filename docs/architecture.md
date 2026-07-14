# Architecture

1. Wazuh collects endpoint, identity, PAM, bastion, VPN, and critical-system telemetry.
2. The ingestion layer normalizes data into the internal event schema.
3. Detection logic evaluates Sigma-derived rules and custom correlations.
4. Analytics computes user and session risk in near real time.
5. Decisioning converts risk into enforcement actions.
6. Keycloak consumes the decision for session control and step-up auth.
7. OpenFGA remains the fine-grained authorization control plane.
8. OpenBao and liboqs-backed workflows protect sensitive artifacts and credential operations.
