# Unified Insider Threat, Privileged Misuse, and Quantum-Safe Access Platform

This repository is a pilot MVP for a banking-focused security platform that combines insider threat detection, privileged access misuse detection, behavioral risk scoring, risk-based access control, and quantum-safe protection of sensitive artifacts.

## What This MVP Includes

- Event normalization for identity, endpoint, PAM, and admin-system telemetry
- Rule-driven detections for privileged misuse and insider threat patterns
- Real-time behavioral scoring for users and sessions
- Risk-based access decisions for `allow`, `step_up`, `restrict`, and `block`
- A Keycloak-compatible risk adapter contract
- An evidence protection service with hybrid classical and post-quantum signing metadata
- Example Sigma-derived detection content and bank-specific scenarios
- A greenfield repo structure that can later integrate Wazuh, Keycloak, OpenFGA, OpenBao, River, and liboqs

## Architecture Stack

- Detection content: `SigmaHQ/sigma`
- Telemetry and monitoring: `wazuh/wazuh`
- Identity and authentication: `keycloak/keycloak`
- Fine-grained authorization: `openfga/openfga`
- Secrets workflows: `openbao/openbao`
- Behavioral analytics: `online-ml/river`
- Post-quantum cryptography: `open-quantum-safe/liboqs`

## Repository Layout

- `api/` standard-library HTTP application and internal APIs
- `ingestion/` event schema, normalization, and sample connectors
- `detections/` detection rules and catalog
- `analytics/` feature engineering and risk scoring
- `decisioning/` access policy evaluation
- `identity_adapters/` Keycloak and OpenFGA integration contracts
- `secrets_crypto/` evidence signing and artifact protection
- `docs/` architecture, threat model, and integration notes
- `tests/` behavioral, API, and detection tests
- `deploy/` sample Compose stack and environment templates

## Quick Start

1. Use Python 3.14 or newer.
2. Run the API with `python3 -m api.main`.
3. Send JSON requests to `http://127.0.0.1:8000`.
