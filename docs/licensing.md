# Licensing Model

The project follows an open-core model:

- Core components are Apache-2.0:
  - `schema/`
  - `crates/`
  - `sdk/`
  - `examples/`
  - `docs/`
- Cloud-layer components are BSL-1.1:
  - `cloud/`

## Why this split

- Apache-2.0 on core maximizes adoption and contribution.
- BSL-1.1 on cloud services preserves a commercial moat for hosted SaaS operations.
- BSL conversion date is defined in `LICENSES/BSL-1.1.md`, after which BSL-covered code becomes Apache-2.0.

## Contribution defaults

Unless stated otherwise in a file header, contributions are assumed Apache-2.0 in this repository.

