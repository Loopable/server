# CONTRIBUTING.md

This repository contains the Loopable Instance Server. It is a Go implementation used to host Loopable instances.

## Before changing code

Read the relevant existing code and documentation first. Follow the repository's existing patterns. Do not add a second mechanism when one already exists.

For any Go work, use the `use-modern-go` skill.

## Protocol compliance

The Loopable Protocol specification at [github.com/loopable/protospec](https://github.com/loopable/protospec) is authoritative for protocol behavior.

Every server implementation of protocol behavior must correspond one-to-one with the specification. Do not duplicate protocol definitions in this repository, reinterpret requirements for convenience, or create server-only protocol behavior.

The server may contain implementation details that the specification does not prescribe, but those details must not contradict the specification. When the specification is ambiguous, incomplete, or appears incorrect, stop and raise the issue. Do not guess, add a workaround, or quietly define a local interpretation.

Changes involving identity, authentication, encryption, key management, serialization, federation, object behavior, compatibility, or protocol versioning may require a corresponding change or discussion in `protospec`.

## Production safety

Loopable instances may be used by government officials, activists, independent journalists, and other people whose safety depends on privacy and reliable service. Treat every change as production-sensitive.

Prioritize correctness, privacy, security, and specification compliance over speed. If a change could break an existing deployment, corrupt or expose data, weaken security, or put users at risk, stop and ask what to do.

Do not make a band-aid fix by changing unrelated software, weakening validation, disabling checks, hiding an error, or replacing a dependency without understanding the cause. Investigate the root problem and escalate when the correct solution is uncertain.

Do not make a change merely because it works on one computer. Code and scripts must work on Windows, macOS, and Linux unless the repository documents a platform-specific requirement. Avoid assumptions about shells, paths, environment variables, line endings, installed tools, or filesystem behavior.

## Privacy and security

Protect user content, credentials, private keys, identifiers, metadata, logs, backups, and instance data. Do not place real secrets or user data in the repository, tests, examples, issues, or pull requests.

Review access control, authentication, authorization, federation validation, error handling, logging, data retention, and failure behavior for relevant changes. A change that preserves content confidentiality may still expose sensitive metadata.

Report security vulnerabilities through `SECURITY.md`. Do not disclose an undisclosed vulnerability in a public issue or pull request.

## Licensing and dependencies

This project is licensed under AGPL-3.0. Do not add code, generated material, examples, assets, or dependencies of unclear origin or incompatible licensing. Check licensing and attribution requirements before copying or introducing external material.

Preserve license and attribution notices. Do not modify `LICENSE` unless the user explicitly requests it and the change has been reviewed for legal correctness.

## Data and compatibility

Treat databases, migrations, stored user data, public APIs, federation behavior, and configuration formats as compatibility-sensitive. Do not make destructive changes without a reviewed migration and upgrade plan.

For changes that may affect existing users or deployments, document the impact, upgrade requirements, rollback behavior, and compatibility risks. If the safe behavior is unclear, stop and ask rather than choosing a potentially breaking option.

## Tests and validation

Run the narrowest relevant checks for the change, then expand validation when the risk requires it. Include or update tests for changed behavior when appropriate. Validate protocol behavior against the specification and existing interoperability expectations.

Do not change unrelated code to make an unrelated check pass. If validation cannot run, report that fact and the reason.

## Protected repository files

Do not modify `README.md`, `SECURITY.md`, `AGENTS.md`, `CONTRIBUTING.md`, `LICENSE`, or other repository-policy, security, deployment, migration, or release files during an ordinary implementation task. Such changes require explicit user authorization for the specific file and purpose.

## Pull requests and commits

Keep each pull request focused on one coherent change. Explain what changed, why it is needed, how it was validated, and any effects on protocol compliance, privacy, security, compatibility, deployment, or stored data.

When using AI tools or agents, the contributor remains responsible for understanding and reviewing the result. Remove unrelated generated changes before submitting the pull request.

Use Conventional Commits when writing commit messages. Use `!` or a `BREAKING CHANGE` footer for breaking changes.
