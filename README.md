<!-- SPDX-FileCopyrightText: 2026 Libre AI contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- Written for the retained Libre AI portfolio on 2026-09-14; earlier source documents and revisions retain their original licensing. -->

# Libre AI Capability Authorization

[Français](README.fr.md)

Services need permissions that specify which action is allowed on which resource and under which conditions. This project explores authorization using Biscuit tokens for developers implementing service access rules. It focuses on bounded permissions and delegation, so a service can pass on a narrower permission for a particular task.

## Intended uses

- Limit a service permission to a specific action and resource.
- Restrict a delegated token further for a particular recipient or use.
- Check expiration, revocation and organization scope against explicit access rules.

## Availability

Source code and tests are available in this repository; no package is published to a registry.

Explore the [Libre AI project catalogue](https://github.com/libre-ai/.github/blob/main/profile/README.md).
