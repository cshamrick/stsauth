# 2. Plugin System for Auth/OTP Workflow

Date: 2022-03-24

## Status

Proposed

## Context

Supporting many organizations' specific Auth/OTP worflows has become cumbersome and messy. Until now, each new workflow needs to be weaved into stsauth core which has the potential to introduce bugs, break backwards-compatible support, etc. It also adds highly-specific code that only supports a specific workflow and won't be used for any other workflows.

## Decision

To open up stsauth to more flexible and rapid development, we will implement a plugin system that allows for flexible Auth/OTP workflows. This plugin system will initially be comprised of 3 main components: stsauth Core, Auth Providers, OTP Providers.

---

### Components

#### stsauth Core

stsauth core will contain the CLI and Config components. These manage user input, loading static config, writing dynamic config, and output back to the user.

#### Auth Providers

Auth providers will implement the logic to interact with the specific web portal that handles user authentication. Until now, ADFS has been the primary auth service.

#### OTP Providers

OTP providers will implement the logic to interact with the OTP service implemented by an organization (if required). Until now, Okta and Symantec VIP are supported by stsauth.

---

Python has identified 3 patterns for implementing plugin systems[^1]. We will implement pattern 3: "Using package metadata". Since stsauth is a CLI tool exposed through entrypoints already, this should be the simplest implementation. We will initially bundle the existing providers with the stsauth core package to be backwards-compatible.

## Consequences

This plugin system allows for the known workflows to be ported over while allowing for new plugin types or providers to be added in the future. At some point, the "core providers" should be moved to external sources. This will require users to install the plugins and should be communicated appropriately. Aside from the mentioned benefits so far, this plugin system should allow for completely private Auth/OTP patterns to be implemented while still leveraging the stsauth core tooling (CLI/Config).

[^1]: https://packaging.python.org/en/latest/guides/creating-and-discovering-plugins/
