# Changelog

All notable changes to this project will be documented in this file.

## v0.5.3

- [bugfix] Fix issue where a `[None]` section would be added to credentials file.
- [bugfix] Fix issue where some error messages on the ADFS portal would not be captured.
- [other] Removes restraints on `urllib3` dependency for new Python versions

## v0.5.1

- [bugfix] Fix issue where using `--profile`/`-l` flag would fail if the profile didn't exist in credentials file.

## v0.5.0

- [feature] Added VIP Access support. Users can now pass VIP Access security codes to `authenticate` command via the
  `--vip-access-security-code` flag.

## v0.4.1

- [bugfix] Fix error when users have unsupported browser
- [improvement] Add support for Brave Browser

## v0.4.0

- [feature] Open the AWS Console with the profile authenticated against by using
  the `--console` flag in the `authenticate` command

## v0.3.12

- [bugfix] Fix out of order roles in selection prompt.
- [bugfix] Fix writing of empty value to credentials file which causes invalid yml.
- [improvement] Add error handling for fetching TOTP code.
- [improvement] Add error handling for when AWS ProfileNotFound.

## v0.3.11

- [bugfix] Fix local calculation of credentials `expiry`.

## v0.3.10

- [bugfix] Allow stsauth to continue without connectivity to `signin.aws.amazon.com` for Account Aliases

## v0.3.9

- [bugfix] Fix issue where AWS accounts without aliases could not be parsed.
- [bugfix] Fix conversion between seconds since epoch and timestamp
- [improvement] Add test coverage for utils module.

## v0.3.8

- [feature] Add ability to query a specific field under the `stsauth profiles` command

## v0.3.7

- [bugfix] Fixed issue where the role returned from the cli selection prompt was a string not an object.

## v0.3.6

- [feature] Show account names in the prompt to select a role

## v0.3.5

- Refactor project structure to support testing
  - Create `okta` and `utils` module

## v0.3.4

- [bug-fix] Fixed assumption of 1 account meaning 1 role is available

## v0.3.3

- [feature] Add expiration status of credentials to `stsauth profiles` output

## v0.3.2

## v0.3.1

- [feature] Add `stsauth profiles [PROFILE]` to get specific profile details
- [feature] Sort the role selection prompt output

## v0.3.0

- Add support for authenticating to Okta through Push notifications and TOTP

## v0.2.5

- Loosen dependency version constraints.
- Update Click dependency to version 7.0.

## v0.2.4

- Add MANIFEST.in which is needed to include requirements file in dist.

## v0.2.3

- Fix issue when installing stsauth in python2.7 where requirements file could not be found.

## v0.2.2

- Fixed bug that resulted in not properly checking `credentials` file for all required fields.
- Changed how `action` URL is assembled to ensure a fully defined URL is returned.
- Remove use of `dateutil` for backwards-compatibility with `py2.7`.
- Return any error messages from the ADFS portal to the CLI.
- Add basic testing framework and configuration.
- Add more DEBUG logging points.
- Change `setup.py` format to be more robust and resuable (i.e. `tox` requirements).
