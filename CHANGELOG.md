### [1.0.2](https://github.com/cshamrick/stsauth/compare/v1.0.1...v1.0.2) (2021-08-03)


### Bug Fixes

* **Dockerfile:** fix docker build ([d492181](https://github.com/cshamrick/stsauth/commit/d492181cf0e15cd50c303faf13d216322de2f4c4))

### [1.0.1](https://github.com/cshamrick/stsauth/compare/v1.0.0...v1.0.1) (2021-07-29)


### Bug Fixes

* **.github/workflows/publish-pypi.yml:** installs `setuptools_scm` before publishing to pypi ([164aefc](https://github.com/cshamrick/stsauth/commit/164aefc89bef49d950c1a3137ed2450ea0d18320))

## [1.0.0](https://github.com/cshamrick/stsauth/compare/v0.9.0...v1.0.0) (2021-07-29)


### ⚠ BREAKING CHANGES

* **setup.py:** 
* 

### Features

* **cli.py,-stsauth.py:** add assume-role command to manage assume role credentials ([f87ff18](https://github.com/cshamrick/stsauth/commit/f87ff1879f14a6c13c96a92574756700922d9955))


### Bug Fixes

* adds back an empty `sts_auth/__init__.py` and writes the version to `sts_auth/_version.py` ([1d6e1a6](https://github.com/cshamrick/stsauth/commit/1d6e1a6f858047a9aa651ad60ae620392a881754))
* fixes unexpired credentials check ([4bb74af](https://github.com/cshamrick/stsauth/commit/4bb74afe7368763eee3d84ab20e139c2d842239b))
* **cli.py:** fix references to sts_auth.profile ([3e897f4](https://github.com/cshamrick/stsauth/commit/3e897f49999d9749093cf84e80da1bb016d206a5))
* **config.py:** use dateutil.parser to handle more date formats ([0bda79d](https://github.com/cshamrick/stsauth/commit/0bda79d0472ccb439b3f7bbb351c1c72fcf60dc0))
* **profile_set.py:** change expiry output to use formatted string ([86225d9](https://github.com/cshamrick/stsauth/commit/86225d9fa575c03b1b8a227f33ba15296fdf73c2))


### Code Refactoring

* refactor to include Config, Profile, and ProfileSet classes ([5a81f25](https://github.com/cshamrick/stsauth/commit/5a81f25da7daee49d11459a87d01532b762e0fa0))


### Build System

* **setup.py:** remove python 2 classifiers ([57b0a28](https://github.com/cshamrick/stsauth/commit/57b0a283af8f34c2652cca4af2643e1dfee19a72))

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
