# Changelog

All notable changes to this project will be documented in this file.

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