# Changelog
All notable changes to this project will be documented in this file.

## v0.2.2
- Fixed bug that resulted in not properly checking `credentials` file for all required fields.
- Changed how `action` URL is assembled to ensure a fully defined URL is returned.
- Remove use of `dateutil` for backwards-compatibility with `py2.7`.
- Return any error messages from the ADFS portal to the CLI.
- Add basic testing framework and configuration.
- Add more DEBUG logging points.
- Change `setup.py` format to be more robust and resuable (i.e. `tox` requirements).