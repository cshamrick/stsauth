# 3. Isolate Configuration System

Date: 2022-03-24

## Status

Proposed

## Context

The current stsauth config system piggy-backs on the AWS CLI configuration. In the initial development, this was the easiest location to store extra information. As stsauth has grown, more configuration details are needed and supported causing there to be more details added to the AWS CLI config. Along with this, the plugin system will need to store configuration as well and this would further muddy the AWS CLI configuration. If the AWS CLI were to change its configuration standard in the future, this would also impact stsauth.

## Decision

We will store a new INI[^1] file in the appropriate location based on the XDG Base Directory Specification[^2]. The INI file will use dot-notation headers to specify configuration for the core and plugin system configuration.

### Example config

```ini
# To specify the default profile, set the core_profile. If not set, stsauth.core
# will be used or a profile can be specified at the CLI.
[stsauth]
core_profile=profile_a

# All configuration for stsauth core (CLI/Config) will be stored here.
[stsauth.core]
config_item=config_value
auth_provider=adfs
otp_provider=okta

# Additionally, a core profile may be defined to quickly switch between providers.
[stsauth.core.profile_a]
config_item=config_value
auth_provider=auth_secondary
otp_provider=otp_secondary

# Based on the plugin system, there will be two initial categories for plugins:
# auth and otp. There can be multiple defined for each. If multiple are defined,
# the desired provider for each must be specified either in the core config
# section or a core profile.

# stsauth.auth.<auth provider name> will be defined to support configuration for
# each specific auth provider.
[stsauth.auth.adfs]
config_item=config_value

[stsauth.auth.auth_secondary]
config_item=config_value

# stsauth.otp.<otp provider name> will be defined to support configuration for
# each specific otp provider.
[stsauth.otp.okta]
config_item=config_value

[stsauth.otp.otp_secondary]
config_item=config_value
```

## Consequences

Moving the configuration removes the dependency/potential failure mode from relying on the AWS CLI. This also allows for growth and flexibility in specifying the stsauth configuration. Moving this configuration will break existing user configuration in the AWS CLI configuration. It will need to be migrated and should be communicated accordingly.

[^1]: https://docs.python.org/3/library/configparser.html#supported-ini-file-structure
[^2]: https://specifications.freedesktop.org/basedir-spec/latest/index.html
