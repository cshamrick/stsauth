# stsauth
[![codecov](https://codecov.io/gh/cshamrick/stsauth/branch/main/graph/badge.svg?token=WZFLZUSK1N)](https://codecov.io/gh/cshamrick/stsauth)
[![GitHub Super-Linter](https://github.com/cshamrick/stsauth/workflows/super-linter/badge.svg)](https://github.com/marketplace/actions/super-linter)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/cshamrick/stsauth.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cshamrick/stsauth/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/cshamrick/stsauth.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cshamrick/stsauth/context:python)

Creates a temporary `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` that can be used with cli tools such as `awscli`, `ansible`, `terraform` and more.

This method of authentication is preferred because it eliminates the need for long-lived access keys and forces every user to use their own credentials when connecting to AWS Services.

- [Installation](#installation)
  - [Using Docker](#using-docker)
  - [Using Pip](#using-pip)
  - [Configuration](#configuration)
- [Usage](#usage)
- [Warning](#warning)
- [Troubleshooting](#troubleshooting)
- [Credits](#credits)

## Installation

### Using `docker`

`docker pull cshamrick/stsauth:latest`

Add the following alias to your `~/.bash_profile`, `~/.bashrc`, or `~/.zshrc`:

```sh
alias stsauth='docker run --rm -it -v ~/.aws:/root/.aws -e AWS_PROFILE=$AWS_PROFILE -e AWS_DEFAULT_REGION=$AWS_DEFAULT_REGION cshamrick/stsauth:latest'
```

### Using `pip`

```shell
# Uninstall if a version of `stsauth` already exists
$ pip uninstall stsauth

# Install the current release
$ pip install stsauth

# Install a specific version
$ pip install stsauth==0.1.0 # Get the latest from: https://github.com/cshamrick/stsauth/releases

# Upgrade an existing installation
$ pip install stsauth --upgrade
```

### Configuration

- A valid AWS CLI configuration is required. For more information about the AWS CLI, see [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html) for more information.

- Sample `~/.aws/credentials` file:

  ```conf
  [default]
  output = json
  region = us-east-1
  idpentryurl = https://<fqdn>/adfs/ls/idpinitiatedsignon.aspx?LoginToRP=urn:amazon:webservices
  domain = MYADDOMAIN
  okta_org = my-organization
  okta_shared_secret = 16CHARLONGSTRING
  aws_access_key_id = awsaccesskeyidstringexample
  aws_secret_access_key = awssecretaccesskeystringexample
  ```

## Usage

```shell
$ stsauth --help
Usage: stsauth [OPTIONS] COMMAND [ARGS]...

Options:
  -v, --verbosity LVL  Either CRITICAL, ERROR, WARNING, INFO or DEBUG
  --version            Show the version and exit.
  --help               Show this message and exit.

Commands:
  authenticate
  profiles      Lists the profile details from the credentialsfile or a...

$ stsauth authenticate --help
Usage: stsauth authenticate [OPTIONS]

Options:
  -u, --username TEXT             IdP endpoint username.
  -p, --password TEXT             Program will prompt for input if not
                                  provided.

  -i, --idpentryurl TEXT          The initial url that starts the
                                  authentication process.

  -d, --domain TEXT               The active directory domain.
  -c, --credentialsfile TEXT      Path to AWS credentials file.
  -l, --profile TEXT              Name of config profile.
  -r, --region TEXT               The AWS region to use. ex: us-east-1
  -k, --okta-org TEXT             The Okta organization to use. ex: my-
                                  organization

  -s, --okta-shared-secret TEXT   Okta Shared Secret for TOTP Authentication.
                                  WARNING! Please use push notifications if at
                                  all possible. Unless you are aware of what
                                  you are doing, this method could potentially
                                  expose your Shared Secret. Proceed with
                                  caution and use a tool like `pass` to
                                  securely store your secrets.

  -t, --vip-access-security-code TEXT
                                  VIP Access security code.
  -b, --browser                   If set, will attempt to open the console in
                                  your default browser.To enable opening the
                                  console in an incognito window, set
                                  `browser_path`in your config file `default`
                                  section to your browser executable.

  -o, --output [json|text|table]
  -f, --force                     Auto-accept confirmation prompts.
  --help                          Show this message and exit.

$ stsauth authenticate
Username: username
Password:

Please choose the role you would like to assume:
Account 000000000000:
[0]: ADFS-Role-One
[1]: ADFS-Role-Two

Account 000000000001:
[2]: ADFS-Role-One

Account 000000000002:
[3]: ADFS-Role-One
[4]: ADFS-Role-Two

Selection: 2

Requesting credentials for role: arn:aws:iam::000000000001:role/ADFS-Role-One

------------------------------------------------------------
Your new access key pair has been generated with the following details:
------------------------------------------------------------
File Path: /Users/username/.aws/credentials
Profile: 000000000001-ADFS-Role-One
Expiration Date: 2018-06-27 16:29:01+00:00
------------------------------------------------------------
To use this credential, call the AWS CLI with the --profile option:
(e.g. aws --profile 000000000001-ADFS-Role-One ec2 describe-instances).
export AWS_PROFILE=000000000001-ADFS-Role-One
--------------------------------------------------------------

$ stsauth profiles --help
Usage: stsauth profiles [OPTIONS] [PROFILE]

  Lists the profile details from the credentialsfile or a specified profile.

  Args:     credentialsfile: the file containing the profile details.
  profile: (Optional) a specific profile to print details for.

Options:
  -c, --credentialsfile TEXT  Path to AWS credentials file.
  --help                      Show this message and exit.

$ stsauth profiles
Account     Profile                    Expire Date         Status
----------- -------------------------- ------------------- -------
None        default                    No Expiry Set       Active
None        saml                       2018-06-25 16:32:20 Expired
Account-One 000000000000-ADFS-Role-One 2018-06-25 16:36:27 Expired
Account-Two 000000000000-ADFS-Role-Two 2018-06-25 16:47:51 Expired
Account-One 000000000001-ADFS-Role-One 2018-06-27 10:04:46 Active
Account-One 000000000002-ADFS-Role-One 2018-06-27 11:23:23 Active
Account-Two 000000000002-ADFS-Role-Two 2018-06-27 11:28:22 Active
```

## Warning

It is **strongly** recommended to use Okta Push Notifications for MFA if at all possible. Storing your Shared Secret or passing it in through the command line comes with the risk of exposing the Shared Secret to unintended persons. If compromised, the security of MFA is lost. **Please proceed with caution and an understanding of the risks associated. _If you believe your Shared Secret has been compromised, please revoke it immediately._**

## Troubleshooting

### An error occurs when authenticating

> An error occurred (AccessDenied) when calling the AssumeRoleWithSAML operation: Access denied

You likely have lost permission. Please try to sign in via AWS Console.

## Credits

This project is based largely on [Enabling Federation to AWS Using Windows Active Directory, ADFS, and SAML 2.0](https://aws.amazon.com/blogs/security/enabling-federation-to-aws-using-windows-active-directory-adfs-and-saml-2-0/)
