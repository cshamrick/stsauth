# stsauth
Creates a temporary `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` that can be used with cli tools such as `awscli`, `ansible`, `terraform` and more.

This method of authentication is preferred because it eliminates the need for long-lived access keys and forces every user to use their own credentials when connecting to AWS Services.

## Prerequisites
1. `python` and `pip` must be installed.
1. Ensure `pip` is configured to work behind your organization's proxy server if necessary. See [PIP Configuration](https://pip.pypa.io/en/stable/user_guide/#configuration) for details on configuration.
1. Must already have access to an AWS account console.

## Install
```
# Uninstall if a version of `stsauth` already exists
$ pip uninstall stsauth

# Install the current release
$ pip install stsauth

# Install a specific version
$ pip install stsauth==0.1.0
```

## Upgrade
```
$ pip install stsauth --upgrade
```

## Configuration
- A valid AWS CLI configuration is required. For more information about the AWS CLI, see [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html) for more information.
- Sample `~/.aws/credentials` file:
```
[default]
output = json
region = us-east-1
idpentryurl = https://<fqdn>/adfs/ls/idpinitiatedsignon.aspx?LoginToRP=urn:amazon:webservices
domain = MYADDOMAIN
aws_access_key_id = ''
aws_secret_access_key = ''
```

## Usage
```
$ stsauth
Usage: stsauth [OPTIONS] COMMAND [ARGS]...

Options:
  -v, --verbosity LVL  Either CRITICAL, ERROR, WARNING, INFO or DEBUG
  --version            Show the version and exit.
  --help               Show this message and exit.

Commands:
  authenticate
  profiles

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
  -o, --output [json|text|table]
  -f, --force                     Auto-accept confirmation prompts.
  --help                          Show this message and exit.

$ stsauth authenticate
Username: username
Password: 

Please choose the role you would like to assume:
Account 000000000000:
[0]: ADFS-Account-One
[1]: ADFS-Account-Two

Account 000000000001:
[2]: ADFS-Account-One

Account 000000000002:
[3]: ADFS-Account-One
[4]: ADFS-Account-Two

Selection: 2

Requesting credentials for role: arn:aws:iam::000000000001:role/ADFS-Account-One

------------------------------------------------------------
Your new access key pair has been generated with the following details:
------------------------------------------------------------
File Path: /Users/username/.aws/credentials
Profile: 000000000001-ADFS-Account-One
Expiration Date: 2018-06-27 16:29:01+00:00
------------------------------------------------------------
To use this credential, call the AWS CLI with the --profile option:
(e.g. aws --profile 000000000001-ADFS-Account-One ec2 describe-instances).
--------------------------------------------------------------

$ stsauth profiles --help
Usage: stsauth profiles [OPTIONS]

Options:
  -c, --credentialsfile TEXT  Path to AWS credentials file.
  --help                      Show this message and exit.

$ stsauth profiles
Profile                           Expire Date        
--------------------------------- -------------------
default                           No Expiry Set      
saml                              2018-06-25 16:32:20
000000000000-ADFS-Account-One     2018-06-25 16:36:27
000000000000-ADFS-Account-Two     2018-06-25 16:47:51
000000000001-ADFS-Account-One     2018-06-27 10:04:46
000000000002-ADFS-Account-One     2018-06-27 11:23:23
000000000002-ADFS-Account-Two     2018-06-27 11:28:22

```

## Credits
This project is based largely on [Enabling Federation to AWS Using Windows Active Directory, ADFS, and SAML 2.0](https://aws.amazon.com/blogs/security/enabling-federation-to-aws-using-windows-active-directory-adfs-and-saml-2-0/)

