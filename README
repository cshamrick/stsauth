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
$ stsauth --help
Usage: stsauth [OPTIONS]

Options:
  -u, --username TEXT             IdP endpoint username.
  -p, --password TEXT             Program will prompt for input if not
                                  provided.
  -i, --idpentryurl TEXT          The initial url that starts the
                                  authentication process.
  -d, --domain TEXT               The active directory domain.
  -c, --credentialsfile TEXT      Path to AWS credentials file.
  -r, --region TEXT               The AWS region to use. ex: us-east-1
  -o, --output [json|text|table]
  -v                              Show the version and exit.
  --help                          Show this message and exit.

$ stsauth
Username: username
Password:

Please choose the role you would like to assume:
[ 0 ]:  arn:aws:iam::000000000001:role/ADFS-Account-One
[ 1 ]:  arn:aws:iam::000000000002:role/ADFS-Account-Two
[ 2 ]:  arn:aws:iam::000000000003:role/ADFS-Account-Three
Selection: 0

Requesting credentials for role: arn:aws:iam::000000000001:role/ADFS-Account-One

------------------------------------------------------------
Your new access key pair has been stored in the AWS configuration file /Users/username/.aws/credentials under the saml profile.
Note that it will expire at 2018-05-07T13:23:22Z.
After this time, you may safely rerun this script to refresh your access key pair.
To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).
--------------------------------------------------------------
```

## Credits
This project is based largely on [Enabling Federation to AWS Using Windows Active Directory, ADFS, and SAML 2.0](https://aws.amazon.com/blogs/security/enabling-federation-to-aws-using-windows-active-directory-adfs-and-saml-2-0/)

