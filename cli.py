#!/usr/bin/env python

import os
import sys

import click

from stsauth import STSAuth


@click.command()
@click.option('--username', '-u', help='IdP endpoint username.', prompt=True)
@click.option('--password', '-p', prompt=True, hide_input=True,
              confirmation_prompt=False, help='Program will prompt for input if not provided.')
@click.option('--idpentryurl', '-i', default=None,
              help='The initial url that starts the authentication process.')
@click.option('--domain', '-d', help='The active directory domain.')
@click.option('--credentialsfile', '-c', help='Path to AWS credentials file.',
              default='~/.aws/credentials')
@click.option('--region', '-r', default=None, help='The AWS region to use. ex: us-east-1')
@click.option('--output', '-o', default=None, type=click.Choice(['json', 'text', 'table']))
@click.version_option('--version', '-v')
def cli(username, password, idpentryurl, domain, credentialsfile, region, output):
    # UNSET any proxy vars that exist in the session
    unset_proxy()

    sts_auth = STSAuth(username, password, credentialsfile,
                       idpentryurl, domain, region, output)
    if not sts_auth.config_file_is_valid:
        sys.exit(1)

    if not sts_auth.credentials_expired:
        if not click.confirm('Credentials still valid, would you like to continue?'):
            sys.exit(0)

    sts_auth.parse_config_file()
    assertion = sts_auth.get_saml_response()
    # Parse the returned assertion and extract the authorized roles
    awsroles = sts_auth.parse_roles_from_assertion(assertion)

    # If more than one role returned, ask the user which one they want,
    # otherwise just proceed
    click.echo("")
    if len(awsroles) > 1:
        role_arn, principal_arn = prompt_for_role(awsroles)
    else:
        role_arn, principal_arn = awsroles[0].split(',')

    click.secho("\nRequesting credentials for role: " + role_arn, fg='green')

    # Use the assertion to get an AWS STS token using Assume Role with SAML
    token = sts_auth.fetch_aws_sts_token(role_arn, principal_arn, assertion)

    # Put the credentials into a saml specific section
    sts_auth.write_saml_conf(token)

    # Give the user some basic info as to what has just happened
    msg = (
        '\n------------------------------------------------------------\n'
        'Your new access key pair has been stored in the AWS configuration '
        'file {config_file} under the saml profile.\n'
        'Note that it will expire at {expiry}.\n'
        'After this time, you may safely rerun this script to refresh your access key pair.\n'
        'To use this credential, call the AWS CLI with the --profile option '
        '(e.g. aws --profile saml ec2 describe-instances).\n'
        '--------------------------------------------------------------\n'
        .format(config_file=sts_auth.credentialsfile,
                expiry=token.get('Credentials', {}).get('Expiration', ''))
    )
    click.secho(msg, fg='green')


def prompt_for_role(roles):
    click.secho("Please choose the role you would like to assume:", fg='green')
    for i, awsrole in enumerate(roles):
        print('[{}]: {}'.format(i, awsrole.split(',')[0]))
    click.echo("Selection: ", nl=False)
    selectedroleindex = input()

    # Basic sanity check of input
    if int(selectedroleindex) not in range(len(roles)):
        click.secho('You selected an invalid role index, please try again', fg='red')
        prompt_for_role(roles)

    return roles[int(selectedroleindex)].split(',')


def unset_proxy():
    env_vars = [
        "http_proxy", "https_proxy", "no_proxy", "all_proxy", "ftp_proxy",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "FTP_PROXY"
    ]
    for var in env_vars:
        if var in os.environ:
            del os.environ[var]
