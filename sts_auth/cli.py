#!/usr/bin/env python

import os
import re
import sys
import webbrowser
import collections
from typing import Optional, Mapping

import click  # type: ignore[import]
import click_log  # type: ignore[import]

from sts_auth import utils
from sts_auth import stsauth
from sts_auth.stsauth import STSAuth
from sts_auth.config import Config

click_log.basic_config(utils.logger)


@click.group()
@click_log.simple_verbosity_option(utils.logger)
@click.version_option(package_name="stsauth")
def cli():
    """Tools for managing AWS credentials through an ADFS portal."""
    pass


@cli.command()
@click.option("--username", "-u", prompt=True, help="IdP endpoint username.")
@click.option(
    "--password",
    "-p",
    prompt=True,
    hide_input=True,
    confirmation_prompt=False,
    help="Program will prompt for input if not provided.",
)
@click.option(
    "--idpentryurl",
    "-i",
    default=None,
    help="The initial url that starts the authentication process.",
)
@click.option("--domain", "-d", help="The active directory domain.")
@click.option(
    "--credentialsfile",
    "-c",
    help="Path to AWS credentials file.",
    default="~/.aws/credentials",
    envvar="AWS_SHARED_CREDENTIALS_FILE",
)
@click.option("--profile", "-l", default=None, help="Name of config profile.")
@click.option("--region", "-r", default=None, envvar="AWS_DEFAULT_REGION", help="The AWS region to use. ex: us-east-1")
@click.option(
    "--okta-org",
    "-k",
    default=None,
    help="The Okta organization to use. ex: my-organization",
)
@click.option(
    "--okta-shared-secret",
    "-s",
    default=None,
    help=(
        "Okta Shared Secret for TOTP Authentication. "
        "\nWARNING! Please use push notifications if at all possible. "
        "Unless you are aware of what you are doing, this method could "
        "potentially expose your Shared Secret. "
        "Proceed with caution and use a tool like `pass` to securely store your secrets."
    ),
)
@click.option("--vip-access-security-code", "-t", default=None, help="VIP Access security code.")
@click.option(
    "--browser",
    "-b",
    is_flag=True,
    help=(
        "If set, will attempt to open the console in your default browser."
        "To enable opening the console in an incognito window, set `browser_path`"
        "in your config file `default` section to your browser executable."
    ),
)
@click.option("--output", "-o", default=None, envvar="AWS_DEFAULT_OUTPUT", type=click.Choice(["json", "text", "table"]))
@click.option("--force", "-f", is_flag=True, help="Auto-accept confirmation prompts.")
def authenticate(
    username,
    password,
    idpentryurl,
    domain,
    credentialsfile,
    profile,
    okta_org,
    okta_shared_secret,
    vip_access_security_code,
    browser,
    region,
    output,
    force,
):
    """Authenticate to and fetch credentials for AWS through an ADFS portal"""
    sts_auth = STSAuth(
        username=username,
        password=password,
        credentialsfile=credentialsfile,
        idpentryurl=idpentryurl,
        profile=profile,
        okta_org=okta_org,
        okta_shared_secret=okta_shared_secret,
        vip_access_security_code=vip_access_security_code,
        domain=domain,
        region=region,
        output=output,
    )

    if not sts_auth.config.valid:
        sys.exit(1)

    if (sts_auth.profile and sts_auth.config.profile_set.get(sts_auth.profile).active) and not force:
        prompt_for_unexpired_credentials(sts_auth.config.profile_set.get(sts_auth.profile).name)

    saml_response = sts_auth.get_saml_response()
    adfs_response = sts_auth.fetch_aws_account_names(saml_response)
    if adfs_response is not None:
        account_map = utils.parse_aws_account_names_from_response(adfs_response)
    else:
        account_map = sts_auth.config.profile_set.aws_account_names
    # Parse the returned assertion and extract the authorized roles
    awsroles = utils.parse_roles_from_assertion(saml_response.assertion)
    account_roles = utils.format_roles_for_display(awsroles, account_map)
    account_roles_len = len(account_roles)
    account_roles_vals_len = len(list(account_roles.values())[0])

    if profile:
        # If a profile is passed in, use that
        role = parse_arn_from_input_profile(account_roles, profile)
    elif (account_roles_len > 1) or (account_roles_len == 1 and account_roles_vals_len > 1):
        # If there is more than one account or there is one account with multiple roles, prompt
        role = prompt_for_role(account_map, account_roles)
    elif account_roles_len == 1 and account_roles_vals_len == 1:
        # If there is one account and only one role, use it
        if isinstance(account_roles, collections.OrderedDict):
            role = account_roles.get(list(account_roles.keys())[0])[0]
        else:
            role = account_roles.values()[0][0]
    else:
        click.secho("No roles are available. Please verify in the ADFS Portal.", fg="red")

    role_arn, principal_arn = role.get("attr").split(",")
    # Generate a safe-name for the profile based on acct no. and role
    role_for_section = parse_role_for_profile(role_arn)

    # Update to use the selected profile and re-check expiry
    selected_profile = sts_auth.config.profile_set.get(role_for_section)
    if not profile and selected_profile and selected_profile.active and not force:
        prompt_for_unexpired_credentials(selected_profile.name)

    if not sts_auth.config.values.has_section(profile) and profile is not None:
        sts_auth.config.values.add_section(profile)

    with open(sts_auth.credentialsfile, "w") as f:
        sts_auth.config.values.write(f)

    click.secho("\nRequesting credentials for role: " + role_arn, fg="green")

    # Use the assertion to get an AWS STS token using Assume Role with SAML
    token = stsauth.fetch_aws_sts_token(role_arn, principal_arn, saml_response.assertion, aws_profile=profile)

    # Put the credentials into a role specific section
    acct_name = role.get("name", "")
    acct_id = role.get("id", "")
    sts_auth.config.write(token, acct_name, acct_id, role_for_section)

    # Give the user some basic info as to what has just happened
    print_credentials_success(
        sts_auth.credentialsfile,
        role_for_section,
        token.get("Credentials", {}).get("Expiration", ""),
    )

    if browser:
        login_url = sts_auth.generate_login_url(token)
        browser_path = sts_auth.config.values.get("default", "browser_path", fallback=None)
        open_console(login_url, browser_path)


@cli.command()
@click.option(
    "--credentialsfile",
    "-c",
    help="Path to AWS credentials file.",
    default="~/.aws/credentials",
    envvar="AWS_SHARED_CREDENTIALS_FILE",
)
@click.argument("profile", nargs=1, required=False)
@click.option("--query", "-q", help="Value to query from the profile.")
def profiles(credentialsfile: str, profile: str, query: str) -> None:
    """Lists the profile details from the credentialsfile or a specified profile.

    Args:
        credentialsfile: The file containing the profile details.
        profile: (Optional) A specific profile to print details for.
    """
    credentialsfile = os.path.expanduser(credentialsfile)
    config = Config(credentialsfile)

    if profile is None:
        if query is not None:
            click.secho("When using the 'query' parameter, 'profile' is required.", fg="red")
            sys.exit(1)
        else:
            config.profile_set.table()
    else:
        if config.profile_set.get(profile):
            if query is not None:
                try:
                    value = config.profile_set.get(profile).query(query)  # type: ignore[union-attr]
                except ValueError as e:
                    click.secho(str(e), fg="red")
                else:
                    click.secho(value)
            else:
                click.secho(str(config.profile_set.get(profile)))
        else:
            msg = "Section '{}' does not exist in {}!"
            click.secho(msg.format(profile, credentialsfile), fg="red")
            sys.exit(1)


@cli.command()
@click.option(
    "--profile",
    "-l",
    envvar="AWS_PROFILE",
    help="The AWS Profile to assume the role-arn from. Uses AWS_PROFILE environment if available.",
)
@click.argument(
    "role-arn",
    required=True,
)
@click.option(
    "--role-session-name",
    default=None,
    help="Specify if a custom session name is required. Otherwise a generated value will be used.",
)
@click.option(
    "--credentialsfile",
    "-c",
    help="Path to AWS credentials file.",
    default="~/.aws/credentials",
    show_default=True,
    envvar="AWS_SHARED_CREDENTIALS_FILE",
)
def assume_role(
    profile,
    role_arn,
    role_session_name,
    credentialsfile,
):
    """Used to assume another AWS IAM Role."""
    credentialsfile = os.path.expanduser(credentialsfile)
    config = Config(credentialsfile)
    config.load()

    role_for_section = parse_role_for_profile(role_arn)
    account_id = parse_role_for_account_id(role_arn)
    if role_session_name is None:
        role_session_name = role_for_section
    token = stsauth.fetch_aws_sts_token_assume_role(
        role_arn,
        role_session_name,
        profile,
        duration_seconds=3600,
    )

    config.write(token, "Assumed Role", account_id, role_for_section)
    # Give the user some basic info as to what has just happened
    print_credentials_success(
        config.credentialsfile,
        role_for_section,
        token.get("Credentials", {}).get("Expiration", ""),
    )


def open_console(login_url: str, browser_path: Optional[str] = None) -> None:
    msg = "Attempting to open the AWS Console..."
    click.secho(msg, fg="green")
    private_flags = {
        "chrome": " --incognito",
        "firefox": " -private-window",
        "brave": " --incognito",
    }
    if browser_path is not None:
        if not os.path.exists(browser_path):
            msg = (
                "Path to browser executable is not valid. Private browsing "
                "not possible.\nAttempting to continue with your default "
                "browser..."
            )
            click.secho(msg, fg="red")
        else:
            if "chrome" in browser_path.lower():
                browser_type = "chrome"
            elif "firefox" in browser_path.lower():
                browser_type = "firefox"
            elif "brave" in browser_path.lower():
                browser_type = "brave"
            else:
                browser_type = "unsupported"
                msg = "Currently private browsing is only supported for Chrome, Firefox, and Brave."
                click.secho(msg, fg="yellow")
            private_flag = private_flags.get(browser_type, "")
            nohup = "&" if browser_type == "firefox" else ""
            browser_path = '"{}"{} %s {}'.format(browser_path, private_flag, nohup)
    browser = webbrowser.get(browser_path)
    try:
        browser.open_new_tab(login_url)
    except webbrowser.Error as e:
        msg = "An exception occured while trying to open the AWS Console."
        click.secho("{}\n{}".format(msg, str(e)), fg="red")


def prompt_for_role(account_map: Mapping[str, str], account_roles: collections.OrderedDict) -> dict:
    """Prompts the user to select a role based off what roles are available to them.

    Provides a prompt listing out accounts available to the user and does some basic
    checks to validate their input. If the input is invalid, re-prompts the user.

    Args:
        account_map: dictionary of account ids and account names
        account_roles: dictionary of account and role details

    Returns:
        Set containing the selected Role ARN and Principal ARN
    """
    click.secho("Please choose the role you would like to assume:", fg="green")
    for acct_id, roles in account_roles.items():
        acct_name = account_map.get(acct_id, "")
        click.secho("Account: {} ({})".format(acct_name, acct_id), fg="blue")
        for role in roles:
            click.secho("[{num}]: {label}".format(**role))
        click.secho("")
    click.secho("Selection: ", nl=False, fg="green")
    selected_role_index: int = int(input())
    flat_roles = [i for sl in account_roles.values() for i in sl]

    # Basic sanity check of input
    if not role_selection_is_valid(selected_role_index, flat_roles):
        return prompt_for_role(account_map, account_roles)

    role = next((v for v in flat_roles if int(v["num"]) == selected_role_index), None)
    utils.logger.debug("Selected Role: ")
    utils.logger.debug(role)

    return role


def role_selection_is_valid(selection: int, account_roles: list) -> bool:
    """Checks that the user input is a valid selection

    Args:
        selection: Value the user entered.
        account_roles: List of valid roles to check against.

    Returns:
        Boolean reflecting the validity of given choice.
    """
    err_msg = "You selected an invalid role index, please try again"
    try:
        selection
    except ValueError:
        click.secho(err_msg, fg="red")
        return False

    if selection not in range(len(account_roles)):
        click.secho(err_msg, fg="red")
        return False

    return True


def parse_role_for_account_id(role: str) -> str:
    """Returns the account ID for a given role.

    Args:
        role: The role to fetch the account ID from.

    Returns:
        Account Id.
    """
    account_id = "000000000000"

    account_re = re.compile(r"::(\d+):")
    _account_id = re.search(account_re, role)
    if _account_id.groups():  # type: ignore[union-attr]
        account_id = _account_id.groups()[0]  # type: ignore[union-attr]

    return account_id


def parse_role_for_profile(role: str) -> str:
    """Returns a 'safe' profile name for a given role.

    Args:
        role: The role to generate a profile name for.

    Returns:
        Formatted profile name.
    """
    account_id = "000000000000"
    role_name = "Unknown-Role-Name"

    account_re = re.compile(r"::(\d+):")
    _account_id = re.search(account_re, role)
    _role_name = role.split("/")
    if _account_id.groups():  # type: ignore[union-attr]
        account_id = _account_id.groups()[0]  # type: ignore[union-attr]
    if len(_role_name) == 2:
        role_name = _role_name[1]

    return "{}-{}".format(account_id, role_name)


def prompt_for_unexpired_credentials(profile: str) -> None:
    """Prompts the user if the given profile's credentials have not expired yet.

    Args:
        profile: The profile for which a user is requesting credentials.
    """
    click.secho("\nCredentials for the following profile are still valid:", fg="red")
    click.secho(profile, fg="red")
    click.echo()
    msg = click.style("Would you like to continue?", fg="red")
    click.confirm(msg, abort=True)


def parse_arn_from_input_profile(account_roles: collections.OrderedDict, profile: str) -> dict:
    """Given a list of account/role details, return the ARNs for the given profile

    Args:
        account_roles: List of dictionaries containing account/role details
        profile: A user-provided profile to retreive the ARN from the account_roles.

    Returns:
        A set with the Role ARN and the Principal ARN. If the profile does not exist, exits the cli.
    """
    click.echo()
    profile_split = profile.split("-")
    acct_number = profile_split[0]
    role_name = "-".join(profile_split[1:])
    role = next(
        (item for item in account_roles[acct_number] if item["label"] == role_name),
        None,
    )
    if role is None:
        click.secho(
            "Profile not found!\n"
            "Please check `stsauth profiles` for a list of available profiles\n"
            "or use `stsauth authenticate` to view profiles available to your user.\n"
            "The profile may no longer be available to your user.",
            fg="red",
        )
        sys.exit()
    return role


def print_credentials_success(config_file_path: str, profile: str, expiry: str) -> None:
    msg = (
        "\n------------------------------------------------------------\n"
        "Your new access key pair has been generated with the following details:\n"
        "------------------------------------------------------------\n"
        f"File Path: {config_file_path}\n"
        f"Profile: {profile}\n"
        f"Expiration Date: {expiry}\n"
        "------------------------------------------------------------\n"
        "To use this credential, call the AWS CLI with the --profile option:\n"
        f"e.g. aws --profile {profile} ec2 describe-instances\n"
        "Or provided as an environment variable:\n"
        f"export AWS_PROFILE={profile}\n"
        "--------------------------------------------------------------\n"
    )
    click.secho(msg, fg="green")


if __name__ == "__main__":
    cli()
