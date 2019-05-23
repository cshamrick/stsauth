import re
import sys
import time

import click
import pyotp
from bs4 import BeautifulSoup

from sts_auth.utils import logger


class Okta(object):
    """Creates an instance to handle Okta tasks.

    :param session: Requests Session instance (required).
    :param state_token: State Token of the active Okta session (required).
    :param okta_org: Okta organization string (required).
    :param okta_shared_secret: If using TOTP, Okta Shared Secret string.
    """

    def __init__(self, session, state_token, okta_org, okta_shared_secret=None):
        self.session = session
        self.state_token = state_token
        self.okta_org = okta_org
        self.okta_shared_secret = okta_shared_secret

    def fetch_available_mfa_factors(self):
        okta_auth_url = 'https://{}.okta.com/api/v1/authn'.format(self.okta_org)
        okta_transaction_state = self.session.post(
            okta_auth_url,
            json={'stateToken': self.state_token}
        )
        okta_factors = okta_transaction_state.json().get('_embedded', {}).get('factors', {})
        if len(okta_factors) > 0:
            # Format the factors as {factorType: {details..}, ..}
            # so it will be easier to pick pull out by type later
            return {f['factorType']: f for f in okta_factors}
        else:
            msg = ('No Okta MFA methods available.\n'
                   'Please visit https://{}.okta.com to configure Okta MFA.')
            click.secho(msg.format(self.okta_org), fg='red')
            sys.exit(1)

    def handle_okta_verification(self, response):
        # If there is no assertion, and we find an Okta portal on the page,
        # we have to pass through the Okta portal regardless of whether MFA
        # will be required or not.
        if not self.okta_org:
            msg = ('Okta MFA required but no Okta Organization set. '
                   'Please either set in the config or use `--okta-org`')
            click.secho(msg, fg='red')
            sys.exit(1)

        verification_status = self.get_verification_status_from_response(response)
        logger.debug('Current Verification Status: {}.'.format(verification_status))
        if verification_status == 'success':
            logger.debug('Okta portal already authenticated, passing through...')
            # If the Okta portal status is already 'success', we can just
            # pass through the Okta portal, otherwise, we will have to do MFA.
            okta_form_submit_response = self.submit_adapter_glue_form(response)
            return okta_form_submit_response
        elif verification_status == 'mfa_required':
            # If the Okta portal is in 'mfa_required' status,
            # we need to begin the MFA process.
            okta_available_factors = self.fetch_available_mfa_factors()
            mfa_verified = self.process_okta_mfa(okta_available_factors)
            if mfa_verified:
                okta_response = self.submit_adapter_glue_form(response)
                return okta_response

        click.secho('Okta verification failed. Exiting...', fg='red')
        sys.exit(1)

    def process_okta_mfa(self, okta_available_factors):
        # The full list of available factor types is available here:
        # https://developer.okta.com/docs/api/resources/factors#factor-type
        # ['token:software:totp', 'push', 'sms', 'question', 'call', 'token', 'token:hardware', 'web']
        logger.debug('Available Okta MFA factors found: {}.'.format(', '.join(okta_available_factors.keys())))
        if 'token:software:totp' in okta_available_factors.keys():
            logger.debug('Okta TOTP Verification Method available, attempting to verify...')
            totp_factor = okta_available_factors.get('token:software:totp')
            if self.okta_totp_verification(totp_factor):
                return True
        if 'push' in okta_available_factors.keys():
            logger.debug('Okta Push Verification Method available, attempting to verify...')
            push_factor = okta_available_factors.get('push')
            if self.okta_push_verification(push_factor):
                return True
        return False

    def get_verification_status_from_response(self, response):
        status_search = re.search(re.compile(r"var status = '(.*?)';"), response.text)
        if status_search:
            if len(status_search.groups()) == 1:
                return status_search.groups()[0]
        click.secho('No Verification Status found in response. Exiting...', fg='red')
        sys.exit(1)

    def submit_adapter_glue_form(self, response):
        response.soup = BeautifulSoup(response.content, 'lxml')
        adapter_glue_form = response.soup.find(id='adapterGlue')
        referer = response.url
        self.session.headers.update({'Referer': referer})
        selectors = ",".join("{}[name]".format(i) for i in ("input", "button", "textarea", "select"))
        data = [(tag.get('name'), tag.get('value')) for tag in adapter_glue_form.select(selectors)]
        logger.debug('Posting data to url: {}\n{}'.format(referer, data))
        return self.session.post(referer, data=data)

    def okta_totp_verification(self, factor_details):
        if not self.okta_shared_secret:
            logger.debug(
                'TOTP Verification available but Okta Shared Secret '
                'is not set. For instructions to set the Shared Secret, '
                'refer to the README: '
                'https://github.com/cshamrick/stsauth/blob/master/README.md'
            )
            return False

        totp = pyotp.TOTP(self.okta_shared_secret)
        verify_url = factor_details.get('_links', {}).get('verify', {}).get('href')
        try:
            pass_code = totp.now()
        except Exception as e:
            msg = 'An error occured fetching your TOTP code. Please check your Shared Secret.'
            click.secho(msg, fg='red')
            click.secho('Error: {}'.format(str(e)), fg='red')
            sys.exit(1)
        if verify_url:
            verify_response = self.session.post(
                verify_url,
                json={
                    'stateToken': self.state_token,
                    'passCode': pass_code
                })
            if verify_response.ok:
                status = verify_response.json().get('status')
                if status == 'SUCCESS':
                    return True
        click.secho(
            'TOTP Verification failed. '
            'Continuing to other methods if available', fg='red'
        )
        return False

    def okta_push_verification(self, factor_details, notify_count=5, poll_count=10):
        status = 'MFA_CHALLENGE'
        tries = 0
        verify_data = {'stateToken': self.state_token}
        verify_url = factor_details.get('_links', {}).get('verify', {}).get('href')
        if verify_url is None:
            click.secho('No Okta verification URL present in response. Exiting...', fg='red')
            sys.exit(1)
        while (status == 'MFA_CHALLENGE' and tries < notify_count):
            msg = '({}/{}) Waiting for Okta push notification to be accepted...'
            click.secho(msg.format(tries + 1, notify_count), fg='green')
            for _ in range(poll_count):
                verify_response = self.session.post(verify_url, json=verify_data)
                if verify_response.ok:
                    verify_response_json = verify_response.json()
                    logger.debug('Okta Verification Response:\n{}'.format(verify_response_json))
                    status = verify_response_json.get('status', 'MFA_CHALLENGE')

                    if verify_response_json.get('factorResult') == 'REJECTED':
                        click.secho('Okta push notification was rejected! Exiting...', fg='red')
                        sys.exit(1)
                    if status == 'SUCCESS':
                        break
                    time.sleep(1)
            tries += 1

        return status == 'SUCCESS'
