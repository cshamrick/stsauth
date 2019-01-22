import re
import sys
import time
import logging
import requests

import click
import pyotp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class Okta:

    def __init__(self, session, okta_org, okta_shared_secret=None):
        self.session = session
        self.okta_org = okta_org
        self.okta_shared_secret = okta_shared_secret

    def handle_okta_verification(self, response):
        # If there is no assertion, and we find an Okta portal on the page,
        # we have to pass through the Okta portal regardless of whether MFA
        # will be required or not.
        if not self.okta_org:
            msg = ('Okta MFA required but no Okta Organization set. '
                    'Please either set in the config or use `--okta-org`')
            click.secho(msg, fg='red')
            sys.exit(1)

        logger.debug('No SAML assertion found in response. Attempting to begin MFA...')
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
            mfa_verified = self.process_okta_mfa(response)
            if mfa_verified:
                okta_response = self.submit_adapter_glue_form(response)
                return okta_response
        else:
            click.secho('Okta verification failed. Exiting...', fg='red')
            sys.exit(1)

    def process_okta_mfa(self, response):
        state_token = self.get_state_token_from_response(response)
        okta_available_factors = self.fetch_available_mfa_factors(state_token)
        if 'token:software:totp' in okta_available_factors.keys():
            logger.debug('Okta TOTP Verification Method available, attempting to verify...')
            totp_factor = okta_available_factors.get('token:software:totp')
            if self.okta_totp_verification(state_token, totp_factor):
                return True
        if 'push' in okta_available_factors.keys():
            logger.debug('Okta Push Verification Method available, attempting to verify...')
            push_factor = okta_available_factors.get('push')
            if self.poll_for_okta_push_verification(state_token, push_factor):
                return True
        return False

    def get_verification_status_from_response(self, response):
        status_search = re.search(re.compile(r"var status = '(.*?)';"), response.text)
        if status_search:
            if len(status_search.groups()) == 1:
                return status_search.groups()[0]
        click.secho('No Verification Status found in response. Exiting...', fg='red')
        sys.exit(1)

    def get_state_token_from_response(self, response):
        state_token_search = re.search(re.compile(r"var stateToken = '(.*?)';"), response.text)
        if state_token_search:
            if len(state_token_search.groups()) == 1:
                state_token = state_token_search.groups()[0]
                logger.debug('Found state_token: {}'.format(state_token))
                return state_token
        click.secho('No State Token found in response. Exiting...', fg='red')
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

    def fetch_available_mfa_factors(self, state_token):
        okta_auth_url = 'https://{}.okta.com/api/v1/authn'.format(self.okta_org)
        okta_transaction_state = self.session.post(
            okta_auth_url,
            json={'stateToken': state_token}
        )
        okta_factors = okta_transaction_state.json().get('_embedded', {}).get('factors', {})
        if len(okta_factors) > 0:
            # Format the factors as {factorType: {details..}, ..}
            # so it will be easier to pick pull out by type later
            return {f['factorType']: f for f in okta_factors}
        else:
            click.secho('No Okta MFA Verification Factors available. Exiting...')
            sys.exit(1)

    def okta_totp_verification(self, state_token, factor_details):
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
        data = {'stateToken': state_token, 'passCode': totp.now()}
        if verify_url:
            verify_response = self.session.post(verify_url, json=data)
            if verify_response.ok:
                status = verify_response.json().get('status')
                if status == 'SUCCESS':
                    return True
        click.secho(
            'TOTP Verification failed. '
            'Continuing to other methods if available', fg='red'
        )
        return False

    def poll_for_okta_push_verification(self, state_token, factor_details,
                                        notify_count=5, poll_count=10):
        status = 'MFA_CHALLENGE'
        tries = 0
        verify_data = {'stateToken': state_token}
        verify_url = factor_details.get('_links', {}).get('verify', {}).get('href')
        if verify_url == None:
            click.secho('No Okta verification URL present in response. Exiting...', fg='red')
            sys.exit(1)
        while (status == 'MFA_CHALLENGE' and tries < notify_count):
            msg = '({}/{}) Waiting for Okta push notification to be accepted...'
            click.secho(msg.format(tries +1, notify_count), fg='green')
            for _ in range(poll_count):
                verify_response = requests.post(verify_url, json=verify_data)
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
