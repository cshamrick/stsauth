import os
import base64


class MockResponse(object):
    def ___init__(self):
        pass


full_attributes = [
    'arn:aws:iam::000000000000:role/ADFS-0a,arn:aws:iam::000000000000:saml-provider/ADFS',
    'arn:aws:iam::000000000001:role/ADFS-1a,arn:aws:iam::000000000001:saml-provider/ADFS',
    'arn:aws:iam::000000000002:role/ADFS-2a,arn:aws:iam::000000000002:saml-provider/ADFS',
    'arn:aws:iam::000000000000:role/ADFS-0b,arn:aws:iam::000000000000:saml-provider/ADFS',
    'arn:aws:iam::000000000001:role/ADFS-1b,arn:aws:iam::000000000001:saml-provider/ADFS',
    'arn:aws:iam::000000000002:role/ADFS-2b,arn:aws:iam::000000000002:saml-provider/ADFS'
]
out_of_order_attributes = [
    'arn:aws:iam::000000000000:role/ADFS-0a,arn:aws:iam::000000000000:saml-provider/ADFS',
    'arn:aws:iam::000000000001:saml-provider/ADFS,arn:aws:iam::000000000001:role/ADFS-1a',
    'arn:aws:iam::000000000002:role/ADFS-2a,arn:aws:iam::000000000002:saml-provider/ADFS',
    'arn:aws:iam::000000000000:saml-provider/ADFS,arn:aws:iam::000000000000:role/ADFS-0b',
    'arn:aws:iam::000000000001:role/ADFS-1b,arn:aws:iam::000000000001:saml-provider/ADFS',
    'arn:aws:iam::000000000002:role/ADFS-2b,arn:aws:iam::000000000002:saml-provider/ADFS'
]
full_account_roles = {
    '000000000000': [
        {
            'label': 'ADFS-0a',
            'attr': 'arn:aws:iam::000000000000:role/ADFS-0a,arn:aws:iam::000000000000:saml-provider/ADFS',
            'id': '000000000000',
            'name': 'AccountOne',
            'num': 0
        },
        {
            'label': 'ADFS-0b',
            'attr': 'arn:aws:iam::000000000000:role/ADFS-0b,arn:aws:iam::000000000000:saml-provider/ADFS',
            'id': '000000000000',
            'name': 'AccountOne',
            'num': 1
        }
    ],
    '000000000001': [
        {
            'label': 'ADFS-1a',
            'attr': 'arn:aws:iam::000000000001:role/ADFS-1a,arn:aws:iam::000000000001:saml-provider/ADFS',
            'id': '000000000001',
            'name': 'AccountTwo',
            'num': 2
        },
        {
            'label': 'ADFS-1b',
            'attr': 'arn:aws:iam::000000000001:role/ADFS-1b,arn:aws:iam::000000000001:saml-provider/ADFS',
            'id': '000000000001',
            'name': 'AccountTwo',
            'num': 3
        }
    ],
    '000000000002': [
        {
            'label': 'ADFS-2a',
            'attr': 'arn:aws:iam::000000000002:role/ADFS-2a,arn:aws:iam::000000000002:saml-provider/ADFS',
            'id': '000000000002',
            'name': 'AccountThree',
            'num': 4
        },
        {
            'label': 'ADFS-2b',
            'attr': 'arn:aws:iam::000000000002:role/ADFS-2b,arn:aws:iam::000000000002:saml-provider/ADFS',
            'id': '000000000002',
            'name': 'AccountThree',
            'num': 5
        }
    ],
}

signature_value = base64.b64encode((('this is a signature value. ' * 9) + 'Its a signature').encode('utf-8'))
attribute_statement = '\n'.join(["<AttributeValue>{}</AttributeValue>".format(attr) for attr in full_attributes])

assertion_decoded = '''
<samlp:Response
    Version="2.0"
    ID="_ID_1"
    IssueInstant="0000-00-00T00:00:00.000Z"
    Destination="https://signin.aws.amazon.com/saml"
    Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified"
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">http://adfs.test.com/adfs/url/endpoint</Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </samlp:Status>
    <Assertion
        Version="2.0" ID="ID_1"
        IssueInstant="0000-00-00T00:00:00.000Z"
        xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
        <Issuer>http://adfs.test.com/adfs/url/endpoint</Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
                <ds:Reference URI="#ID_1">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                    <ds:DigestValue>dGhpcyBpcyBhIGRpZ2VzdCB2YWx1ZSBvZiBsZW5ndGg=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>
                {signature_value}
            </ds:SignatureValue>
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>
                        MIICIDCCAYkCAgPoMA0GCSqGSIb3DQEBBQUAMFgxCzAJBgNVBAYTAlRFMQ0wCwYD
                        VQQIDARURVNUMQ0wCwYDVQQHDARURVNUMQ0wCwYDVQQKDARURVNUMQ0wCwYDVQQL
                        DARURVNUMQ0wCwYDVQQDDARURVNUMB4XDTE5MDEzMDEzNTAzOFoXDTI5MDEyNzEz
                        NTAzOFowWDELMAkGA1UEBhMCVEUxDTALBgNVBAgMBFRFU1QxDTALBgNVBAcMBFRF
                        U1QxDTALBgNVBAoMBFRFU1QxDTALBgNVBAsMBFRFU1QxDTALBgNVBAMMBFRFU1Qw
                        gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANEqwspd8hKtFcIJsLk6SHLNUH5c
                        3bJshqWytLZFJ5YCx2onGLlnrFcxxnOq5sVMUfAMyeiPC73ZMBtd4U32Y6Tv5Bnd
                        nixT1axCWFFEryyZ+CrCJ6c7N9dw7Dn8c8V5n+F+yXSh9UpRF6/naDfrEqpa8KAC
                        OPiP+r4EKXOUdtSnAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAZ24+yjs0VsKoXI+Y
                        JJRIJSTooigOTXayypOAhUdSfgbt3LxnUu9FbNZQVKeH5ukUIvYALYS7gUlVF81e
                        ViH0TIOmEtBSfOiKmJZ9BKKSFfYH5nKNtqErcV1sLVRp/Ynnmm+YxePawMFnOYO9
                        FX49um0pG+Mfp2NCkN4Salh3kUs=
                    </ds:X509Certificate>
                </ds:X509Data>
            </KeyInfo>
        </ds:Signature>
        <Subject>
            <NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">DOMAIN\\user</NameID>
            <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <SubjectConfirmationData
                    NotOnOrAfter="0000-00-00T00:00:00.000Z"
                    Recipient="https://signin.aws.amazon.com/saml" />
            </SubjectConfirmation>
        </Subject>
        <Conditions NotBefore="0000-00-00T00:00:00.000Z" NotOnOrAfter="0000-00-00T00:00:00.000Z">
            <AudienceRestriction>
                <Audience>urn:amazon:webservices</Audience>
            </AudienceRestriction>
        </Conditions>
        <AttributeStatement>
            <Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
                <AttributeValue>user.email@domain.com</AttributeValue>
            </Attribute>
            <Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">{attribute_statement}</Attribute>
        </AttributeStatement>
        <AuthnStatement AuthnInstant="0000-00-00T00:00:00.000Z" SessionIndex="_ID_1">
            <AuthnContext>
                <AuthnContextClassRef>
                    urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
                </AuthnContextClassRef>
            </AuthnContext>
        </AuthnStatement>
    </Assertion>
</samlp:Response>
'''

assertion_decoded_fmt = assertion_decoded.format(
    signature_value=signature_value,
    attribute_statement=attribute_statement
)

assertion = base64.b64encode(assertion_decoded_fmt.encode('utf-8'))

account_map = {
    '000000000000': 'AccountOne',
    '000000000001': 'AccountTwo',
    '000000000002': 'AccountThree',
    '000000000003': '',
}


def generate_account_list_page():
    curr_dir = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(curr_dir, 'html/account_list.html')) as f:
        account_list_template = f.read()

    with open(os.path.join(curr_dir, 'html/saml_account.html')) as f:
        saml_account_template = f.read()

    with open(os.path.join(curr_dir, 'html/saml_role.html')) as f:
        saml_role_template = f.read()

    account_list_data = {
        '000000000000': {
            'name': 'AccountOne',
            'roles': [
                'arn:aws:iam::000000000000:role/ADFS-0a',
                'arn:aws:iam::000000000000:role/ADFS-0b'
            ]
        },
        '000000000001': {
            'name': 'AccountTwo',
            'roles': [
                'arn:aws:iam::000000000001:role/ADFS-1a',
                'arn:aws:iam::000000000001:role/ADFS-1b'
            ]
        },
        '000000000002': {
            'name': 'AccountThree',
            'roles': [
                'arn:aws:iam::000000000002:role/ADFS-2a',
                'arn:aws:iam::000000000002:role/ADFS-2b'
            ]
        },
        '000000000003': {
            'name': '',
            'roles': [
                'arn:aws:iam::000000000002:role/ADFS-3a',
                'arn:aws:iam::000000000002:role/ADFS-3b'
            ]
        }
    }

    saml_accounts = ""
    for i, (k, v) in enumerate(account_list_data.items()):
        roles = ""
        for role in v['roles']:
            roles += saml_role_template.format(role_arn=role, role_name=role.split('/')[1])
        account_name = (v['name'] + ' ') if v['name'] else v['name']
        account_title = 'Account: {account_name}{account_id}'.format(account_name=account_name, account_id=k)
        saml_account = saml_account_template.format(
            account_index=i, account_title=account_title, saml_roles=roles
        )
        saml_accounts += saml_account
    account_list = account_list_template.format(assertion=assertion, saml_accounts=saml_accounts)

    return account_list


aws_credentials_conf = {
    'default': {
        'output': 'json',
        'region': 'us-east-1',
        'idpentryurl': 'https://my.portal.com/adfs/ls/idpinitiatedsignon.aspx?LoginToRP=urn:amazon:webservices',
        'domain': 'MYADDOMAIN',
        'okta_org': 'my-organization',
        'okta_shared_secret': '16CHARLONGSTRING',
        'aws_access_key_id': 'awsaccesskeyidstringexample',
        'aws_secret_access_key': 'awssecretaccesskeystringexample',
    },
    '000000000000 - ADFS - Account1': {
        'output': 'json',
        'region': 'us - east - 1',
        'aws_access_key_id': 'awsaccesskeyidstringexample',
        'aws_secret_access_key': 'awssecretaccesskeystringexample',
        'aws_session_token': 'awssessiontoken',
        'aws_credentials_expiry': '1547158293.0',
    }
}
