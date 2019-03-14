from datetime import datetime
from unittest import TestCase

from bs4 import BeautifulSoup

from sts_auth import utils
from .fixtures import fixtures


class TestGetStateTokenFromResponse(TestCase):

    def test_get_state_token_from_response_no_token(self):
        test_str = ""
        token = utils.get_state_token_from_response(test_str)
        self.assertIsNone(token)

    def test_get_state_token_from_response_token(self):
        _token = "my_state_token"
        test_str = "var stateToken = '{}';".format(_token)
        token = utils.get_state_token_from_response(test_str)
        self.assertEqual(_token, token)


class TestFormatRolesForDisplay(TestCase):

    def test_format_roles_for_display_full(self):
        attrs = fixtures.full_attributes
        account_map = fixtures.account_map
        account_roles = utils.format_roles_for_display(attrs, account_map)
        self.assertDictEqual(fixtures.full_account_roles, account_roles)

    def test_format_roles_for_display_empty(self):
        account_roles = utils.format_roles_for_display([], {})
        self.assertDictEqual({}, account_roles)

    # def test_format_roles_for_display_out_of_order(self):
    #     attrs = fixtures.out_of_order_attributes
    #     account_roles = utils.format_roles_for_display(attrs)
    #     self.assertDictEqual(fixtures.full_account_roles, account_roles)


class TestParseRolesFromAssertion(TestCase):

    def test_parse_roles_from_assertion_full(self):
        roles = utils.parse_roles_from_assertion(fixtures.assertion)
        self.assertListEqual(roles, fixtures.full_attributes)


class TestFormatRoleOrder(TestCase):

    def test_format_role_order_in_order(self):
        roles = utils.format_role_order(fixtures.full_attributes)
        self.assertListEqual(roles, fixtures.full_attributes)

    def test_format_role_order_out_of_order(self):
        roles = utils.format_role_order(fixtures.out_of_order_attributes)
        self.assertListEqual(roles, fixtures.full_attributes)


class TestGetAccountIdFromRole(TestCase):

    def setUp(self):
        self.acct_id_1 = '000000000000'
        self.acct_id_2 = '000000000001'
        self.short_acct_id = '00000000'
        self._role = (
            'arn:aws:iam::{}:role/ADFS-0a,'
            'arn:aws:iam::{}:saml-provider/ADFS'
        )
        self.role = self._role.format(
            self.acct_id_1,
            self.acct_id_1
        )
        self.short_acct_id_role = self._role.format(
            self.short_acct_id,
            self.short_acct_id
        )
        self.different_ids_role = self._role.format(
            self.acct_id_1,
            self.acct_id_2
        )

    def test_get_account_id_from_role(self):
        acct_id = utils.get_account_id_from_role(self.role)
        self.assertEqual(acct_id, self.acct_id_1)

    def test_get_account_id_from_role_short(self):
        with self.assertRaises(Exception) as exc:
            utils.get_account_id_from_role(self.short_acct_id_role)
        self.assertTrue(self.short_acct_id_role in exc.exception.args[0])

    def test_get_account_id_from_role_different(self):
        with self.assertRaises(Exception) as exc:
            utils.get_account_id_from_role(self.different_ids_role)
        self.assertTrue(self.different_ids_role in exc.exception.args[0])


class TestToFromEpoch(TestCase):

    def setUp(self):
        self.now = datetime.utcnow()

    def testConvertBackAndForth(self):
        epoch = utils.to_epoch(self.now)
        dt = utils.from_epoch(epoch)
        self.assertEqual(self.now, dt)


class TestParseAwsAccountNamesFromResponse(TestCase):

    def setUp(self):
        self.response = fixtures.MockResponse()
        account_list_page = fixtures.generate_account_list_page()
        self.response.soup = BeautifulSoup(account_list_page, "lxml")

    def test_parse_aws_account_names_from_response(self):
        account_map = utils.parse_aws_account_names_from_response(self.response)
        self.assertDictEqual(account_map, fixtures.account_map)
