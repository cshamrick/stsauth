from typing import Optional, Mapping
from collections.abc import ValuesView

from sts_auth import utils
from sts_auth.profile import Profile


class ProfileSet(object):
    def __init__(self, profiles: ValuesView):
        # Explicitly exclude RawConfigParser DEFAULT section.
        self.profiles = [Profile(p) for p in profiles if p.name != "DEFAULT"]

    def table(
        self,
        columns: Optional[Mapping[str, str]] = {
            "Account": "account",
            "Profile": "name",
            "Expire Date": "expiry_string",
            "Status": "status",
        },
    ):
        headers = list(columns.keys())  # type: ignore[union-attr]
        rows = [
            list(row)
            for row in zip(
                *[
                    [str(getattr(p, c, None)) for c in list(columns.values())]  # type: ignore[union-attr]
                    for p in self.profiles
                ]
            )
        ]
        return utils.table_format(headers, rows)

    def get(self, profile: str) -> Optional[Profile]:
        lookup: Optional[Profile] = None
        try:
            lookup = next(filter(lambda p: p.name == profile, self.profiles))
        except StopIteration:
            pass
        return lookup

    @property
    def aws_account_names(self) -> Mapping[str, str]:
        acct_map = {p.account_id: p.account for p in self.profiles}
        utils.logger.debug("Account Names: {}".format(acct_map))
        return acct_map


class ProfileNotFound(Exception):
    """Exception raised if Profile is not in Config .

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, profile=None, message="Profile not found."):
        self.profile = profile
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"({self.profile}) {self.message}"
