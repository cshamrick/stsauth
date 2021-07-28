from datetime import datetime
from configparser import SectionProxy

import click  # type: ignore[import]

from sts_auth import utils


class Profile(object):
    def __init__(self, section: SectionProxy):
        self.name = section.name
        self.attributes = []
        # Load all attributes from config file into class
        for k, v in section.items():
            setattr(self, k, v)
            self.attributes.append(k)

        # For known attributes, ensure their fallback is correct
        self.account = section.get("account_name", fallback="None")
        self.account_id = section.get("account_id", fallback="None")
        self.expiry = section.get("aws_credentials_expiry", fallback=None)

        # Custom attributes
        self.status = "active" if self.active else "expired"

    def __repr__(self):
        return self.name

    def __str__(self):
        output = click.style("[{}]".format(self.name), fg="green")
        output += "\n"

        for k in self.attributes:
            v = getattr(self, k)
            output += click.style("{}=".format(k), fg="blue")
            if k == "aws_credentials_expiry":
                v = "{} ({})".format(v, str(utils.from_epoch(v)))
            output += click.style(v, fg="green")
            output += "\n"

        output += click.style("status=", fg="blue")
        if self.active:
            output += click.style("active", fg="green")
        else:
            output += click.style("expired", fg="red")
        return output

    @property
    def expiry_string(self) -> str:
        return str(utils.from_epoch(self.expiry)) if self.expiry else "No Expiry Set"

    @property
    def active(self) -> bool:
        return utils.from_epoch(self.expiry) > datetime.utcnow() if self.expiry else True

    def query(self, query: str) -> str:
        try:
            attribute_value = getattr(self, query)
        except AttributeError:
            message = "Invalid value {!r} for 'query' parameter. Valid choices: ".format(query)
            message += ", ".join(self.attributes)
            raise ValueError(message)
        else:
            return attribute_value
