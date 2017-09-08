"""
requests_xf5auth.exceptions
~~~~~~~~~~~~~~~~~~~
This module contains the set of exceptions.
"""
from requests.exceptions import RequestException


class F5AuthenticationError(RequestException):
    """F5 Authentication Error"""

class F5TokenExchangeError(RequestException):
    """Refresh Token Exchange Failed Error"""
