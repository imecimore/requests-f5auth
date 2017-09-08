# -*- coding: utf-8 -*-
import logging

import requests

from .exceptions import F5AuthenticationError, F5TokenExchangeError

log = logging.getLogger(__name__)


class XF5Session(requests.Session):
    """Signs the request using an X-F5-Auth-Token"""

    def __init__(self, username=None,
        password=None,
        loginProviderName=None,
        loginReference=None,
        access_token=None,
        refresh_token=None,
        **kwargs):

        self.username=username
        self.password=password
        self.loginProviderName=loginProviderName
        self.loginReference=loginReference
        self.access_token=access_token
        self.refresh_token=refresh_token


    def __call__(self, r):
        """Send a request using an X-F5-Auth-Token."""

        # if we have don't have an access token...
        if not self.access_token:
            # use the refresh token to get an access token
            if self.refresh_token:
                self.access_token = _exchange_token(r, self.refresh_token)
            # otherwise use the username and password to login
            else:
                self.access_token, self.refresh_token = _login(r, self.username,
                        self.password)

        log.debug('Sending requests %s using access token %s', r, self.access_token)
        r.headers[X_F5_AUTH_TOKEN_HEADER] = self.access_token




