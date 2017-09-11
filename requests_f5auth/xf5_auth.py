# -*- coding: utf-8 -*-
try:
        from urlparse import urlparse
except ImportError:
        from urllib.parse import urlparse

import logging

from requests.auth import AuthBase

from .utils import (f5_login, f5_exchange_token)

log = logging.getLogger(__name__)

X_F5_AUTH_TOKEN_HEADER = 'X-F5-Auth-Token'

class XF5Auth(AuthBase):
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
            host = urlparse(r.url).hostname
            # use the refresh token to get an access token
            if self.refresh_token:
                self.access_token = f5_exchange_token(host, self.refresh_token)
            # otherwise use the username and password to login
            else:
                self.access_token, self.refresh_token = f5_login(host, self.username,
                        self.password)

        log.debug('Sending request %s using access token %s', r,
                self.access_token)

        headers = r.headers
        headers[X_F5_AUTH_TOKEN_HEADER] = self.access_token

        r.prepare_headers(headers)

        return r


