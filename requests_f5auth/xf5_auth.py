# -*- coding: utf-8 -*-
try:
        from urlparse import urlparse
except ImportError:
        from urllib.parse import urlparse

import logging
import time

from requests.auth import AuthBase

from .utils import (f5_login, f5_exchange_token)
from .exceptions import F5AuthenticationError

log = logging.getLogger(__name__)

X_F5_AUTH_TOKEN_HEADER = 'X-F5-Auth-Token'
ACCESS_TOKEN_TIMEOUT_SECS = 5*60 # 5 minutes
REFRESH_TOKEN_TIMEOUT_SECS = 10*60*60 # 10 hours


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

        if self.access_token:
            self.access_retrieve_time = time.time()
        else:
            self.access_retrieve_time = 0

        if self.refresh_token:
            self.refresh_retrieve_time = time.time()
        else:
            self.refresh_retrieve_time = 0

    # expiration tracking can be improved if we use JWT
    # but avoiding it now for simplicity and
    # to avoid another dependency
    def _is_refresh_expired(self):
        return time.time() - self.refresh_retrieve_time > REFRESH_TOKEN_TIMEOUT_SECS


    def _is_access_expired(self):
        return time.time() - self.access_retrieve_time > ACCESS_TOKEN_TIMEOUT_SECS


    def __call__(self, r):
        """Send a request using an X-F5-Auth-Token."""

        # if we have don't have an access token...
        if not self.access_token or self._is_access_expired():
            host = urlparse(r.url).hostname
            # use the refresh token to get an access token
            if self.refresh_token and not self._is_refresh_expired():
                self.access_token = f5_exchange_token(host, self.refresh_token)
            # otherwise use the username and password to login
            elif self.username and self.password:
                self.access_token, self.refresh_token = f5_login(host, self.username,
                        self.password)
            else:
                raise F5AuthenticationError("No valid tokens and no username or password were provided")

        log.debug('Sending request %s using access token %s', r,
                self.access_token)

        headers = r.headers
        headers[X_F5_AUTH_TOKEN_HEADER] = self.access_token

        r.prepare_headers(headers)

        return r


