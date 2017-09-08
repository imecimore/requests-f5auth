# -*- coding: utf-8 -*-
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

import logging

import requests
from requests.auth import AuthBase

from .exceptions import F5AuthenticationError, F5TokenExchangeError

log = logging.getLogger(__name__)

X_F5_AUTH_TOKEN_HEADER = 'X-F5-Auth-Token'
EXCHANGE_PATH = '/mgmt/shared/authn/exchange'
LOGIN_PATH = '/mgmt/shared/authn/login'

def _exchange_token(r, refresh_token):
    host = urlparse(r.url).hostname
    url = 'https://%s%s' % (host, EXCHANGE_PATH)
    body = {'refreshToken':refresh_token}

    log.debug('Sending refresh token exchange request.')
    resp = requests.post(url=url, json=body, verify=False)

    if not resp.ok:
        try:
            msg = resp.json()['message']
        except Exception:
            pass
        errorMsg = "Failed to exchange refresh token."
        if msg:
            errorMsg += '  Reason: %s' % msg
        raise F5AuthenticationError(errorMsg)

    resp_json = resp.json()
    access_token = resp_json['token']['token']
    log.debug('Received access token %s', access_token)
    return access_token



def _login(r, username, password, providerName=None, loginReference=None):
    host = urlparse(r.url).hostname
    url = 'https://%s/%s' % (host, LOGIN_PATH)
    body = {'username': username, 'password':password}

    if providerName:
        body['loginProviderName'] = providerName

    if loginReference:
        body['loginReference'] = loginReference

    log.debug('Sending login request for %s', username)
    resp = requests.post(url=url, json=body, verify=False)

    if not resp.ok:
        try:
            msg = resp.json()['message']
        except Exception:
            pass
        errorMsg = "Failed to login user %s." % username
        if msg:
            errorMsg += '  Reason: %s' % msg
        raise F5AuthenticationError(errorMsg)

    resp_json = resp.json()
    access_token = resp_json['token']['token']
    refresh_token = resp_json['refreshToken']['token']
    log.debug('Received refresh token %s.', refresh_token)
    log.debug('Received access token %s.', access_token)
    return access_token, refresh_token



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
            # use the refresh token to get an access token
            if self.refresh_token:
                self.access_token = _exchange_token(r, self.refresh_token)
            # otherwise use the username and password to login
            else:
                self.access_token, self.refresh_token = _login(r, self.username,
                        self.password)

        log.debug('Sending request %s using access token %s', r,
                self.access_token)

        headers = r.headers
        headers[X_F5_AUTH_TOKEN_HEADER] = self.access_token

        r.prepare_headers(headers)

        return r


