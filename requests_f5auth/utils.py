# -*- coding: utf-8 -*-

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

import logging

import requests

from .exceptions import F5AuthenticationError, F5TokenExchangeError

log = logging.getLogger(__name__)

EXCHANGE_PATH = '/mgmt/shared/authn/exchange'
LOGIN_PATH = '/mgmt/shared/authn/login'

def f5_exchange_token(r, refresh_token):

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



def f5_login(r,
        username,
        password,
        providerName=None,
        loginReference=None):

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


