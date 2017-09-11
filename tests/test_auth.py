import unittest

import requests
from requests import Request, Session
from requests_f5auth import XF5Auth
from requests_f5auth.exceptions import F5AuthenticationError
from requests_f5auth import utils



class XF5AuthTest(unittest.TestCase):

    def setUp(self):
        self.bigiq_addr = '10.145.196.234'
        self.username = 'admin'
        self.password = 'f5site02'
        self.url = 'https://' + self.bigiq_addr + '/mgmt/shared/echo'

    def test_username_password(self):
        auth = XF5Auth(self.username, self.password)
        r = Request('GET', self.url, auth=auth).prepare()

        # ensure url didn't get messed up
        self.assertEqual(r.url, self.url)
        self.assertTrue(r.headers.get('X-F5-Auth-Token', ''))

        s = Session()
        resp = s.send(r, verify=False)

        self.assertEquals(resp.status_code, 200)

    def test_refresh_token(self):
        (access_token, refresh_token) = utils.f5_login(self.bigiq_addr, self.username, self.password)

        auth = XF5Auth(refresh_token=refresh_token)
        r = Request('GET', self.url, auth=auth).prepare()

        # ensure url didn't get messed up
        self.assertEqual(r.url, self.url)
        self.assertTrue(r.headers.get('X-F5-Auth-Token', ''))

        s = Session()
        resp = s.send(r, verify=False)

        self.assertEquals(resp.status_code, 200)


    def test_access_token(self):
        (access_token, refresh_token) = utils.f5_login(self.bigiq_addr, self.username, self.password)

        auth = XF5Auth(access_token=access_token)
        r = Request('GET', self.url, auth=auth).prepare()

        # ensure url didn't get messed up
        self.assertEqual(r.url, self.url)
        self.assertTrue(r.headers.get('X-F5-Auth-Token', ''))

        s = Session()
        resp = s.send(r, verify=False)

        self.assertEquals(resp.status_code, 200)


    def test_fail_login(self):
        auth = XF5Auth(self.username, self.password + 'NOT RIGHT')

        with self.assertRaises(F5AuthenticationError) as cm:
            r = Request('GET', self.url, auth=auth).prepare()

    def test_bad_refresh_token(self):
        auth = XF5Auth(refresh_token='abc')

        with self.assertRaises(F5AuthenticationError) as cm:
            r = Request('GET', self.url, auth=auth).prepare()


    def test_bad_access_token(self):
        auth = XF5Auth(access_token='abc')
        resp = requests.get(self.url, auth=auth, verify=False)
        self.assertEquals(resp.status_code, 401)


