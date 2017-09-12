import unittest
import time

import requests
from requests import Request, Session
from requests_f5auth import XF5Auth
from requests_f5auth.exceptions import F5AuthenticationError
from requests_f5auth import utils

from requests.packages.urllib3.exceptions import InsecureRequestWarning

from testconfig import config

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class XF5AuthTest(unittest.TestCase):

    def setUp(self):
        self.is_long_test_allowed = config['settings']['is_long_test_allowed']

        self.bigiq_addr = config['device']['address']
        self.username = config['device']['username']
        self.password = config['device']['password']
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


    def test_req_username(self):
        auth = XF5Auth(username='admin', password='f5site02')

        r = requests.get(self.url, auth=auth, verify=False)
        self.assertEquals(r.status_code, 200)

    def test_req_refresh(self):
        (access_token, refresh_token) = utils.f5_login(self.bigiq_addr,
                self.username, self.password)
        auth = XF5Auth(refresh_token=refresh_token)

        r = requests.get(self.url, auth=auth, verify=False)
        self.assertEquals(r.status_code, 200)

    def test_req_access(self):
        (access_token, refresh_token) = utils.f5_login(self.bigiq_addr,
                self.username, self.password)
        auth = XF5Auth(access_token=access_token)

        r = requests.get(self.url, auth=auth, verify=False)
        self.assertEquals(r.status_code, 200)

    def _verify_session(self, s):
        test_time_len = 60*12
        wait_time = 60
        while self.is_long_test_allowed and test_time_len > 0:
            test_time_len -= wait_time
            time.sleep(wait_time)

            r = s.get(self.url)
            self.assertEquals(r.status_code, 200)

    def test_session_username(self):
        s = requests.Session()
        s.auth = XF5Auth(username='admin', password='f5site02')
        s.verify = False

        r = s.get(self.url)
        self.assertEquals(r.status_code, 200)

        self._verify_session(s)


    def test_session_refresh(self):
        (access_token, refresh_token) = utils.f5_login(self.bigiq_addr,
                self.username, self.password)
        s = requests.Session()
        s.auth = XF5Auth(refresh_token=refresh_token)
        s.verify = False

        r = s.get(self.url)
        self.assertEquals(r.status_code, 200)

        self._verify_session(s)

    def test_session_access(self):
        (access_token, refresh_token) = utils.f5_login(self.bigiq_addr,
                self.username, self.password)
        s = requests.Session()
        s.auth = XF5Auth(access_token=access_token)
        s.verify = False

        r = s.get(self.url)
        self.assertEquals(r.status_code, 200)

        if self.is_long_test_allowed:
            with self.assertRaises(F5AuthenticationError) as cm:
                try:
                    self._verify_session(s)
                except F5AuthenticationError as e:
                    self.assertIn("username", e.args[0])
                    self.assertIn("password", e.args[0])
                    raise

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



