import unittest

from requests import Request, Session
from requests_f5auth import XF5Auth


class XF5AuthTest(unittest.TestCase):

    def setUp(self):
        self.bigiq_addr = '10.145.196.234'
        self.username = 'admin'
        self.password = 'f5site02'

    def test_username_password(self):
        url = 'https://' + self.bigiq_addr + '/mgmt/shared/echo'
        auth = XF5Auth(self.username, self.password)
        r = Request('GET', url, auth=auth).prepare()

        # ensure url didn't get messed up
        self.assertEqual(r.url, url)
        self.assertTrue(r.headers.get('X-F5-Auth-Token', ''))

        s = Session()
        resp = s.send(r, verify=False)

        self.assertEquals(resp.status_code, 200)

    def test_refresh_token(self):
        login = 'https://'


    def test_access_token(self):
        pass

