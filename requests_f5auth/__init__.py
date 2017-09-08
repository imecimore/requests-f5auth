import logging

from .xf5_auth import XF5Auth
from .xf5_session import XF5Session

__version__ = '0.1.0'

import requests
if requests.__version__ < '2.0.0':
        msg = ('You are using requests version %s, which is older than'
                'requests-xf5auth expects, please upgrade to 2.0.0 or later.')
        raise Warning(msg % requests.__version__)

        logging.getLogger('requests_oauthlib').addHandler(logging.NullHandler())
