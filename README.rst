Requests-F5Auth 
=========================================================

This project provides F5 Authentication support for BIG-IQ and BIG-IP using `Requests <http://python-requests.org>`_.

The workflow
--------------------

F5's BIG-IQ and BIG-IP use token based authentication.  While the implementation differs on each,
requests_f5auth hides most of the differences.

Accessing protected resources using requests_f5auth is as simple as:

.. code-block:: pycon

    >>> from requests_f5auth import F5Auth
	>>> f5auth = F5Auth(username, password)
	>>> resp = requests.get(url='https://10.10.10.10/mgmt/shared/echo', auth=f5auth)

Installation
-------------

To install requests and requests_oauthlib you can use pip:

.. code-block:: bash

    $ pip install requests requests_f5auth

