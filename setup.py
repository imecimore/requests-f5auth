#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re

from setuptools import setup


# Get the version
version_regex = r'__version__ = ["\']([^"\']*)["\']'
with open('requests_f5auth/__init__.py', 'r') as f:
    text = f.read()
    match = re.search(version_regex, text)

    if match:
        VERSION = match.group(1)
    else:
        raise RuntimeError("No version number found!")


APP_NAME = 'requests-f5auth'
DESCRIPTION = 'F5 REST Authentication support for Requests.'

# Publish Helper.
if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()


setup(
    name=APP_NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=open('README.rst').read(),
    author='Ivan Mecimore',
    author_email='imecimore@gmail.com',
    url='https://github.com/requests/requests-f5auth',
    packages=['requests_f5auth'],
    install_requires=['requests>=2.0.0'],
    license='ISC',
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ),
    zip_safe=False,
    tests_require=[
        'nose',
        'nose-testconfig',
        'pyyaml'
    ],
    test_suite='tests'
)
