#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2014 Mozilla Corporation
# Author: gdestuynder@mozilla.com

import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "mozdef_client",
        py_modules = ['mozdef_client'],
        version = "1.0.7",
        author = "Guillaume Destuynder",
        author_email = "gdestuynder@mozilla.com",
        description = ("A client library to send messages/events using MozDef"),
        license = "MPL",
        keywords = "mozdef client library",
        url = "https://github.com/gdestuynder/mozdef_client",
        long_description = read('README.rst'),
        install_requires = ['requests_futures', 'pytz', 'boto3'],
        classifiers = [
            "Development Status :: 5 - Production/Stable",
            "Topic :: System :: Logging",
            "Topic :: Software Development :: Libraries :: Python Modules",
            "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        ],
)
