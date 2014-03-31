#!/usr/bin/env python

import os
from distutils.core import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "mozdef",
	py_modules=['mozdef'],
    version = "1.0.0",
    author = "Guillaume Destuynder",
    author_email = "gdestuynder@mozilla.com",
    description = ("A client library to send messages using MozDef"),
    license = "MPL",
    keywords = "mozdef client library",
    url = "https://github.com/gdestuynder/mozdef_lib",
    long_description=read('README.rst'),
	requires=['requests_futures', 'pytz'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Topic :: System :: Logging",
		"Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
    ],
)
