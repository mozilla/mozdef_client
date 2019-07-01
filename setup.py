#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2014-2017 Mozilla Corporation
# Author: gdestuynder@mozilla.com

import os
import subprocess
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

VERSION = '1.0.11'


def git_version():
    """ Return the git revision as a string """
    def _minimal_ext_cmd(cmd):
        # construct minimal environment
        env = {}
        for envvar in ['SYSTEMROOT', 'PATH']:
            val = os.environ.get(envvar)
            if val is not None:
                env[envvar] = val
        # LANGUAGE is used on win32
        env['LANGUAGE'] = 'C'
        env['LANG'] = 'C'
        env['LC_ALL'] = 'C'
        out = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               env=env).communicate()[0]
        return out

    try:
        out = _minimal_ext_cmd(['git', 'rev-parse', 'HEAD'])
        git_revision = out.strip().decode('ascii')
    except OSError:
        git_revision = u"Unknown"

    return git_revision


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name="mozdef_client",
    packages=["mozdef_client"],
    version=VERSION,
    author="Guillaume Destuynder",
    author_email="gdestuynder@mozilla.com",
    description=('A client library to send messages/events using MozDef\n' +
                 'This package is built upon commit ' + git_version()),
    license="MPL",
    keywords="mozdef client library",
    url="https://github.com/mozilla/mozdef_client",
    long_description=read('README.rst'),
    install_requires=[
        'requests_futures',
        'pytz',
        'boto3'
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Topic :: System :: Logging",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
    ],
)
