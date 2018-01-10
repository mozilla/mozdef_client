# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2014-2017 Mozilla Corporation
# Author: gdestuynder@mozilla.com

all:
	./setup.py build

install:
	./setup.py install

rpm:
	fpm -s python -t rpm -d pytz -d python-requests-futures --replaces python-mozdef ./setup.py

deb:
	fpm -s python -t deb ./setup.py

tests: test
test:
	python ./test_mozdef_client.py

pypi:
	 python setup.py sdist check upload --sign

twine:
	twine upload -s dist/mozdef_client-1.0.11.tar.gz

clean:
	rm -rf *pyc
	rm -rf build
	rm -rf __pycache__
	rm -rf dist
