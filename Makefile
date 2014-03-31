all:
	./setup.py build

install:
	./setup.py install

rpm:
	fpm -s python -t rpm ./setup.py

deb:
	fpm -s python -t deb ./setup.py

clean:
	rm -rf *pyc
	rm -rf build
	rm -rf __pycache__
