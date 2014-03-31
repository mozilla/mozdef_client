all:
	./setup.py build

install:
	./setup.py install

clean:
	rm -rf *pyc
	rm -rf build
	rm -rf __pycache__
