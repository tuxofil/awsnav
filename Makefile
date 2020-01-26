.PHONY: all lint clean

all: lint

lint:
	pep8 --ignore W503 -- *.py
	pylint -- *.py

clean:
	rm -f -- *.pyc *.pyo
