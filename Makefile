

default: update unittest

ve: ve/bin/activate

ve/bin/activate:
	python3 -m venv ve
	./ve/bin/pip install --upgrade pip
	./ve/bin/pip install --upgrade pip-tools

update-deps: ve
	./ve/bin/pip-compile --upgrade --generate-hashes
	./ve/bin/pip-compile --upgrade --generate-hashes --output-file dev-requirements.txt dev-requirements.in
	./ve/bin/pip install --upgrade -r requirements.txt  -r dev-requirements.txt

install: ve
	./ve/bin/pip install --editable .

update: update-deps install

unittest:
	./ve/bin/pytest . -v

# leaves construct running
#test:
#	killall construct
#	./ve/bin/construct -c construct.conf > construct.log 2>&1 &
#	./ve/bin/python testcase.py

clean:
	rm -rf ve .eggs construct/__pycache__ tests/__pycache__ construct.egg-info
	rm -f aLlowed.log  bAnned.log  chAnoper_.log  cHanoper.log  gUest.log  sErveroper.log construct.log


.PHONY: update-deps update install unittest test clean
