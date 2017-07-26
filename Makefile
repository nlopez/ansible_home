shell: init
	pipenv shell

init:
	pip install pipenv --quiet
	pipenv --venv || pipenv --bare install --two

clean:
	pipenv --rm
