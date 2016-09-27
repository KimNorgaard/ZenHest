sdist:
	python setup.py sdist

sdist_upload:
	python setup.py sdist upload 2>&1 |tee upload.log
