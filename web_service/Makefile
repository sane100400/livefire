.PHONY: run check verify login push build

PORT ?= 8000

run:
	uvicorn main:app --host 0.0.0.0 --port $(PORT) --reload

check:
	python ../scripts/gitctf.py check --repo . --port $(PORT)

verify: check

login:
	python ../scripts/gitctf.py login

push:
	python ../scripts/gitctf.py push --repo . --message "submit service"

build:
	docker build -t and-service-local .
