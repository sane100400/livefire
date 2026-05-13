.PHONY: run check verify build

PORT ?= 8000

run:
	uvicorn main:app --host 0.0.0.0 --port $(PORT) --reload

check:
	python ../scripts/gitctf.py check --repo . --port $(PORT)

verify: check

build:
	docker build -t and-service-local .
