.PHONY: run verify verify-verbose build

PORT ?= 8000

run:
	uvicorn main:app --host 0.0.0.0 --port $(PORT) --reload

verify:
	python ../scripts/verify.py --port $(PORT)

verify-verbose:
	python ../scripts/verify.py --port $(PORT) --verbose

build:
	docker build -t and-service-local .
