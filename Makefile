.PHONY: bootstrap doctor test demo
bootstrap:
	python3 -I review.py bootstrap
doctor:
	python3 -I review.py doctor
test:
	python3 -I tests/run_tests.py
demo:
	python3 -I review.py demo
