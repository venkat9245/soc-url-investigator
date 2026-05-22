.PHONY: install run init-db clean

PORT ?= 8443

help:
	@echo "SOC URL Investigator Commands"
	@echo "  make install     - Install all dependencies"
	@echo "  make init-db     - Initialize database + admin user"
	@echo "  make run         - Start the dashboard"
	@echo "  make clean       - Remove temporary files"

install:
	pip3 install -r requirements.txt
	@echo "[+] Dependencies installed"

init-db:
	python3 run.py --init-db

run:
	python3 run.py --port $(PORT)

run-debug:
	python3 run.py --debug --port $(PORT)

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf logs/*.log
	@echo "[+] Cleanup complete"
