.PHONY: install test lint run clean migrate wiki-push start export

install:
	python -m pip install -U pip
	python -m pip install -r requirements.txt || true

migrate:
	python -m ace_t_osint.migrate

test:
	pytest

lint:
	python -m pylint ace_t_osint || true

run:
	python -m ace_t_osint.cli run --sources all --once

start:
	./start_ace_t.sh

export:
	@if [ -z "$(DEST)" ]; then \
		echo "Usage: make export DEST=/path/to/archive_root" >&2; \
		exit 2; \
	fi
	python scripts/export_run_data.py --dest "$(DEST)" --clean

clean:
	rm -rf __pycache__ */__pycache__
	rm -rf .pytest_cache
	rm -f data/osint.db
	rm -rf data/alerts


wiki-push:
	python utilities/publish_wiki.py --remote origin
