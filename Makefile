.PHONY: install test lint run clean migrate wiki-push

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

clean:
rm -rf __pycache__ */__pycache__
rm -rf .pytest_cache
rm -f data/osint.db
rm -rf data/alerts


wiki-push:
	python utilities/publish_wiki.py --remote origin
