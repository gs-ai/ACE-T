# Makefile for ACE-T Backend

.PHONY: clean initdb run test

clean:
	find . -type d -name '__pycache__' -exec rm -rf {} +
	rm -f test.db

initdb:
	python initialize_db.py

run:
	uvicorn backend.app.main:app --reload

test:
	curl -X POST "http://127.0.0.1:8000/api/users/" \
	  -H "Content-Type: application/json" \
	  -d '{"name": "Test User", "email": "testuser@example.com"}'
	curl "http://127.0.0.1:8000/api/users/"
