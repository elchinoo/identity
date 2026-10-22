.PHONY: test test-db lint
lint:      ; .venv/bin/ruff check src tests
test:      ; .venv/bin/pytest -q
# Needs POSTGRES_PASSWORD exported (set -a; . ./.env; set +a) and a Postgres on 127.0.0.1:5435 (docker compose up -d db).
test-db:   ; docker compose exec -T db psql -U identity -c "DROP DATABASE IF EXISTS identity_test" -c "CREATE DATABASE identity_test" && \
	TEST_DATABASE_URL=postgresql://identity:$$POSTGRES_PASSWORD@127.0.0.1:5436/identity_test .venv/bin/pytest -q
