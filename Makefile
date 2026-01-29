.PHONY: lint format test test-cov ci dev down

lint:
	uv run ruff check api/ tests/
	uv run ruff format --check api/ tests/

format:
	uv run ruff check --fix api/ tests/
	uv run ruff format api/ tests/

test:
	uv run pytest tests/unit/ -v

test-cov:
	uv run pytest tests/unit/ --cov=api --cov-report=term-missing --cov-fail-under=45

ci: lint test-cov

dev:
	./scripts/dev-deploy.sh

down:
	docker compose -f docker/compose/dev.yml down
