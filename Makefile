.PHONY: run test build up down seed lint format

run:
	uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest tests/unit tests/integration -v

eval:
	python tests/eval/run_evaluation.py

build:
	docker compose -f infrastructure/docker/docker-compose.yml build

up:
	docker compose -f infrastructure/docker/docker-compose.yml up -d

down:
	docker compose -f infrastructure/docker/docker-compose.yml down

up-dev:
	docker compose -f infrastructure/docker/docker-compose.yml up -d postgres redis

logs:
	docker compose -f infrastructure/docker/docker-compose.yml logs -f

seed:
	python scripts/seed_data.py

lint:
	ruff check .

format:
	ruff format .

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete