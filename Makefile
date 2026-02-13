.PHONY: install dev lint format typecheck test test-cov run db-up db-down clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

lint:
	ruff check src/ tests/ config/
	ruff format --check src/ tests/ config/

format:
	ruff format src/ tests/ config/
	ruff check --fix src/ tests/ config/

typecheck:
	mypy src/

test:
	pytest

test-cov:
	pytest --cov=src --cov-report=html

run:
	streamlit run src/app.py

db-up:
	docker compose up -d

db-down:
	docker compose down

clean:
	python -c "import shutil, pathlib; [shutil.rmtree(p) for p in pathlib.Path('.').rglob('__pycache__')]"
	python -c "import shutil, pathlib; [shutil.rmtree(p) for p in pathlib.Path('.').rglob('.pytest_cache')]"
	python -c "import shutil, pathlib; [shutil.rmtree(p) for p in pathlib.Path('.').rglob('.mypy_cache')]"