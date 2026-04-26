.PHONY: install test lint format clean

# Install dependencies using Poetry
install:
	poetry install

# Run tests with pytest
test:
	poetry run pytest

# Run linters (ruff and mypy)
lint:
	poetry run ruff check src/ tests/
	poetry run mypy src/

# Format code with black and ruff
format:
	poetry run black src/ tests/
	poetry run ruff check --fix src/ tests/

# Clean up cache files
clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
