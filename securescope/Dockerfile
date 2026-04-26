FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry==1.7.1

# Copy project files
COPY pyproject.toml poetry.lock* ./
COPY src/ ./src/
COPY README.md ./

# Configure poetry to not use virtual environments inside docker
RUN poetry config virtualenvs.create false \
    && poetry install --only main --no-interaction --no-ansi

# Set the entrypoint
ENTRYPOINT ["securescope"]
CMD ["--help"]
