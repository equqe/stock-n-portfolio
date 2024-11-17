FROM python:3.11.8-bookworm AS base

# установка переменных среды
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100

# установка зависимостей для сборки
RUN apt update && apt install -y gcc g++ dos2unix && rm -rf /var/lib/apt/lists/*

# создание директории приложения
WORKDIR /app

# установка зависимостей
COPY requirements.txt /app/
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt gunicorn daphne \
    && pip install channels \
    && pip uninstall -y channels \
    && pip install channels

# копирование кода приложения
COPY . /app

# преобразование скрипта wait-for-it.sh в Unix-формат
RUN dos2unix /app/wait-for-it.sh && chmod +x /app/wait-for-it.sh

# установка переменных среды для приложения
ENV SERVICE_DEBUG=False \
    SERVICE_DB_PATH=/data \
    SERVICE_HOST="0.0.0.0" \
    SERVICE_PORT=8000

# команда запуска контейнера
CMD ["sh", "-c", "/app/wait-for-it.sh -t 15 postgres:5432 && python manage.py makemigrations app && python manage.py migrate && python create_superuser.py && daphne -b 0.0.0.0 -p 8000 stock.asgi:application"]
