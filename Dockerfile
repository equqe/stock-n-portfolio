FROM python:3.11.8-bookworm as base

ENV PKGS_DIR=/install
ENV PIP_NO_CACHE_DIR=off
ENV PIP_DISABLE_PIP_VERSION_CHECK=on
ENV PIP_DEFAULT_TIMEOUT=100

FROM base as builder
RUN apt update
RUN apt install -y gcc g++
RUN pip install --upgrade pip

RUN mkdir $PKGS_DIR
RUN mkdir /app

WORKDIR /app

COPY requirements.txt /app/

# Install dependencies to local folder
RUN pip install --no-cache-dir --target=$PKGS_DIR -r ./requirements.txt
RUN pip install --no-cache-dir --target=$PKGS_DIR gunicorn daphne

# Main image with service
FROM base
ARG SRC_PATH=.

ENV PYTHONPATH=/usr/local
COPY --from=builder $PKGS_DIR /usr/local

COPY $SRC_PATH/stock /app/stock
COPY $SRC_PATH/app /app/app
COPY $SRC_PATH/manage.py /app/manage.py
COPY $SRC_PATH/static /app/static
COPY $SRC_PATH/templates /app/templates

ENV SERVICE_DEBUG=False
ENV SERVICE_DB_PATH=/data
ENV SERVICE_HOST="0.0.0.0"
ENV SERVICE_PORT=8000

# Copying wait-for-it.sh inside the container
COPY wait-for-it.sh /usr/local/bin/wait-for-it.sh
RUN apt update && apt install -y dos2unix
RUN dos2unix /usr/local/bin/wait-for-it.sh

# Run service
CMD python manage.py makemigrations app && python manage.py migrate && python manage.py createsuperuser --noinput --username arsennazranov --email arsennazranov@gmail.com && daphne -p 8000 stock.asgi:application
