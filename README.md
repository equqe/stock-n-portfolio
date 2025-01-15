# stock-n-portfolio

figma template https://www.figma.com/design/68NEHfAxbe8I6v8GEyUmWc/Untitled?node-id=0-1&node-type=canvas

используется asgi, вебсокеты для чата

сборка образа через докерфайл, контейнеры с постгрес+нжинкс+апп - сборка через compose(+wait-for-it скрипт)

запуск локально:

```
git clone https://github.com/equqe/stock-n-portfolio

cd stock-n-portfolio

docker-compose build

docker-compose up -d
```

доступ - 127.0.0.1:8000

## если занят порт 8000 - докер не запустится. меняйте конфиги/убейте процесс по pid номеру, который занимает 8000 порт

первый админ:
почта - arsennazranov@gmail.com, 
юзер - arsennazranov, 
пароль - arsennazranov

общая админпанель: /op/admin

ДЛЯ ЗАПУСКА ТРЕБУЕТСЯ УСТАНОВЛЕННЫЙ ДОКЕР
