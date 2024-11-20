# ProcMonitor
## Описание
ProcMonitor — это высокопроизводительный сервис для мониторинга событий процессов в Linux. Он использует proc connector для отслеживания событий процессов и предоставляет три режима работы для передачи данных:

Unix Domain Socket: Передает события всем подключённым клиентам через Unix Domain Socket.
TCP-сокет с аутентификацией: Передает события клиентам через TCP после успешной аутентификации.
Прямой вывод: Выводит события непосредственно в консоль.
ProcMonitor разработан с учётом многопоточности, что позволяет эффективно обрабатывать сотни событий в секунду и обслуживать множество клиентов одновременно.

## Возможности
### Мониторинг событий процессов:

Fork: Отслеживает создание дочерних процессов.
Exec: Отслеживает выполнение новых программ в процессе.
Exit: Отслеживает завершение процессов.
### Режимы работы:

Unix Domain Socket: Локальное взаимодействие с клиентами через Unix-сокеты.
TCP-сокет с аутентификацией: Удалённый доступ через сеть с защитой паролем.
Прямой вывод: Выводит события непосредственно в терминал для отладки или локального использования.
Многопоточность: Использует POSIX Threads для параллельной обработки событий и взаимодействия с клиентами.

### Безопасность:

Аутентификация клиентов в TCP-сокетном режиме.
Ограничение количества одновременных подключений.
Гибкая конфигурация: Настраиваемые параметры через командную строку.

### Установка
Требования
ОС: Linux (поддержка proc connector)
Компилятор: GCC
Библиотеки: POSIX Threads
Скачивание
Склонируйте репозиторий или загрузите исходный код:


> git clone https://github.com/FxProjects/procMonitor.git
>cd procMonitor

### Компиляция
Используйте предоставленный Makefile для сборки приложения:

bash

>make

После успешной компиляции в текущем каталоге появится исполняемый файл procMonitor.

### Установка
Для установки приложения можно использовать cp или создать пакет Debian. Пример копирования:


>sudo cp procMonitor /usr/local/bin/

### Использование

>procMonitor [options]

Опции

>   -e, --events exec,exit  

Список событий для отслеживания, разделённых запятыми (например: exec,exit,fork)

> -c, --clients <number>

Устанавливает максимальное количество одновременных клиентов.
По умолчанию: 10

> -s, --socket <path>

Устанавливает путь к Unix Domain Socket.

По умолчанию: /var/run/procMonitor.sock

> -t, --tcp <port>

Включает TCP-сокетный режим и устанавливает порт для прослушивания.

> -a, --auth <password>

Устанавливает пароль для аутентификации клиентов в TCP-сокетном режиме.

>-d, --direct

Включает режим прямого вывода в консоль.

> -h, --help

Отображает справочную информацию.

## Примеры использования
### 1. Режим Unix Domain Socket
Запуск ProcMonitor с Unix Domain Socket по пути /tmp/procMonitor.sock и максимальным количеством клиентов 20:


> sudo ./procMonitor --clients 20 --socket /tmp/procMonitor.sock

### 2. TCP-сокетный режим с аутентификацией
Запуск ProcMonitor в TCP-сокетном режиме на порту 8080 с паролем mysecretpassword и максимальным количеством клиентов 50:


>sudo ./procMonitor --tcp 8080 --auth mysecretpassword --clients 50

### 3. Прямой вывод в консоль
Запуск ProcMonitor в режиме прямого вывода в консоль:


> sudo ./procMonitor --direct

## Клиентское Приложение
Для подключения к ProcMonitor и получения событий можно использовать предоставленный клиент processClient.js на Node.js.

### Требования
Node.js: Установите Node.js версии 12 или выше.
#### Установка
Скачайте или создайте файл processClient.js с содержимым, предоставленным в репозитории.

### Использование
#### 1. Подключение через Unix Domain Socket
> node processClient.js --socket /tmp/procMonitor.sock

#### 2. Подключение через TCP-сокет с аутентификацией
В TCP-сокетном режиме используется простой механизм аутентификации по паролю. Убедитесь, что пароль достаточно сложный и хранится в безопасности.

>node processClient.js --tcp --host 127.0.0.1 --port 8080 --auth mysecretpassword

#### 3. Подключение через Unix Domain Socket:

> node processClient.js --socket /tmp/procMonitor.sock

Подключение через TCP-сокет:




### Ограничение доступа к Unix Domain Socket
По умолчанию Unix Domain Socket создается с правами 0666, что позволяет всем пользователям подключаться к нему. Для повышения безопасности вы можете изменить эти права, изменив строку chmod(opts.socket_path, 0666); в исходном коде.

### Рекомендации
Запуск от привилегированного пользователя: Запускайте ProcMonitor с необходимыми привилегиями, чтобы он мог отслеживать события процессов.

Ограничение доступа: Ограничьте доступ к Unix Domain Socket только доверенным пользователям или группам.

Использование SSH: Для удаленного доступа через TCP-сокет рекомендуется использовать SSH-туннелирование для дополнительной безопасности.

### Логирование
ProcMonitor выводит информацию о подключениях клиентов и событиях процессов в стандартный вывод. Для более продвинутого логирования можно интегрировать его с системным логгером syslog.

### Завершение Работы
ProcMonitor корректно обрабатывает сигналы SIGINT и SIGTERM, закрывая все открытые сокеты и освобождая ресурсы перед завершением работы.


### Структура проекта

>procMonitor/
>├── procMonitor.c          # Исходный код сервера
>├── Makefile               # Файл сборки
>├── processClient.js       # Клиентское приложение на Node.js
>├── README.md              # Документация

### Внесение изменений
#### Форк репозитория:

Склонируйте репозиторий и создайте свою ветку:


>git clone https://github.com/FxProjects/procMonitor.git
>cd procMonitor
>git checkout -b feature/your-feature

#### Внесение изменений:

Внесите необходимые изменения в исходный код или документацию.

#### Коммит и отправка:


> git add .
> git commit -m "Добавлена новая функция X"
> git push origin feature/your-feature
> Создание Pull Request:

Создайте Pull Request в оригинальный репозиторий для рассмотрения ваших изменений.

 