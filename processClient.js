// processClient.js

/**
 * processClient.js
 *
 * Описание:
 *   Клиентское приложение для подключения к сервису ProcMonitor и получения событий процессов.
 *   Поддерживает подключение через Unix Domain Socket или TCP-сокет с аутентификацией.
 *
 * Использование:
 *   node processClient.js [options]
 *
 * Опции:
 *   -s, --socket <path>        Путь к Unix Domain Socket (по умолчанию: /var/run/procMonitor.sock)
 *   -H, --host <hostname>      Хост для подключения через TCP (по умолчанию: localhost)
 *   -p, --port <port>          Порт для подключения через TCP (по умолчанию: 8080)
 *   -a, --auth <password>      Пароль для аутентификации в TCP-сокетном режиме
 *   -t, --tcp                  Включает TCP-сокетный режим
 *   -h, --help                 Отображает справочную информацию
 *
 * Примеры:
 *   node processClient.js --socket /var/run/procMonitor.sock
 *   node processClient.js --tcp --host 127.0.0.1 --port 8080 --auth mysecretpassword
 */

const net = require('net');
const readline = require('readline');
const yargs = require('yargs');

// Парсинг аргументов командной строки
const argv = yargs
    .option('socket', {
        alias: 's',
        description: 'Path to Unix Domain Socket',
        type: 'string',
        default: '/var/run/procMonitor.sock'
    })
    .option('host', {
        alias: 'H',
        description: 'Hostname for TCP connection',
        type: 'string',
        default: 'localhost'
    })
    .option('port', {
        alias: 'p',
        description: 'Port for TCP connection',
        type: 'number',
        default: 8080
    })
    .option('auth', {
        alias: 'a',
        description: 'Password for TCP authentication',
        type: 'string'
    })
    .option('tcp', {
        alias: 't',
        description: 'Enable TCP mode',
        type: 'boolean',
        default: false
    })
    .help()
    .alias('help', 'h')
    .argv;

// Функция для подключения к Unix Domain Socket
function connectUnixSocket(socketPath) {
    const client = net.createConnection({ path: socketPath }, () => {
        console.log(`Подключено к ProcMonitor через Unix Domain Socket: ${socketPath}`);
    });

    client.on('error', (err) => {
        console.error(`Ошибка подключения: ${err.message}`);
        process.exit(1);
    });

    const rl = readline.createInterface({
        input: client,
        crlfDelay: Infinity
    });

    rl.on('line', (line) => {
        try {
            const event = JSON.parse(line);
            switch (event.event) {
                case 'fork':
                    console.log(`Процесс Форка: Родитель PID=${event.parent_pid}, Дочерний PID=${event.child_pid}, Пользователь=${event.user}, Команда="${event.cmdline}"`);
                    break;
                case 'exec':
                    console.log(`Процесс Exec: PID=${event.pid}, Пользователь=${event.user}, Команда="${event.cmdline}"`);
                    break;
                case 'exit':
                    console.log(`Процесс Завершен: PID=${event.pid}, Код выхода=${event.exit_code}, Пользователь=${event.user}`);
                    break;
                default:
                    console.log('Неизвестное событие:', event);
            }
        } catch (err) {
            console.error('Не удалось разобрать JSON:', err, 'Строка:', line);
        }
    });

    rl.on('close', () => {
        console.log('Отключено от ProcMonitor');
        process.exit(0);
    });

    client.on('end', () => {
        console.log('Отключено от ProcMonitor');
    });
}

// Функция для подключения к TCP-сокету с аутентификацией
function connectTCPSocket(host, port, password) {
    const client = new net.Socket();

    client.connect(port, host, () => {
        console.log(`Подключено к ProcMonitor через TCP: ${host}:${port}`);
        if (password) {
            client.write(`${password}\n`);
        }
    });

    client.on('data', (data) => {
        const message = data.toString();
        if (message.includes('Authentication successful')) {
            console.log('Аутентификация успешна. Получение событий...');
        } else if (message.includes('Authentication failed')) {
            console.error('Аутентификация не удалась. Отключение.');
            client.end();
        } else {
            // Обработка полученных событий
            try {
                const event = JSON.parse(message);
                switch (event.event) {
                    case 'fork':
                        console.log(`Процесс Форка: Родитель PID=${event.parent_pid}, Дочерний PID=${event.child_pid}, Пользователь=${event.user}, Команда="${event.cmdline}"`);
                        break;
                    case 'exec':
                        console.log(`Процесс Exec: PID=${event.pid}, Пользователь=${event.user}, Команда="${event.cmdline}"`);
                        break;
                    case 'exit':
                        console.log(`Процесс Завершен: PID=${event.pid}, Код выхода=${event.exit_code}, Пользователь=${event.user}`);
                        break;
                    default:
                        console.log('Неизвестное событие:', event);
                }
            } catch (err) {
                console.error('Не удалось разобрать JSON:', err, 'Сообщение:', message);
            }
        }
    });

    client.on('error', (err) => {
        console.error(`Ошибка подключения: ${err.message}`);
        process.exit(1);
    });

    client.on('close', () => {
        console.log('Отключено от ProcMonitor');
        process.exit(0);
    });
}

// Основная логика подключения
if (argv.tcp) {
    // TCP-сокетный режим
    if (!argv.auth) {
        console.error("Ошибка: В TCP-режиме необходима опция --auth <password>.");
        process.exit(1);
    }
    connectTCPSocket(argv.host, argv.port, argv.auth);
} else if (argv.socket) {
    // Unix Domain Socket режим
    connectUnixSocket(argv.socket);
} else {
    // Если ни один режим не выбран, по умолчанию использовать Unix Domain Socket
    connectUnixSocket(argv.socket);
}
