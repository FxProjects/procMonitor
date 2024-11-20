// procMonitor.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <pwd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <sys/stat.h> // Для chmod

/* Константы */
#define DEFAULT_MAX_CLIENTS 10
#define DEFAULT_SOCKET_PATH "/var/run/procMonitor.sock"
#define DEFAULT_BUFFER_SIZE 8192
#define MAX_CMDLINE_LENGTH 1024
#define MAX_PASSWORD_LENGTH 256
#define MAX_EVENTS 10

/* Перечисление типов событий процесса уже определено в /usr/include/linux/cn_proc.h */
/* Используем enum what из cn_proc.h */

/* Структура для хранения информации о событии */
typedef struct proc_event_data {
    enum what what;          // Используем enum what из cn_proc.h
    pid_t pid;
    pid_t parent_pid;       // Используется только для PROC_EVENT_FORK, можно убрать при необходимости
    int exit_code;          // Используется только для PROC_EVENT_EXIT
    char cmdline[MAX_CMDLINE_LENGTH];
    const char *username;
} proc_event_data_t;

/* Узел очереди */
typedef struct event_node {
    proc_event_data_t event;
    struct event_node *next;
} event_node_t;

/* Структура очереди */
typedef struct event_queue {
    event_node_t *head;
    event_node_t *tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} event_queue_t;

/* Структура для параметров программы */
typedef struct {
    int max_clients;
    char *socket_path;
    int tcp_mode;
    int tcp_port;
    char *auth_password;
    int direct_output;
    enum what monitored_events[MAX_EVENTS];
    int num_monitored_events;
} program_options;

/* Структура для передачи аргументов рабочим потокам */
typedef struct {
    event_queue_t *queue;
    program_options *opts;
} worker_args_t;

/* Глобальные переменные */
int server_sock = -1;
int *client_socks = NULL;
int num_clients = 0;
char *global_socket_path = NULL;
char *global_auth_password = NULL;
pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile sig_atomic_t stop = 0;

/* Функция для обработки сигналов */
void cleanup(int signo);

/* Функция для получения имени пользователя по UID или "unknown" при ошибке */
const char* get_username(uid_t uid) {
    struct passwd *pw = getpwuid(uid);
    if (pw) {
        return pw->pw_name;
    }
    return "unknown";
}

/* Функция для получения UID процесса по PID */
uid_t get_process_uid(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[256];
    uid_t uid = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            sscanf(line, "Uid:\t%u", &uid);
            break;
        }
    }
    fclose(f);
    return uid;
}

/* Функция для получения командной строки процесса по PID */
void get_process_cmdline(pid_t pid, char *cmdline, size_t size) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        strncpy(cmdline, "unknown", size);
        cmdline[size - 1] = '\0';
        return;
    }

    size_t len = fread(cmdline, 1, size - 1, f);
    fclose(f);
    if (len > 0) {
        for (size_t i = 0; i < len; i++) {
            if (cmdline[i] == '\0') {
                cmdline[i] = ' ';
            }
        }
        cmdline[len] = '\0';
    } else {
        strncpy(cmdline, "unknown", size);
        cmdline[size - 1] = '\0';
    }
}

/* Функция для экранирования строки в формате JSON */
int json_escape(const char* input, char* output, size_t out_size) {
    if (input == NULL || output == NULL) return -1;

    size_t in_len = strlen(input);
    size_t out_index = 0;

    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = input[i];
        const char* esc_seq = NULL;
        size_t esc_len = 0;

        switch (c) {
            case '\"': esc_seq = "\\\""; esc_len = 2; break;
            case '\\': esc_seq = "\\\\"; esc_len = 2; break;
            case '\b': esc_seq = "\\b";  esc_len = 2; break;
            case '\f': esc_seq = "\\f";  esc_len = 2; break;
            case '\n': esc_seq = "\\n";  esc_len = 2; break;
            case '\r': esc_seq = "\\r";  esc_len = 2; break;
            case '\t': esc_seq = "\\t";  esc_len = 2; break;
            default:
                if (c < 0x20 || c > 0x7E) {
                    esc_len = 6;
                    if (out_index + esc_len >= out_size) return -1;
                    snprintf(&output[out_index], esc_len + 1, "\\u%04x", c);
                    out_index += esc_len;
                    continue;
                } else {
                    esc_seq = NULL;
                    esc_len = 1;
                }
        }

        if (esc_seq) {
            if (out_index + esc_len >= out_size) return -1;
            memcpy(&output[out_index], esc_seq, esc_len);
            out_index += esc_len;
        } else {
            if (out_index + esc_len >= out_size) return -1;
            output[out_index++] = c;
        }
    }

    if (out_index >= out_size) return -1;
    output[out_index] = '\0';
    return (int)out_index;
}

/* Функция для отправки сообщений всем клиентам или вывода в консоль */
void send_message(const char *message, size_t len, program_options *opts) {
    if (opts->direct_output) {
        printf("%s", message);
        fflush(stdout);
    } else {
        pthread_mutex_lock(&send_mutex);
        for (int i = 0; i < opts->max_clients; i++) {
            if (client_socks[i] != -1) {
                if (send(client_socks[i], message, len, 0) == -1) {
                    perror("send");
                    close(client_socks[i]);
                    client_socks[i] = -1;
                }
            }
        }
        pthread_mutex_unlock(&send_mutex);
    }
}

/* Функция для отображения справочной информации */
void print_help(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("\n");
    printf("Options:\n");
    printf("  -c, --clients <number>    Максимальное количество одновременных клиентов (по умолчанию: %d)\n", DEFAULT_MAX_CLIENTS);
    printf("  -s, --socket <path>       Путь к Unix Domain Socket (по умолчанию: %s)\n", DEFAULT_SOCKET_PATH);
    printf("  -t, --tcp <port>          Включает TCP-сокетный режим и устанавливает порт для прослушивания\n");
    printf("  -a, --auth <password>     Устанавливает пароль для аутентификации клиентов в TCP-сокетном режиме\n");
    printf("  -e, --events <events>     Список событий для отслеживания, разделённых запятыми (например: exec,exit)\n");
    printf("  -d, --direct              Включает режим прямого вывода в консоль\n");
    printf("  -h, --help                Отображает эту справочную информацию\n");
    printf("\n");
    printf("Примеры:\n");
    printf("  %s --clients 20 --socket /tmp/procMonitor.sock --events exec,exit\n", prog_name);
    printf("  %s --tcp 8080 --auth mysecretpassword --events exec,exit\n", prog_name);
    printf("  %s --direct --events exec,exit,fork\n", prog_name);
    printf("\n");
}

/* Функция для преобразования строки события в enum */
int parse_event(const char *event_str, enum what *event_type) {
    if (strcasecmp(event_str, "fork") == 0) {
        *event_type = PROC_EVENT_FORK;
    } else if (strcasecmp(event_str, "exec") == 0) {
        *event_type = PROC_EVENT_EXEC;
    } else if (strcasecmp(event_str, "exit") == 0) {
        *event_type = PROC_EVENT_EXIT;
    } else if (strcasecmp(event_str, "uid") == 0) {
        *event_type = PROC_EVENT_UID;
    } else if (strcasecmp(event_str, "gid") == 0) {
        *event_type = PROC_EVENT_GID;
    } else if (strcasecmp(event_str, "sid") == 0) {
        *event_type = PROC_EVENT_SID;
    } else if (strcasecmp(event_str, "ptrace") == 0) {
        *event_type = PROC_EVENT_PTRACE;
    } else if (strcasecmp(event_str, "comm") == 0) {
        *event_type = PROC_EVENT_COMM;
    } else if (strcasecmp(event_str, "coredump") == 0) {
        *event_type = PROC_EVENT_COREDUMP;
    } else {
        return -1; // Неизвестное событие
    }
    return 0;
}

/* Функция для аутентификации клиента в TCP-сокетном режиме */
int authenticate_client(int client_sock, const char *password) {
    char buffer[MAX_PASSWORD_LENGTH];
    memset(buffer, 0, sizeof(buffer));

    const char *prompt = "Password: ";
    if (send(client_sock, prompt, strlen(prompt), 0) == -1) {
        perror("send");
        return 0;
    }

    ssize_t bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        perror("recv");
        return 0;
    }

    for (ssize_t i = 0; i < bytes_received; i++) {
        if (buffer[i] == '\n' || buffer[i] == '\r') {
            buffer[i] = '\0';
            break;
        }
    }

    if (strcmp(buffer, password) == 0) {
        const char *success = "Authentication successful.\n";
        send(client_sock, success, strlen(success), 0);
        return 1;
    } else {
        const char *failure = "Authentication failed. Disconnecting.\n";
        send(client_sock, failure, strlen(failure), 0);
        return 0;
    }
}

/* Инициализация очереди событий */
void init_event_queue(event_queue_t *queue) {
    queue->head = queue->tail = NULL;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond, NULL);
}

/* Добавление события в очередь */
void enqueue_event(event_queue_t *queue, proc_event_data_t *event) {
    event_node_t *node = malloc(sizeof(event_node_t));
    if (!node) {
        perror("malloc");
        return;
    }
    node->event = *event;
    node->next = NULL;

    pthread_mutex_lock(&queue->mutex);
    if (queue->tail) {
        queue->tail->next = node;
        queue->tail = node;
    } else {
        queue->head = queue->tail = node;
    }
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);
}

/* Извлечение события из очереди */
int dequeue_event(event_queue_t *queue, proc_event_data_t *event) {
    pthread_mutex_lock(&queue->mutex);
    while (queue->head == NULL && !stop) {
        pthread_cond_wait(&queue->cond, &queue->mutex);
    }

    if (stop && queue->head == NULL) {
        pthread_mutex_unlock(&queue->mutex);
        return 0;
    }

    event_node_t *node = queue->head;
    if (node) {
        *event = node->event;
        queue->head = node->next;
        if (queue->head == NULL) {
            queue->tail = NULL;
        }
        free(node);
        pthread_mutex_unlock(&queue->mutex);
        return 1;
    }

    pthread_mutex_unlock(&queue->mutex);
    return 0;
}

/* Очистка очереди событий */
void destroy_event_queue(event_queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);
    event_node_t *current = queue->head;
    while (current) {
        event_node_t *tmp = current;
        current = current->next;
        free(tmp);
    }
    queue->head = queue->tail = NULL;
    pthread_mutex_unlock(&queue->mutex);
    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->cond);
}

/* Поток приема событий */
void* event_receiver_thread(void *args) {
    // Распаковка аргументов
    event_queue_t *queue = ((event_queue_t **)args)[0];
    program_options *opts = ((program_options **)args)[1];
    int nl_sock = *((int *)(((event_queue_t **)args)[2]));

    while (!stop) {
        char buffer[DEFAULT_BUFFER_SIZE];
        int len = recv(nl_sock, buffer, sizeof(buffer), 0);
        if (len == -1) {
            if (errno == EINTR) continue;
            perror("recv from Netlink");
            continue;
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
        while (NLMSG_OK(nlh, len)) {
            struct cn_msg *cn_msg = NLMSG_DATA(nlh);
            struct proc_event *event = (struct proc_event *)cn_msg->data;

            proc_event_data_t proc_event;
            memset(&proc_event, 0, sizeof(proc_event));

            // Фильтрация событий на основе пользовательских настроек
            int should_monitor = 0;
            for (int i = 0; i < opts->num_monitored_events; i++) {
                if (event->what == opts->monitored_events[i]) {
                    should_monitor = 1;
                    break;
                }
            }

            if (should_monitor) {
                proc_event.what = event->what;

                if (proc_event.what == PROC_EVENT_EXEC) {
                    proc_event.pid = event->event_data.exec.process_pid;
                } else if (proc_event.what == PROC_EVENT_EXIT) {
                    proc_event.pid = event->event_data.exit.process_pid;
                    proc_event.exit_code = event->event_data.exit.exit_code;
                }

                // Получение имени пользователя и командной строки
                if (proc_event.pid > 0) {
                    proc_event.username = get_username(get_process_uid(proc_event.pid));
                    get_process_cmdline(proc_event.pid, proc_event.cmdline, sizeof(proc_event.cmdline));
                }

                enqueue_event(queue, &proc_event);
            }

            nlh = NLMSG_NEXT(nlh, len);
        }
    }

    return NULL;
}

/* Рабочий поток обработки событий */
void* worker_thread(void *args) {
    worker_args_t *w_args = (worker_args_t *)args;
    event_queue_t *queue = w_args->queue;
    program_options *opts = w_args->opts;

    char escaped_cmdline_buffer[6145]; // 1024 * 6 + 1

    while (!stop) {
        proc_event_data_t event;
        if (dequeue_event(queue, &event)) {
            if (stop) break;

            int esc_len = json_escape(event.cmdline, escaped_cmdline_buffer, sizeof(escaped_cmdline_buffer));
            if (esc_len == -1) {
                fprintf(stderr, "Ошибка экранирования cmdline. Используем 'unknown'.\n");
                strncpy(escaped_cmdline_buffer, "unknown", sizeof(escaped_cmdline_buffer) - 1);
                escaped_cmdline_buffer[sizeof(escaped_cmdline_buffer) - 1] = '\0';
            }

            char json[8192]; // Увеличен размер буфера для предотвращения обрезки
            switch (event.what) {
                case PROC_EVENT_EXEC:
                    snprintf(json, sizeof(json),
                             "{\"event\":\"exec\", \"pid\":%d, \"user\":\"%s\", \"cmdline\":\"%s\"}\n",
                             event.pid,
                             event.username,
                             escaped_cmdline_buffer);
                    break;
                case PROC_EVENT_EXIT:
                    snprintf(json, sizeof(json),
                             "{\"event\":\"exit\", \"pid\":%d, \"exit_code\":%d, \"user\":\"%s\"}\n",
                             event.pid,
                             event.exit_code,
                             event.username);
                    break;
                default:
                    // Должны обрабатывать только exec и exit
                    continue;
            }

            send_message(json, strlen(json), opts);
        }
    }

    return NULL;
}

/* Функция обработки сигналов */
void cleanup(int signo) {
    stop = 1;

    /* Закрываем серверный сокет и удаляем файл сокета, если необходимо */
    if (server_sock != -1) {
        close(server_sock);
        if (global_socket_path != NULL) {
            unlink(global_socket_path);
        }
    }

    /* Закрываем Netlink сокет */
    // Предполагается, что поток приема событий завершится после закрытия сокета

    /* Закрываем все клиентские сокеты */
    if (client_socks != NULL) {
        pthread_mutex_lock(&send_mutex);
        for (int i = 0; i < DEFAULT_MAX_CLIENTS; i++) {
            if (client_socks[i] != -1) {
                close(client_socks[i]);
                client_socks[i] = -1;
            }
        }
        pthread_mutex_unlock(&send_mutex);
        free(client_socks);
    }

    /* Освобождаем память */
    if (global_socket_path != NULL) {
        free(global_socket_path);
    }

    if (global_auth_password != NULL) {
        free(global_auth_password);
    }

    exit(0);
}

int main(int argc, char *argv[]) {
    /* Инициализация структуры с параметрами программы */
    program_options opts;
    opts.max_clients = DEFAULT_MAX_CLIENTS;
    opts.socket_path = strdup(DEFAULT_SOCKET_PATH);
    opts.tcp_mode = 0;
    opts.tcp_port = 0;
    opts.auth_password = NULL;
    opts.direct_output = 0;
    opts.num_monitored_events = 0;

    /* Сохранение пути к сокету и пароля в глобальные переменные для обработки сигналов */
    global_socket_path = strdup(opts.socket_path);
    global_auth_password = NULL;

    /* Определение опций командной строки с использованием getopt_long */
    int opt;
    int option_index = 0;

    /* Определение длинных опций */
    static struct option long_options[] = {
            {"clients", required_argument, 0, 'c'},
            {"socket",  required_argument, 0, 's'},
            {"tcp",     required_argument, 0, 't'},
            {"auth",    required_argument, 0, 'a'},
            {"events",  required_argument, 0, 'e'},
            {"direct",  no_argument,       0, 'd'},
            {"help",    no_argument,       0, 'h'},
            {0,         0,                 0,  0 }
    };

    /* Парсинг аргументов командной строки */
    while ((opt = getopt_long(argc, argv, "c:s:t:a:e:dh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'c':
                opts.max_clients = atoi(optarg);
                if (opts.max_clients <= 0) {
                    fprintf(stderr, "Invalid value for MAX_CLIENTS: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 's':
                opts.tcp_mode = 0;
                opts.direct_output = 0;
                free(opts.socket_path);
                opts.socket_path = strdup(optarg);
                free(global_socket_path);
                global_socket_path = strdup(opts.socket_path);
                break;
            case 't':
                opts.tcp_mode = 1;
                opts.direct_output = 0;
                opts.tcp_port = atoi(optarg);
                if (opts.tcp_port <= 0 || opts.tcp_port > 65535) {
                    fprintf(stderr, "Invalid TCP port: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'a':
                if (!opts.tcp_mode) {
                    fprintf(stderr, "--auth option can only be used with --tcp option.\n");
                    exit(EXIT_FAILURE);
                }
                opts.auth_password = strdup(optarg);
                if (strlen(opts.auth_password) > MAX_PASSWORD_LENGTH - 1) {
                    fprintf(stderr, "Password too long (max %d characters).\n", MAX_PASSWORD_LENGTH - 1);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'e':
            {
                // Разделение списка событий по запятой
                char *events_str = strdup(optarg);
                char *token = strtok(events_str, ",");
                while (token != NULL && opts.num_monitored_events < MAX_EVENTS) {
                    enum what evt;
                    if (parse_event(token, &evt) == 0) {
                        opts.monitored_events[opts.num_monitored_events++] = evt;
                    } else {
                        fprintf(stderr, "Unknown event type: %s\n", token);
                        free(events_str);
                        exit(EXIT_FAILURE);
                    }
                    token = strtok(NULL, ",");
                }
                free(events_str);
                break;
            }
            case 'd':
                opts.direct_output = 1;
                opts.tcp_mode = 0;
                break;
            case 'h':
                print_help(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            default:
                print_help(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    /* Проверка на наличие событий для отслеживания */
    if (opts.num_monitored_events == 0) {
        fprintf(stderr, "Error: At least one event must be specified using --events option.\n");
        print_help(argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Проверка на взаимную исключаемость режимов */
    int modes_selected = opts.direct_output + opts.tcp_mode + (strcmp(opts.socket_path, DEFAULT_SOCKET_PATH) != 0);
    if (modes_selected > 1) {
        fprintf(stderr, "Error: Modes --direct, --socket, and --tcp are mutually exclusive.\n");
        print_help(argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Проверка наличия пароля в TCP-сокетном режиме */
    if (opts.tcp_mode && opts.auth_password == NULL) {
        fprintf(stderr, "Error: --auth option is required when using --tcp mode.\n");
        exit(EXIT_FAILURE);
    }

    /* Сохранение пароля в глобальную переменную для доступа в обработчике сигналов */
    if (opts.auth_password != NULL) {
        global_auth_password = strdup(opts.auth_password);
    }

    /* Установка обработчиков сигналов для корректного завершения программы */
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    /* Выделение памяти для клиентских сокетов, если не в прямом режиме */
    if (!opts.direct_output) {
        client_socks = malloc(sizeof(int) * opts.max_clients);
        if (!client_socks) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        for (int i = 0; i < opts.max_clients; i++) {
            client_socks[i] = -1; // Инициализация дескрипторов клиентских сокетов
        }
    }

    /* Создание Netlink сокета для proc connector */
    int nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_sock == -1) {
        perror("socket");
        if (client_socks) free(client_socks);
        free(opts.socket_path);
        free(global_socket_path);
        if (opts.auth_password) free(opts.auth_password);
        free(global_auth_password);
        exit(EXIT_FAILURE);
    }

    /* Настройка адреса Netlink */
    struct sockaddr_nl addr_nl;
    memset(&addr_nl, 0, sizeof(addr_nl));
    addr_nl.nl_family = AF_NETLINK;
    addr_nl.nl_groups = CN_IDX_PROC;

    /* Привязка сокета к адресу */
    if (bind(nl_sock, (struct sockaddr *)&addr_nl, sizeof(addr_nl)) == -1) {
        perror("bind");
        close(nl_sock);
        if (client_socks) free(client_socks);
        free(opts.socket_path);
        free(global_socket_path);
        if (opts.auth_password) free(opts.auth_password);
        free(global_auth_password);
        exit(EXIT_FAILURE);
    }

    /* Подписка на события процессов через proc connector */
    struct {
        struct nlmsghdr nl_hdr;
        struct cn_msg cn_msg;
        enum proc_cn_mcast_op op;
    } msg_struct;

    memset(&msg_struct, 0, sizeof(msg_struct));
    msg_struct.nl_hdr.nlmsg_len = sizeof(msg_struct);
    msg_struct.nl_hdr.nlmsg_type = NLMSG_DONE;
    msg_struct.nl_hdr.nlmsg_flags = 0;
    msg_struct.cn_msg.id.idx = CN_IDX_PROC;
    msg_struct.cn_msg.id.val = CN_VAL_PROC;
    msg_struct.cn_msg.len = sizeof(enum proc_cn_mcast_op);
    msg_struct.op = PROC_CN_MCAST_LISTEN;

    /* Отправка запроса на подписку */
    if (send(nl_sock, &msg_struct, sizeof(msg_struct), 0) == -1) {
        perror("send");
        close(nl_sock);
        if (client_socks) free(client_socks);
        free(opts.socket_path);
        free(global_socket_path);
        if (opts.auth_password) free(opts.auth_password);
        free(global_auth_password);
        exit(EXIT_FAILURE);
    }

    /* Создание Unix Domain Socket или TCP-сокета в зависимости от режима */
    if (!opts.direct_output) {
        if (opts.tcp_mode) {
            /* TCP-сокетный режим */
            server_sock = socket(AF_INET, SOCK_STREAM, 0);
            if (server_sock == -1) {
                perror("socket");
                close(nl_sock);
                free(client_socks);
                free(opts.socket_path);
                free(global_socket_path);
                if (opts.auth_password) free(opts.auth_password);
                free(global_auth_password);
                exit(EXIT_FAILURE);
            }

            /* Настройка адреса TCP */
            struct sockaddr_in server_addr_tcp;
            memset(&server_addr_tcp, 0, sizeof(server_addr_tcp));
            server_addr_tcp.sin_family = AF_INET;
            server_addr_tcp.sin_addr.s_addr = INADDR_ANY;
            server_addr_tcp.sin_port = htons(opts.tcp_port);

            /* Привязка TCP-сокета к адресу */
            if (bind(server_sock, (struct sockaddr *)&server_addr_tcp, sizeof(server_addr_tcp)) == -1) {
                perror("bind");
                close(nl_sock);
                close(server_sock);
                free(client_socks);
                free(opts.socket_path);
                free(global_socket_path);
                if (opts.auth_password) free(opts.auth_password);
                free(global_auth_password);
                exit(EXIT_FAILURE);
            }

            /* Прослушивание входящих соединений */
            if (listen(server_sock, opts.max_clients) == -1) {
                perror("listen");
                close(nl_sock);
                close(server_sock);
                free(client_socks);
                free(opts.socket_path);
                free(global_socket_path);
                if (opts.auth_password) free(opts.auth_password);
                free(global_auth_password);
                exit(EXIT_FAILURE);
            }

            printf("ProcMonitor запущен в TCP-режиме и слушает порт %d с максимальным количеством клиентов: %d\n",
                   opts.tcp_port, opts.max_clients);
        } else {
            /* Unix Domain Socket режим */
            server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
            if (server_sock == -1) {
                perror("socket");
                close(nl_sock);
                free(client_socks);
                free(opts.socket_path);
                free(global_socket_path);
                if (opts.auth_password) free(opts.auth_password);
                free(global_auth_password);
                exit(EXIT_FAILURE);
            }

            /* Удаление существующего сокета, если он есть */
            unlink(opts.socket_path);

            struct sockaddr_un server_addr_unix;
            memset(&server_addr_unix, 0, sizeof(server_addr_unix));
            server_addr_unix.sun_family = AF_UNIX;
            strncpy(server_addr_unix.sun_path, opts.socket_path, sizeof(server_addr_unix.sun_path) - 1);

            /* Привязка серверного сокета к адресу */
            if (bind(server_sock, (struct sockaddr *)&server_addr_unix, sizeof(server_addr_unix)) == -1) {
                perror("bind");
                close(nl_sock);
                close(server_sock);
                free(client_socks);
                free(opts.socket_path);
                free(global_socket_path);
                if (opts.auth_password) free(opts.auth_password);
                free(global_auth_password);
                exit(EXIT_FAILURE);
            }

            /* Прослушивание входящих соединений */
            if (listen(server_sock, opts.max_clients) == -1) {
                perror("listen");
                close(nl_sock);
                close(server_sock);
                free(client_socks);
                free(opts.socket_path);
                free(global_socket_path);
                if (opts.auth_password) free(opts.auth_password);
                free(global_auth_password);
                exit(EXIT_FAILURE);
            }

            /* Установка прав на сокет */
            chmod(opts.socket_path, 0666);

            printf("ProcMonitor запущен и слушает %s с максимальным количеством клиентов: %d\n",
                   opts.socket_path, opts.max_clients);
        }
    } else {
        /* Прямой вывод в консоль */
        printf("ProcMonitor запущен в режиме прямого вывода в консоль.\n");
    }

    /* Инициализация очереди событий */
    event_queue_t event_queue;
    init_event_queue(&event_queue);

    /* Создание потоков */
    pthread_t event_receiver_tid;
    void *args_for_receiver[3] = { &event_queue, &opts, &nl_sock };
    if (pthread_create(&event_receiver_tid, NULL, event_receiver_thread, args_for_receiver) != 0) {
        perror("pthread_create event_receiver");
        close(nl_sock);
        if (server_sock != -1) close(server_sock);
        if (client_socks) free(client_socks);
        free(opts.socket_path);
        free(global_socket_path);
        if (opts.auth_password) free(opts.auth_password);
        free(global_auth_password);
        destroy_event_queue(&event_queue);
        exit(EXIT_FAILURE);
    }

    /* Создание рабочих потоков */
    int num_workers = 4; // Настроить в зависимости от нагрузки и числа ядер
    pthread_t workers[num_workers];
    worker_args_t worker_args = { &event_queue, &opts };
    for (int i = 0; i < num_workers; i++) {
        if (pthread_create(&workers[i], NULL, worker_thread, &worker_args) != 0) {
            perror("pthread_create worker");
            for (int j = 0; j < i; j++) {
                pthread_cancel(workers[j]);
            }
            pthread_cancel(event_receiver_tid);
            close(nl_sock);
            if (server_sock != -1) close(server_sock);
            if (client_socks) free(client_socks);
            free(opts.socket_path);
            free(global_socket_path);
            if (opts.auth_password) free(opts.auth_password);
            free(global_auth_password);
            destroy_event_queue(&event_queue);
            exit(EXIT_FAILURE);
        }
    }

    /* Главный цикл: обработка новых подключений и отключений клиентов */
    while (!stop) {
        fd_set read_fds;
        int max_fd = 0;

        FD_ZERO(&read_fds);
        if (!opts.direct_output) {
            FD_SET(server_sock, &read_fds);
            if (server_sock > max_fd) max_fd = server_sock;

            /* Добавление клиентских сокетов в набор для отслеживания */
            pthread_mutex_lock(&send_mutex);
            for (int i = 0; i < opts.max_clients; i++) {
                if (client_socks[i] != -1) {
                    FD_SET(client_socks[i], &read_fds);
                    if (client_socks[i] > max_fd) max_fd = client_socks[i];
                }
            }
            pthread_mutex_unlock(&send_mutex);
        }

        /* Установка таймаута на select */
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        /* Ожидание активности на серверном и клиентских сокетах */
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (activity == -1) {
            if (errno == EINTR)
                continue;
            perror("select");
            break;
        }

        if (!opts.direct_output) {
            /* Проверка наличия новых подключений на серверном сокете */
            if (FD_ISSET(server_sock, &read_fds)) {
                if (opts.tcp_mode) {
                    /* TCP-сокетный режим */
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
                    if (client_sock == -1) {
                        perror("accept");
                        continue;
                    }

                    /* Аутентификация клиента */
                    if (!authenticate_client(client_sock, opts.auth_password)) {
                        close(client_sock);
                        continue;
                    }

                    /* Добавление нового клиента в массив */
                    pthread_mutex_lock(&send_mutex);
                    int added = 0;
                    for (int i = 0; i < opts.max_clients; i++) {
                        if (client_socks[i] == -1) {
                            client_socks[i] = client_sock;
                            num_clients++;
                            printf("Новый TCP-клиент подключён: FD=%d, IP=%s, PORT=%d\n",
                                   client_sock,
                                   inet_ntoa(client_addr.sin_addr),
                                   ntohs(client_addr.sin_port));
                            added = 1;
                            break;
                        }
                    }
                    pthread_mutex_unlock(&send_mutex);

                    /* Если максимальное количество клиентов достигнуто, отклоняем новое подключение */
                    if (!added) {
                        printf("Максимальное количество клиентов достигнуто. Отклонение клиента: FD=%d\n", client_sock);
                        close(client_sock);
                    }
                } else {
                    /* Unix Domain Socket режим */
                    int client_sock = accept(server_sock, NULL, NULL);
                    if (client_sock == -1) {
                        perror("accept");
                        continue;
                    }

                    /* Добавление нового клиента в массив */
                    pthread_mutex_lock(&send_mutex);
                    int added = 0;
                    for (int i = 0; i < opts.max_clients; i++) {
                        if (client_socks[i] == -1) {
                            client_socks[i] = client_sock;
                            num_clients++;
                            printf("Новый Unix Domain Socket клиент подключён: FD=%d\n", client_sock);
                            added = 1;
                            break;
                        }
                    }
                    pthread_mutex_unlock(&send_mutex);

                    /* Если максимальное количество клиентов достигнуто, отклоняем новое подключение */
                    if (!added) {
                        printf("Максимальное количество клиентов достигнуто. Отклонение клиента: FD=%d\n", client_sock);
                        close(client_sock);
                    }
                }
            }

            /* Проверка наличия событий на клиентских сокетах (например, отключение клиента) */
            pthread_mutex_lock(&send_mutex);
            for (int i = 0; i < opts.max_clients; i++) {
                if (client_socks[i] != -1 && FD_ISSET(client_socks[i], &read_fds)) {
                    char dummy;
                    int res = recv(client_socks[i], &dummy, 1, MSG_PEEK);
                    if (res == 0) {
                        /* Клиент отключился */
                        if (opts.tcp_mode) {
                            printf("TCP-клиент отключился: FD=%d\n", client_socks[i]);
                        } else {
                            printf("Unix Domain Socket клиент отключился: FD=%d\n", client_socks[i]);
                        }
                        close(client_socks[i]);
                        client_socks[i] = -1;
                        num_clients--;
                    }
                }
            }
            pthread_mutex_unlock(&send_mutex);
        }
    }

    /* Завершение работы: закрытие сокетов и освобождение ресурсов */
    cleanup(0);

    return 0;
}
