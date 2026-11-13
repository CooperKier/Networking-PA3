#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_SIZE 16384

static volatile sig_atomic_t running = 1;

static void stop(int sig)
{
    (void)sig;
    running = 0;
}

static int send_all(int fd, const char *data, size_t length)
{
    if (fd < 0) /* Prefetch requests only save the response to disk. */
        return 0;
    while (length > 0) {
        ssize_t n = send(fd, data, length, 0);
        if (n <= 0)
            return -1;
        data += n;
        length -= n;
    }
    return 0;
}

static void send_error(int client, int code, const char *message)
{
    char response[256];
    int n = snprintf(response, sizeof(response),
                     "HTTP/1.0 %d %s\r\nContent-Length: 0\r\n"
                     "Connection: close\r\n\r\n", code, message);
    send_all(client, response, n);
}

static int blocked(const char *host)
{
    FILE *file = fopen("blocklist", "r");
    char line[1024];
    if (!file)
        return 0;
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strcasecmp(line, host) == 0) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

static void handle_request(int client, int ttl, char *request, size_t used,
                           int prefetch);

static void prefetch_links(const char *filename, const char *url, int ttl, int client)
{
    if (fork() != 0)
        return;
    close(client);
    FILE *file = fopen(filename, "rb");
    if (!file)
        _exit(0);
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);
    char *page = size > 0 ? malloc((size_t)size + 1) : NULL;
    if (!page) {
        fclose(file);
        _exit(0);
    }
    size_t length = fread(page, 1, size, file);
    page[length] = '\0';
    fclose(file);
    char *body = strstr(page, "\r\n\r\n");
    char *type = strstr(page, "text/html");
    if (!body || !type || type > body) {
        free(page);
        _exit(0);
    }

    /* Read href and src attributes, accepting single or double quotes. */
    for (char *p = body + 4; *p; p++) {
        if (p > body + 4 && !isspace((unsigned char)p[-1]) && p[-1] != '<')
            continue;
        int name_length = strncasecmp(p, "href", 4) == 0 ? 4 :
                          strncasecmp(p, "src", 3) == 0 ? 3 : 0;
        if (!name_length)
            continue;
        char *value = p + name_length;
        while (isspace((unsigned char)*value))
            value++;
        if (*value++ != '=')
            continue;
        while (isspace((unsigned char)*value))
            value++;
        char quote = (*value == '\'' || *value == '"') ? *value++ : 0;
        char *end = value;
        while (*end && (quote ? *end != quote :
               !isspace((unsigned char)*end) && *end != '>'))
            end++;
        size_t link_length = end - value;
        char link[4096], target[4096], request[BUFFER_SIZE];
        if (!link_length || link_length >= sizeof(link))
            continue;
        memcpy(link, value, link_length);
        link[link_length] = '\0';
        link[strcspn(link, "#")] = '\0';
        if (!*link || strchr(link, '?'))
            continue;

        const char *host_end = strchr(url + 7, '/');
        size_t origin_length = host_end ? (size_t)(host_end - url) : strlen(url);
        int n;
        if (strncmp(link, "http://", 7) == 0)
            n = snprintf(target, sizeof(target), "%s", link);
        else if (strncmp(link, "//", 2) == 0)
            n = snprintf(target, sizeof(target), "http:%s", link);
        else if (strchr(link, ':'))
            continue; /* Skip HTTPS, mailto, and other non-HTTP links. */
        else if (*link == '/')
            n = snprintf(target, sizeof(target), "%.*s%s", (int)origin_length, url, link);
        else {
            const char *slash = host_end ? strrchr(host_end, '/') : NULL;
            size_t base_length = slash ? (size_t)(slash + 1 - url) : origin_length;
            n = snprintf(target, sizeof(target), "%.*s%s%s", (int)base_length,
                         url, slash ? "" : "/", link);
        }
        if (n < 0 || n >= (int)sizeof(target) || strcmp(target, url) == 0)
            continue;
        n = snprintf(request, sizeof(request), "GET %s HTTP/1.0\r\n\r\n", target);
        if (fork() == 0) {
            handle_request(-1, ttl, request, n, 0);
            _exit(0);
        }
    }
    free(page);
    _exit(0);
}

static void handle_request(int client, int ttl, char *request, size_t used,
                           int prefetch)
{
    char buffer[BUFFER_SIZE];
    char method[16], url[4096], version[16];
    char host[4096], path[4096], port[16] = "80";
    char cache_name[128], temporary[160];
    char *end, *line, *authority, *separator;
    long body_length = 0;
    ssize_t n;
    struct timeval timeout = {15, 0};
    end = strstr(request, "\r\n\r\n");
    if (!end || sscanf(request, "%15s %4095s %15s", method, url, version) != 3 ||
        strcmp(method, "GET") != 0 || strncmp(url, "http://", 7) != 0 ||
        (strcmp(version, "HTTP/1.0") != 0 && strcmp(version, "HTTP/1.1") != 0)) {
        send_error(client, 400, "Bad Request");
        return;
    }

    authority = url + 7;
    separator = strpbrk(authority, "/?");
    if (separator) {
        snprintf(path, sizeof(path), "%s%s", *separator == '?' ? "/" : "", separator);
        snprintf(host, sizeof(host), "%.*s", (int)(separator - authority), authority);
    } else {
        strcpy(path, "/");
        strcpy(host, authority);
    }
    separator = strchr(host, ':');
    if (separator) {
        *separator++ = '\0';
        char *port_end;
        long value = strtol(separator, &port_end, 10);
        if (!*separator || *port_end || value < 1 || value > 65535) {
            send_error(client, 400, "Bad Request");
            return;
        }
        snprintf(port, sizeof(port), "%ld", value);
    }
    if (!*host) {
        send_error(client, 400, "Bad Request");
        return;
    }
    if (blocked(host)) {
        send_error(client, 403, "Forbidden");
        return;
    }

    struct addrinfo hints = {0}, *addresses, *address;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &addresses) != 0) {
        send_error(client, 404, "Not Found");
        return;
    }
    for (address = addresses; address; address = address->ai_next) {
        char ip[INET_ADDRSTRLEN];
        struct sockaddr_in *addr = (struct sockaddr_in *)address->ai_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        if (blocked(ip)) {
            freeaddrinfo(addresses);
            send_error(client, 403, "Forbidden");
            return;
        }
    }

    /* Use a simple URL hash as the cache filename. */
    unsigned long long hash = 5381;
    for (size_t i = 0; url[i]; i++)
        hash = hash * 33 + (unsigned char)url[i];
    snprintf(cache_name, sizeof(cache_name), "cache/%016llx", hash);
    int cacheable = strchr(url, '?') == NULL && ttl > 0;
    struct stat info;
    FILE *cache = NULL;
    if (cacheable && stat(cache_name, &info) == 0 &&
        difftime(time(NULL), info.st_mtime) < ttl)
        cache = fopen(cache_name, "rb");
    if (cache) {
        freeaddrinfo(addresses);
        while ((n = fread(buffer, 1, sizeof(buffer), cache)) > 0)
            if (send_all(client, buffer, n) < 0)
                break;
        fclose(cache);
        if (prefetch)
            prefetch_links(cache_name, url, ttl, client);
        return;
    }

    int server = -1;
    for (address = addresses; address; address = address->ai_next) {
        server = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (server < 0)
            continue;
        setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(server, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        if (connect(server, address->ai_addr, address->ai_addrlen) == 0)
            break;
        close(server);
        server = -1;
    }
    freeaddrinfo(addresses);
    if (server < 0) {
        send_error(client, 502, "Bad Gateway");
        return;
    }

    int length = snprintf(buffer, sizeof(buffer), "GET %s HTTP/1.0\r\n", path);
    if (send_all(server, buffer, length) < 0)
        goto done;
    /* Preserve client headers, replacing connection headers to request EOF. */
    line = strstr(request, "\r\n") + 2;
    while (line < end) {
        char *next = strstr(line, "\r\n");
        if (strncasecmp(line, "Content-Length:", 15) == 0)
            body_length = strtol(line + 15, NULL, 10);
        if (strncasecmp(line, "Connection:", 11) != 0 &&
            strncasecmp(line, "Proxy-Connection:", 17) != 0 &&
            strncasecmp(line, "Host:", 5) != 0)
            if (send_all(server, line, next + 2 - line) < 0)
                goto done;
        line = next + 2;
    }
    length = snprintf(buffer, sizeof(buffer),
                      "Host: %s:%s\r\nConnection: close\r\n\r\n", host, port);
    if (send_all(server, buffer, length) < 0)
        goto done;
    size_t received_body = used - (size_t)(end + 4 - request);
    if (body_length > 0) {
        size_t amount = received_body < (size_t)body_length ? received_body : (size_t)body_length;
        if (send_all(server, end + 4, amount) < 0)
            goto done;
        body_length -= amount;
        while (body_length > 0) {
            size_t amount_left = body_length < BUFFER_SIZE ? (size_t)body_length : BUFFER_SIZE;
            n = recv(client, buffer, amount_left, 0);
            if (n <= 0 || send_all(server, buffer, n) < 0)
                goto done;
            body_length -= n;
        }
    }

    snprintf(temporary, sizeof(temporary), "%s.%ld.tmp", cache_name, (long)getpid());
    if (cacheable)
        cache = fopen(temporary, "wb");
    int cache_ok = 1;
    while ((n = recv(server, buffer, sizeof(buffer), 0)) > 0) {
        if (cache && fwrite(buffer, 1, n, cache) != (size_t)n)
            cache_ok = 0;
        if (send_all(client, buffer, n) < 0) {
            cache_ok = 0;
            break;
        }
    }
    if (cache) {
        if (fclose(cache) != 0)
            cache_ok = 0;
        if (n == 0 && cache_ok) {
            if (rename(temporary, cache_name) == 0 && prefetch) {
                close(server);
                prefetch_links(cache_name, url, ttl, client);
                return;
            }
        } else
            unlink(temporary);
    }
done:
    close(server);
}

static void handle_client(int client, int ttl)
{
    char request[BUFFER_SIZE];
    size_t used = 0;
    struct timeval timeout = {15, 0};
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    while (used < sizeof(request) - 1) {
        ssize_t n = recv(client, request + used, sizeof(request) - 1 - used, 0);
        if (n <= 0)
            return;
        used += n;
        request[used] = '\0';
        if (strstr(request, "\r\n\r\n"))
            break;
    }
    handle_request(client, ttl, request, used, 1);
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <port> [cache timeout]\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);
    int ttl = argc == 3 ? atoi(argv[2]) : 60;
    if (port < 1 || port > 65535 || ttl < 0)
        return 1;
    if (mkdir("cache", 0755) < 0 && errno != EEXIST) {
        perror("cache");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    struct sigaction action = {0};
    action.sa_handler = stop;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(listener, 32) < 0) {
        perror("listen");
        if (listener >= 0)
            close(listener);
        return 1;
    }
    while (running) {
        int client = accept(listener, NULL, NULL);
        if (client < 0)
            continue;
        pid_t pid = fork();
        if (pid == 0) {
            close(listener);
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            handle_client(client, ttl);
            close(client);
            _exit(0);
        }
        close(client);
    }
    close(listener);
    return 0;
}
