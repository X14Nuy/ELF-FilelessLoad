#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define SERVER_IP "127.0.0.1" // 服务器 IP 地址
#define SERVER_PORT 12345     // 服务器端口
#define BUFFER_SIZE 1024      // 传输缓冲区大小

void send_file(const char *file_path) {
    int sock;
    struct sockaddr_in server_addr;
    int file_fd;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read, bytes_sent;

    // 创建套接字
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 配置服务器地址
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid server address");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // 连接到服务器
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to server failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server: %s:%d\n", SERVER_IP, SERVER_PORT);

    // 打开文件
    file_fd = open(file_path, O_RDONLY);
    if (file_fd < 0) {
        perror("File open failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // 读取文件内容并发送
    while ((bytes_read = read(file_fd, buffer, BUFFER_SIZE)) > 0) {
        bytes_sent = send(sock, buffer, bytes_read, 0);
        if (bytes_sent < 0) {
            perror("File send failed");
            close(file_fd);
            close(sock);
            exit(EXIT_FAILURE);
        }
    }

    if (bytes_read < 0) {
        perror("File read failed");
    }

    printf("File sent successfully.\n");

    // 关闭文件和套接字
    close(file_fd);
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file_path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    send_file(argv[1]);
    return 0;
}
