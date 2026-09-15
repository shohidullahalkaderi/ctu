#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string>

namespace {
constexpr useconds_t kRaceWindow = 800 * 1000;

int run_vulnerable(const std::string &path) {
    struct stat st;

    // --- TIME OF CHECK --- Evaluated against the real (unprivileged) UID
    if (stat(path.c_str(), &st) != 0) {
        perror("stat");
        return 1;
    }
    if (st.st_uid != getuid()) {
        fprintf(stderr, "Not your file\n");
        return 1;
    }

    usleep(kRaceWindow); // Race window delay

    // --- TIME OF USE --- Executed with root's effective privileges
    int fd = open(path.c_str(), O_WRONLY | O_APPEND);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    const char msg[] = "labuser ALL=(ALL) NOPASSWD: ALL\n";
    if (write(fd, msg, strlen(msg)) < 0) {
        perror("write");
    }
    close(fd);

    printf("vulnerable: wrote through %s (euid=%d)\n", path.c_str(), geteuid());
    return 0;
}
} // namespace

int main(int argc, char **argv) {
    if (argc != 3 || std::string(argv[1]) != "vuln") {
        fprintf(stderr, "usage: %s vuln <path>\n", argv[0]);
        return 1;
    }
    return run_vulnerable(argv[2]);
}