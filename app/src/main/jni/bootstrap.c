#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define BLKROSET   0x125d
#define KSUD_STAGE "/data/user_de/0/df.root/ksud"
#define KSUD       "/data/adb/ksud"
#define PREFS_PATH "/data/user_de/0/df.root/shared_prefs/dfroot.xml"
#define MODULES_DIR "/data/adb/modules"
#define DIAG_PATH  "/data/user_de/0/df.root/diag.txt"

static int pref_true(const char *buf, const char *key)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "name=\"%s\"", key);
    char *p = strstr(buf, needle);
    if (!p) return 0;
    char *tag_end = strchr(p, '>');
    char *v = strstr(p, "value=\"true\"");
    return v && tag_end && v < tag_end;
}

static int read_prefs(char *su_manager, size_t su_manager_size, int *soft_reboot,
                      int *disable_modules, int *adb_root)
{
    int fd = open(PREFS_PATH, O_RDONLY);
    if (fd < 0) return -1;

    char buf[4096];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    char *p = strstr(buf, "name=\"su_manager\">");
    if (!p) return -1;
    p += strlen("name=\"su_manager\">");
    char *end = strchr(p, '<');
    if (!end) return -1;
    size_t len = end - p;
    if (len == 0 || len >= su_manager_size) return -1;
    memcpy(su_manager, p, len);
    su_manager[len] = '\0';

    *soft_reboot = pref_true(buf, "soft_reboot");
    *disable_modules = pref_true(buf, "disable_modules");
    *adb_root = pref_true(buf, "adb_root");

    return 0;
}

static int adopt_zygote_env(void)
{
    FILE *f = popen("pidof zygote64 zygote", "r");
    if (!f) return -1;
    int pid = 0;
    fscanf(f, "%d", &pid);
    pclose(f);
    if (!pid) return -1;

    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    static char buf[16384];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    for (char *p = buf, *end = buf + n; p < end; p += strlen(p) + 1)
        putenv(p);
    return 0;
}

static int should_ro(const char *name)
{
    size_t len = strlen(name);
    if (!strcmp(name, "super"))  return 1;
    if (!strcmp(name, "misc"))   return 1;
    if (!strcmp(name, "steady")) return 1;
    if (len >= 2 && name[len - 2] == '_' &&
        (name[len - 1] == 'a' || name[len - 1] == 'b'))
        return 1;
    return 0;
}

static int set_partitions_ro(void)
{
    DIR *dir = opendir("/dev/block/by-name");
    if (!dir)
        return -1;

    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (!should_ro(ent->d_name))
            continue;

        char path[128];
        snprintf(path, sizeof(path), "/dev/block/by-name/%s", ent->d_name);

        int fd = open(path, O_RDONLY);
        if (fd < 0)
            continue;

        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)) {
            int on = 1;
            ioctl(fd, BLKROSET, &on);
        }
        close(fd);
    }

    closedir(dir);
    return 0;
}

static int late_load_running(void)
{
    DIR *d = opendir("/proc");
    if (!d)
        return 0;
    struct dirent *e;
    char path[64], buf[256];
    int found = 0;
    while ((e = readdir(d)) != NULL) {
        char *end;
        strtol(e->d_name, &end, 10);
        if (*end) continue;
        snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = '\0';
        for (int i = 0; i < n; i++)
            if (!buf[i]) buf[i] = ' ';
        if (strstr(buf, "ksud") && strstr(buf, "late-load")) {
            found = 1;
            break;
        }
    }
    closedir(d);
    return found;
}

static int run_ctx(const char *ctx, char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (ctx) {
            int fd = open("/proc/self/attr/exec", O_WRONLY);
            if (fd >= 0) { write(fd, ctx, strlen(ctx)); close(fd); }
        }
        execv(argv[0], argv);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Make adbd run as uid 0 so that "adb shell" is root. adbd restarts itself
 * when service.adb.root flips; ctl.restart covers the case where it does not.
 * The current adb session drops, which is expected. */
static void restart_adbd_as_root(void)
{
    run_ctx(NULL, (char *[]){ "/system/bin/setprop", "service.adb.root", "1", NULL });
    run_ctx(NULL, (char *[]){ "/system/bin/setprop", "ctl.restart", "adbd", NULL });
}

/* We run as root here, but the app (and adb shell) cannot read /data/adb or
 * dmesg, so dump everything we can see into a file the app owns. */
static void dump_diagnostics(const char *su_manager)
{
    char cmd[1400];
    snprintf(cmd, sizeof(cmd),
             "{ echo '=== bootstrap build ==='; echo build " __DATE__ " " __TIME__ "; "
             "echo '=== /data/adb ==='; ls -la /data/adb; "
             "echo '=== ksud --help ==='; %s --help; echo rc=$?; "
             "echo '=== ksud late-load --help ==='; %s late-load --help; echo rc=$?; "
             "echo '=== ksud late-load (verbose retry) ==='; "
             "%s late-load --package-name %s; echo rc=$?; "
             "echo '=== /data/adb/ksu ==='; ls -la /data/adb/ksu; "
             "echo '=== any .ko in /data/adb ==='; find /data/adb -name '*.ko' 2>/dev/null; "
             "echo '=== late-load --kmi android14-11 ==='; "
             "%s late-load --package-name %s --kmi android14-11; echo rc=$?; "
             "echo '=== late-load --allow-shell ==='; "
             "%s late-load --package-name %s --allow-shell; echo rc=$?; "
             "echo '=== still no module? ==='; cat /proc/modules | grep -i ksu; echo rc=$?; "
             "echo '=== ksud insmod our own dfroot.ko ==='; "
             "%s insmod /data/user_de/0/df.root/ko; echo rc=$?; "
             "echo '=== ksud insmod kernelsu.ko ==='; "
             "%s insmod /data/user_de/0/df.root/kernelsu.ko; echo rc=$?; "
             "echo '=== modules with ksu now? ==='; cat /proc/modules | grep -i ksu; echo rc=$?; "
             "echo '=== /proc/modules ==='; cat /proc/modules; "
             "echo '=== processes ==='; ps -A | grep -iE 'ksu|dfroot'; "
             "echo '=== dmesg ==='; dmesg | grep -iE 'ksu|kernelsu|module|avc' | tail -40; "
             "} > %s 2>&1",
             KSUD_STAGE, KSUD_STAGE, KSUD_STAGE, su_manager,
             KSUD_STAGE, su_manager, KSUD_STAGE, su_manager,
             KSUD_STAGE, KSUD_STAGE, DIAG_PATH);
    run_ctx(NULL, (char *[]){ "/system/bin/sh", "-c", cmd, NULL });
}

static void touch(const char *path)
{
    int fd = open(path, O_CREAT | O_WRONLY, 0666);
    if (fd >= 0)
        close(fd);
}

/* Mark every installed module disabled before ksud runs. A broken module
 * otherwise loads on the next boot and bootloops the device. */
static int disable_modules(void)
{
    DIR *dir = opendir(MODULES_DIR);
    if (!dir)
        return -1;

    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (ent->d_name[0] == '.')
            continue;
        char path[256];
        snprintf(path, sizeof(path), MODULES_DIR "/%s/disable", ent->d_name);
        touch(path);
    }
    closedir(dir);
    return 0;
}

int main(void)
{
    touch("/dev/dfm1");
    char su_manager[256];
    int soft_reboot, disable_mods, adb_root;
    if (read_prefs(su_manager, sizeof(su_manager), &soft_reboot, &disable_mods, &adb_root) != 0) {
        touch("/dev/dfme0");
        return 1;
    }

    touch("/dev/dfm2");
    if (adopt_zygote_env())
        touch("/dev/dfmw0");

    touch("/dev/dfm3");
    if (set_partitions_ro())
        touch("/dev/dfmw1");

    if (disable_mods) {
        touch("/dev/dfm4");
        if (disable_modules()) {
            touch("/dev/dfme1");
            return 1;
        }
    }

    touch("/dev/dfm5");    
    if (run_ctx(NULL, (char *[]){ KSUD_STAGE, "late-load", "--package-name", su_manager, NULL }) == 0) {
        dump_diagnostics(su_manager);
        touch("/dev/dfm6");
        if (adb_root) {
            restart_adbd_as_root();
            touch("/dev/dfm7");
        }
        if (soft_reboot) {
            while (late_load_running()) sleep(1);
            run_ctx("u:r:ksu:s0", (char *[]){ KSUD, "soft-reboot", NULL });
        }
    } else {
        dump_diagnostics(su_manager);
        touch("/dev/dfme2");
    }
        
    return 0;
}
