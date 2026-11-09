// fand.c — Pulse's privileged fan helper (runs as a root LaunchDaemon).
//
// Listens on /var/run/pulse-fand.sock for one-line commands:
//   status            -> JSON with each fan's actual/min/max/target RPM and mode
//   auto              -> give control back to macOS
//   set <rpm> [rpm..] -> hold fan 0,1,.. at these speeds (clamped to the fan's min..max)
//
// Access: only the user account that installed Pulse (--allow-uid) and root may send
// commands; the kernel reports the caller's uid for each connection (getpeereid).
//
// Safety: speeds are always clamped to the hardware's own min/max; if no command
// arrives for 30 s while fans are in manual mode (Pulse quit or crashed), or the
// daemon is stopped, the fans are returned to automatic control.
//
// Build: clang -O2 -o pulse-fand fand.c -framework IOKit -framework CoreFoundation
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include "smc.h"

#define SOCK_PATH "/var/run/pulse-fand.sock"
#define WATCHDOG_SECS 30

static int manual = 0;
static int has_ftst = -1;

static int fan_count(void) {
  int ok; int n = (int)smc_num("FNum", &ok);
  return ok ? (n > 8 ? 8 : n) : 0;
}

static int ftst_present(void) {
  if (has_ftst < 0) { unsigned char b[32]; has_ftst = smc_read("Ftst", b, NULL) > 0; }
  return has_ftst;
}

static void go_auto(void) {
  char k[8];
  for (int i = 0; i < fan_count(); i++) { snprintf(k, sizeof k, "F%dMd", i); smc_write_u8(k, 0); }
  if (ftst_present()) smc_write_u8("Ftst", 0);
  manual = 0;
}

static int set_speeds(double *rpm, int n) {
  int fans = fan_count(), ok_all = 1;
  char k[8];
  if (ftst_present() && !manual) { smc_write_u8("Ftst", 1); usleep(200000); }
  for (int i = 0; i < fans && i < n; i++) {
    int ok;
    snprintf(k, sizeof k, "F%dMn", i); double mn = smc_num(k, &ok); if (!ok) mn = 0;
    snprintf(k, sizeof k, "F%dMx", i); double mx = smc_num(k, &ok); if (!ok || mx <= 0) { ok_all = 0; continue; }
    double v = rpm[i] < mn ? mn : rpm[i] > mx ? mx : rpm[i];
    snprintf(k, sizeof k, "F%dMd", i); if (!smc_write_u8(k, 1)) ok_all = 0;
    snprintf(k, sizeof k, "F%dTg", i); if (!smc_write_rpm(k, v)) ok_all = 0;
  }
  manual = 1;
  return ok_all;
}

static void status(char *out, size_t cap) {
  int n = fan_count(), ok;
  size_t len = snprintf(out, cap, "{\"manual\":%d,\"fans\":[", manual);
  char k[8];
  for (int i = 0; i < n && len < cap; i++) {
    double v[4]; const char *s[] = {"Ac", "Mn", "Mx", "Tg"};
    for (int j = 0; j < 4; j++) { snprintf(k, sizeof k, "F%d%s", i, s[j]); v[j] = smc_num(k, &ok); }
    snprintf(k, sizeof k, "F%dMd", i);
    int md = (int)smc_num(k, &ok);
    len += snprintf(out + len, cap - len, "%s{\"ac\":%.0f,\"mn\":%.0f,\"mx\":%.0f,\"tg\":%.0f,\"md\":%d}",
                    i ? "," : "", v[0], v[1], v[2], v[3], md);
  }
  if (len < cap) snprintf(out + len, cap - len, "]}\n");
}

static void on_signal(int sig) { (void)sig; go_auto(); unlink(SOCK_PATH); _exit(0); }

int main(int argc, char **argv) {
  long allow_uid = -1;
  for (int i = 1; i < argc - 1; i++)
    if (!strcmp(argv[i], "--allow-uid")) allow_uid = strtol(argv[i + 1], NULL, 10);
  if (allow_uid < 0) { fprintf(stderr, "pulse-fand: --allow-uid is required\n"); return 2; }
  if (!smc_open()) { fprintf(stderr, "pulse-fand: cannot open SMC\n"); return 1; }
  signal(SIGTERM, on_signal); signal(SIGINT, on_signal); signal(SIGHUP, on_signal);
  signal(SIGPIPE, SIG_IGN);

  int srv = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un addr = {0};
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, SOCK_PATH, sizeof addr.sun_path - 1);
  unlink(SOCK_PATH);
  if (bind(srv, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(srv, 8) != 0) {
    perror("pulse-fand: bind"); return 1;
  }
  chmod(SOCK_PATH, 0666);   // the Pulse app runs as you, not root

  time_t last_cmd = time(NULL);
  for (;;) {
    fd_set rf; FD_ZERO(&rf); FD_SET(srv, &rf);
    struct timeval tv = {5, 0};
    int r = select(srv + 1, &rf, NULL, NULL, &tv);
    if (manual && time(NULL) - last_cmd > WATCHDOG_SECS) go_auto();
    if (r <= 0) continue;
    int c = accept(srv, NULL, NULL);
    if (c < 0) continue;
    uid_t peer_uid; gid_t peer_gid;
    if (getpeereid(c, &peer_uid, &peer_gid) != 0 || (peer_uid != (uid_t)allow_uid && peer_uid != 0)) {
      write(c, "denied\n", 7);
      close(c);
      continue;
    }
    struct timeval to = {2, 0};
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof to);
    char buf[256] = {0};
    ssize_t n = read(c, buf, sizeof buf - 1);
    char resp[1024] = "error\n";
    if (n > 0) {
      buf[n] = 0;
      last_cmd = time(NULL);
      if (!strncmp(buf, "status", 6)) status(resp, sizeof resp);
      else if (!strncmp(buf, "auto", 4)) { go_auto(); status(resp, sizeof resp); }
      else if (!strncmp(buf, "set ", 4)) {
        double rpm[8]; int cnt = 0; char *p = buf + 4, *end;
        while (cnt < 8) { double v = strtod(p, &end); if (end == p) break; rpm[cnt++] = v; p = end; }
        if (cnt > 0) { set_speeds(rpm, cnt); status(resp, sizeof resp); }
      }
    }
    write(c, resp, strlen(resp));
    close(c);
  }
}
