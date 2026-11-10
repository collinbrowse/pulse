// probe.c — Pulse's native sensor reader. Runs as one long-lived process:
// each line read on stdin is a request, answered with one JSON line on stdout.
//   "s\n"  -> system sample: per-core CPU ticks, memory, temperatures, network,
//             disk I/O and GPU utilisation
//   "p\n"  -> process list (pid, ppid, uid, status, cpu ns, rss, start, path)
// No sudo needed. Build:
//   clang -O2 -o probe probe.c -framework IOKit -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <ifaddrs.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include "smc.h"

typedef struct __IOHIDEventSystemClient *IOHIDEventSystemClientRef;
typedef struct __IOHIDServiceClient *IOHIDServiceClientRef;
typedef struct __IOHIDEvent *IOHIDEventRef;
#define kIOHIDEventTypeTemperature 15
#define IOHIDEventFieldBase(t) ((t) << 16)
IOHIDEventSystemClientRef IOHIDEventSystemClientCreate(CFAllocatorRef);
int IOHIDEventSystemClientSetMatching(IOHIDEventSystemClientRef, CFDictionaryRef);
CFArrayRef IOHIDEventSystemClientCopyServices(IOHIDEventSystemClientRef);
IOHIDEventRef IOHIDServiceClientCopyEvent(IOHIDServiceClientRef, int64_t, int32_t, int64_t);
CFTypeRef IOHIDServiceClientCopyProperty(IOHIDServiceClientRef, CFStringRef);
double IOHIDEventGetFloatValue(IOHIDEventRef, int32_t);

static void jstr(const char *s) {
  putchar('"');
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') { putchar('\\'); putchar(c); }
    else if (c >= 0x20) putchar(c);
  }
  putchar('"');
}

// ---------------------------------------------------------------- temperatures
static IOHIDEventSystemClientRef hid;
static CFArrayRef hid_services;
static char **hid_names;

static void temps_init(void) {
  hid = IOHIDEventSystemClientCreate(kCFAllocatorDefault);
  if (!hid) return;
  int page = 0xff00, usage = 5;
  CFNumberRef np = CFNumberCreate(NULL, kCFNumberIntType, &page);
  CFNumberRef nu = CFNumberCreate(NULL, kCFNumberIntType, &usage);
  const void *keys[] = {CFSTR("PrimaryUsagePage"), CFSTR("PrimaryUsage")};
  const void *vals[] = {np, nu};
  CFDictionaryRef match = CFDictionaryCreate(NULL, keys, vals, 2, &kCFTypeDictionaryKeyCallBacks,
                                             &kCFTypeDictionaryValueCallBacks);
  IOHIDEventSystemClientSetMatching(hid, match);
  hid_services = IOHIDEventSystemClientCopyServices(hid);
  CFRelease(match); CFRelease(np); CFRelease(nu);
  if (!hid_services) return;
  CFIndex n = CFArrayGetCount(hid_services);
  hid_names = calloc(n, sizeof(char *));
  for (CFIndex i = 0; i < n; i++) {
    CFStringRef name = IOHIDServiceClientCopyProperty(
        (IOHIDServiceClientRef)CFArrayGetValueAtIndex(hid_services, i), CFSTR("Product"));
    char buf[128] = {0};
    if (name) { CFStringGetCString(name, buf, sizeof buf, kCFStringEncodingUTF8); CFRelease(name); }
    hid_names[i] = strdup(buf);
  }
}

static void temps(void) {
  printf("\"temps\":{");
  int first = 1;
  if (hid_services) {
    for (CFIndex i = 0; i < CFArrayGetCount(hid_services); i++) {
      if (!hid_names[i][0]) continue;
      IOHIDEventRef ev = IOHIDServiceClientCopyEvent(
          (IOHIDServiceClientRef)CFArrayGetValueAtIndex(hid_services, i), kIOHIDEventTypeTemperature, 0, 0);
      if (!ev) continue;
      double t = IOHIDEventGetFloatValue(ev, IOHIDEventFieldBase(kIOHIDEventTypeTemperature));
      CFRelease(ev);
      if (t <= -20 || t >= 150) continue;
      if (!first) putchar(',');
      first = 0;
      jstr(hid_names[i]);
      printf(":%.2f", t);
    }
  }
  printf("}");
}

// ---------------------------------------------------------------- cpu / memory
static void cpu(void) {
  natural_t ncpu; processor_info_array_t info; mach_msg_type_number_t n;
  printf("\"cpu\":[");
  if (host_processor_info(mach_host_self(), PROCESSOR_CPU_LOAD_INFO, &ncpu, &info, &n) == KERN_SUCCESS) {
    for (natural_t i = 0; i < ncpu; i++) {
      unsigned *t = (unsigned *)&info[i * CPU_STATE_MAX];
      printf("%s[%u,%u,%u,%u]", i ? "," : "", t[CPU_STATE_USER], t[CPU_STATE_SYSTEM], t[CPU_STATE_IDLE], t[CPU_STATE_NICE]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)info, n * sizeof(integer_t));
  }
  printf("]");
}

static void mem(void) {
  vm_statistics64_data_t vm; mach_msg_type_number_t cnt = HOST_VM_INFO64_COUNT;
  vm_size_t page; host_page_size(mach_host_self(), &page);
  uint64_t total = 0; size_t len = sizeof total;
  sysctlbyname("hw.memsize", &total, &len, NULL, 0);
  struct xsw_usage sw = {0}; len = sizeof sw;
  sysctlbyname("vm.swapusage", &sw, &len, NULL, 0);
  int pressure = 0; len = sizeof pressure;
  sysctlbyname("kern.memorystatus_vm_pressure_level", &pressure, &len, NULL, 0);
  host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&vm, &cnt);
  printf("\"mem\":{\"total\":%llu,\"page\":%lu,\"free\":%u,\"active\":%u,\"inactive\":%u,\"wired\":%u,"
         "\"compressed\":%u,\"purgeable\":%u,\"speculative\":%u,\"external\":%u,\"internal\":%u,"
         "\"swapins\":%llu,\"swapouts\":%llu,\"swap_used\":%llu,\"swap_total\":%llu,\"pressure\":%d}",
         total, (unsigned long)page, vm.free_count, vm.active_count, vm.inactive_count, vm.wire_count,
         vm.compressor_page_count, vm.purgeable_count, vm.speculative_count, vm.external_page_count,
         vm.internal_page_count, vm.swapins, vm.swapouts, sw.xsu_used, sw.xsu_total, pressure);
}

// ---------------------------------------------------------------- network
static void net(void) {
  // NET_RT_IFLIST2 gives 64-bit counters (getifaddrs' if_data wraps at 4 GB).
  int mib[6] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0};
  size_t len = 0;
  unsigned long long rx = 0, tx = 0;
  if (sysctl(mib, 6, NULL, &len, NULL, 0) == 0) {
    char *buf = malloc(len);
    if (sysctl(mib, 6, buf, &len, NULL, 0) == 0) {
      for (char *p = buf; p < buf + len;) {
        struct if_msghdr *ifm = (struct if_msghdr *)p;
        if (ifm->ifm_msglen == 0) break;
        if (ifm->ifm_type == RTM_IFINFO2) {
          struct if_msghdr2 *m2 = (struct if_msghdr2 *)ifm;
          if (!(m2->ifm_flags & IFF_LOOPBACK)) {
            rx += m2->ifm_data.ifi_ibytes;
            tx += m2->ifm_data.ifi_obytes;
          }
        }
        p += ifm->ifm_msglen;
      }
    }
    free(buf);
  }
  printf("\"net\":[%llu,%llu]", rx, tx);
}

// ---------------------------------------------------------------- disk / gpu (IOKit registry)
static long long dict_num(CFDictionaryRef d, CFStringRef key) {
  CFNumberRef n = d ? CFDictionaryGetValue(d, key) : NULL;
  long long v = 0;
  if (n && CFGetTypeID(n) == CFNumberGetTypeID()) CFNumberGetValue(n, kCFNumberLongLongType, &v);
  return v;
}

static void disk(void) {
  long long r = 0, w = 0;
  io_iterator_t it;
  if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOBlockStorageDriver"), &it) == KERN_SUCCESS) {
    io_object_t o;
    while ((o = IOIteratorNext(it))) {
      CFDictionaryRef st = IORegistryEntryCreateCFProperty(o, CFSTR("Statistics"), NULL, 0);
      if (st) {
        r += dict_num(st, CFSTR("Bytes (Read)"));
        w += dict_num(st, CFSTR("Bytes (Write)"));
        CFRelease(st);
      }
      IOObjectRelease(o);
    }
    IOObjectRelease(it);
  }
  printf("\"disk\":[%lld,%lld]", r, w);
}

static void gpu(void) {
  long long best = -1;
  io_iterator_t it;
  if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOAccelerator"), &it) == KERN_SUCCESS) {
    io_object_t o;
    while ((o = IOIteratorNext(it))) {
      CFDictionaryRef ps = IORegistryEntryCreateCFProperty(o, CFSTR("PerformanceStatistics"), NULL, 0);
      if (ps) {
        if (CFDictionaryContainsKey(ps, CFSTR("Device Utilization %"))) {
          long long v = dict_num(ps, CFSTR("Device Utilization %"));
          if (v > best) best = v;
        }
        CFRelease(ps);
      }
      IOObjectRelease(o);
    }
    IOObjectRelease(it);
  }
  if (best >= 0) printf("\"gpu\":%lld", best); else printf("\"gpu\":null");
}

// ---------------------------------------------------------------- processes
static mach_timebase_info_data_t tb;

static void procs(void) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
  size_t len = 0;
  sysctl(mib, 3, NULL, &len, NULL, 0);
  len += 64 * sizeof(struct kinfo_proc);
  struct kinfo_proc *kp = malloc(len);
  if (sysctl(mib, 3, kp, &len, NULL, 0) != 0) len = 0;
  int n = len / sizeof(struct kinfo_proc);
  printf("{\"procs\":[");
  int first = 1;
  for (int i = 0; i < n; i++) {
    struct kinfo_proc *k = &kp[i];
    pid_t pid = k->kp_proc.p_pid;
    if (pid <= 0) continue;
    struct proc_taskinfo ti;
    unsigned long long cpu_ns = 0, rss = 0;
    int have_task = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti, sizeof ti) == sizeof ti;
    if (have_task) {
      cpu_ns = (ti.pti_total_user + ti.pti_total_system) * tb.numer / tb.denom;
      rss = ti.pti_resident_size;
    }
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (proc_pidpath(pid, path, sizeof path) <= 0) strncpy(path, k->kp_proc.p_comm, MAXCOMLEN);
    if (!first) putchar(',');
    first = 0;
    printf("[%d,%d,%u,%d,%llu,%llu,%ld,%d,", pid, k->kp_eproc.e_ppid, k->kp_eproc.e_ucred.cr_uid,
           (int)k->kp_proc.p_stat, cpu_ns, rss, (long)k->kp_proc.p_starttime.tv_sec, have_task);
    jstr(path);
    putchar(']');
  }
  printf("]}\n");
  free(kp);
}

static void fans(void) {
  printf("\"fans\":[");
  int ok, n = smc_open() ? (int)smc_num("FNum", &ok) : 0;
  if (n > 8) n = 8;
  char k[8];
  for (int i = 0; i < n; i++) {
    double v[5]; const char *s[] = {"Ac", "Mn", "Mx", "Tg", "Md"};
    for (int j = 0; j < 5; j++) { snprintf(k, sizeof k, "F%d%s", i, s[j]); v[j] = smc_num(k, &ok); }
    printf("%s[%.0f,%.0f,%.0f,%.0f,%.0f]", i ? "," : "", v[0], v[1], v[2], v[3], v[4]);
  }
  printf("]");
}

// What System Settings calls "Available": free space plus space macOS can purge on demand.
static void capacity(void) {
  long long total = -1, free_now = -1, important = -1;
  CFURLRef u = CFURLCreateWithFileSystemPath(NULL, CFSTR("/"), kCFURLPOSIXPathStyle, true);
  const CFStringRef keys[3] = {kCFURLVolumeTotalCapacityKey, kCFURLVolumeAvailableCapacityKey,
                               kCFURLVolumeAvailableCapacityForImportantUsageKey};
  long long *out[3] = {&total, &free_now, &important};
  for (int i = 0; i < 3; i++) {
    CFTypeRef v = NULL;
    if (CFURLCopyResourcePropertyForKey(u, keys[i], &v, NULL) && v) {
      if (CFGetTypeID(v) == CFNumberGetTypeID()) CFNumberGetValue((CFNumberRef)v, kCFNumberLongLongType, out[i]);
      CFRelease(v);
    }
  }
  CFRelease(u);
  printf("{\"total\":%lld,\"free\":%lld,\"available\":%lld}\n", total, free_now, important);
}

static void sample(void) {
  putchar('{');
  cpu(); putchar(','); mem(); putchar(','); temps(); putchar(',');
  net(); putchar(','); disk(); putchar(','); gpu(); putchar(','); fans();
  printf("}\n");
}

int main(int argc, char **argv) {
  mach_timebase_info(&tb);
  temps_init();
  if (argc > 1 && strcmp(argv[1], "--once") == 0) { sample(); return 0; }
  char line[64];
  while (fgets(line, sizeof line, stdin)) {
    if (line[0] == 'p') procs(); else if (line[0] == 'c') capacity(); else sample();
    fflush(stdout);
  }
  return 0;
}
