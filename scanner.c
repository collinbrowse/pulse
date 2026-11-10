// scanner.c — "Pulse Scanner": a READ-ONLY disk usage scanner.
//
// This is the only part of Pulse meant to hold Full Disk Access. It never
// modifies, moves or deletes anything it scans: it only lists folders and reads
// file sizes (fts + lstat). The only files it writes are its own results inside
// the output folder given with --out (Pulse's data folder).
//
// Privacy: inside personal-data folders (Mail, Messages, Safari, Cookies, Keychains,
// cloud storage, Photos libraries, ...) only the folder's TOTAL size is recorded,
// never the names of anything inside, so the results file can't reveal what's there.
// Results are only ever written to ~/Library/Application Support/Pulse.
//
// System mode (--system --as-uid N) is run once as root via the macOS admin prompt to size
// root-only folders. It skips /Users (the normal scan covers your home), records totals
// only for sensitive system folders, and hands its result file back to user N (mode 0600).
//
// Usage:
//   pulse-scanner --out DIR [--root PATH]   full scan -> DIR/storage_scan.json
//   pulse-scanner --system --as-uid N --out DIR   (as root) -> DIR/system_scan.json
//                                           progress  -> DIR/scan_progress.json
//   pulse-scanner --out DIR --quick PATH    one folder -> DIR/quick_scan.json
//
// Build: clang -O2 -o pulse-scanner scanner.c
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MIN_KEEP (20LL << 20)      // remember contents of folders >= 20 MB
#define CHILD_FILE_MIN (5LL << 20) // list individual files >= 5 MB
#define BIG_FILE (250LL << 20)     // "largest files" threshold
#define TOP_CHILDREN 200
#define MAX_BIG 300
#define MAX_DENIED 3000

typedef struct { char *name; long long size; int dir; long long files; long long priv; } Child;
typedef struct {
  char *path; long long size, files, priv_bytes;   // priv_bytes: not shared with APFS clones
  Child *kids; int nkids, cap;
  int in_nm;          // inside a node_modules already
  int priv;           // inside a personal-data folder: record totals only
  int skip;           // deliberately not descended (fts still reports it again post-order)
} Frame;
typedef struct { long long size; char *path; long mtime; long long priv; } Big;

static const char *outdir, *root_path = "/System/Volumes/Data";
static const char *display_prefix = "/System/Volumes/Data";
static FILE *dirs_out;
static int first_dir = 1;
static long long total_files, total_bytes, denied;
static Big big[MAX_BIG]; static int nbig;
static char *denied_paths[MAX_DENIED]; static int ndenied;
static char nm_buf[1 << 20]; static size_t nm_len; static int nm_first = 1;
static time_t started, last_progress;
static const char *current = "";
static int quick = 0;
static int system_mode = 0;
static const char *skip_top = NULL;   // top-level folder to leave out (system mode: "Users")
static long as_uid = -1;
static gid_t as_gid = 0;

static const char *disp(const char *p) {
  size_t n = strlen(display_prefix);
  if (n > 1 && !strncmp(p, display_prefix, n)) return p[n] ? p + n : "/";
  return p;
}

static void jstr(FILE *f, const char *s) {
  fputc('"', f);
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') { fputc('\\', f); fputc(c, f); }
    else if (c < 0x20) fprintf(f, "\\u%04x", c);
    else fputc(c, f);
  }
  fputc('"', f);
}

static void write_atomic(const char *name, const char *content) {
  char tmp[PATH_MAX], dst[PATH_MAX];
  snprintf(dst, sizeof dst, "%s/%s", outdir, name);
  snprintf(tmp, sizeof tmp, "%s/.%s.tmp", outdir, name);
  FILE *f = fopen(tmp, "w");
  if (!f) return;
  fputs(content, f);
  fclose(f);
  if (system_mode) chown(tmp, (uid_t)as_uid, as_gid);   // readable by the user's Pulse while scanning
  rename(tmp, dst);
}

static void progress(const char *status) {
  char buf[PATH_MAX + 512], cur[PATH_MAX * 2];
  // escape current path
  size_t j = 0;
  for (const char *s = disp(current); *s && j < sizeof cur - 8; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') cur[j++] = '\\';
    if (c >= 0x20) cur[j++] = c;
  }
  cur[j] = 0;
  snprintf(buf, sizeof buf, "{\"status\":\"%s\",\"files\":%lld,\"bytes\":%lld,\"denied\":%lld,"
           "\"current\":\"%s\",\"started\":%ld,\"pid\":%d}\n",
           status, total_files, total_bytes, denied, cur, (long)started, getpid());
  write_atomic(quick ? "quick_progress.json" : system_mode ? "system_progress.json" : "scan_progress.json", buf);
}

static int ends_with(const char *s, const char *suf) {
  size_t a = strlen(s), b = strlen(suf);
  return a >= b && !strcmp(s + a - b, suf);
}

static char home[PATH_MAX];
static const char *PRIVATE_DIRS[] = {
  "/Library/Mail", "/Library/Messages", "/Library/Safari", "/Library/Cookies", "/Library/Keychains",
  "/Library/Mobile Documents", "/Library/CloudStorage", "/Library/Group Containers", "/Library/Containers",
  "/Library/Application Support/AddressBook", "/Library/Application Support/CallHistoryDB",
  "/Library/Application Support/com.apple.TCC", "/Library/Application Support/MobileSync",
  "/Library/Calendars", "/Library/Accounts", "/Library/IdentityServices", "/Library/Suggestions",
  "/Library/Biome", "/Library/HomeKit", "/Library/Sharing", "/Library/Metadata/CoreSpotlight",
  "/.ssh", "/.gnupg", NULL };

static const char *SYSTEM_PRIVATE[] = {
  "/private/var/root", "/private/var/db/sudo", "/private/var/db/dslocal", "/private/var/db/TCC",
  "/private/var/protected", "/private/var/db/SystemPolicyConfiguration", "/Library/Keychains",
  "/Library/Application Support/com.apple.TCC", "/private/var/db/ConfigurationProfiles", NULL };

static int is_private_root(const char *path) {
  const char *p = disp(path);
  for (int i = 0; SYSTEM_PRIVATE[i]; i++) if (!strcmp(p, SYSTEM_PRIVATE[i])) return 1;
  size_t hl = strlen(home);
  if (strncmp(p, home, hl)) return 0;
  const char *rest = p + hl;
  for (int i = 0; PRIVATE_DIRS[i]; i++) if (!strcmp(rest, PRIVATE_DIRS[i])) return 1;
  size_t n = strlen(rest);   // Photos / iPhoto libraries anywhere in home
  return n > 14 && !strcmp(rest + n - 14, ".photoslibrary");
}

#ifndef ATTR_CMNEXT_PRIVATESIZE
#define ATTR_CMNEXT_PRIVATESIZE 0x00000008
#endif
// APFS "private size": the part of a file NOT shared with clones, i.e. what deleting it frees.
static long long private_size(const char *path, long long fallback) {
  struct attrlist al = {ATTR_BIT_MAP_COUNT, 0, 0, 0, 0, 0, 0};
  al.forkattr = ATTR_CMNEXT_PRIVATESIZE;
  struct { uint32_t len; off_t ps; } __attribute__((packed)) buf;
  if (getattrlist(path, &al, &buf, sizeof buf, FSOPT_NOFOLLOW | FSOPT_ATTR_CMN_EXTENDED) == 0) return buf.ps;
  return fallback;
}

static int cmp_child(const void *a, const void *b) {
  long long x = ((const Child *)a)->size, y = ((const Child *)b)->size;
  return x < y ? 1 : x > y ? -1 : 0;
}

static void add_child(Frame *f, const char *name, long long size, int dir, long long files, long long priv) {
  if (f->nkids == f->cap) {
    f->cap = f->cap ? f->cap * 2 : 16;
    f->kids = realloc(f->kids, sizeof(Child) * f->cap);
  }
  f->kids[f->nkids++] = (Child){strdup(name), size, dir, files, priv};
}

static void emit_dir(Frame *f) {
  qsort(f->kids, f->nkids, sizeof(Child), cmp_child);
  long long listed = 0, rest_size = 0;
  int shown = f->nkids < TOP_CHILDREN ? f->nkids : TOP_CHILDREN;
  for (int i = 0; i < f->nkids; i++) { listed += f->kids[i].size; if (i >= shown) rest_size += f->kids[i].size; }
  long long other = (f->size > listed ? f->size - listed : 0) + rest_size;
  if (!first_dir) fputc(',', dirs_out);
  first_dir = 0;
  jstr(dirs_out, f->path);
  fprintf(dirs_out, ":{\"size\":%lld,\"priv\":%lld,\"files\":%lld,\"children\":[", f->size, f->priv_bytes, f->files);
  for (int i = 0; i < shown; i++) {
    if (i) fputc(',', dirs_out);
    fputc('[', dirs_out); jstr(dirs_out, f->kids[i].name);
    fprintf(dirs_out, ",%lld,%s,%lld,%lld]", f->kids[i].size, f->kids[i].dir ? "true" : "false", f->kids[i].files, f->kids[i].priv);
  }
  fprintf(dirs_out, "],\"other\":%lld,\"other_count\":%d,\"done\":true}", other, f->nkids - shown);
}

static void add_big(long long size, const char *path, long mtime, long long priv) {
  int slot = -1;
  if (nbig < MAX_BIG) slot = nbig++;
  else {
    int mi = 0;
    for (int i = 1; i < nbig; i++) if (big[i].size < big[mi].size) mi = i;
    if (big[mi].size >= size) return;
    free(big[mi].path);
    slot = mi;
  }
  big[slot] = (Big){size, strdup(disp(path)), mtime, priv};
}

static void note_node_modules(const char *path, long long size) {
  char proj[PATH_MAX];
  strncpy(proj, path, sizeof proj - 1); proj[sizeof proj - 1] = 0;
  char *slash = strrchr(proj, '/');
  if (!slash) return;
  *slash = 0;
  long mt = 0;
  const char *names[] = {"", "/package.json", "/package-lock.json", "/yarn.lock", "/pnpm-lock.yaml", "/src"};
  for (int i = 0; i < 6; i++) {
    char p[PATH_MAX]; struct stat st;
    snprintf(p, sizeof p, "%s%s", proj, names[i]);
    if (lstat(p, &st) == 0 && st.st_mtime > mt) mt = st.st_mtime;
  }
  char entry[PATH_MAX * 2 + 128];
  char a[PATH_MAX], b[PATH_MAX];
  snprintf(a, sizeof a, "%s", disp(path)); snprintf(b, sizeof b, "%s", disp(proj));
  // minimal escaping (quotes/backslashes)
  char ea[PATH_MAX * 2], eb[PATH_MAX * 2]; size_t j = 0;
  for (char *s = a; *s; s++) { if (*s == '"' || *s == '\\') ea[j++] = '\\'; ea[j++] = *s; } ea[j] = 0; j = 0;
  for (char *s = b; *s; s++) { if (*s == '"' || *s == '\\') eb[j++] = '\\'; eb[j++] = *s; } eb[j] = 0;
  int n = snprintf(entry, sizeof entry, "%s{\"path\":\"%s\",\"size\":%lld,\"project\":\"%s\",\"mtime\":%ld}",
                   nm_first ? "" : ",", ea, size, eb, mt);
  if (nm_len + n < sizeof nm_buf) { memcpy(nm_buf + nm_len, entry, n); nm_len += n; nm_first = 0; }
}

int main(int argc, char **argv) {
  const char *quick_path = NULL;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--out") && i + 1 < argc) outdir = argv[++i];
    else if (!strcmp(argv[i], "--root") && i + 1 < argc) root_path = argv[++i];
    else if (!strcmp(argv[i], "--quick") && i + 1 < argc) { quick_path = argv[++i]; quick = 1; }
    else if (!strcmp(argv[i], "--system")) { system_mode = 1; skip_top = "Users"; }
    else if (!strcmp(argv[i], "--skip-top") && i + 1 < argc) skip_top = argv[++i];
    else if (!strcmp(argv[i], "--as-uid") && i + 1 < argc) as_uid = atol(argv[++i]);
  }
  if (!outdir) { fprintf(stderr, "usage: pulse-scanner --out DIR [--root PATH | --quick PATH]\n"); return 2; }
  if (system_mode && (getuid() != 0 || as_uid < 0 || quick)) {
    fprintf(stderr, "pulse-scanner: --system must run as root with --as-uid\n");
    return 2;
  }
  struct passwd *pw = getpwuid(system_mode ? (uid_t)as_uid : getuid());
  if (!pw) return 1;
  as_gid = pw->pw_gid;
  snprintf(home, sizeof home, "%s", pw->pw_dir);
  static char allowed[PATH_MAX];
  snprintf(allowed, sizeof allowed, "%s/Library/Application Support/Pulse", home);
  if (strcmp(outdir, allowed) && !getenv("PULSE_SCANNER_DEV_OUT")) {
    fprintf(stderr, "pulse-scanner: results can only be written to %s\n", allowed);
    return 2;
  }
  mkdir(allowed, 0700);
  if (system_mode) chown(allowed, (uid_t)as_uid, pw->pw_gid);
  umask(077);
  if (access("/System/Volumes/Data/Users", F_OK) != 0) display_prefix = "";
  if (quick) {
    // Map a display path (/Users/x) to the data volume path for consistent keys.
    static char rp[PATH_MAX];
    if (*display_prefix && strncmp(quick_path, "/System/", 8)) snprintf(rp, sizeof rp, "%s%s", display_prefix, quick_path);
    else snprintf(rp, sizeof rp, "%s", quick_path);
    root_path = rp;
  }
  started = time(NULL);

  char tmpdirs[PATH_MAX];
  const char *result_name = quick ? "quick_scan.json" : system_mode ? "system_scan.json" : "storage_scan.json";
  snprintf(tmpdirs, sizeof tmpdirs, "%s/.%s.tmp", outdir, result_name);
  dirs_out = fopen(tmpdirs, "w");
  if (!dirs_out) { perror("pulse-scanner: output"); return 1; }
  fprintf(dirs_out, "{\"dirs\":{");
  progress("scanning");

  char *paths[] = {(char *)root_path, NULL};
  FTS *fts = fts_open(paths, FTS_PHYSICAL | FTS_XDEV | FTS_NOCHDIR, NULL);
  if (!fts) { perror("pulse-scanner: fts_open"); return 1; }
  Frame stack[512]; int sp = 0;
  FTSENT *e;
  while ((e = fts_read(fts))) {
    switch (e->fts_info) {
    case FTS_D:
      if (sp >= 511) { fts_set(fts, e, FTS_SKIP); break; }   // too deep: never pushed, never popped (see FTS_DP)
      stack[sp] = (Frame){strdup(e->fts_path), 0, 0, 0, NULL, 0, 0,
                          sp > 0 && (stack[sp - 1].in_nm || ends_with(stack[sp - 1].path, "/node_modules")),
                          (sp > 0 && stack[sp - 1].priv) || is_private_root(e->fts_path), 0};
      // System mode leaves /Users to the normal scan. A skipped folder still comes back as
      // FTS_DP, so it must have a frame of its own or the parent's frame would be popped.
      if (skip_top && e->fts_level == 1 && !strcmp(e->fts_name, skip_top)) {
        stack[sp].skip = 1;
        fts_set(fts, e, FTS_SKIP);
      }
      sp++;
      current = e->fts_path;
      break;
    case FTS_DP: {
      if (sp == 0 || strcmp(stack[sp - 1].path, e->fts_path)) break;   // not ours (e.g. depth-limited)
      Frame *f = &stack[--sp];
      if (f->skip) {
        for (int i = 0; i < f->nkids; i++) free(f->kids[i].name);
        free(f->kids); free(f->path);
        break;
      }
      int nested_private = f->priv && sp > 0 && stack[sp - 1].priv;
      int keep = !nested_private && (f->size >= MIN_KEEP || e->fts_level <= 1 || (quick && e->fts_level == 0));
      if (keep && f->priv) {       // totals only
        for (int i = 0; i < f->nkids; i++) free(f->kids[i].name);
        f->nkids = 0;
      }
      if (keep) emit_dir(f);
      if (!strcmp(e->fts_name, "node_modules") && !f->in_nm && !f->priv && f->size >= (50LL << 20))
        note_node_modules(f->path, f->size);
      if (sp > 0) {
        Frame *p = &stack[sp - 1];
        p->size += f->size; p->files += f->files; p->priv_bytes += f->priv_bytes;
        if (!p->priv) add_child(p, e->fts_name, f->size, 1, f->files, f->priv_bytes);
      }
      for (int i = 0; i < f->nkids; i++) free(f->kids[i].name);
      free(f->kids); free(f->path);
      break;
    }
    case FTS_DNR: case FTS_ERR: case FTS_NS:
      denied++;
      if (ndenied < MAX_DENIED) denied_paths[ndenied++] = strdup(disp(e->fts_path));
      // An unreadable folder gets FTS_D then FTS_DNR (no FTS_DP): drop its frame, and list it in
      // its parent as a blocked entry (priv = -1) so the UI can show what macOS kept hidden.
      if (sp > 0 && !strcmp(stack[sp - 1].path, e->fts_path)) {
        Frame *f = &stack[--sp];
        for (int i = 0; i < f->nkids; i++) free(f->kids[i].name);
        free(f->kids); free(f->path);
        if (sp > 0 && !stack[sp - 1].priv) add_child(&stack[sp - 1], e->fts_name, 0, 1, 0, -1);
      }
      break;
    case FTS_DC:
      break;
    default: {   // files, symlinks, specials: count their own blocks only
      if (!e->fts_statp) break;
      long long size = (long long)e->fts_statp->st_blocks * 512;
      long long pv = (e->fts_info == FTS_F && size > 0) ? private_size(e->fts_accpath, size) : size;
      total_files++; total_bytes += size;
      if (sp > 0) {
        Frame *p = &stack[sp - 1];
        p->size += size; p->files++; p->priv_bytes += pv;
        if (size >= CHILD_FILE_MIN && !p->priv) add_child(p, e->fts_name, size, 0, 1, pv);
      }
      if (size >= BIG_FILE && !(sp > 0 && stack[sp - 1].priv)) add_big(size, e->fts_path, e->fts_statp->st_mtime, pv);
    }
    }
    time_t now = time(NULL);
    if (now != last_progress) { last_progress = now; progress("scanning"); }
  }
  fts_close(fts);

  fprintf(dirs_out, "},\"big_files\":[");
  for (int i = 0; i < nbig; i++) {
    fprintf(dirs_out, "%s[%lld,", i ? "," : "", big[i].size); jstr(dirs_out, big[i].path);
    fprintf(dirs_out, ",%ld,%lld]", big[i].mtime, big[i].priv);
  }
  fprintf(dirs_out, "],\"node_modules\":[%.*s],\"denied_paths\":[", (int)nm_len, nm_buf);
  for (int i = 0; i < ndenied; i++) { if (i) fputc(',', dirs_out); jstr(dirs_out, denied_paths[i]); }
  fprintf(dirs_out, "],\"started\":%ld,\"finished\":%ld,\"files\":%lld,\"denied\":%lld}\n",
          (long)started, (long)time(NULL), total_files, denied);
  fclose(dirs_out);
  char dst[PATH_MAX];
  snprintf(dst, sizeof dst, "%s/%s", outdir, result_name);
  rename(tmpdirs, dst);
  progress("done");
  if (system_mode) {       // give the results back to the user who asked for them
    char pf[PATH_MAX];
    chown(dst, (uid_t)as_uid, pw->pw_gid);
    snprintf(pf, sizeof pf, "%s/system_progress.json", outdir);
    chown(pf, (uid_t)as_uid, pw->pw_gid);
  }
  return 0;
}
