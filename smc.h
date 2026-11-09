// smc.h — minimal Apple System Management Controller access (fans).
// Reading works as a normal user; writing requires root.
#pragma once
#include <IOKit/IOKitLib.h>
#include <stdint.h>
#include <string.h>

typedef struct { char major, minor, build, reserved; uint16_t release; } SMCVers;
typedef struct { uint16_t version, length; uint32_t cpuPLimit, gpuPLimit, memPLimit; } SMCPLimit;
typedef struct { uint32_t dataSize, dataType; char dataAttributes; } SMCKeyInfo;
typedef struct {
  uint32_t key;
  SMCVers vers;
  SMCPLimit pLimitData;
  SMCKeyInfo keyInfo;
  char result, status, data8;
  uint32_t data32;
  unsigned char bytes[32];
} SMCKeyData;

#define SMC_KERNEL_INDEX 2
#define SMC_CMD_READ_BYTES 5
#define SMC_CMD_WRITE_BYTES 6
#define SMC_CMD_READ_KEYINFO 9

static io_connect_t smc_conn;

static uint32_t smc_k(const char *s) { return ((uint32_t)s[0] << 24) | ((uint32_t)s[1] << 16) | ((uint32_t)s[2] << 8) | (uint32_t)s[3]; }

static int smc_open(void) {
  if (smc_conn) return 1;
  io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleSMC"));
  if (!svc) return 0;
  kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &smc_conn);
  IOObjectRelease(svc);
  return kr == KERN_SUCCESS;
}

static int smc_call(SMCKeyData *in, SMCKeyData *out) {
  size_t sz = sizeof(SMCKeyData);
  return IOConnectCallStructMethod(smc_conn, SMC_KERNEL_INDEX, in, sizeof(SMCKeyData), out, &sz) == KERN_SUCCESS
         && out->result == 0;
}

static int smc_info(const char *key, SMCKeyInfo *info) {
  SMCKeyData in = {0}, out = {0};
  in.key = smc_k(key);
  in.data8 = SMC_CMD_READ_KEYINFO;
  if (!smc_call(&in, &out)) return 0;
  *info = out.keyInfo;
  return 1;
}

// Returns number of bytes read (0 on failure); type receives the 4-char data type.
static int smc_read(const char *key, unsigned char *buf, char type[5]) {
  SMCKeyInfo info;
  if (!smc_info(key, &info)) return 0;
  SMCKeyData in = {0}, out = {0};
  in.key = smc_k(key);
  in.keyInfo.dataSize = info.dataSize;
  in.data8 = SMC_CMD_READ_BYTES;
  if (!smc_call(&in, &out)) return 0;
  memcpy(buf, out.bytes, info.dataSize > 32 ? 32 : info.dataSize);
  if (type) {
    type[0] = info.dataType >> 24; type[1] = info.dataType >> 16; type[2] = info.dataType >> 8; type[3] = info.dataType; type[4] = 0;
  }
  return info.dataSize;
}

static int smc_write(const char *key, const unsigned char *buf, uint32_t len) {
  SMCKeyInfo info;
  if (!smc_info(key, &info) || info.dataSize != len) return 0;
  SMCKeyData in = {0}, out = {0};
  in.key = smc_k(key);
  in.data8 = SMC_CMD_WRITE_BYTES;
  in.keyInfo.dataSize = len;
  memcpy(in.bytes, buf, len);
  return smc_call(&in, &out);
}

// Numeric read supporting the fan key types used on Intel (fpe2, ui8/ui16) and Apple Silicon (flt).
static double smc_num(const char *key, int *ok) {
  unsigned char b[32]; char t[5];
  int n = smc_read(key, b, t);
  if (ok) *ok = n > 0;
  if (n <= 0) return 0;
  if (!strcmp(t, "flt ") && n == 4) { float f; memcpy(&f, b, 4); return f; }
  if (!strcmp(t, "fpe2") && n == 2) return ((b[0] << 8) | b[1]) / 4.0;
  if (!strcmp(t, "ui8 ")) return b[0];
  if (!strcmp(t, "ui16")) return (b[0] << 8) | b[1];
  if (!strcmp(t, "ui32")) return ((uint32_t)b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
  if (ok) *ok = 0;
  return 0;
}

// Write a fan speed (RPM) in whatever format the key uses.
static int smc_write_rpm(const char *key, double rpm) {
  unsigned char b[32] = {0}; char t[5];
  int n = smc_read(key, b, t);
  if (n <= 0) return 0;
  if (!strcmp(t, "flt ") && n == 4) { float f = (float)rpm; memcpy(b, &f, 4); return smc_write(key, b, 4); }
  if (!strcmp(t, "fpe2") && n == 2) { int v = (int)(rpm * 4); b[0] = v >> 8; b[1] = v & 0xff; return smc_write(key, b, 2); }
  return 0;
}

static int smc_write_u8(const char *key, unsigned char v) { return smc_write(key, &v, 1); }
