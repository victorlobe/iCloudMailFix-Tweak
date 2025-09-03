// Tweak.xm — DNS redirect and SSL blocking for iCloud Mail streams
#import <substrate.h>
#import <dlfcn.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <netinet/in.h>
#import <CoreFoundation/CoreFoundation.h>
#import <CFNetwork/CFNetwork.h>
#import <ctype.h>
#import <stdlib.h>
#import <string.h>
#import <stdio.h>

static const char* kICMFHookVer = "0.0.2 (reorganized)";

// Sets, used to mark streams where we must block SSL
static CFMutableSetRef gNoSSLStreams = NULL;

// ---------------- logging ----------------
static void write_log(const char *fmt, ...) {
	FILE *f = fopen("/var/log/iCloudMailFix-hook.log", "a");
	if (!f) return;
	va_list ap; va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	fprintf(f, "\n");
	va_end(ap);
	fclose(f);
}

__attribute__((constructor))
static void icmf_ctor(void) {
	if (!gNoSSLStreams) {
		gNoSSLStreams = CFSetCreateMutable(kCFAllocatorDefault, 0, &kCFTypeSetCallBacks);
	}
	write_log("[hook] start pid=%d ver=%s", getpid(), kICMFHookVer);
}

// ---------------- helpers ----------------
static inline int is_digit_str(const char *s) {
	if (!s || !*s) return 0;
	for (const char *p = s; *p; ++p) if (!isdigit((unsigned char)*p)) return 0;
	return 1;
}
static void normalize_host(char *h) {
	size_t L = strlen(h);
	if (L > 0 && h[L-1] == '.') h[L-1] = '\0';
}
typedef enum { HOST_NONE=0, HOST_IMAP=1, HOST_SMTP=2 } host_kind_t;

static host_kind_t classify_host_cstr(const char *host) {
	if (!host) return HOST_NONE;
	char h[256]; memset(h, 0, sizeof(h));
	size_t n = strlcpy(h, host, sizeof(h));
	if (n >= sizeof(h)) return HOST_NONE;
	for (size_t i=0;i<strlen(h);++i) h[i] = (char)tolower((unsigned char)h[i]);
	normalize_host(h);
	if (!strcmp(h, "imap.mail.me.com"))  return HOST_IMAP;
	if (!strcmp(h, "smtp.mail.me.com"))  return HOST_SMTP;
	// handle pXX-<host> aliases Apple sometimes uses
	if (h[0] == 'p') {
		const char *p = h + 1;
		const char *dash = strchr(p, '-');
		if (!dash) return HOST_NONE;
		char numbuf[16] = {0};
		size_t len = (size_t)(dash - p);
		if (len == 0 || len >= sizeof(numbuf)) return HOST_NONE;
		memcpy(numbuf, p, len);
		if (!is_digit_str(numbuf)) return HOST_NONE;
		const char *rest = dash + 1;
		if (!strncmp(rest, "imap.mail.me.com", 16)) return HOST_IMAP;
		if (!strncmp(rest, "smtp.mail.me.com", 16)) return HOST_SMTP;
	}
	return HOST_NONE;
}

// ---------------- getaddrinfo hook ----------------
static int (*orig_getaddrinfo)(const char *node, const char *service,
							   const struct addrinfo *hints, struct addrinfo **res);

static int make_loopback_result_with_kind(host_kind_t kind, const char *service,
										  const struct addrinfo *hints, struct addrinfo **res) {
	(void)service;
	int socktype = hints ? hints->ai_socktype : 0;
	int proto    = hints ? hints->ai_protocol : 0;
	uint16_t port = (kind == HOST_IMAP) ? 143 : 587;

	struct addrinfo *ai = (struct addrinfo *)calloc(1, sizeof(struct addrinfo));
	if (!ai) return EAI_MEMORY;
	ai->ai_family   = AF_INET;
	ai->ai_socktype = socktype;
	ai->ai_protocol = proto;
	ai->ai_addrlen  = sizeof(struct sockaddr_in);
	ai->ai_addr     = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
	if (!ai->ai_addr) { free(ai); return EAI_MEMORY; }

	struct sockaddr_in *sa = (struct sockaddr_in *)ai->ai_addr;
	sa->sin_family = AF_INET; inet_pton(AF_INET, "127.0.0.1", &sa->sin_addr);
	sa->sin_port = htons(port);

	*res = ai;
	return 0;
}

static int hooked_getaddrinfo(const char *node, const char *service,
							  const struct addrinfo *hints, struct addrinfo **res) {
	host_kind_t kind = classify_host_cstr(node);
	if (kind != HOST_NONE) {
		write_log("[getaddrinfo] %s:%s -> 127.0.0.1:%s",
				  node ? node : "(null)", service ? service : "(null)",
				  (kind==HOST_IMAP) ? "143" : "587");
		return make_loopback_result_with_kind(kind, service, hints, res);
	}
	return orig_getaddrinfo(node, service, hints, res);
}

// ---------------- CFStreamCreatePairWithSocketToHost hook ----------------
typedef void (*CFStreamCreatePairWithSocketToHost_t)(
	CFAllocatorRef, CFStringRef, UInt32, CFReadStreamRef*, CFWriteStreamRef*);
static CFStreamCreatePairWithSocketToHost_t orig_CFStreamCreatePairWithSocketToHost = NULL;

static inline Boolean cf_host_matches(CFStringRef host, CFStringRef needle) {
	if (!host || !needle) return false;
	CFRange r = CFStringFind(host, needle, kCFCompareCaseInsensitive);
	return r.location != kCFNotFound;
}

static void hooked_CFStreamCreatePairWithSocketToHost(
	CFAllocatorRef alloc, CFStringRef host, UInt32 port,
	CFReadStreamRef *readStream, CFWriteStreamRef *writeStream)
{
	CFStringRef useHost = host;
	UInt32      usePort = port;
	Boolean     blockSSL = false;

	if (cf_host_matches(host, CFSTR("imap.mail.me.com")) && (port == 993 || port == 143)) {
		// IMAP -> local cleartext 143
		useHost = CFSTR("127.0.0.1");
		usePort = 143;
		blockSSL = true;
	} else if (cf_host_matches(host, CFSTR("smtp.mail.me.com")) && (port == 465 || port == 587)) {
		// SMTP -> local cleartext 587 (we do TLS only upstream)
		useHost = CFSTR("127.0.0.1");
		usePort = 587;
		blockSSL = true;
	}

	orig_CFStreamCreatePairWithSocketToHost(alloc, useHost, usePort, readStream, writeStream);

	if (blockSSL && gNoSSLStreams) {
		if (readStream && *readStream)   CFSetAddValue(gNoSSLStreams, *readStream);
		if (writeStream && *writeStream) CFSetAddValue(gNoSSLStreams, *writeStream);
		write_log("[hook] CFStream pair redirected to %s:%u, SSL-block flagged",
				  (usePort==143)?"127.0.0.1 (IMAP)":"127.0.0.1 (SMTP)", (unsigned)usePort);
	}
}

// ---------------- CFRead/WriteStreamSetProperty hooks ----------------
// (single, non-duplicated typedefs + originals)
typedef Boolean (*CFReadStreamSetProperty_t)(CFReadStreamRef, CFStringRef, CFTypeRef);
typedef Boolean (*CFWriteStreamSetProperty_t)(CFWriteStreamRef, CFStringRef, CFTypeRef);
static CFReadStreamSetProperty_t  orig_CFReadStreamSetProperty  = NULL;
static CFWriteStreamSetProperty_t orig_CFWriteStreamSetProperty = NULL;

// identify SSL-related properties WITHOUT linking kCFStreamPropertySSLSettings symbols
static inline Boolean isSSLProperty(CFStringRef key){
	if (!key) return false;
	// Compare by content using CFSTR literals (avoids unresolved externs on iOS 6 toolchain)
	return CFEqual(key, CFSTR("kCFStreamPropertySSLSettings")) ||
		   CFEqual(key, CFSTR("kCFStreamPropertySocketSecurityLevel")) ||
		   CFEqual(key, CFSTR("kCFStreamSocketSecurityLevelNegotiatedSSL")) ||
		   CFEqual(key, CFSTR("kCFStreamSocketSecurityLevelTLSv1")) ||
		   CFEqual(key, CFSTR("kCFStreamSocketSecurityLevelTLSv1_1")) ||
		   CFEqual(key, CFSTR("kCFStreamSocketSecurityLevelTLSv1_2")) ||
		   CFEqual(key, CFSTR("kCFStreamSocketSecurityLevelSSLv2")) ||
		   CFEqual(key, CFSTR("kCFStreamSocketSecurityLevelSSLv3"));
}

static Boolean hooked_CFReadStreamSetProperty(CFReadStreamRef stream, CFStringRef key, CFTypeRef value) {
	if (isSSLProperty(key) && gNoSSLStreams && CFSetContainsValue(gNoSSLStreams, stream)) {
		write_log("[hook] CFReadStreamSetProperty blocked SSL on stream=%p", stream);
		return true; // pretend success, but do nothing -> stay plaintext
	}
	return orig_CFReadStreamSetProperty(stream, key, value);
}

static Boolean hooked_CFWriteStreamSetProperty(CFWriteStreamRef stream, CFStringRef key, CFTypeRef value) {
	if (isSSLProperty(key) && gNoSSLStreams && CFSetContainsValue(gNoSSLStreams, stream)) {
		write_log("[hook] CFWriteStreamSetProperty blocked SSL on stream=%p", stream);
		return true;
	}
	return orig_CFWriteStreamSetProperty(stream, key, value);
}

// ---------------- constructor: install hooks ----------------
__attribute__((constructor))
static void icloudmailfix_init() {
	write_log("[hook] constructor begin pid=%d", getpid());

	void *sym_gai = dlsym(RTLD_DEFAULT, "getaddrinfo");
	if (sym_gai) {
		MSHookFunction(sym_gai, (void*)&hooked_getaddrinfo, (void**)&orig_getaddrinfo);
		write_log("[hook] hooked getaddrinfo");
	} else {
		write_log("[hook] getaddrinfo not found");
	}

	void *sym_pair = dlsym(RTLD_DEFAULT, "CFStreamCreatePairWithSocketToHost");
	if (sym_pair) {
		MSHookFunction(sym_pair, (void*)&hooked_CFStreamCreatePairWithSocketToHost,
					   (void**)&orig_CFStreamCreatePairWithSocketToHost);
		write_log("[hook] hooked CFStreamCreatePairWithSocketToHost");
	} else {
		write_log("[hook] CFStreamCreatePairWithSocketToHost not found");
	}

	void *sym_r = dlsym(RTLD_DEFAULT, "CFReadStreamSetProperty");
	if (sym_r) {
		MSHookFunction(sym_r, (void*)&hooked_CFReadStreamSetProperty,
					   (void**)&orig_CFReadStreamSetProperty);
		write_log("[hook] hooked CFReadStreamSetProperty");
	} else {
		write_log("[hook] CFReadStreamSetProperty not found");
	}

	void *sym_w = dlsym(RTLD_DEFAULT, "CFWriteStreamSetProperty");
	if (sym_w) {
		MSHookFunction(sym_w, (void*)&hooked_CFWriteStreamSetProperty,
					   (void**)&orig_CFWriteStreamSetProperty);
		write_log("[hook] hooked CFWriteStreamSetProperty");
	} else {
		write_log("[hook] CFWriteStreamSetProperty not found");
	}
}