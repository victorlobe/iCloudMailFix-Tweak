// iCloudMailFixd.c — IMAP/SMTP proxy for iOS 6 Mail with TLS upstream
// Architecture: Client (plain) ↔ Local Proxy (127.0.0.1) ↔ Upstream (TLS)

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/file.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"

/* mbedTLS errno fallback for iOS6 headers */
#ifndef MBEDTLS_ERR_NET_SEND_FAILED
#  define MBEDTLS_ERR_NET_SEND_FAILED  -0x0052
#endif
#ifndef MBEDTLS_ERR_NET_RECV_FAILED
#  define MBEDTLS_ERR_NET_RECV_FAILED  -0x004E
#endif

#if defined(__clang__) || defined(__GNUC__)
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

// ============================================================================
// FUNCTION PROTOTYPES
// ============================================================================

// Logging and utilities
static void ts_now(char* out, size_t cap);
static void vlogf(const char* tag, const char* fmt, va_list ap);
static void logf(const char* tag, const char* fmt, ...);
static const char* tls_err(int ret);
static void name_of_fd(int fd, char* out, size_t cap);
static long ms_since(const struct timeval* a, const struct timeval* b);

// Socket utilities
static int set_nonblock(int fd);
static int set_nosigpipe(int fd);
static int send_all(int fd, const void* b, size_t n);
static int write_all(int fd, const void* buf, size_t len);
static int tcp_listen(const char* ip, int port);
static int tcp_connect_blocking(const char* host, const char* port);

// TLS environment and wrapping
typedef struct {
	mbedtls_entropy_context  entropy;
	mbedtls_ctr_drbg_context ctr;
	mbedtls_ssl_config       conf;
} tls_env_t;

static int tls_env_init(tls_env_t* E);
static void tls_env_free(tls_env_t* E);
static int tls_wrap_fd(mbedtls_ssl_context* ssl, tls_env_t* E, int up_fd, const char* sni);

// BIO callbacks
typedef struct { int fd; } tls_bio_t;
static int bio_send(void* ctx, const unsigned char* buf, size_t len);
static int bio_recv(void* ctx, unsigned char* buf, size_t len);

// Proxy loop
static void proxy_loop_plain_tls(int cs, mbedtls_ssl_context* ssl);

// Line reading utilities
static int recv_line_crlf_to(int fd, char* buf, size_t cap, int timeout_ms);

// SMTP helpers
static size_t filter_caps_remove_starttls(const char* in, size_t inlen, char* out, size_t cap);
static int smtp_starttls_plain_phase(int cs, int up_fd);
static int smtp_post_tls_ehlo(mbedtls_ssl_context* ssl);



// Protocol handlers
static void handle_imap(int cs, tls_env_t* env);
static void handle_smtp(int cs, tls_env_t* env);

// Threading and main
typedef struct { int ls; int is_imap; tls_env_t* env; } serve_args_t;
static void* serve_thread_impl(void* arg);
static void* hb(void* _);
static void on_sig(int s);

// ============================================================================
// CONFIGURATION
// ============================================================================

#define LISTEN_IP      "127.0.0.1"
#define LISTEN_IMAP    143
#define LISTEN_SMTP    587
#define UP_IMAP_HOST   "imap.mail.me.com"
#define UP_IMAP_PORT   "993"
#define UP_SMTP_HOST   "smtp.mail.me.com"
#define UP_SMTP_PORT   "587"

// ============================================================================
// GLOBALS
// ============================================================================

static volatile int g_run = 1;
static volatile int g_imap_clients = 0;
static volatile int g_smtp_clients = 0;
static char g_ehlo_name[256] = {0};

// ============================================================================
// LOGGING SYSTEM
// ============================================================================

static inline void ts_now(char* out, size_t cap){
	struct timeval tv; gettimeofday(&tv, NULL);
	struct tm tm; localtime_r(&tv.tv_sec, &tm);
	snprintf(out, cap, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
		tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec/1000));
}

static void vlogf(const char* tag, const char* fmt, va_list ap){
	char t[32]; ts_now(t, sizeof(t));
	fprintf(stderr, "[%s] %s ", tag, t);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
}

static void logf(const char* tag, const char* fmt, ...){
	va_list ap; va_start(ap, fmt); vlogf(tag, fmt, ap); va_end(ap);
}

#define LOGE(...) logf("ERR", __VA_ARGS__)
#define LOGI(...) logf("INF", __VA_ARGS__)
#define LOGD(...) logf("DBG", __VA_ARGS__)
#define LOGV(...) logf("VRB", __VA_ARGS__)

static const char* tls_err(int ret){
	static char buf[128];
	mbedtls_strerror(ret, buf, sizeof(buf));
	return buf;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

static void name_of_fd(int fd, char* out, size_t cap){
	struct sockaddr_in sa; socklen_t sl=sizeof(sa);
	if (getpeername(fd,(struct sockaddr*)&sa,&sl)==0){
		char ip[64]; inet_ntop(AF_INET,&sa.sin_addr,ip,sizeof(ip));
		snprintf(out,cap,"%s:%u",ip,(unsigned)ntohs(sa.sin_port));
	}else{
		snprintf(out,cap,"fd=%d",fd);
	}
}

static long ms_since(const struct timeval* a, const struct timeval* b){
	return (long)((b->tv_sec - a->tv_sec)*1000 + (b->tv_usec - a->tv_usec)/1000);
}

// ============================================================================
// SOCKET UTILITIES
// ============================================================================

static int set_nonblock(int fd){
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl < 0) return -1;
	return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int set_nosigpipe(int fd){
	int one = 1;
	return setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
}

static int send_all(int fd, const void* b, size_t n){
	const char *p = (const char*)b; size_t off = 0;
	while (off < n){
		ssize_t w = send(fd, p + off, n - off, 0);
		if (w < 0){
			if (errno == EINTR) continue;
			return -1;
		}
		if (w == 0) return -1;
		off += (size_t)w;
	}
	return 0;
}

static int write_all(int fd, const void* buf, size_t len){
	const char *p = (const char*)buf;
	while (len){
		ssize_t w = write(fd, p, len);
		if (w < 0){
			if (errno == EINTR) continue;
			return -1;
		}
		if (w == 0) return -1;
		p   += w;
		len -= (size_t)w;
	}
	return 0;
}

static int tcp_listen(const char* ip, int port){
	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) { LOGE("socket listen: %s", strerror(errno)); return -1; }
	int one = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port   = htons((uint16_t)port);
	inet_pton(AF_INET, ip, &sa.sin_addr);

	if (bind(s, (struct sockaddr*)&sa, sizeof(sa)) < 0){
		LOGE("bind %s:%d: %s", ip, port, strerror(errno));
		close(s); return -1;
	}
	if (listen(s, 16) < 0){
		LOGE("listen: %s", strerror(errno));
		close(s); return -1;
	}
	return s;
}

static int tcp_connect_blocking(const char* host, const char* port){
	struct timeval t0, t1;
	gettimeofday(&t0, NULL);

	struct addrinfo hints; memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo* ai = NULL;
	int rc = getaddrinfo(host, port, &hints, &ai);
	if (rc != 0){
		LOGE("getaddrinfo %s:%s: %s", host, port, gai_strerror(rc));
		return -1;
	}

	int s = -1;
	for (struct addrinfo* p = ai; p; p = p->ai_next){
		s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (s < 0) continue;

		struct timeval tv; tv.tv_sec = 8; tv.tv_usec = 0;
		setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

		// log target
		if (p->ai_family == AF_INET){
			char ipbuf[64];
			inet_ntop(AF_INET, &((struct sockaddr_in*)p->ai_addr)->sin_addr, ipbuf, sizeof(ipbuf));
			LOGD("connect try %s:%s -> %s", host, port, ipbuf);
		}

		if (connect(s, p->ai_addr, p->ai_addrlen) == 0){
			break; // success
		}
		close(s); s = -1;
	}
	freeaddrinfo(ai);

	gettimeofday(&t1, NULL);
	if (s < 0){
		LOGE("connect %s:%s failed: errno=%d (%s)", host, port, errno, strerror(errno));
	}else{
		LOGD("connect %s:%s ok in %ld ms", host, port, ms_since(&t0,&t1));
	}
	return s;
}

// ============================================================================
// TLS ENVIRONMENT
// ============================================================================

static int tls_env_init(tls_env_t* E){
	mbedtls_entropy_init(&E->entropy);
	mbedtls_ctr_drbg_init(&E->ctr);
	mbedtls_ssl_config_init(&E->conf);

	const char* pers = "iCloudMailFixd-rng";
	int ret = mbedtls_ctr_drbg_seed(&E->ctr, mbedtls_entropy_func, &E->entropy,
									(const unsigned char*)pers, strlen(pers));
	if (ret != 0){ LOGE("ctr_drbg_seed: %d", ret); return ret; }

	ret = mbedtls_ssl_config_defaults(&E->conf,
									  MBEDTLS_SSL_IS_CLIENT,
									  MBEDTLS_SSL_TRANSPORT_STREAM,
									  MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0){ LOGE("ssl_config_defaults: %d", ret); return ret; }

	mbedtls_ssl_conf_authmode(&E->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_rng(&E->conf, mbedtls_ctr_drbg_random, &E->ctr);
	return 0;
}

static void tls_env_free(tls_env_t* E){
	mbedtls_ssl_config_free(&E->conf);
	mbedtls_ctr_drbg_free(&E->ctr);
	mbedtls_entropy_free(&E->entropy);
}

// ============================================================================
// TLS BIO CALLBACKS
// ============================================================================

static int bio_send(void* ctx, const unsigned char* buf, size_t len){
	int fd = ((tls_bio_t*)ctx)->fd;
	ssize_t w = send(fd, buf, len, 0);
	if (w < 0){
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return MBEDTLS_ERR_SSL_WANT_WRITE;
		return MBEDTLS_ERR_NET_SEND_FAILED;
	}
	return (int)w;
}

static int bio_recv(void* ctx, unsigned char* buf, size_t len){
	int fd = ((tls_bio_t*)ctx)->fd;
	ssize_t r = recv(fd, buf, len, 0);
	if (r < 0){
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return MBEDTLS_ERR_SSL_WANT_READ;
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}
	if (r == 0) return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
	return (int)r;
}

static int tls_wrap_fd(mbedtls_ssl_context* ssl, tls_env_t* E, int up_fd, const char* sni){
	set_nosigpipe(up_fd);
	mbedtls_ssl_init(ssl);

	int ret = mbedtls_ssl_setup(ssl, &E->conf);
	if (ret != 0){ LOGE("ssl_setup: %d", ret); return ret; }

	if (sni && *sni){
		ret = mbedtls_ssl_set_hostname(ssl, sni);
		if (ret != 0){ LOGE("set_hostname: %d", ret); return ret; }
	}

	tls_bio_t* bio = (tls_bio_t*)calloc(1, sizeof(tls_bio_t));
	if (!bio) return -1;
	bio->fd = up_fd;
	mbedtls_ssl_set_bio(ssl, bio, bio_send, bio_recv, NULL);

	struct timeval t0, t1; gettimeofday(&t0,NULL);
	while ((ret = mbedtls_ssl_handshake(ssl)) != 0){
		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE){
			struct timeval tv = {0, 20000}; select(0, NULL, NULL, NULL, &tv);
			continue;
		}
		gettimeofday(&t1,NULL);
		LOGE("TLS handshake err %d (%s) after %ld ms", ret, tls_err(ret), ms_since(&t0,&t1));
		free(bio);
		return ret;
	}
	gettimeofday(&t1,NULL);
	LOGD("TLS handshake ok in %ld ms", ms_since(&t0,&t1));
	return 0;
}

// ============================================================================
// PROXY LOOP
// ============================================================================

static void proxy_loop_plain_tls(int cs, mbedtls_ssl_context* ssl){
	// Get upstream FD from BIO
	tls_bio_t* bio = (tls_bio_t*)ssl->p_bio;
	int up = bio ? bio->fd : -1;
	if (up < 0){ LOGE("proxy: invalid upstream fd"); return; }

	set_nonblock(cs);
	set_nonblock(up);
	set_nosigpipe(cs);

	unsigned char ubuf[4096];
	unsigned char cbuf[4096];
	size_t up_to_client = 0, client_to_up = 0;
	// int loop_count = 0;

	// LOGD("SMTP[PROXY]: starting proxy loop, plain_fd=%d, ssl_bio=%d", cs, up);

	while (1){
		// loop_count++;
		fd_set rfds; FD_ZERO(&rfds);
		FD_SET(cs, &rfds);
		FD_SET(up, &rfds);
		int maxfd = (cs > up ? cs : up) + 1;

		// LOGD("SMTP[PROXY]: loop %d, waiting for data on fds %d,%d", loop_count, cs, up);

		struct timeval tv; tv.tv_sec = 30; tv.tv_usec = 0;
		int r = select(maxfd, &rfds, NULL, NULL, &tv);
		if (r < 0){
			if (errno == EINTR) continue;
			LOGE("select: %s", strerror(errno));
			break;
		}
		if (r == 0) {
			LOGD("SMTP[PROXY]: select timeout after 30s, breaking");
			break;
		}
		
		// LOGD("SMTP[PROXY]: select returned %d, checking fds", r);
		
		// Client -> TLS
		if (FD_ISSET(cs, &rfds)){
			// LOGD("SMTP[PROXY]: data available on client_fd=%d", cs);
			ssize_t n = recv(cs, cbuf, sizeof(cbuf), 0);
			// LOGD("SMTP[PROXY]: recv from client returned %zd", n);
			if (n <= 0) { 
				LOGD("SMTP[PROXY]: client disconnected (%zd), breaking", n); 
				break; 
			}
			
			// Log first few bytes for debugging
			if (n > 0) {
				// SECURITY: could contain passwords - NEVER use in production
				// LOGD("SMTP[PROXY]: client data: %.*s", n > 50 ? 50 : (int)n, cbuf);
			}
			
			size_t off = 0;
			while (off < (size_t)n){
				int w = mbedtls_ssl_write(ssl, cbuf + off, (size_t)n - off);
				if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
				if (w <= 0){ 
					// LOGD("SMTP[PROXY]: ssl_write failed (%d), breaking", w); 
					goto out; 
				}
				off += (size_t)w;
			}
			client_to_up += (size_t)n;
			// LOGD("SMTP[PROXY]: forwarded %zd bytes from client to upstream", n);
		}
		// TLS -> Client
		if (FD_ISSET(up, &rfds)){
			// LOGD("SMTP[PROXY]: data available on upstream_fd=%d", up);
			int n = mbedtls_ssl_read(ssl, ubuf, sizeof(ubuf));
			// LOGD("SMTP[PROXY]: ssl_read returned %d", n);
			if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) { /* noop */ }
			else if (n <= 0){ 
				LOGD("SMTP[PROXY]: upstream disconnected (%d), breaking", n); 
				break; 
			}
			else{
				// Log first few bytes for debugging
				if (n > 0) {
					// SECURITY: could contain passwords - NEVER use in production
					// LOGD("SMTP[PROXY]: upstream data: %.*s", n > 50 ? 50 : n, ubuf);
				}
				
				if (send_all(cs, ubuf, (size_t)n) != 0){ 
					// LOGD("SMTP[PROXY]: send_all to client failed, breaking"); 
					break; 
				}
				up_to_client += (size_t)n;
				// LOGD("SMTP[PROXY]: forwarded %d bytes from upstream to client", n);
			}
		}
	}
out:
	// LOGD("SMTP[PROXY]: proxy loop ended after %d iterations", loop_count);
	LOGD("proxy summary: up->client=%uB client->up=%uB", (unsigned)up_to_client, (unsigned)client_to_up);
}

// ============================================================================
// LINE READING UTILITIES
// ============================================================================

static int recv_line_crlf_to(int fd, char* buf, size_t cap, int timeout_ms){
	size_t off = 0; if (cap == 0) return -1;
	while (off + 1 < cap){
		fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
		struct timeval tv; tv.tv_sec = timeout_ms/1000; tv.tv_usec = (timeout_ms%1000)*1000;
		int r = select(fd+1, &rfds, NULL, NULL, &tv);
		if (r <= 0) return -1;
		char c; ssize_t n = recv(fd, &c, 1, 0);
		if (n <= 0) return -1;
		buf[off++] = c;
		if (off >= 2 && buf[off-2] == '\r' && buf[off-1] == '\n') break;
	}
	buf[off] = 0;
	return (int)off;
}

// ============================================================================
// SMTP HELPERS
// ============================================================================

static size_t filter_caps_remove_starttls(const char* in, size_t inlen, char* out, size_t cap){
	size_t o = 0, i = 0;
	while (i < inlen){
		size_t l = i;
		while (l < inlen && in[l] != '\n') l++;
		size_t len = (l < inlen ? (l+1 - i) : (inlen - i));
		int drop = 0;
		if (len >= 4) {
			// Line starts with "250"?
			if (in[i]=='2' && in[i+1]=='5' && in[i+2]=='0'){
				// Case-insensitive "STARTTLS" in the line?
				for (size_t k=i; k<i+len; ++k){
					if ((k+8) <= i+len){
						if ((in[k]=='S'||in[k]=='s') && (in[k+1]=='T'||in[k+1]=='t') &&
							(in[k+2]=='A'||in[k+2]=='a') && (in[k+3]=='R'||in[k+3]=='r') &&
							(in[k+4]=='T'||in[k+4]=='t') && (in[k+5]=='T'||in[k+5]=='t') &&
							(in[k+6]=='L'||in[k+6]=='l') && (in[k+7]=='S'||in[k+7]=='s')) {
							drop = 1; break;
						}
					}
				}
			}
		}
		if (!drop){
			if (o + len <= cap){ memcpy(out + o, in + i, len); o += len; }
		}
		i += len;
	}
	return o;
}

static int smtp_starttls_plain_phase(int cs, int up_fd){
	char buf[4096];

	// 1) Read upstream banner
	int n = recv_line_crlf_to(up_fd, buf, sizeof(buf), 8000);
	if (n <= 0) { LOGE("SMTP[587]: no banner from upstream (%d)", n); return -1; }
	buf[n] = 0;
	// LOGD("SMTP[587] upstream banner: %.*s", n-2, buf); // -2: don't log CRLF

	// Send to client
	if (write_all(cs, buf, n) != 0) { LOGE("SMTP[587]: write banner to client failed"); return -1; }

	// 2) Read client EHLO/HELO and forward to upstream
	n = recv_line_crlf_to(cs, buf, sizeof(buf), 8000);
	if (n <= 0) { LOGE("SMTP[587]: no EHLO from client (%d)", n); return -1; }
	if (!strncasecmp(buf, "HELO ", 5)) { memmove(buf+1, buf, n); buf[0] = 'E'; } // HELO->EHLO
	// LOGD("SMTP[587] client first: %.*s", n-2, buf);
	if (write_all(up_fd, buf, n) != 0) { LOGE("SMTP[587]: forward EHLO to upstream failed"); return -1; }

	// 3) Read 250* capabilities, filter STARTTLS, ensure AUTH
	char caps[8192], filtered[8192];
	size_t tot = 0;
	int done = 0;
	while (!done && tot + 1 < sizeof(caps)){
		char line[1024];
		int l = recv_line_crlf_to(up_fd, line, sizeof(line), 8000);
		if (l <= 0) { LOGE("SMTP[587]: failed to read 250* (%d)", l); return -1; }
		if (tot + (size_t)l >= sizeof(caps)) return -1;
		memcpy(caps + tot, line, (size_t)l);
		tot += (size_t)l;
		// Is this the final line? ("250 " with space)
		if (l >= 4 && line[0]=='2' && line[1]=='5' && line[2]=='0' && line[3]==' ') done = 1;
	}
	caps[tot] = 0;

	size_t outlen = filter_caps_remove_starttls(caps, tot, filtered, sizeof(filtered));
	
	// Always ensure AUTH PLAIN LOGIN is present
	if (!strcasestr(filtered, "AUTH PLAIN") && !strcasestr(filtered, "AUTH LOGIN")) {
		// Find the last line (250 with space) and insert AUTH before it
		char* final_250 = strstr(filtered, "250 ");
		if (final_250) {
			// Find the start of the final line
			char* line_start = final_250;
			while (line_start > filtered && line_start[-1] != '\n') {
				line_start--;
			}
			
			// Calculate the length of the final line
			size_t final_line_len = strlen(final_250);
			
			// Move the final line to make room for AUTH
			memmove(line_start + 22, line_start, final_line_len + 1);
			
			// Insert AUTH capability
			memcpy(line_start, "250-AUTH PLAIN LOGIN\r\n", 22);
			
			outlen += 22;
		} else {
			// Fallback: append at the end
			outlen = strlcat(filtered, "250-AUTH PLAIN LOGIN\r\n", sizeof(filtered));
		}
	}

	if (write_all(cs, filtered, outlen) != 0) { LOGE("SMTP[587]: write 250* to client failed"); return -1; }
	LOGD("SMTP[587]: 250* capabilities forwarded (STARTTLS stripped, AUTH injected/present)");
	LOGD("SMTP[587]: capabilities sent to client (%d bytes)", (int)outlen-2);

	// 4) Send STARTTLS to upstream
	static const char *cmd = "STARTTLS\r\n";
	if (write_all(up_fd, cmd, (int)strlen(cmd)) != 0) { LOGE("SMTP[587]: send STARTTLS failed"); return -1; }

	// 5) Wait for 220 Ready
	n = recv_line_crlf_to(up_fd, buf, sizeof(buf), 8000);
	if (n <= 0) { LOGE("SMTP[587]: no reply to STARTTLS (%d)", n); return -1; }
	buf[n] = 0;
	// LOGD("SMTP[587] upstream after STARTTLS: %.*s", n-2, buf);
	if (strncmp(buf, "220", 3) != 0) { LOGE("SMTP[587]: STARTTLS rejected: %.*s", n-2, buf); return -1; }

	return 0;
}

static int smtp_post_tls_ehlo(mbedtls_ssl_context* ssl){
	const char* name = (g_ehlo_name[0] ? g_ehlo_name : "[127.0.0.1]");
	char line[320];
	int w = snprintf(line, sizeof(line), "EHLO %s\r\n", name);
	if (w <= 0) return -1;
	
	int s = mbedtls_ssl_write(ssl, (const unsigned char*)line, (size_t)w);
	if (s <= 0){
		LOGE("SMTP[587/TLS]: send EHLO failed (%d)", s);
		return -1;
	}
	
	// Read 250* until terminator "250 <space>"
	unsigned char rbuf[2048];
	int done = 0;
	for (int i=0; i<16 && !done; i++){
		int r = mbedtls_ssl_read(ssl, rbuf, sizeof(rbuf));
		if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE){ i--; continue; }
		if (r <= 0) break;
		for (int j = 3; j < r; j++){
			if (rbuf[j-3]=='\n' && rbuf[j-2]=='2' && rbuf[j-1]=='5' && rbuf[j]=='0' && (j+1<r && rbuf[j+1]==' ')){
				done = 1; break;
			}
		}
	}
	// LOGD("SMTP[587/TLS]: post-TLS EHLO done");
	return 0;
}





// ============================================================================
// PROTOCOL HANDLERS
// ============================================================================

static void handle_imap(int cs, tls_env_t* env){
	char who[64]; name_of_fd(cs, who, sizeof(who));
	__sync_add_and_fetch(&g_imap_clients, 1);
	LOGD("IMAP: client connected (%s) active=%d", who, g_imap_clients);

	int up = tcp_connect_blocking(UP_IMAP_HOST, UP_IMAP_PORT);
	if (up < 0){
		LOGE("IMAP: connect %s:%s failed: errno=%d (%s)", UP_IMAP_HOST, UP_IMAP_PORT, errno, strerror(errno));
		goto out;
	}

	mbedtls_ssl_context ssl; memset(&ssl, 0, sizeof(ssl));
	int hr = tls_wrap_fd(&ssl, env, up, UP_IMAP_HOST);
	if (hr != 0){
		LOGE("IMAP: TLS handshake failed: %d (%s)", hr, tls_err(hr));
		close(up);
		goto out;
	}
	LOGD("IMAP: TLS handshake ok; proxying");

	// CRITICAL: Read upstream *OK banner and send to client immediately
	char line[2048];
	int n = mbedtls_ssl_read(&ssl, (unsigned char*)line, sizeof(line));
	if (n <= 0){
		LOGE("IMAP: failed to read upstream banner (%d)", n);
	}else{
		if (write_all(cs, line, (size_t)n) != 0){
			LOGE("IMAP: write banner to client failed");
		}else{
			// LOGD("IMAP upstream banner forwarded (%d bytes)", n);
		}
	}

	// Then transparent proxy (Client<->UpstreamTLS)
	proxy_loop_plain_tls(cs, &ssl);

	// Cleanup
	mbedtls_ssl_close_notify(&ssl);
	tls_bio_t* bio = (tls_bio_t*)ssl.p_bio; if (bio) free(bio);
	mbedtls_ssl_free(&ssl);
	close(up);

out:
	close(cs);
	int left = __sync_sub_and_fetch(&g_imap_clients, 1);
	LOGD("IMAP: session closed active=%d", left);
}

static void handle_smtp(int cs, tls_env_t* env){
	char who[64]; name_of_fd(cs, who, sizeof(who));
	__sync_add_and_fetch(&g_smtp_clients, 1);
	LOGD("SMTP: client connected (%s) active=%d", who, g_smtp_clients);

	// Connect to 587 + STARTTLS
	int up_fd = tcp_connect_blocking(UP_SMTP_HOST, UP_SMTP_PORT);
	if (up_fd < 0){
		LOGE("connect %s:%s failed: errno=%d (%s)", UP_SMTP_HOST, UP_SMTP_PORT, errno, strerror(errno));
		goto out;
	}
	LOGD("SMTP: connected to 587; entering STARTTLS phase");

	if (smtp_starttls_plain_phase(cs, up_fd) != 0){
		LOGE("SMTP: STARTTLS phase failed");
		close(up_fd);
		goto out;
	}

	// Negotiate upstream TLS immediately
	mbedtls_ssl_context ssl; memset(&ssl, 0, sizeof(ssl));
	int hr = tls_wrap_fd(&ssl, env, up_fd, UP_SMTP_HOST);
	if (hr != 0){
		LOGE("SMTP: TLS handshake fail: %d (%s)", hr, tls_err(hr));
		close(up_fd);
		goto out;
	}
	LOGD("SMTP: TLS handshake ok");

	// Send post-TLS EHLO and consume 250* internally
	if (smtp_post_tls_ehlo(&ssl) != 0){
		LOGE("SMTP: post-TLS EHLO failed");
		mbedtls_ssl_close_notify(&ssl);
		tls_bio_t* bio = (tls_bio_t*)ssl.p_bio; if (bio) free(bio);
		mbedtls_ssl_free(&ssl);
		close(up_fd);
		goto out;
	}

	LOGD("SMTP: entering proxy loop (client plain <-> upstream TLS)...");
	LOGD("SMTP: client socket=%d, upstream socket=%d", cs, up_fd);
	proxy_loop_plain_tls(cs, &ssl);

	// Cleanup
	mbedtls_ssl_close_notify(&ssl);
	tls_bio_t* bio = (tls_bio_t*)ssl.p_bio; if (bio) free(bio);
	mbedtls_ssl_free(&ssl);
	close(up_fd);

out:
	close(cs);
	int left = __sync_sub_and_fetch(&g_smtp_clients, 1);
	LOGD("SMTP: session closed active=%d", left);
}

// ============================================================================
// THREADING AND MAIN
// ============================================================================

static void* serve_thread_impl(void* arg){
	serve_args_t* a = (serve_args_t*)arg;
	while (g_run){
		struct sockaddr_in ca; socklen_t cl=sizeof(ca);
		int cs = accept(a->ls, (struct sockaddr*)&ca, &cl);
		if (cs < 0){
			if (errno==EINTR) continue;
			LOGE("accept error: errno=%d (%s)", errno, strerror(errno));
			continue;
		}
		set_nosigpipe(cs);
		if (a->is_imap) handle_imap(cs, a->env);
		else            handle_smtp(cs, a->env);
	}
	return NULL;
}

static void* hb(void* _){
	while (g_run){
		LOGD("hb: alive pid=%d imap=%d smtp=%d", getpid(), g_imap_clients, g_smtp_clients);
		sleep(20);
	}
	return NULL;
}

static void on_sig(int s){ (void)s; g_run = 0; LOGI("signal -> shutdown request"); }

int main(int argc, char** argv){
	(void)argc; (void)argv; // Suppress unused parameter warnings
	
	signal(SIGTERM, on_sig);
	signal(SIGINT,  on_sig);

	// Single-instance PID lock
	mkdir("/var/run", 0755);
	int lock_fd = open("/var/run/iCloudMailFixd.pid", O_RDWR|O_CREAT, 0644);
	if (lock_fd >= 0){
		if (lockf(lock_fd, F_TLOCK, 0) != 0){
			LOGE("already running, exiting");
			return 0;
		}
		char buf[32]; int n = snprintf(buf, sizeof(buf), "%d\n", getpid());
		if (n>0) write(lock_fd, buf, (size_t)n);
	}

	LOGI("start: iCloudMailFixd pid=%d", getpid());

	tls_env_t env;
	if (tls_env_init(&env) != 0){
		LOGE("tls_env_init failed");
		return 2;
	}

	int ls_imap = tcp_listen(LISTEN_IP, LISTEN_IMAP);
	int ls_smtp = tcp_listen(LISTEN_IP, LISTEN_SMTP);
	if (ls_imap < 0 || ls_smtp < 0){
		LOGE("listen failed");
		tls_env_free(&env);
		return 0;
	}
	LOGI("listening on %s:%d", LISTEN_IP, LISTEN_IMAP);
	LOGI("listening on %s:%d", LISTEN_IP, LISTEN_SMTP);

	serve_args_t a_imap = { ls_imap, 1, &env };
	serve_args_t a_smtp = { ls_smtp, 0, &env };

	pthread_t th_imap, th_smtp, th_hb;
	pthread_create(&th_imap, NULL, serve_thread_impl, &a_imap);
	pthread_create(&th_smtp, NULL, serve_thread_impl, &a_smtp);
	pthread_create(&th_hb,   NULL, hb,           NULL);

	while (g_run) sleep(1);

	shutdown(ls_imap, SHUT_RDWR); close(ls_imap);
	shutdown(ls_smtp, SHUT_RDWR); close(ls_smtp);

	pthread_cancel(th_imap); pthread_cancel(th_smtp); pthread_cancel(th_hb);
	pthread_join(th_imap, NULL); pthread_join(th_smtp, NULL); pthread_join(th_hb, NULL);

	tls_env_free(&env);
	LOGI("stopped");
	return 0;
}