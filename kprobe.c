// +build ignore

#include "bpf_tracing.h"
#include "common.h"
#include <linux/types.h>
#define TASK_COMM_LEN 16

#define EVENT_TYPE_CONNECT 0
#define EVENT_TYPE_ACCEPT 1
#define EVENT_TYPE_RECV 2
#define EVENT_TYPE_SEND 3
#define EVENT_TYPE_CLOSE 4

char __license[] SEC("license") = "Dual MIT/GPL";


struct connectlist_t {
	int  sockfd;
	void *sock;
};
struct bpf_map_def SEC("maps/connectlist") connectlist = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(struct connectlist_t *),
	.max_entries = 256,
};

struct probe_cache_t {
	int  sockfd;
	void *buf;
};
struct bpf_map_def SEC("maps/probe_cache") probe_cache = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32), // pid
	.value_size  = sizeof(struct probe_cache_t), // sockfd, *buf
	.max_entries = 256,
};

struct bpf_map_def SEC("maps/dataevent") dataevent = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};

// Create Buffer on BPF map
// BPF stack size is limited to 512 bytes
struct dataevent_t {
	u8   type;
	u32  sock_fd;
	u8   buf[1024];
};
const struct dataevent_t *unused __attribute__((unused));
struct bpf_map_def SEC("maps/messagelist") messagelist = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(struct dataevent_t),
	.max_entries = 1,
};


//
// sys_connect
//
SEC("kprobe/sys_connect")
int kprobe__sys_connect(struct pt_regs *ctx) {
	int sockfd = (int)PT_REGS_PARM1(ctx);
	u32 pid = bpf_get_current_pid_tgid();

	struct sock *sk;
	sk = (struct sock *)PT_REGS_PARM1(ctx);

	struct connectlist_t connect = {};
	connect.sockfd = sockfd;
	connect.sock = sk;
	bpf_map_update_elem(&connectlist, &pid, &connect, BPF_ANY);

	return 0;
}
SEC("kretprobe/sys_connect")
int kretprobe__sys_connect(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid();

	struct connectlist_t *connect;
	connect = bpf_map_lookup_elem(&connectlist, &pid);
	if (connect == 0) {
		return 0;
	}

	int zero = 0;
	struct dataevent_t* data = bpf_map_lookup_elem(&messagelist, &zero);
	if (!data)
		return 0;

	data->type = EVENT_TYPE_CONNECT;
	data->sock_fd = connect->sockfd;

	bpf_perf_event_output(ctx, &dataevent, BPF_F_CURRENT_CPU, data, sizeof(*data));

	return 0;
}

//
// sys_read
//
SEC("kprobe/sys_read")
int kprobe__sys_read(struct pt_regs *ctx) {
	int sockfd = (int)PT_REGS_PARM1(ctx);
	char *buf;
	buf = (char *)PT_REGS_PARM2(ctx);

	u32 pid = bpf_get_current_pid_tgid();

	struct connectlist_t *connect;
	connect = bpf_map_lookup_elem(&connectlist, &pid);
	if (connect == 0)
		return 0;

	struct probe_cache_t cache = {};
	cache.sockfd = sockfd; 
	cache.buf = buf;
	bpf_map_update_elem(&probe_cache, &pid, &cache, BPF_ANY);
	return 0;
}
SEC("kretprobe/sys_read")
int kretprobe__sys_read(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid();

	struct probe_cache_t* cache;
	cache = bpf_map_lookup_elem(&probe_cache, &pid);
	if (cache == 0) 
		return 0;

	int zero = 0;
	struct dataevent_t* data = bpf_map_lookup_elem(&messagelist, &zero);
	if (!data)
		return 0;

	data->type = EVENT_TYPE_RECV;
	data->sock_fd = cache->sockfd;
	bpf_probe_read(&data->buf, sizeof(data->buf), (void *)cache->buf);
	bpf_perf_event_output(ctx, &dataevent, BPF_F_CURRENT_CPU, data, sizeof(*data));
	bpf_map_delete_elem(&probe_cache, &pid);
	return 0;
}

//
// sys_recv
//
SEC("kprobe/sys_recv")
int kprobe__sys_recv(struct pt_regs *ctx) {
	int sockfd = (int)PT_REGS_PARM1(ctx);
	char *buf;
	buf = (char *)PT_REGS_PARM2(ctx);

	u32 pid = bpf_get_current_pid_tgid();

	struct connectlist_t *connect;
	connect = bpf_map_lookup_elem(&connectlist, &pid);
	if (connect == 0)
		return 0;

	struct probe_cache_t cache = {};
	cache.sockfd = sockfd; 
	cache.buf = buf;
	bpf_map_update_elem(&probe_cache, &pid, &cache, BPF_ANY);
	return 0;
}
SEC("kretprobe/sys_recv")
int kretprobe__sys_recv(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid();

	struct probe_cache_t* cache;
	cache = bpf_map_lookup_elem(&probe_cache, &pid);
	if (cache == 0) 
		return 0;

	int zero = 0;
	struct dataevent_t* data = bpf_map_lookup_elem(&messagelist, &zero);
	if (!data)
		return 0;

	data->type = EVENT_TYPE_RECV;
	data->sock_fd = cache->sockfd;
	bpf_probe_read(&data->buf, sizeof(data->buf), (void *)cache->buf);
	bpf_perf_event_output(ctx, &dataevent, BPF_F_CURRENT_CPU, data, sizeof(*data));
	bpf_map_delete_elem(&probe_cache, &pid);
	return 0;
}

//
// sys_recvfrom
//
SEC("kprobe/sys_recvfrom")
int kprobe__sys_recvfrom(struct pt_regs *ctx) {
	int sockfd = (int)PT_REGS_PARM1(ctx);
	char *buf;
	buf = (char *)PT_REGS_PARM2(ctx);

	u32 pid = bpf_get_current_pid_tgid();

	struct connectlist_t *connect;
	connect = bpf_map_lookup_elem(&connectlist, &pid);
	if (connect == 0)
		return 0;

	struct probe_cache_t cache = {};
	cache.sockfd = sockfd; 
	cache.buf = buf;
	bpf_map_update_elem(&probe_cache, &pid, &cache, BPF_ANY);
	return 0;
}
SEC("kretprobe/sys_recvfrom")
int kretprobe__sys_recvfrom(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid();

	struct probe_cache_t* cache;
	cache = bpf_map_lookup_elem(&probe_cache, &pid);
	if (cache == 0) 
		return 0;

	int zero = 0;
	struct dataevent_t* data = bpf_map_lookup_elem(&messagelist, &zero);
	if (!data)
		return 0;

	data->type = EVENT_TYPE_RECV;
	data->sock_fd = cache->sockfd;
	bpf_probe_read(&data->buf, sizeof(data->buf), (void *)cache->buf);
	bpf_perf_event_output(ctx, &dataevent, BPF_F_CURRENT_CPU, data, sizeof(*data));
	bpf_map_delete_elem(&probe_cache, &pid);
	return 0;
}

//
// sys_write
//
SEC("kprobe/sys_write")
int kprobe__sys_write(struct pt_regs *ctx) {
	int sockfd = (int)PT_REGS_PARM1(ctx);
	char *buf;
	buf = (char *)PT_REGS_PARM2(ctx);

	u32 pid = bpf_get_current_pid_tgid();

	struct connectlist_t *connect;
	connect = bpf_map_lookup_elem(&connectlist, &pid);
	if (connect == 0)
		return 0;

	struct probe_cache_t cache = {};
	cache.sockfd = sockfd; 
	cache.buf = buf;
	bpf_map_update_elem(&probe_cache, &pid, &cache, BPF_ANY);
	return 0;
}
SEC("kretprobe/sys_write")
int kretprobe__sys_write(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid();

	struct probe_cache_t* cache;
	cache = bpf_map_lookup_elem(&probe_cache, &pid);
	if (cache == 0)
		return 0;
	
	int zero = 0;
	struct dataevent_t* data = bpf_map_lookup_elem(&messagelist, &zero);
	if (!data)
		return 0;

	data->type = EVENT_TYPE_SEND;
	data->sock_fd = cache->sockfd;
	bpf_probe_read(&data->buf, sizeof(data->buf), (void *)cache->buf);
	bpf_perf_event_output(ctx, &dataevent, BPF_F_CURRENT_CPU, data, sizeof(*data));
	bpf_map_delete_elem(&probe_cache, &pid);
	return 0;
}

//
// sys_send
//
SEC("kprobe/sys_send")
int kprobe__sys_send(struct pt_regs *ctx) {
	int sockfd = (int)PT_REGS_PARM1(ctx);
	char *buf;
	buf = (char *)PT_REGS_PARM2(ctx);

	u32 pid = bpf_get_current_pid_tgid();

	struct connectlist_t *connect;
	connect = bpf_map_lookup_elem(&connectlist, &pid);
	if (connect == 0)
		return 0;

	struct probe_cache_t cache = {};
	cache.sockfd = sockfd; 
	cache.buf = buf;
	bpf_map_update_elem(&probe_cache, &pid, &cache, BPF_ANY);
	return 0;
}
SEC("kretprobe/sys_send")
int kretprobe__sys_send(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid();

	struct probe_cache_t* cache;
	cache = bpf_map_lookup_elem(&probe_cache, &pid);
	if (cache == 0)
		return 0;
	
	int zero = 0;
	struct dataevent_t* data = bpf_map_lookup_elem(&messagelist, &zero);
	if (!data)
		return 0;

	data->type = EVENT_TYPE_SEND;
	data->sock_fd = cache->sockfd;
	bpf_probe_read(&data->buf, sizeof(data->buf), (void *)cache->buf);
	bpf_perf_event_output(ctx, &dataevent, BPF_F_CURRENT_CPU, data, sizeof(*data));
	bpf_map_delete_elem(&probe_cache, &pid);
	return 0;
}


//
// sys_sendto
//
SEC("kprobe/sys_sendto")
int kprobe__sys_sendto(struct pt_regs *ctx) {
	int sockfd = (int)PT_REGS_PARM1(ctx);
	char *buf;
	buf = (char *)PT_REGS_PARM2(ctx);

	u32 pid = bpf_get_current_pid_tgid();

	struct connectlist_t *connect;
	connect = bpf_map_lookup_elem(&connectlist, &pid);
	if (connect == 0)
		return 0;

	struct probe_cache_t cache = {};
	cache.sockfd = sockfd; 
	cache.buf = buf;
	bpf_map_update_elem(&probe_cache, &pid, &cache, BPF_ANY);
	return 0;
}
SEC("kretprobe/sys_sendto")
int kretprobe__sys_sendto(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid();

	struct probe_cache_t* cache;
	cache = bpf_map_lookup_elem(&probe_cache, &pid);
	if (cache == 0)
		return 0;
	
	int zero = 0;
	struct dataevent_t* data = bpf_map_lookup_elem(&messagelist, &zero);
	if (!data)
		return 0;

	data->type = EVENT_TYPE_SEND;
	data->sock_fd = cache->sockfd;
	bpf_probe_read(&data->buf, sizeof(data->buf), (void *)cache->buf);
	bpf_perf_event_output(ctx, &dataevent, BPF_F_CURRENT_CPU, data, sizeof(*data));
	bpf_map_delete_elem(&probe_cache, &pid);
	return 0;
}

//
// sys_close
//
SEC("kprobe/sys_close")
int kprobe__sys_close(struct pt_regs *ctx) {
	int sockfd = PT_REGS_PARM1(ctx);

	u32 pid = bpf_get_current_pid_tgid();

	struct connectlist_t *connect;
	connect = bpf_map_lookup_elem(&connectlist, &pid);
	if (connect == 0)
		return 0;

	int zero = 0;
	struct dataevent_t* data = bpf_map_lookup_elem(&messagelist, &zero);
	if (!data)
		return 0;

	data->type = EVENT_TYPE_CLOSE;
	data->sock_fd = sockfd;

	bpf_perf_event_output(ctx, &dataevent, BPF_F_CURRENT_CPU, data, sizeof(*data));

	return 0;
}
/* printk
   const char fmt_str[] = "close(%d)\n";
   bpf_trace_printk(fmt_str, sizeof(fmt_str), fd);
*/

/*SEC("kretprobe/sys_close")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid();

	struct sock *sk;
	sk = bpf_map_lookup_elem(&connectlist, &pid);
	if (sk == 0) {
		return 0;
	}
	
	return 0;
}*/
