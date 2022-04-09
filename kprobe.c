// +build ignore

#include "bpf_tracing.h"
#include "common.h"
#include <linux/types.h>
#define TASK_COMM_LEN 16

#define EVENT_TYPE_RECV 0
#define EVENT_TYPE_SEND 1

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps/connectlist") connectlist = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(void *),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps/acceptlist") acceptlist = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(void *),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps/recvfromlist") recvfromlist = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(void *),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps/sendtolist") sendtolist = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(void *),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps/dataevent") dataevent = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};

struct dataevent_t {
	u8   type;
	char buf[1024];
};

struct bpf_map_def SEC("maps/messagelist") messagelist = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(struct dataevent_t),
	.max_entries = 1,
};


//
// tcp_v4_connect
//
SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid();

	struct sock *sk;
	sk = (struct sock *)PT_REGS_PARM1(ctx);

	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(&comm, sizeof(comm));
	if (comm[0] == 'c' && comm[1] == 'u') {
		bpf_map_update_elem(&connectlist, &pid, &sk, BPF_ANY);
	}
	return 0;
}
SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid();

	struct sock *sk;
	sk = bpf_map_lookup_elem(&connectlist, &pid);
	if (sk == 0) {
		return 0;
	}
	// bpf_trace_printk("sockp->sk_family: %d\\n", sk->__sk_common.skc_dport);
	return 0;
}

//
// recvfrom
//
SEC("kprobe/sys_recvfrom")
int kprobe__sys_recvfrom(struct pt_regs *ctx) {
	char *buf;
	buf = (char *)PT_REGS_PARM2(ctx);

	u32 pid = bpf_get_current_pid_tgid();

	struct sock *sk;
	sk = bpf_map_lookup_elem(&connectlist, &pid);
	if (sk == 0)
		return 0;
	bpf_map_update_elem(&recvfromlist, &pid, &buf, BPF_ANY);
	return 0;
}
SEC("kretprobe/sys_recvfrom")
int kretprobe__sys_recvfrom(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid();

	char **buf, *bufp;
	buf = bpf_map_lookup_elem(&recvfromlist, &pid);
	if (buf == 0) 
		return 0;
	bufp = *buf;

	// Create Buffer on BPF map
	// BPF stack size is limited to 512 bytes
	int zero = 0;
	struct dataevent_t* data = bpf_map_lookup_elem(&messagelist, &zero);
	if (!data)
		return 0;
	bpf_probe_read(&data->buf, sizeof(data->buf), (void *)bufp);

	data->type = EVENT_TYPE_RECV;
	bpf_perf_event_output(ctx, &dataevent, BPF_F_CURRENT_CPU, data, sizeof(*data));
	bpf_map_delete_elem(&recvfromlist, &pid);
	return 0;
}

//
// sendto
//
SEC("kprobe/sys_sendto")
int kprobe__sys_sendto(struct pt_regs *ctx) {
	char *buf;
	buf = (char *)PT_REGS_PARM2(ctx);

	u32 pid = bpf_get_current_pid_tgid();

	struct sock *sk;
	sk = bpf_map_lookup_elem(&connectlist, &pid);
	if (sk == 0)
		return 0;
	bpf_map_update_elem(&sendtolist, &pid, &buf, BPF_ANY);
	return 0;
}
SEC("kretprobe/sys_sendto")
int kretprobe__sys_sendto(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid();

	char **buf, *bufp;
	buf = bpf_map_lookup_elem(&sendtolist, &pid);
	if (buf == 0)
		return 0;
	bufp = *buf;

	// Create Buffer on BPF map
	// BPF stack size is limited to 512 bytes
	int zero = 0;
	struct dataevent_t* data = bpf_map_lookup_elem(&messagelist, &zero);
	if (!data)
		return 0;
	data->type = EVENT_TYPE_SEND;
	bpf_probe_read(&data->buf, sizeof(data->buf), (void *)bufp);

	bpf_perf_event_output(ctx, &dataevent, BPF_F_CURRENT_CPU, data, sizeof(*data));
	bpf_map_delete_elem(&sendtolist, &pid);
	return 0;
}
