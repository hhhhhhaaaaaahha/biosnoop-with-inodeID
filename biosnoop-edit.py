#! /usr/bin/python3
# @lint-avoid-python-3-compatibility-imports
#
# biosnoop  Trace block device I/O and print details including issuing PID.
#           For Linux, uses BCC, eBPF.
#
# This uses in-kernel eBPF maps to cache process details (PID and comm) by I/O
# request, as well as a starting timestamp for calculating I/O latency.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 16-Sep-2015   Brendan Gregg   Created this.
# 11-Feb-2016   Allan McAleavy  updated for BPF_PERF_OUTPUT

from __future__ import print_function
from bcc import BPF
import re
import argparse

# arguments
examples = """examples:
    ./biosnoop           # trace all block I/O
    ./biosnoop -Q        # include OS queued time
"""
parser = argparse.ArgumentParser(
    description="Trace block I/O",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-Q", "--queue", action="store_true",
    help="include OS queued time")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/fs.h>

// bug fix
struct start_req_t {
    u64 ts;
    u64 data_len;
};
// end of bug fix

struct val_t {
    u64 ts;
    u32 pid;
    u64 inode_id; // new line
    char name[TASK_COMM_LEN];
};

struct data_t {
    u32 pid;
    u64 rwflag;
    u64 delta;
    u64 qdelta;
    u64 sector;
    u64 len;
    u64 ts;
    u64 inode_id; // new line
    char disk_name[DISK_NAME_LEN];
    char name[TASK_COMM_LEN];
};

// BPF_HASH(start, struct request *); // bug fix
BPF_HASH(start, struct request *, struct start_req_t); // new line
BPF_HASH(infobyreq, struct request *, struct val_t);
BPF_PERF_OUTPUT(events);

// cache PID and comm by-req
int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct val_t val = {};
    u64 ts;

    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.inode_id = req->bio->i_ino;
        val.pid = bpf_get_current_pid_tgid() >> 32;
        if (##QUEUE##) {
            val.ts = bpf_ktime_get_ns();
        }
        infobyreq.update(&req, &val);
    }
    return 0;
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    // bug fix
    /*
    u64 ts;
    ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
    */

    struct start_req_t start_req = {
        .ts = bpf_ktime_get_ns(),
        .data_len = req->__data_len
    };
    start.update(&req, &start_req);
    // end of bug fix

    return 0;
}

// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    // u64 *tsp; // bug fix
    struct start_req_t *startp; // bug fix
    struct val_t *valp;
    struct data_t data = {};
    u64 ts;

    // fetch timestamp and calculate delta
    // tsp = start.lookup(&req);
    // if (tsp == 0) {
    startp = start.lookup(&req); // bug fix
    if (startp == 0) {           // bug fix
        // missed tracing issue
        return 0;
    }
    ts = bpf_ktime_get_ns();
    // data.delta = ts - *tsp;
    data.delta = ts - startp->ts; // bug fix
    data.ts = ts / 1000;
    data.qdelta = 0;

    valp = infobyreq.lookup(&req);
    data.len = startp->data_len; // bug fix
    if (valp == 0) {
        // data.len = req->__data_len; // bug fix
        strcpy(data.name, "?");
    } else {
        if (##QUEUE##) {
            // data.qdelta = *tsp - valp->ts; // bug fix
            data.qdelta = startp->ts - valp->ts; // bug fix
        }
        data.pid = valp->pid;
        // data.len = req->__data_len; // bug fix
        data.sector = req->__sector;
        data.inode_id = valp->inode_id; // new line
        bpf_probe_read(&data.name, sizeof(data.name), valp->name);
        struct gendisk *rq_disk = req->rq_disk;
        bpf_probe_read(&data.disk_name, sizeof(data.disk_name),
                       rq_disk->disk_name);
    }

/*
 * The following deals with a kernel version change (in mainline 4.7, although
 * it may be backported to earlier kernels) with how block request write flags
 * are tested. We handle both pre- and post-change versions here. Please avoid
 * kernel version tests like this as much as possible: they inflate the code,
 * test, and maintenance burden.
 */
#ifdef REQ_WRITE
    data.rwflag = !!(req->cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    data.rwflag = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    data.rwflag = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif

    events.perf_submit(ctx, &data, sizeof(data));
    start.delete(&req);
    infobyreq.delete(&req);

    return 0;
}
"""
if args.queue:
    bpf_text = bpf_text.replace('##QUEUE##', '1')
else:
    bpf_text = bpf_text.replace('##QUEUE##', '0')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")
if BPF.get_kprobe_functions(b'blk_start_request'): # can be removed due to Linux no longer using single queue
    b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start") # can be removed due to Linux no longer using single queue
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_account_io_done",
    fn_name="trace_req_completion")

# header
print("%-11s %-14s %-6s %-10s %-7s %-1s %-22s %-7s" % ("TIME(s)", "COMM", "PID", "inodeID", # new line
    "DISK", "T", "SECTOR", "BYTES"), end="")
if args.queue:
    print("%7s " % ("QUE(ms)"), end="")
print("%7s" % "LAT(ms)")

rwflg = ""
start_ts = 0
prev_ts = 0
delta = 0

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    global start_ts
    if start_ts == 0:
        start_ts = event.ts

    if event.rwflag == 1:
        rwflg = "W"
    else:
        rwflg = "R"

    delta = float(event.ts) - start_ts

    print("%-11.6f %-14.14s %-6s %-10s %-7s %-1s %-22s %-7s" % (  # new line
        delta / 1000000, event.name.decode('utf-8', 'replace'), event.pid, event.inode_id, # new line
        event.disk_name.decode('utf-8', 'replace'), rwflg, event.sector,
        event.len), end="")
    if args.queue:
        print("%7.2f " % (float(event.qdelta) / 1000000), end="")
    print("%7.2f" % (float(event.delta) / 1000000))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

