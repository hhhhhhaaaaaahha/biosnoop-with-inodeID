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