#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/fs.h>

// bug fix
struct start_req_t
{
    u64 ts;
    u64 data_len;
};
// end of bug fix

struct val_t
{
    u64 ts;
    u32 pid;
    char name[TASK_COMM_LEN];
};

// added by Ray
struct inode_t
{
    u64 inode_id[20];
};

struct data_t
{
    u32 pid;
    u64 rwflag;
    u64 delta;
    u64 qdelta;
    u64 sector;
    u64 len;
    u64 ts;
    char disk_name[DISK_NAME_LEN];
    char name[TASK_COMM_LEN];

    // added by Ray
    u64 inode_id_0;
    u64 inode_id_1;
    u64 inode_id_2;
    u64 inode_id_3;
    u64 inode_id_4;
    u64 inode_id_5;
    u64 inode_id_6;
    u64 inode_id_7;
    u64 inode_id_8;
    u64 inode_id_9;
    u64 inode_id_10;
    u64 inode_id_11;
    u64 inode_id_12;
    u64 inode_id_13;
    u64 inode_id_14;
    u64 inode_id_15;
    u64 inode_id_16;
    u64 inode_id_17;
    u64 inode_id_18;
    u64 inode_id_19;
};

// BPF_HASH(start, struct request *); // bug fix
BPF_HASH(start, struct request *, struct start_req_t); // bug fix
BPF_HASH(infobyreq, struct request *, struct val_t);
BPF_HASH(i_inobyreq, struct request *, struct inode_t); // added by Ray
BPF_PERF_OUTPUT(events);

// cache PID and comm by-req
int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct val_t val = {};
    u64 ts;

    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0)
    {
        val.pid = bpf_get_current_pid_tgid() >> 32;
        if (##QUEUE##)
        {
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

    // added by Ray
    struct inode_t inode;
    for (int i = 0; i < 20; i++)
    {
        inode.inode_id[i] = 999999999999999;
    }
    struct bio *tmp = req->bio;
    for (int i = 0; i < 20; i++)
    {
        if (tmp != NULL)
        {
            inode.inode_id[i] = tmp->i_ino;
            tmp = tmp->bi_next;
        }
        else
        {
            break;
        }
    }
    i_inobyreq.update(&req, &inode);

    // bug fix
    struct start_req_t start_req = {
        .ts = bpf_ktime_get_ns(),
        .data_len = req->__data_len};
    start.update(&req, &start_req);

    return 0;
}

// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    // u64 *tsp; // bug fix
    struct start_req_t *startp; // bug fix
    struct val_t *valp;
    struct inode_t *inodep; // added by Ray
    struct data_t data = {};
    u64 ts;

    // fetch timestamp and calculate delta
    // tsp = start.lookup(&req);
    // if (tsp == 0) {
    startp = start.lookup(&req); // bug fix
    if (startp == 0)
    { // bug fix
        // missed tracing issue
        return 0;
    }
    ts = bpf_ktime_get_ns();
    // data.delta = ts - *tsp;
    data.delta = ts - startp->ts; // bug fix
    data.ts = ts / 1000;
    data.qdelta = 0;

    // added by Ray
    inodep = i_inobyreq.lookup(&req);
    if (inodep == 0)
    {
        // missed tracing issue
        return 0;
    }
    data.inode_id_0 = inodep->inode_id[0];
    data.inode_id_1 = inodep->inode_id[1];
    data.inode_id_2 = inodep->inode_id[2];
    data.inode_id_3 = inodep->inode_id[3];
    data.inode_id_4 = inodep->inode_id[4];
    data.inode_id_5 = inodep->inode_id[5];
    data.inode_id_6 = inodep->inode_id[6];
    data.inode_id_7 = inodep->inode_id[7];
    data.inode_id_8 = inodep->inode_id[8];
    data.inode_id_9 = inodep->inode_id[9];
    data.inode_id_10 = inodep->inode_id[10];
    data.inode_id_11 = inodep->inode_id[11];
    data.inode_id_12 = inodep->inode_id[12];
    data.inode_id_13 = inodep->inode_id[13];
    data.inode_id_14 = inodep->inode_id[14];
    data.inode_id_15 = inodep->inode_id[15];
    data.inode_id_16 = inodep->inode_id[16];
    data.inode_id_17 = inodep->inode_id[17];
    data.inode_id_18 = inodep->inode_id[18];
    data.inode_id_19 = inodep->inode_id[19];

    valp = infobyreq.lookup(&req);
    data.len = startp->data_len; // bug fix
    if (valp == 0)
    {
        // data.len = req->__data_len; // bug fix
        strcpy(data.name, "?");
    }
    else
    {
        if (##QUEUE##)
        {
            // data.qdelta = *tsp - valp->ts; // bug fix
            data.qdelta = startp->ts - valp->ts; // bug fix
        }
        data.pid = valp->pid;
        // data.len = req->__data_len; // bug fix
        data.sector = req->__sector;
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