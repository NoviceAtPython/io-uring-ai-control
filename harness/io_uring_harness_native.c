/* Native Nyx io_uring harness (persistent mode) — WIDENED op surface.
 *
 * Speaks the raw Nyx hypercall API directly:
 *   - one-time handshake + all setup BEFORE the snapshot
 *   - snapshot at ACQUIRE; each RELEASE resets to it with a fresh payload
 * so every iteration only submits fuzzed ops (no per-iter setup).
 * Submits the KERNEL text range for Intel-PT, so coverage = io_uring kernel paths.
 *
 * v2: 22 -> ~60 ops. The previous op table saturated at ~5,600 edges after 800M
 * execs because most of io_uring was unreachable. This adds sockets (accept/
 * connect/send_zc/msg), cancellation, msg_ring (2nd ring), registered files+
 * buffers (fixed I/O, files_update), futex, waitid, xattr, path ops, multishot.
 */
#define _GNU_SOURCE
#include "nyx.h"
#include <liburing.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <linux/openat2.h>
#include <signal.h>
#include <sys/syscall.h>

/* raw io_uring_register() so we can fuzz the whole 33-opcode register surface,
 * not just the 2 liburing wrappers we were using. */
static int reg_raw(int fd, unsigned opcode, void *arg, unsigned nr)
{
    return syscall(__NR_io_uring_register, fd, opcode, arg, nr);
}

#define KERNEL_STEXT 0xffffffff81000000ULL
#define KERNEL_ETEXT 0xffffffff82305508ULL
#define MAX_OPS   96
#define MAX_INPUT 2048
#define NOPS      61          /* number of distinct op cases below */
#define NRINGS    8           /* pool of rings with different IORING_SETUP_* personalities */

/* Each ring config is a structurally different machine inside the kernel
 * (poll thread, polled I/O, 128-byte SQEs, restricted, no-mmap, ...). Creating
 * them all pre-snapshot lets the input pick one per exec at zero perf cost. */
/* NOTE: SQPOLL is deliberately excluded. Its kernel poll thread submits
 * asynchronously, so identical inputs produce different coverage — it dropped
 * fleet stability from ~30% to 14%, poisoning the feedback signal for only ~2%
 * more edges. The remaining personalities are deterministic enough to keep. */
static const unsigned ring_cfg[NRINGS] = {
    IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN,
    0,
    IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQSIZE,
    IORING_SETUP_IOPOLL,
    IORING_SETUP_SQE128 | IORING_SETUP_CQE32,
    IORING_SETUP_CLAMP | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_TASKRUN_FLAG,
    IORING_SETUP_NO_SQARRAY | IORING_SETUP_COOP_TASKRUN,
    IORING_SETUP_R_DISABLED,   /* rejects submits until REGISTER_ENABLE_RINGS */
};

static void detect_kernel_range(uint64_t *stext, uint64_t *etext)
{
    *stext = KERNEL_STEXT; *etext = KERNEL_ETEXT;
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return;
    char line[256], name[128]; unsigned long long a; char ty; uint64_t s = 0, e = 0;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%llx %c %127s", &a, &ty, name) == 3) {
            if (!strcmp(name, "_stext")) s = a;
            else if (!strcmp(name, "_etext")) e = a;
        }
    }
    fclose(f);
    if (s && e && e > s) { *stext = s; *etext = e; }
}

static uint8_t *PL; static uint32_t PLEN, POS;
static int rd8(unsigned *v){ if (POS >= PLEN) return -1; *v = PL[POS++]; return 0; }

int main(void)
{
    hprintf("[iou] native harness (widened) start\n");

    host_config_t host_config;
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
    if (host_config.host_magic != NYX_HOST_MAGIC) habort("[iou] bad NYX_HOST_MAGIC");

    agent_config_t agent_config = {0};
    agent_config.agent_magic = NYX_AGENT_MAGIC;
    agent_config.agent_version = NYX_AGENT_VERSION;
    agent_config.agent_timeout_detection = 0;
    agent_config.agent_tracing = 0;
    agent_config.agent_ijon_tracing = 0;
    agent_config.agent_non_reload_mode = 0;
    agent_config.coverage_bitmap_size = host_config.bitmap_size;
    uint8_t *tb = mmap(NULL, host_config.bitmap_size ? host_config.bitmap_size : 0x10000,
                       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(tb, 0, host_config.bitmap_size);
    agent_config.trace_buffer_vaddr = (uintptr_t)tb;
    agent_config.ijon_trace_buffer_vaddr = 0;
    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

    kAFL_payload *payload = mmap(NULL, host_config.payload_buffer_size,
                                 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(payload, 0, host_config.payload_buffer_size);
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload);

    uint64_t stext, etext;
    detect_kernel_range(&stext, &etext);
    hprintf("[iou] kernel PT range 0x%llx-0x%llx\n", (unsigned long long)stext, (unsigned long long)etext);
    uint64_t range0[3] = { stext, etext, 0 };
    kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uintptr_t)range0);
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    /* ================= one-time setup (lives in the snapshot) ================= */
    /* Sockets/pipes in the fd pool mean send/write ops can raise SIGPIPE, which
     * kills the harness silently (no dmesg) and looks like "harness returned
     * unexpectedly". Errors come back via CQE instead. */
    signal(SIGPIPE, SIG_IGN);

    /* ring pool: one per IORING_SETUP_* personality (fall back to plain on failure) */
    struct io_uring rings[NRINGS], ring2;
    int ring_ok[NRINGS];
    for (int i = 0; i < NRINGS; i++) {
        struct io_uring_params rp; memset(&rp, 0, sizeof rp);
        rp.flags = ring_cfg[i];
        if (rp.flags & IORING_SETUP_CQSIZE) rp.cq_entries = 128;   /* required or init fails */
        ring_ok[i] = (io_uring_queue_init_params(64, &rings[i], &rp) == 0);
        if (!ring_ok[i]) ring_ok[i] = (io_uring_queue_init(64, &rings[i], 0) == 0);
    }
    if (!ring_ok[0]) habort("[iou] no usable ring");
    if (io_uring_queue_init(64, &ring2, 0) < 0) habort("[iou] ring2 init failed");  /* msg_ring target */

    /* scratch dir + files for path ops */
    mkdir("/tmp/fz", 0777);
    int t;
    t = open("/tmp/fz/a", O_RDWR | O_CREAT, 0644); if (t >= 0) { (void)!write(t, "aaaa", 4); close(t); }
    t = open("/tmp/fz/b", O_RDWR | O_CREAT, 0644); if (t >= 0) { (void)!write(t, "bbbb", 4); close(t); }

    /* fd pool: files, pipes, eventfd, epoll, and REAL sockets */
    int pp[2] = {-1,-1}; (void)!pipe(pp);
    int sp[2] = {-1,-1}; (void)!socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); sa.sin_port = 0;
    int lsn = socket(AF_INET, SOCK_STREAM, 0);
    if (lsn >= 0) { (void)!bind(lsn, (struct sockaddr *)&sa, sizeof sa); (void)!listen(lsn, 16); }
    socklen_t slen = sizeof sa;
    if (lsn >= 0) (void)!getsockname(lsn, (struct sockaddr *)&sa, &slen);  /* sa now = live loopback addr */

    int fds[16];
    fds[0]  = open("/dev/null", O_RDWR);
    fds[1]  = memfd_create("m0", 0); if (fds[1] >= 0) (void)!ftruncate(fds[1], 8192);
    fds[2]  = eventfd(0, EFD_NONBLOCK);
    fds[3]  = pp[0];
    fds[4]  = pp[1];
    fds[5]  = open("/tmp/fz/a", O_RDWR);
    fds[6]  = socket(AF_INET, SOCK_DGRAM, 0);
    fds[7]  = lsn;                       /* listening TCP socket */
    fds[8]  = sp[0];                     /* connected unix pair */
    fds[9]  = sp[1];
    fds[10] = epoll_create1(0);
    fds[11] = open("/dev/zero", O_RDONLY);
    fds[12] = memfd_create("m1", 0); if (fds[12] >= 0) (void)!ftruncate(fds[12], 8192);
    fds[13] = socket(AF_INET, SOCK_STREAM, 0);   /* spare, for connect */
    fds[14] = open("/tmp/fz/b", O_RDWR);
    fds[15] = dup(fds[0]);
    const int NF = 16;
    #define FD(i) fds[(i) % NF]

    static char b0[2048], b1[2048];
    struct iovec iov[2] = { { b0, sizeof b0 }, { b1, sizeof b1 } };

    /* registered files + buffers -> enables fixed I/O, files_update, direct ops */
    for (int i = 0; i < NRINGS; i++) {
        if (!ring_ok[i]) continue;
        io_uring_register_files(&rings[i], fds, NF);
        io_uring_register_buffers(&rings[i], iov, 2);
    }

    static uint32_t futex_word = 0;
    static struct futex_waitv waitv[1];
    memset(waitv, 0, sizeof waitv);
    waitv[0].uaddr = (uintptr_t)&futex_word;
    waitv[0].flags = FUTEX2_SIZE_U32;
    static struct msghdr mh; memset(&mh, 0, sizeof mh);
    mh.msg_iov = iov; mh.msg_iovlen = 1;
    static struct epoll_event evs[4];
    static siginfo_t si;
    static struct open_how how; memset(&how, 0, sizeof how); how.flags = O_RDWR;
    static struct __kernel_timespec ts_short = { 0, 50000 };

    hprintf("[iou] setup done (%d ops, %d fds), entering persistent loop\n", NOPS, NF);

    /* ================= persistent fuzz loop ================= */
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
    while (1) {
        kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

        PLEN = payload->size;
        if (PLEN > MAX_INPUT) PLEN = MAX_INPUT;
        PL = payload->data; POS = 0;

        /* the input picks which ring personality to drive this iteration */
        unsigned ri = 0; rd8(&ri);
        for (int k = 0; k < NRINGS && !ring_ok[ri % NRINGS]; k++) ri++;
        struct io_uring *R = &rings[ri % NRINGS];

        unsigned op, a, b, c;
        int queued = 0, nops = 0;
        while (rd8(&op) == 0) {
            if (++nops > MAX_OPS) break;
            struct io_uring_sqe *sqe = io_uring_get_sqe(R);
            if (!sqe) { io_uring_submit(R); queued = 0; sqe = io_uring_get_sqe(R); if (!sqe) break; }
            a = b = c = 0;
            switch (op % NOPS) {
            /* --- original core --- */
            case 0:  io_uring_prep_nop(sqe); break;
            case 1:  rd8(&a); io_uring_prep_readv(sqe, FD(a), iov, 1, 0); break;
            case 2:  rd8(&a); io_uring_prep_writev(sqe, FD(a), iov, 1, 0); break;
            case 3:  rd8(&a); io_uring_prep_read(sqe, FD(a), b0, (rd8(&b), b ? b : 64) % sizeof b0, 0); break;
            case 4:  rd8(&a); io_uring_prep_write(sqe, FD(a), b0, 64, 0); break;
            case 5:  rd8(&a); io_uring_prep_fsync(sqe, FD(a), (rd8(&b), b & 1) ? IORING_FSYNC_DATASYNC : 0); break;
            case 6:  rd8(&a); io_uring_prep_poll_add(sqe, FD(a), POLLIN | POLLOUT); break;
            case 7:  io_uring_prep_poll_remove(sqe, (rd8(&a), (__u64)a)); break;
            case 8:  io_uring_prep_timeout(sqe, &ts_short, (rd8(&a), a), (rd8(&b), b)); break;
            case 9:  io_uring_prep_timeout_remove(sqe, (rd8(&a), (__u64)a), 0); break;
            case 10: rd8(&a); io_uring_prep_recv(sqe, FD(a), b0, 64, 0); break;
            case 11: rd8(&a); io_uring_prep_send(sqe, FD(a), b0, 64, 0); break;
            case 12: rd8(&a); io_uring_prep_fadvise(sqe, FD(a), 0, 4096, POSIX_FADV_NORMAL); break;
            case 13: rd8(&a); io_uring_prep_fallocate(sqe, FD(a), 0, 0, 4096); break;
            case 14: io_uring_prep_openat(sqe, AT_FDCWD, "/tmp/fz/a", O_RDWR, 0); break;
            case 15: rd8(&a); rd8(&b); io_uring_prep_splice(sqe, FD(a), -1, FD(b), -1, 64, 0); break;
            case 16: rd8(&a); rd8(&b); io_uring_prep_tee(sqe, FD(a), FD(b), 64, 0); break;
            case 17: rd8(&a); io_uring_prep_epoll_ctl(sqe, FD(10), FD(a), EPOLL_CTL_ADD, &evs[0]); break;
            case 18: io_uring_prep_provide_buffers(sqe, b1, 256, 2, (rd8(&a), a), 0); break;
            case 19: io_uring_prep_remove_buffers(sqe, 2, (rd8(&a), a)); break;
            case 20: rd8(&a); io_uring_prep_sync_file_range(sqe, FD(a), 4096, 0, 0); break;
            case 21: rd8(&a); io_uring_prep_statx(sqe, FD(a), "", AT_EMPTY_PATH, 0, NULL); break;

            /* --- NEW: sockets --- */
            case 22: slen = sizeof sa; io_uring_prep_accept(sqe, FD(7), (struct sockaddr *)&sa, &slen, (rd8(&a), a & 0x800)); break;
            case 23: slen = sizeof sa; io_uring_prep_multishot_accept(sqe, FD(7), (struct sockaddr *)&sa, &slen, 0); break;
            case 24: rd8(&a); io_uring_prep_connect(sqe, FD(a), (struct sockaddr *)&sa, sizeof sa); break;
            case 25: rd8(&a); io_uring_prep_bind(sqe, FD(a), (struct sockaddr *)&sa, sizeof sa); break;
            case 26: rd8(&a); io_uring_prep_listen(sqe, FD(a), (rd8(&b), b)); break;
            case 27: io_uring_prep_socket(sqe, AF_INET, (rd8(&a), (a & 1) ? SOCK_DGRAM : SOCK_STREAM), 0, 0); break;
            case 28: rd8(&a); io_uring_prep_shutdown(sqe, FD(a), (rd8(&b), b % 3)); break;
            case 29: rd8(&a); io_uring_prep_sendmsg(sqe, FD(a), &mh, 0); break;
            case 30: rd8(&a); io_uring_prep_recvmsg(sqe, FD(a), &mh, 0); break;
            case 31: rd8(&a); io_uring_prep_recvmsg_multishot(sqe, FD(a), &mh, 0); break;
            case 32: rd8(&a); io_uring_prep_recv_multishot(sqe, FD(a), b0, 64, 0); break;
            case 33: rd8(&a); io_uring_prep_send_zc(sqe, FD(a), b0, 64, 0, (rd8(&b), b & 1)); break;
            case 34: rd8(&a); io_uring_prep_sendmsg_zc(sqe, FD(a), &mh, 0); break;

            /* --- NEW: cancellation / linking (historically buggy) --- */
            case 35: io_uring_prep_cancel(sqe, (void *)(unsigned long)(rd8(&a), a), 0); break;
            case 36: rd8(&a); io_uring_prep_cancel_fd(sqe, FD(a), (rd8(&b), b & IORING_ASYNC_CANCEL_ALL)); break;
            case 37: io_uring_prep_link_timeout(sqe, &ts_short, (rd8(&a), a & 1)); break;
            case 38: io_uring_prep_timeout_update(sqe, &ts_short, (rd8(&a), (__u64)a), 0); break;
            case 39: io_uring_prep_poll_update(sqe, (rd8(&a), (__u64)a), (rd8(&b), (__u64)b), POLLIN, (rd8(&c), c & 3)); break;
            case 40: rd8(&a); io_uring_prep_poll_multishot(sqe, FD(a), POLLIN); break;

            /* --- NEW: registered files/buffers (fixed I/O) --- */
            /* fixed I/O: buf MUST lie inside the registered buffer at buf_index,
             * otherwise the kernel derives a bogus offset from the wrong region. */
            case 41: rd8(&a); rd8(&b); { int bi = b % 2;
                     io_uring_prep_read_fixed(sqe, FD(a), iov[bi].iov_base, 64, 0, bi); } break;
            case 42: rd8(&a); rd8(&b); { int bi = b % 2;
                     io_uring_prep_write_fixed(sqe, FD(a), iov[bi].iov_base, 64, 0, bi); } break;
            case 43: io_uring_prep_files_update(sqe, fds, (rd8(&a), (a % NF) + 1), (rd8(&b), b % NF)); break;
            case 44: rd8(&a); io_uring_prep_fixed_fd_install(sqe, FD(a), 0); break;
            case 45: io_uring_prep_close_direct(sqe, (rd8(&a), a % NF)); break;
            case 46: rd8(&a); io_uring_prep_close(sqe, FD(a)); break;

            /* --- NEW: msg_ring (cross-ring) --- */
            case 47: io_uring_prep_msg_ring(sqe, ring2.ring_fd, (rd8(&a), a), (rd8(&b), (__u64)b), 0); break;
            case 48: rd8(&a); io_uring_prep_msg_ring_fd(sqe, ring2.ring_fd, FD(a), (rd8(&b), b % NF), 0, 0); break;

            /* --- NEW: futex / waitid --- */
            case 49: io_uring_prep_futex_wake(sqe, &futex_word, 1, FUTEX_BITSET_MATCH_ANY, FUTEX2_SIZE_U32, 0); break;
            case 50: io_uring_prep_futex_wait(sqe, &futex_word, (rd8(&a), a), FUTEX_BITSET_MATCH_ANY, FUTEX2_SIZE_U32, 0); break;
            case 51: io_uring_prep_futex_waitv(sqe, waitv, 1, 0); break;
            case 52: io_uring_prep_waitid(sqe, P_ALL, 0, &si, WEXITED | WNOHANG, 0); break;

            /* --- NEW: path / xattr / misc --- */
            case 53: io_uring_prep_renameat(sqe, AT_FDCWD, "/tmp/fz/a", AT_FDCWD, "/tmp/fz/c", 0); break;
            case 54: io_uring_prep_unlinkat(sqe, AT_FDCWD, "/tmp/fz/c", (rd8(&a), a & AT_REMOVEDIR)); break;
            case 55: io_uring_prep_mkdirat(sqe, AT_FDCWD, "/tmp/fz/d", 0755); break;
            case 56: io_uring_prep_linkat(sqe, AT_FDCWD, "/tmp/fz/a", AT_FDCWD, "/tmp/fz/e", 0); break;
            case 57: rd8(&a); io_uring_prep_fsetxattr(sqe, FD(a), "user.fz", b0, 0, 8); break;
            case 58: rd8(&a); io_uring_prep_ftruncate(sqe, FD(a), (rd8(&b), (loff_t)b * 64)); break;
            case 59: io_uring_prep_epoll_wait(sqe, FD(10), evs, 4, 0); break;

            /* NEW: the whole io_uring_register() surface — 33 opcodes, we used 2.
             * A fuzzed opcode + real-memory arg drives dispatch/validation of
             * PBUF_RING / RESTRICTIONS / PERSONALITY / IOWQ_* / ENABLE_RINGS / etc.
             * (ENABLE_RINGS is also what un-gates the R_DISABLED ring in the pool.) */
            default: { unsigned ropc = 0, rnr = 0; rd8(&ropc); rd8(&rnr);
                       reg_raw(R->ring_fd, ropc % 34, b1, rnr % 8);
                       io_uring_prep_nop(sqe); } break;   /* case 60 */
            }

            /* widened SQE flags: BUFFER_SELECT + FIXED_FILE were never exercised */
            rd8(&c);
            io_uring_sqe_set_flags(sqe, c & (IOSQE_IO_LINK | IOSQE_IO_DRAIN | IOSQE_ASYNC |
                                             IOSQE_IO_HARDLINK | IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE));
            sqe->buf_group = (c >> 4);      /* give BUFFER_SELECT a group to resolve */
            io_uring_sqe_set_data(sqe, (void *)(unsigned long)op);
            if (++queued >= 64) { io_uring_submit(R); queued = 0; }
        }
        io_uring_submit(R);
        io_uring_get_events(R);      /* DEFER_TASKRUN: deterministic completion point */

        struct io_uring_cqe *cqe;
        for (int i = 0; i < 256; i++) {
            if (io_uring_peek_cqe(R, &cqe) != 0) break;
            io_uring_cqe_seen(R, cqe);
        }
        for (int i = 0; i < 64; i++) {   /* drain the msg_ring target too */
            if (io_uring_peek_cqe(&ring2, &cqe) != 0) break;
            io_uring_cqe_seen(&ring2, cqe);
        }

        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
    return 0;
}
