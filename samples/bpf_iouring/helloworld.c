/** helloworld.c
 *  userspace program of helloworld.bpf.c
*/
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "helloworld.skel.h"


 
static int libbpf_print_fn(enum libbpf_print_level level, 
                        const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char const *argv[])
{
    struct helloworld *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* open BPF application */
    skel = helloworld__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* load & verify BPF prorgams */
    err = helloworld__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* attach tracepoint handler */
    err = helloworld__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started!\n \
            Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see the output\n");

    while (1) {
        /* trigger the BPF program */
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    helloworld__destroy(skel);
    return -err;
}


