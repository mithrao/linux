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
    struct helloworld *payload;
    int ret;
    /* set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);
    /* open BPF application */
    payload = helloworld__open_and_load();
	if (!payload) {
		printf("load failed");
		return 0;
	}

    /* attach tracepoint handler */
    ret = helloworld__attach(payload);
    if (ret) {
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
    helloworld__destroy(payload);
    return -ret;
}


