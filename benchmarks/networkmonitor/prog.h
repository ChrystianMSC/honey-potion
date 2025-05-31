#ifndef COMMON_H
#define COMMON_H

#include <linux/types.h>  // for __u32, __u64, etc.

struct anomaly_event {
    __u32 src_ip;
    __u64 total_bytes;
};

#endif
