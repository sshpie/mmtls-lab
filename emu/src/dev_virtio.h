/* dev_virtio.h — virtio-mmio transport + virtio-blk device */
#pragma once
#include <stdint.h>
#include <stdbool.h>

/* virtio-mmio register offsets */
#define VIRTIO_MM_MAGIC         0x000   /* 0x74726976 */
#define VIRTIO_MM_VERSION       0x004   /* 2 (modern) */
#define VIRTIO_MM_DEVICE_ID     0x008
#define VIRTIO_MM_VENDOR_ID     0x00c
#define VIRTIO_MM_DEVICE_FEATS  0x010
#define VIRTIO_MM_DEVICE_FEATS_SEL 0x014
#define VIRTIO_MM_DRIVER_FEATS  0x020
#define VIRTIO_MM_DRIVER_FEATS_SEL 0x024
#define VIRTIO_MM_QUEUE_SEL     0x030
#define VIRTIO_MM_QUEUE_NUM_MAX 0x034
#define VIRTIO_MM_QUEUE_NUM     0x038
#define VIRTIO_MM_QUEUE_READY   0x044
#define VIRTIO_MM_QUEUE_NOTIFY  0x050
#define VIRTIO_MM_INTERRUPT_STATUS 0x060
#define VIRTIO_MM_INTERRUPT_ACK    0x064
#define VIRTIO_MM_STATUS        0x070
#define VIRTIO_MM_QUEUE_DESC_LO 0x080
#define VIRTIO_MM_QUEUE_DESC_HI 0x084
#define VIRTIO_MM_QUEUE_AVAIL_LO 0x090
#define VIRTIO_MM_QUEUE_AVAIL_HI 0x094
#define VIRTIO_MM_QUEUE_USED_LO 0x0a0
#define VIRTIO_MM_QUEUE_USED_HI 0x0a4
#define VIRTIO_MM_CONFIG_GEN    0x0fc
#define VIRTIO_MM_CONFIG        0x100

/* virtio device IDs */
#define VIRTIO_ID_NET   1
#define VIRTIO_ID_BLOCK 2

/* virtio-blk feature bits */
#define VIRTIO_BLK_F_RO         5
#define VIRTIO_BLK_F_BLK_SIZE   6
#define VIRTIO_BLK_F_GEOMETRY   4
#define VIRTIO_F_VERSION_1      32

/* virtio-blk config */
typedef struct __attribute__((packed)) VirtioBlkConfig {
    uint64_t capacity;      /* sectors */
    uint32_t size_max;
    uint32_t seg_max;
    struct { uint16_t cylinders; uint8_t heads; uint8_t sectors; } geometry;
    uint32_t blk_size;      /* 512 */
    struct { uint8_t physical_block_exp, alignment_offset; uint16_t min_io_size; uint32_t opt_io_size; } topology;
    uint8_t  writeback;
    uint8_t  _pad0[3];
    uint32_t max_discard_sectors;
    uint32_t max_discard_seg;
    uint32_t discard_sector_alignment;
    uint32_t max_write_zeroes_sectors;
    uint32_t max_write_zeroes_seg;
    uint8_t  write_zeroes_may_unmap;
    uint8_t  _pad1[3];
} VirtioBlkConfig;

/* virtio-blk request types */
#define VIRTIO_BLK_T_IN     0
#define VIRTIO_BLK_T_OUT    1
#define VIRTIO_BLK_T_FLUSH  4

/* virtio descriptor */
typedef struct __attribute__((packed)) VirtqDesc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} VirtqDesc;

#define VIRTQ_DESC_F_NEXT     1
#define VIRTQ_DESC_F_WRITE    2

typedef struct __attribute__((packed)) VirtqAvail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
} VirtqAvail;

typedef struct __attribute__((packed)) VirtqUsedElem {
    uint32_t id;
    uint32_t len;
} VirtqUsedElem;

typedef struct __attribute__((packed)) VirtqUsed {
    uint16_t        flags;
    uint16_t        idx;
    VirtqUsedElem   ring[];
} VirtqUsed;

#define VIRTQ_NUM_MAX 256

typedef struct VirtQueue {
    uint32_t num;
    uint64_t desc_addr;
    uint64_t avail_addr;
    uint64_t used_addr;
    bool     ready;
    uint16_t last_avail_idx;
} VirtQueue;

struct PhysMem;  /* forward */

typedef struct VirtioBlk {
    /* mmio transport state */
    uint32_t device_feats_sel;
    uint32_t driver_feats;
    uint32_t driver_feats_sel;
    uint32_t queue_sel;
    uint32_t status;
    uint32_t interrupt_status;

    VirtQueue vq[2];   /* typically 1 queue for blk */
    VirtioBlkConfig config;

    /* backing disk */
    int      disk_fd;
    bool     read_only;
    uint64_t disk_sectors;

    /* IRQ */
    int irq;
    void (*raise_irq)(void *gic, int irq, bool level);
    void *gic;

    /* back-pointer to phys mem for descriptor walking */
    struct PhysMem *mem;
} VirtioBlk;

void     virtio_blk_init(VirtioBlk *v, const char *disk_path, bool ro,
                         int irq, void *gic,
                         void (*raise_irq)(void*, int, bool),
                         struct PhysMem *mem);
uint64_t virtio_blk_read(void *dev, uint64_t off, int size);
void     virtio_blk_write(void *dev, uint64_t off, uint64_t val, int size);
void     virtio_blk_process(VirtioBlk *v);   /* called on QUEUE_NOTIFY */
