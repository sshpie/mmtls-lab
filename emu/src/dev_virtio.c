/* dev_virtio.c — virtio-mmio transport + virtio-blk */
#include "dev_virtio.h"
#include "mem.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct __attribute__((packed)) {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
} VirtioBlkReq;

void virtio_blk_init(VirtioBlk *v, const char *disk_path, bool ro,
                     int irq, void *gic,
                     void (*raise_irq)(void*, int, bool),
                     struct PhysMem *mem)
{
    memset(v, 0, sizeof(*v));
    v->irq       = irq;
    v->gic       = gic;
    v->raise_irq = raise_irq;
    v->mem       = mem;
    v->read_only = ro;

    int flags = ro ? O_RDONLY : O_RDWR;
    v->disk_fd = open(disk_path, flags);
    if (v->disk_fd < 0) {
        perror(disk_path);
        return;
    }

    struct stat st;
    fstat(v->disk_fd, &st);
    v->disk_sectors = st.st_size / 512;

    memset(&v->config, 0, sizeof(v->config));
    v->config.capacity = v->disk_sectors;
    v->config.blk_size = 512;
    v->config.seg_max  = 128;
}

uint64_t virtio_blk_read(void *dev, uint64_t off, int size)
{
    VirtioBlk *v = dev;
    (void)size;

    switch (off) {
    case VIRTIO_MM_MAGIC:         return 0x74726976;
    case VIRTIO_MM_VERSION:       return 2;
    case VIRTIO_MM_DEVICE_ID:     return VIRTIO_ID_BLOCK;
    case VIRTIO_MM_VENDOR_ID:     return 0x554d4551;
    case VIRTIO_MM_DEVICE_FEATS:
        if (v->device_feats_sel == 0) {
            uint32_t f = (1u << VIRTIO_F_VERSION_1) |
                         (1u << VIRTIO_BLK_F_BLK_SIZE);
            if (v->read_only) f |= (1u << VIRTIO_BLK_F_RO);
            return f;
        }
        return 1; /* VIRTIO_F_VERSION_1 high word */
    case VIRTIO_MM_QUEUE_NUM_MAX: return VIRTQ_NUM_MAX;
    case VIRTIO_MM_QUEUE_READY:
        if (v->queue_sel < 2) return v->vq[v->queue_sel].ready;
        return 0;
    case VIRTIO_MM_INTERRUPT_STATUS: return v->interrupt_status;
    case VIRTIO_MM_STATUS:           return v->status;
    case VIRTIO_MM_CONFIG_GEN:       return 0;
    default:
        if (off >= VIRTIO_MM_CONFIG &&
            off < VIRTIO_MM_CONFIG + sizeof(v->config)) {
            uint64_t coff = off - VIRTIO_MM_CONFIG;
            uint64_t val = 0;
            uint8_t *cp = (uint8_t*)&v->config + coff;
            int n = size;
            if (n + coff > sizeof(v->config)) n = sizeof(v->config) - coff;
            memcpy(&val, cp, n);
            return val;
        }
        return 0;
    }
}

void virtio_blk_write(void *dev, uint64_t off, uint64_t val, int size)
{
    VirtioBlk *v = dev;
    (void)size;

    switch (off) {
    case VIRTIO_MM_DEVICE_FEATS_SEL:  v->device_feats_sel = val; break;
    case VIRTIO_MM_DRIVER_FEATS_SEL:  v->driver_feats_sel = val; break;
    case VIRTIO_MM_DRIVER_FEATS:      v->driver_feats = val; break;
    case VIRTIO_MM_QUEUE_SEL:
        if (val < 2) v->queue_sel = val;
        break;
    case VIRTIO_MM_QUEUE_NUM:
        if (v->queue_sel < 2) v->vq[v->queue_sel].num = val;
        break;
    case VIRTIO_MM_QUEUE_READY:
        if (v->queue_sel < 2) v->vq[v->queue_sel].ready = val;
        break;
    case VIRTIO_MM_QUEUE_DESC_LO:
        if (v->queue_sel < 2)
            v->vq[v->queue_sel].desc_addr =
                (v->vq[v->queue_sel].desc_addr & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF);
        break;
    case VIRTIO_MM_QUEUE_DESC_HI:
        if (v->queue_sel < 2)
            v->vq[v->queue_sel].desc_addr =
                (v->vq[v->queue_sel].desc_addr & 0x00000000FFFFFFFFULL) | ((val & 0xFFFFFFFF) << 32);
        break;
    case VIRTIO_MM_QUEUE_AVAIL_LO:
        if (v->queue_sel < 2)
            v->vq[v->queue_sel].avail_addr =
                (v->vq[v->queue_sel].avail_addr & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF);
        break;
    case VIRTIO_MM_QUEUE_AVAIL_HI:
        if (v->queue_sel < 2)
            v->vq[v->queue_sel].avail_addr =
                (v->vq[v->queue_sel].avail_addr & 0x00000000FFFFFFFFULL) | ((val & 0xFFFFFFFF) << 32);
        break;
    case VIRTIO_MM_QUEUE_USED_LO:
        if (v->queue_sel < 2)
            v->vq[v->queue_sel].used_addr =
                (v->vq[v->queue_sel].used_addr & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF);
        break;
    case VIRTIO_MM_QUEUE_USED_HI:
        if (v->queue_sel < 2)
            v->vq[v->queue_sel].used_addr =
                (v->vq[v->queue_sel].used_addr & 0x00000000FFFFFFFFULL) | ((val & 0xFFFFFFFF) << 32);
        break;
    case VIRTIO_MM_QUEUE_NOTIFY:
        virtio_blk_process(v);
        break;
    case VIRTIO_MM_INTERRUPT_ACK:
        v->interrupt_status &= ~val;
        break;
    case VIRTIO_MM_STATUS:
        v->status = val;
        if (val == 0) {
            /* Reset */
            for (int i = 0; i < 2; i++) {
                v->vq[i].ready = 0;
                v->vq[i].last_avail_idx = 0;
            }
            v->interrupt_status = 0;
        }
        break;
    default: break;
    }
}

/* Read a descriptor from guest memory */
static VirtqDesc read_desc(VirtioBlk *v, uint64_t base, uint16_t idx)
{
    uint64_t pa = base + (uint64_t)idx * sizeof(VirtqDesc);
    VirtqDesc d;
    uint8_t *p = mem_ptr(v->mem, pa);
    if (p) {
        memcpy(&d, p, sizeof(d));
    } else {
        d.addr  = (uint64_t)mem_read(v->mem, pa, 8);
        d.len   = (uint32_t)mem_read(v->mem, pa + 8, 4);
        d.flags = (uint16_t)mem_read(v->mem, pa + 12, 2);
        d.next  = (uint16_t)mem_read(v->mem, pa + 14, 2);
    }
    return d;
}

void virtio_blk_process(VirtioBlk *v)
{
    VirtQueue *vq = &v->vq[0];
    if (!vq->ready || !vq->avail_addr || !vq->desc_addr || !vq->used_addr)
        return;

    uint16_t avail_idx;
    {
        uint8_t *p = mem_ptr(v->mem, vq->avail_addr + 2);
        if (p) avail_idx = *(uint16_t*)p;
        else   avail_idx = (uint16_t)mem_read(v->mem, vq->avail_addr + 2, 2);
    }

    bool did_work = false;

    while (vq->last_avail_idx != avail_idx) {
        uint16_t ring_idx = vq->last_avail_idx % vq->num;
        uint64_t ring_pa  = vq->avail_addr + 4 + (uint64_t)ring_idx * 2;
        uint16_t desc_idx;
        {
            uint8_t *p = mem_ptr(v->mem, ring_pa);
            if (p) desc_idx = *(uint16_t*)p;
            else   desc_idx = (uint16_t)mem_read(v->mem, ring_pa, 2);
        }

        /* desc[0]: request header */
        VirtqDesc d0 = read_desc(v, vq->desc_addr, desc_idx);
        VirtioBlkReq req;
        {
            uint8_t *p = mem_ptr(v->mem, d0.addr);
            if (p) memcpy(&req, p, sizeof(req));
            else {
                req.type     = (uint32_t)mem_read(v->mem, d0.addr, 4);
                req.reserved = (uint32_t)mem_read(v->mem, d0.addr + 4, 4);
                req.sector   = (uint64_t)mem_read(v->mem, d0.addr + 8, 8);
            }
        }

        /* Collect data descriptors and find status descriptor */
        uint32_t bytes_done = 0;
        uint8_t  status     = 0;  /* success */
        VirtqDesc last_d    = {0};
        VirtqDesc cur = d0;

        /* Walk to data desc(s) */
        uint16_t cur_idx = desc_idx;
        while (cur.flags & VIRTQ_DESC_F_NEXT) {
            VirtqDesc next = read_desc(v, vq->desc_addr, cur.next);
            cur_idx = cur.next;

            /* Is this a data buffer or the status byte? */
            if (!(next.flags & VIRTQ_DESC_F_NEXT) &&
                !(next.flags & VIRTQ_DESC_F_WRITE) == 0 &&
                next.len == 1) {
                /* Might be status — skip for now, save as last */
                last_d = next;
                cur = next;
                break;
            }

            /* Data buffer */
            uint8_t *gptr = mem_ptr(v->mem, next.addr);
            if (req.type == VIRTIO_BLK_T_IN) {
                /* Read from disk into guest memory */
                if (gptr) {
                    ssize_t r = pread(v->disk_fd, gptr, next.len,
                                      (off_t)(req.sector * 512) + bytes_done);
                    if (r < 0) status = 1;
                    else bytes_done += r;
                } else {
                    uint8_t tmp[4096];
                    uint32_t rem = next.len;
                    uint64_t ga = next.addr;
                    uint32_t bd = 0;
                    while (rem > 0) {
                        uint32_t chunk = rem < sizeof(tmp) ? rem : sizeof(tmp);
                        ssize_t r = pread(v->disk_fd, tmp, chunk,
                                          (off_t)(req.sector * 512) + bytes_done + bd);
                        if (r <= 0) { status = 1; break; }
                        for (ssize_t i = 0; i < r; i++)
                            mem_write(v->mem, ga + bd + i, tmp[i], 1);
                        bd += r; rem -= r;
                    }
                    bytes_done += bd;
                }
            } else if (req.type == VIRTIO_BLK_T_OUT && !v->read_only) {
                if (gptr) {
                    ssize_t w = pwrite(v->disk_fd, gptr, next.len,
                                       (off_t)(req.sector * 512) + bytes_done);
                    if (w < 0) status = 1;
                    else bytes_done += w;
                } else {
                    uint8_t tmp[4096];
                    uint32_t rem = next.len;
                    uint64_t ga = next.addr;
                    uint32_t bd = 0;
                    while (rem > 0) {
                        uint32_t chunk = rem < sizeof(tmp) ? rem : sizeof(tmp);
                        for (uint32_t i = 0; i < chunk; i++)
                            tmp[i] = (uint8_t)mem_read(v->mem, ga + bd + i, 1);
                        ssize_t w = pwrite(v->disk_fd, tmp, chunk,
                                           (off_t)(req.sector * 512) + bytes_done + bd);
                        if (w <= 0) { status = 1; break; }
                        bd += w; rem -= w;
                    }
                    bytes_done += bd;
                }
            } else if (req.type == VIRTIO_BLK_T_FLUSH) {
                fdatasync(v->disk_fd);
            }

            cur = next;
        }

        /* last_d or cur is the status descriptor */
        VirtqDesc status_d = (last_d.addr != 0) ? last_d : cur;
        if (status_d.addr) {
            uint8_t *sp = mem_ptr(v->mem, status_d.addr);
            if (sp) *sp = status;
            else    mem_write(v->mem, status_d.addr, status, 1);
        }

        /* Write to used ring */
        uint64_t used_ring_pa = vq->used_addr + 4 +
                                (uint64_t)(mem_read(v->mem, vq->used_addr + 2, 2) % vq->num)
                                * sizeof(VirtqUsedElem);
        {
            uint8_t *p = mem_ptr(v->mem, used_ring_pa);
            if (p) {
                ((VirtqUsedElem*)p)->id  = desc_idx;
                ((VirtqUsedElem*)p)->len = bytes_done;
            } else {
                mem_write(v->mem, used_ring_pa,     desc_idx,    4);
                mem_write(v->mem, used_ring_pa + 4, bytes_done,  4);
            }
        }
        /* Increment used->idx */
        uint64_t used_idx_pa = vq->used_addr + 2;
        uint16_t used_idx = (uint16_t)mem_read(v->mem, used_idx_pa, 2);
        used_idx++;
        {
            uint8_t *p = mem_ptr(v->mem, used_idx_pa);
            if (p) *(uint16_t*)p = used_idx;
            else   mem_write(v->mem, used_idx_pa, used_idx, 2);
        }

        vq->last_avail_idx++;
        did_work = true;
    }

    if (did_work) {
        v->interrupt_status |= 1;
        if (v->raise_irq && v->gic)
            v->raise_irq(v->gic, v->irq, true);
    }
}
