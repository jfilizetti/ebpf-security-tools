#!/usr/bin/env python3
# vim: ts=4 sts=4 sw=4 ai et
#
# ./world_writable_monitor.py
#
# world_writable_monitor.py Monitor files for when they are changed to
#                           world writable or when they are used.
#
# Copyright (c) 2023 Jeremy Filizetti
#
# Adopting the same license as the rest of the BCC
# Licensed under the Apache License, Version 2.0 (the "License")
#
# June 2023   Jeremy Filizetti    Created

from __future__ import print_function
from bcc import BPF
import optparse
import stat
import re
import os
import sys

# taken from /usr/include/linux/magic.h
fstype_to_magic = {
    'adfs' : 0xadf5,
    'affs' : 0xadff,
    'afs' : 0x5346414f,
    'autofs' : 0x0187,
    'ceph' : 0x00c36400,
    'coda' : 0x73757245,
    'ecryptfs' : 0xf15f,
    'efs' : 0x414a53,
    'ext2' : 0xef53,
    'ext3' : 0xef53,
    'xenfs' : 0xabba1974,
    'ext4' : 0xef53,
    'btrfs' : 0x9123683e,
    'nilfs' : 0x3434,
    'f2fs' : 0xf2f52010,
    'hpfs' : 0xf995e849,
    'isofs' : 0x9660,
    'jffs2' : 0x72b6,
    'xfs' : 0x58465342,
    'hostfs' : 0x00c0ffee,
    'overlayfs' : 0x794c7630,
    'fuse' : 0x65735546,
    'minix' : 0x137f,
    'minix2' : 0x2468,
    'minix3' : 0x4d5a,
    'msdos' : 0x4d44,
    'exfat' : 0x2011bab0,
    'ncp' : 0x564c,
    'nfs' : 0x6969,
    'ocfs2' : 0x7461636f,
    'openprom' : 0x9fa1,
    'qnx4' : 0x002f,
    'qnx6' : 0x68191122,
    'afs' : 0x6b414653,
    'reiserfs' : 0x52654973,
    'smb' : 0x517b,
    'cifs' : 0xff534d42,
    'smb2' : 0xfe534d42,
    'cgroup' : 0x27e0eb,
    'cgroup2' : 0x63677270,
    'rdtgroup' : 0x7655821,
    'stack' : 0x57ac6e9d,
    'devpts' : 0x1cd1,
    'binderfs' : 0x6c6f6f70,
    'futexfs' : 0xbad1dea,
    'proc' : 0x9fa0,
    'usbdevice' : 0x9fa2,
    'btrfs' : 0x73727279,
    'bpf' : 0xcafe4a11,
    'udf' : 0x15013346,
    'dma' : 0x444d4142,
}

fstypes = list(fstype_to_magic)
fstypes.sort()

usage = '''
Valid file types:
    all         - all types (default)
    regular     - standard file
    directory   - directory
    socket      - socket
    char        - character device
    block       - block device
    fifo        - FIFO
    link        - symbolic link

Supported file system types:
    %s

Examples:
    ./world_writable_monitor.py                 # monitor operations on or creating world writable files (or setting via chmod)
    ./world_writable_monitor.py -t xfs,ext4     # monitor operations only xfs or ext4 files systems
    ./world_writable_monitor.py -f regular      # monitor operations only regular files
    ./world_writable_monitor.py -f char         # monitor operations only on character devices
''' % (' '.join(fstypes))

class Origin(object):
    TRACE_CHMOD = 0
    TRACE_OPEN = 1
    TRACE_EXECVE = 2

def get_open_flags(value):
    flags = ''
    if value & os.O_ACCMODE:	flags += 'ACCMODE '
    if value & os.O_APPEND:	    flags += 'APPEND '
    if value & os.O_ASYNC:	    flags += 'ASYNC '
    if value & os.O_CLOEXEC:	flags += 'CLOEXEC '
    if value & os.O_CREAT:	    flags += 'CREAT '
    if value & os.O_DIRECT:	    flags += 'DIRECT '
    if value & os.O_DIRECTORY:	flags += 'DIRECTORY '
    if value & os.O_DSYNC:	    flags += 'DSYNC '
    if value & os.O_EXCL:	    flags += 'EXCL '
    if value & os.O_NDELAY:	    flags += 'NDELAY '
    if value & os.O_NOATIME:	flags += 'NOATIME '
    if value & os.O_NOCTTY:	    flags += 'NOCTTY '
    if value & os.O_NOFOLLOW:	flags += 'NOFOLLOW '
    if value & os.O_NONBLOCK:	flags += 'NONBLOCK '
    if value & os.O_PATH:	    flags += 'PATH '
    if value & os.O_RDONLY:	    flags += 'RDONLY '
    if value & os.O_RDWR:	    flags += 'RDWR '
    if value & os.O_RSYNC:	    flags += 'RSYNC '
    if value & os.O_SYNC:	    flags += 'SYNC '
    if value & os.O_TMPFILE:	flags += 'TMPFILE '
    if value & os.O_TRUNC:	    flags += 'TRUNC '
    if value & os.O_WRONLY:	    flags += 'WRONLY '
    # TODO: add a check for this on old systems
    if value & os.O_FSYNC:      flags += 'FSYNC '
    return flags

def print_event(cpu, data, size):
    event = b["events"].event(data)
    if event.type == Origin.TRACE_CHMOD:
        print('%-8s   ' % ('chmod'), end='')
    elif event.type == Origin.TRACE_OPEN:
        print('%-8s   ' % ('open'), end='')
    elif event.type == Origin.TRACE_EXECVE:
        print('%-8s   ' % ('exec'), end='')

    print('%-4o   %5d:%-5d   %-7d   %-15s   %5d   %-30s   %-8d   %-60s' % (event.mode, event.uid, event.gid, event.pid, event.task.decode('utf-8'), event.error, get_open_flags(event.open_flags), event.dfd, event.file.decode('utf-8')))

parser = optparse.OptionParser()
parser.epilog = usage
parser.format_epilog = lambda _ : usage
parser.add_option('-f', '--filetypes', dest='filetypes', default='all', help='Comma separated list of file types defaults to all')
parser.add_option('-t', '--fstypes', dest='fstypes', help='Comma separated list of file system types defaults to all')
parser.add_option('-e', '--ebf', dest='ebpf', action='store_true', help='Print ebpf program and exit (for debugging)')
(options, args) = parser.parse_args()

ftypes = 0
for t in options.filetypes.split(','):
    if t == 'all':       ftypes |= stat.S_IFSOCK | stat.S_IFCHR | stat.S_IFBLK | stat.S_IFREG | stat.S_IFIFO | stat.S_IFDIR | stat.S_IFLNK
    if t == 'socket':    ftypes |= stat.S_IFSOCK
    if t == 'char':      ftypes |= stat.S_IFCHR
    if t == 'block':     ftypes |= stat.S_IFBLK
    if t == 'regular':   ftypes |= stat.S_IFREG
    if t == 'fifo':      ftypes |= stat.S_IFIFO
    if t == 'directory': ftypes |= stat.S_IFDIR
    if t == 'link':      ftypes |= stat.S_IFLNK

filetype_filter = 'if (!(de->d_inode->i_mode & 0x%x)) { filter = 1; }' % (ftypes)

magic_list = []
if options.fstypes:
    for fstype in options.fstypes.split(','):
        m = fstype_to_magic.get(fstype)
        if not m:
            print('No magic number found for file system type: %s' % (fstype))
        else:
            magic_list.append(m)

# use a switch statement for handling the magic numbers in case there is multiple
magic_filter = ''
if len(magic_list) > 0:
    magic_filter = 'switch (de->d_inode->i_sb->s_magic) {\n'
    for m in magic_list:
        magic_filter += '\tcase 0x%x: break;\n' % (m)
    magic_filter += '\tdefault: filter = 1; break; }'

# bpf program
bpf_text = '''
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/magic.h>
#include <linux/fs.h>

enum origin {
    TRACE_CHMOD = 0,
    TRACE_OPEN,
    TRACE_EXEC,
};

/* taken from fs/internal.h */
struct open_flags {
        int open_flag;
        umode_t mode;
        int acc_mode;
        int intent;
        int lookup_flags;
};

struct event_data {
    enum origin type;
    u32 uid;
    u32 gid;
    u32 pid;
    u32 mode;
    int dfd;
    int error;
    int open_flags;
    int lookup_flags;
    char task[TASK_COMM_LEN];
    char file[PATH_MAX];
};

BPF_HASH(data_hash, u64, struct event_data);
BPF_PERCPU_ARRAY(data_array, struct event_data, 1);
BPF_PERF_OUTPUT(events);

int trace_do_fchmodat(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u64 uidgid = bpf_get_current_uid_gid();
    u32 pid = id >> 32;
    u32 zero = 0;
    u32 mode;
    char *filename;

    struct event_data *data = data_array.lookup(&zero);
    if (!data)
    	return 0;

    data->type = TRACE_CHMOD;
    data->pid = pid;
    data->dfd = PT_REGS_PARM1(ctx);
    filename = (char *) PT_REGS_PARM2(ctx);
    mode = PT_REGS_PARM3(ctx);

    if (!(mode & S_IWOTH))
	    return 0;

    data->error = 0;
    data->uid = uidgid & 0xffffffff;
    data->gid = uidgid >> 32;
    data->mode = mode & ~S_IFMT;
    data->open_flags = 0;
    data->lookup_flags = 0;
    bpf_get_current_comm(&data->task, sizeof(data->task));
    bpf_probe_read_user(&data->file, sizeof(data->file), filename);
    data_hash.update(&id, data);
    return 0;
}

int trace_chmod_common(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 mode;
    char *filename;
    u8 filter = 0;

    struct event_data *data = data_hash.lookup(&id);
    if (!data)
        return 0;


    struct path *p = (struct path *) PT_REGS_PARM1(ctx);
    struct dentry *de = p->dentry;

    /* no update to the attributes just need to filter here since we have
       the information needed */
    FILTER_BY_FILETYPE
    FILTER_BY_MAGIC
    if (!filter) {
        events.perf_submit(ctx, data, sizeof(*data));
    }

    data_hash.delete(&id);
    return 0;
}

int trace_do_filp_open_entry(struct pt_regs *ctx)
{
    struct filename *fn;
    struct open_flags *of;
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 zero = 0;

    struct event_data *data = data_array.lookup(&zero);
    if (!data)
    	return 0;

    data->dfd = PT_REGS_PARM1(ctx);
    fn = (struct filename *) PT_REGS_PARM2(ctx);
    of = (struct open_flags *) PT_REGS_PARM3(ctx);

    /* __FMODE_EXEC is only in the do_execve path */
    if (of->open_flag & __FMODE_EXEC)
        data->type = TRACE_EXEC;
    else
        data->type = TRACE_OPEN;
    data->open_flags = of->open_flag;
    data->lookup_flags = of->lookup_flags;
    bpf_probe_read_kernel_str(data->file, sizeof(data->file), fn->name);
    data_hash.update(&id, data);
    return 0;
}

int trace_do_filp_open_return(struct pt_regs *ctx)
{
    struct file *filp;
    u64 uidgid = bpf_get_current_uid_gid();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 zero = 0;
    u8 filter = 0;

    struct event_data *data = data_hash.lookup(&id);
    if (!data)
        return 0;

    data->error = 0;
    data->pid = pid;
    data->uid = uidgid & 0xffffffff;
    data->gid = uidgid >> 32;
    bpf_get_current_comm(&data->task, sizeof(data->task));
    data_hash.delete(&id);

    filp = (struct file *) PT_REGS_RC(ctx);
    if (IS_ERR(filp))
        data->error = PTR_ERR(filp);

    struct dentry *de = filp->f_path.dentry;
    if (!(de->d_inode->i_mode & S_IWOTH))
	    return 0;

    FILTER_BY_FILETYPE
    FILTER_BY_MAGIC

    if (!filter) {
        /* return just the mode part */
        data->mode = de->d_inode->i_mode & ~S_IFMT;
        events.perf_submit(ctx, data, sizeof(*data));
    }

    return 0;
}
'''

bpf_text = bpf_text.replace('FILTER_BY_FILETYPE', filetype_filter)
bpf_text = bpf_text.replace('FILTER_BY_MAGIC', magic_filter)

if options.ebpf:
    print(bpf_text)
    exit()

# initialize BPF
b = BPF(text=bpf_text)

b.attach_kretprobe(event="do_filp_open", fn_name="trace_do_filp_open_return")
b.attach_kprobe(event="do_filp_open", fn_name="trace_do_filp_open_entry")
b.attach_kprobe(event="do_fchmodat", fn_name="trace_do_fchmodat")
b.attach_kprobe(event="chmod_common", fn_name="trace_chmod_common")

# header
print('%-8s   %4s   %5s:%-5s   %-7s   %-15s   %-5s   %-30s   %-8s   %-60s' % ('Type', 'Mode', 'UID', 'GID', 'PID', 'Command', 'Error', 'Open Flags', 'DFD', 'Path'))

# read events
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
