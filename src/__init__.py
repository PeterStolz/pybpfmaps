#!/usr/bin/env python
# -*- coding: utf-8 -*-
import ctypes
import os
import time
from enum import IntEnum

libbpf_so = ctypes.CDLL("./dependencies/libbpf/src/libbpf.so.0")

class Bpf_prog_info(ctypes.Structure):
    # info struct def https://github.com/torvalds/linux/blob/b4a5ea09b29371c2e6a10783faa3593428404343/tools/include/uapi/linux/bpf.h#L5880
    _fields_ = [
        ("type", 	ctypes.c_uint32),
        ("id", 	ctypes.c_uint32),
        ("tag", 	ctypes.c_uint8),
        ("jited_prog_len", 	ctypes.c_uint32),
        ("xlated_prog_len", 	ctypes.c_uint32),
        ("jited_prog_insns", 	ctypes.c_uint64),
        ("xlated_prog_insns", 	ctypes.c_uint64),
        ("load_time", 	ctypes.c_uint64),
        ("created_by_uid", 	ctypes.c_uint32),
        ("nr_map_ids", 	ctypes.c_uint32),
        ("map_ids", 	ctypes.c_uint64),
        ("name", 	ctypes.c_char * 16),
        ("ifindex", 	ctypes.c_uint32),
        ("gpl_compatible:1", 	ctypes.c_uint32),
        ("padding", 	ctypes.c_uint32),
        ("netns_dev", 	ctypes.c_uint64),
        ("netns_ino", 	ctypes.c_uint64),
        ("nr_jited_ksyms", 	ctypes.c_uint32),
        ("nr_jited_func_lens", 	ctypes.c_uint32),
        ("jited_ksyms", 	ctypes.c_uint64),
        ("jited_func_lens", 	ctypes.c_uint64),
        ("btf_id", 	ctypes.c_uint32),
        ("func_info_rec_size", 	ctypes.c_uint32),
        ("func_info", 	ctypes.c_uint64),
        ("nr_func_info", 	ctypes.c_uint32),
        ("nr_line_info", 	ctypes.c_uint32),
        ("line_info", 	ctypes.c_uint64),
        ("jited_line_info", 	ctypes.c_uint64),
        ("nr_jited_line_info", 	ctypes.c_uint32),
        ("line_info_rec_size", 	ctypes.c_uint32),
        ("jited_line_info_rec_size", 	ctypes.c_uint32),
        ("nr_prog_tags", 	ctypes.c_uint32),
        ("prog_tags", 	ctypes.c_uint64),
        ("run_time_ns", 	ctypes.c_uint64),
        ("run_cnt", 	ctypes.c_uint64),
        ("recursion_misses", 	ctypes.c_uint64),
        ("verified_insns", 	ctypes.c_uint32),
    ]

class Bpf_map_info(ctypes.Structure):
    # info struct def https://github.com/torvalds/linux/blob/b4a5ea09b29371c2e6a10783faa3593428404343/tools/include/uapi/linux/bpf.h#L5880
    _fields_ = [
        ("type", 	ctypes.c_uint32),
        ("id", 	ctypes.c_uint32),
        ("key_size", 	ctypes.c_uint32),
        ("value_size", 	ctypes.c_uint32),
        ("max_entries", 	ctypes.c_uint32),
        ("map_flags", 	ctypes.c_uint32),
        ("name", 	ctypes.c_char * 16),
        ("ifindex", 	ctypes.c_uint32),
        ("btf_vmlinux_value_type_id", 	ctypes.c_uint32),
        ("netns_dev", 	ctypes.c_uint64),
        ("netns_ino", 	ctypes.c_uint64),
        ("btf_id", 	ctypes.c_uint32),
        ("btf_key_type_id", 	ctypes.c_uint32),
        ("btf_value_type_id", 	ctypes.c_uint32),
        ("padding", 	ctypes.c_uint32),
        ("map_extra", 	ctypes.c_uint64),
    ]

class MapTypes(IntEnum):
    BPF_MAP_TYPE_HASH = 1
    BPF_MAP_TYPE_ARRAY = 2
    BPF_MAP_TYPE_PROG_ARRAY = 3
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
    BPF_MAP_TYPE_PERCPU_HASH = 5
    BPF_MAP_TYPE_PERCPU_ARRAY = 6
    BPF_MAP_TYPE_STACK_TRACE = 7
    BPF_MAP_TYPE_CGROUP_ARRAY = 8
    BPF_MAP_TYPE_LRU_HASH = 9
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10
    BPF_MAP_TYPE_LPM_TRIE = 11
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12
    BPF_MAP_TYPE_HASH_OF_MAPS = 13
    BPF_MAP_TYPE_DEVMAP = 14
    BPF_MAP_TYPE_SOCKMAP = 15
    BPF_MAP_TYPE_CPUMAP = 16
    BPF_MAP_TYPE_XSKMAP = 17
    BPF_MAP_TYPE_SOCKHASH = 18
    BPF_MAP_TYPE_CGROUP_STORAGE = 19
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21
    BPF_MAP_TYPE_QUEUE = 22
    BPF_MAP_TYPE_STACK = 23
    BPF_MAP_TYPE_SK_STORAGE = 24
    BPF_MAP_TYPE_DEVMAP_HASH = 25
    BPF_MAP_TYPE_STRUCT_OPS = 26
    BPF_MAP_TYPE_RINGBUF = 27
    BPF_MAP_TYPE_INODE_STORAGE = 28
    BPF_MAP_TYPE_TASK_STORAGE = 29


#import pudb; pudb.set_trace()

class BPF_Object():
    pass

class BPF_Map():
    def __init__(self, map_type, map_name, key_size, value_size, max_entries, map_flags, pinning=False):
        self.map_type = map_type
        self.map_name = map_name
        self.key_size = key_size
        self.value_size = value_size
        self.max_entries = max_entries
        self.map_flags = map_flags
        # maye this is the wrong function to call
        """
        struct bpf_map_create_opts {
            size_t sz; /* size of this struct for forward/backward compatibility */

            __u32 btf_fd;
            __u32 btf_key_type_id;
            __u32 btf_value_type_id;
            __u32 btf_vmlinux_value_type_id;

            __u32 inner_map_fd;
            __u32 map_flags;
            __u64 map_extra;

            __u32 numa_node;
            __u32 map_ifindex;
        };
        #define bpf_map_create_opts__last_field map_ifindex

        LIBBPF_API int bpf_map_create(enum bpf_map_type map_type,
                          const char *map_name,
                          __u32 key_size,
                          __u32 value_size,
                          __u32 max_entries,
			      const struct bpf_map_create_opts *opts);
        """
        self.__map_fd = libbpf_so.bpf_map_create(ctypes.c_int(self.map_type), 
                                         self.map_name,
                                         ctypes.c_int(self.key_size), 
                                         ctypes.c_int(self.value_size), 
                                         ctypes.c_int(self.max_entries), 
                                         ctypes.c_int(self.map_flags)
                                        )
        print(self.__map_fd)
        assert self.__map_fd > 0, f"Failed to create map, {self.__map_fd}"
        self.__pinned_path = None
        if pinning:
            # Pin the map to the filesystem, so we can use it in other programs
            # This might be achievable with bpf_obj_pin and bpf_obj_get
            # TODO ensure /sys/fs/bpf is mounted as bpf
            # int bpf_obj_pin(int fd, const char *pathname);
            path = b"/sys/fs/bpf/" + self.map_name
            pin_res = libbpf_so.bpf_obj_pin(ctypes.c_int(self.__map_fd), path)
            assert pin_res == 0, f"Failed to pin map, {pin_res}"
            self.__pinned_path = path


    def __getitem__(self, key):
        """
        LIBBPF_API int bpf_map_lookup_elem(int fd, const void *key, void *value);
        """
        value = ctypes.c_void_p(0)
        key = ctypes.c_int(key)
        err = libbpf_so.bpf_map_lookup_elem(ctypes.c_int(self.__map_fd), 
                                      ctypes.byref(key), 
                                      ctypes.byref(value)
                                     )
        assert err == 0, f"Failed to lookup map elem {key}, {err}"
        return value.value


    def __setitem__(self, key, value):
        """
        LIBBPF_API int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
        """
        # there is the option to specify a _as_parameter for custom classes, so they can be used when calling the function
        
        key = ctypes.c_int(key)
        value = ctypes.c_int(value)
        err = libbpf_so.bpf_map_update_elem(ctypes.c_int(self.__map_fd), 
                                      ctypes.byref(key), 
                                      ctypes.byref(value), 
                                      ctypes.c_int(0)
                                     )
        assert err == 0, f"Failed to update map, {err}"

    @classmethod
    def get_map_by_fd(cls, map_fd: int) -> 'BPF_Map':
        assert map_fd > 0, f"Invalid map fd {map_fd}"
        # Map info can be retrieved using bpf_obj_get_info_by_fd(fd, info, info_len);
        bpf_map_info = Bpf_map_info()
        err = libbpf_so.bpf_obj_get_info_by_fd(ctypes.c_int(map_fd), 
                                               ctypes.byref(bpf_map_info), 
                                               ctypes.byref(ctypes.c_int(ctypes.sizeof(bpf_map_info)))
                                              )
        assert not err, f"Failed to get map info, {err}"
        map_type = bpf_map_info.type
        map_name = bpf_map_info.name
        key_size = bpf_map_info.key_size
        value_size = bpf_map_info.value_size
        max_entries = bpf_map_info.max_entries
        map_flags = 0
        # print(map_type, map_name, key_size, value_size, max_entries, map_flags)
        return cls(map_type, map_name, key_size, value_size, max_entries, map_flags, pinning=False)

    @classmethod
    def get_map_by_name(cls, name: str) -> 'BPF_Map':
        if isinstance(name, str):
            name = name.encode()
        mapfd = libbpf_so.bpf_obj_get(b"/sys/fs/bpf/" + name)
        assert mapfd > 0, f"Failed to get map, {mapfd} {name}"
        return cls.get_map_by_fd(mapfd)

    def unpin(self):
        """
        Remove the pinning
        """
        if self.__pinned_path:
            err = libbpf_so.bpf_map__unpin(ctypes.c_int(0))
            self.__pinned_path = None
            return err


if __name__ == "__main__":
    mymap = BPF_Map(MapTypes.BPF_MAP_TYPE_ARRAY, b"mymap", 4, 4, 10, 0)
    print(mymap)
    pass
