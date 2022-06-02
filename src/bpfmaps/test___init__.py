#!/usr/bin/env python
# -*- coding: utf-8 -*-
import random
import os
import ctypes

import pytest

from . import BPF_Map, MapTypes


@pytest.fixture()
def rand_name():
    return b"testm_" + b"".join(bytes([random.choice(b"0123456789")]) for _ in range(9))


def test_insert_retrieve_succeeds(rand_name):
    mymap = BPF_Map(MapTypes.BPF_MAP_TYPE_ARRAY, rand_name, 4, 4, 10, 0)
    mymap[0] = 1
    assert mymap[0] == 1, f"Map value is not 1 but was {mymap[0]}"


def test_insert_retrieve_succeeds_pinned(rand_name):
    mymap = BPF_Map(MapTypes.BPF_MAP_TYPE_ARRAY, rand_name, 4, 4, 10, 0, pinning=True)
    mymap[0] = 1
    assert mymap[0] == 1, f"Map value is not 1 but {mymap[0]}"
    mymap.unpin()


def test_insert_retrieve_succeeds_different_values(rand_name):
    mymap = BPF_Map(MapTypes.BPF_MAP_TYPE_ARRAY, rand_name, 4, 4, 10, 0)
    mymap[0] = 69
    assert mymap[0] == 69, f"Map value is not 69 but {mymap[0]}"


def test_slicing_succeeds(rand_name):
    mymap = BPF_Map(MapTypes.BPF_MAP_TYPE_ARRAY, rand_name, 4, 4, 10, 0)
    mymap[0] = 1
    mymap[1] = 2
    mymap[2] = 3
    mymap[3] = 4
    assert mymap[0:4] == [
        1,
        2,
        3,
        4,
    ], f"Map values are not [1, 2, 3, 4] but {mymap[0:4]}"


def test_for_in(rand_name):
    mymap = BPF_Map(MapTypes.BPF_MAP_TYPE_ARRAY, rand_name, 4, 4, 10, 0)
    mymap[0] = 1
    mymap[1] = 2
    mymap[2] = 3
    mymap[3] = 4
    for i, v in enumerate(mymap):
        assert v == mymap[i], f"Map value is not {mymap[i]} but {v}"
    assert list(iter(mymap)) == list(
        mymap
    ), f"Map values are not {list(mymap)} but {list(iter(mymap))}"
    assert list(iter(mymap)) == [
        1,
        2,
        3,
        4,
        0,
        0,
        0,
        0,
        0,
        0,
    ], f"Map values are not [1, 2, 3, 4, 0, 0, 0, 0, 0, 0] but {list(iter(mymap))}"


def test_zero_is_not_none(rand_name):
    mymap = BPF_Map(MapTypes.BPF_MAP_TYPE_ARRAY, rand_name, 4, 4, 10, 0)
    assert mymap[0] == 0, f"Map value is not 0 but {mymap[0]}"
    mymap[0] = 0
    assert mymap[0] == 0, f"Map value is not 0 but {mymap[0]}"


def test_types_in_constructor(rand_name):
    mymap = BPF_Map(
        MapTypes.BPF_MAP_TYPE_ARRAY,
        rand_name,
        4,
        4,
        10,
        0,
        value_type=ctypes.c_int,
        key_type=ctypes.c_int,
    )
    mymap[3] = 3
    assert mymap[3] == 3, f"Map value is not 0 but {mymap[0]}"


def test_types_in_constructor_longs(rand_name):
    mymap = BPF_Map(
        MapTypes.BPF_MAP_TYPE_ARRAY,
        rand_name,
        4,
        8,
        10,
        0,
        value_type=ctypes.c_long,
        key_type=ctypes.c_int,
    )
    mymap[6] = 2**33
    assert mymap[6] == 2**33, f"Map value is not 0 but {mymap[0]}"


def test_unpin_succeeds(rand_name):
    mymap = BPF_Map(MapTypes.BPF_MAP_TYPE_ARRAY, rand_name, 4, 4, 10, 0, pinning=True)
    assert os.path.exists(b"/sys/fs/bpf/" + rand_name), "Map file does not exist"
    mymap.unpin()
    assert not os.path.exists(
        b"/sys/fs/bpf/" + rand_name
    ), "Map file does exist after unpinning"


def test_load_pinned_map(rand_name):
    mymap = BPF_Map(MapTypes.BPF_MAP_TYPE_ARRAY, rand_name, 4, 4, 10, 0, pinning=True)
    assert os.path.exists(b"/sys/fs/bpf/" + rand_name), "Map file does not exist"
    mymap[0] = 1111
    assert mymap[0] == 1111, f"Map value is not 1111 but {mymap[0]}"

    map2 = BPF_Map.get_map_by_name(rand_name)
    assert map2 is not None, "Map is not loaded"
    assert map2.map_name == rand_name, f"Map name is not %s but %s" % (
        rand_name,
        map2.map_name,
    )
    assert map2[0] == 1111, f"Map value is not 1111 but {map2[0]}"
    mymap.unpin()


def test_hash_map(rand_name):
    mymap = BPF_Map(
        MapTypes.BPF_MAP_TYPE_HASH,
        rand_name,
        8,
        8,
        10,
        0,
        value_type=ctypes.c_long,
        key_type=ctypes.c_long,
    )
    mymap[2**35] = 2**36
    assert mymap[2**35] == 2**36


def test_hash_map_iter(rand_name):
    mymap = BPF_Map(
        MapTypes.BPF_MAP_TYPE_HASH,
        rand_name,
        8,
        8,
        10,
        0,
        value_type=ctypes.c_long,
        key_type=ctypes.c_long,
    )
    mymap[2**35] = 2**36
    mymap[2**36] = 2**37
    mymap[2**37] = 2**38
    entries = [e for e in iter(mymap)]
    assert all(
        map(
            lambda e: e in [(2**35, 2**36), (2**36, 2**37), (2**37, 2**38)],
            entries,
        )
    )


def test_structs_as_values(rand_name):
    """Idea of this test is to verify that we can store and retrieve actual structs"""

    class POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long), ("z", ctypes.c_long)]

    point = POINT(1, 2, 3)

    mymap = BPF_Map(
        MapTypes.BPF_MAP_TYPE_HASH,
        rand_name,
        8,
        ctypes.sizeof(POINT),
        1,
        0,
        value_type=POINT,
        key_type=ctypes.c_long,
    )

    mymap[0] = point
    pointcopy = mymap[0]
    assert pointcopy.x == 1 and pointcopy.y == 2 and pointcopy.z == 3
    for e in mymap:
        e = pointcopy
        assert pointcopy.x == 1 and pointcopy.y == 2 and pointcopy.z == 3


def test_structs_as_key(rand_name):
    class POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long), ("z", ctypes.c_long)]

    point_key = POINT(1, 2, 3)
    point_value = POINT(4, 5, 6)

    mymap = BPF_Map(
        MapTypes.BPF_MAP_TYPE_HASH,
        rand_name,
        ctypes.sizeof(POINT),
        ctypes.sizeof(POINT),
        1,
        0,
        value_type=POINT,
        key_type=POINT,
    )

    mymap[point_key] = point_value
    pointcopy = mymap[point_key]
    assert pointcopy.x == 4 and pointcopy.y == 5 and pointcopy.z == 6

def test_mep_get_by_id(rand_name):
    mymap = BPF_Map(
        MapTypes.BPF_MAP_TYPE_ARRAY,
        rand_name,
        4,
        4,
        10,
        0,
        value_type=ctypes.c_int,
        key_type=ctypes.c_int,
    )
    assert BPF_Map.get_map_by_id(mymap.id).map_name == rand_name

