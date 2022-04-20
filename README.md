# Pybpfmaps
[![Python 3.10](https://img.shields.io/badge/python-3.10-blue.svg)](https://www.python.org/downloads/release/python-3100/)
[![pytests](https://github.com/PeterStolz/pybpfmaps/actions/workflows/pytests.yml/badge.svg)](https://github.com/PeterStolz/pybpfmaps/actions/workflows/pytests.yml)
[![codecov](https://codecov.io/gh/PeterStolz/pybpfmaps/branch/main/graph/badge.svg?token=HMYY954POH)](https://codecov.io/gh/PeterStolz/pybpfmaps)
[![PyPI version](https://badge.fury.io/py/bpfmaps.svg)](https://badge.fury.io/py/bpfmaps)

Simple standalone python library to interact with bpf/ebpf maps via libbpf bindings.

## Installation

`pip install bpfmaps`

## Usage
```python3
import bpfmaps

my_map = bpfmaps.BPF_Map.get_map_by_name('some_global')
my_map[0] = 10
```
