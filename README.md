# Pybpfmaps
<p align="center">
<a href="https://www.python.org/downloads/release/python-3100/"><img src="https://img.shields.io/badge/python-3.10-blue.svg"></a>
<a href="https://github.com/PeterStolz/pybpfmaps/actions/workflows/pytests.yml"><img src="https://github.com/PeterStolz/pybpfmaps/actions/workflows/pytests.yml/badge.svg"></a>
<a href="https://codecov.io/gh/PeterStolz/pybpfmaps"><img src="https://codecov.io/gh/PeterStolz/pybpfmaps/branch/main/graph/badge.svg?token=HMYY954POH"></a>
<a href="https://pypi.org/project/bpfmaps/"><img src="https://badge.fury.io/py/bpfmaps.svg"></a>
<a href="https://github.com/psf/black"><img src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
</p>

Simple standalone python library to interact with bpf/ebpf maps via libbpf bindings.

This project aims to ease communication with eBPF programs using eBPF maps.

## Installation

`pip install bpfmaps`

No need for any other dependencies, because the libbpf binary is built from source inside the [github action](https://github.com/PeterStolz/pybpfmaps/blob/main/.github/workflows/pytests.yml) and included in the python package.
You can verify its authenticity by comparing the hashes of the pypi package with the ones printed in the github action that released it.

## Usage
```python3
import bpfmaps

my_map = bpfmaps.BPF_Map.get_map_by_name('some_global')
my_map[0] = 10
```
## Contributing
### Dependencies
To locally work on this project you need to get the libbpf binary and put it into src/bpfmaps/libbpf/

This can be done by extracting it from the pypi package or building from source:

```bash
git clone --recurse-submodules git@github.com:PeterStolz/pybpfmaps.git
cd pybpfmaps/dependencies/libbpf/src
OBJDIR=../../../src/bpfmaps/libbpf/ make
cd ../../../
```
To install the build dependencies you may run:
```bash
sudo apt-get update
sudo apt-get install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential linux-libc-dev
```

### Testing
This project uses pytest for testing and the tests for `x.py` are stored in the file `test_x.py`.
As working with eBPF maps requires root you can execute the tests with:

`sudo python3.10 -m pytest ./src`

The tests may leave some bpf maps lying around, but they will perish after a reboot.
