# Programmatic on Linux Kernel with eBPF via Python

## Prerequisite for MacOS
1. Install lima
```bash
brew install lima
```

2. Running lima
```bash
limactl start --name=ebpf-lima-vm ../lima/ubuntu-lts-ebpf.yaml
```

3. Shell to lima
```bash
limactl shell ebpf-lima-vm
``` 

4. Prepare the dependencies that need to run eBPF Programming
```
sudo apt update
sudo apt install libbpf-dev make clang llvm libelf-dev
sudo apt install bpfcc-tools linux-headers-generic
```

## Prerequisite for Windows
comming soon...
if you want or rush, please try as same as MacOS

## How to run
### Running eBPF Program
```bash
sudo python3 <name.py>
```
1. Running hello world
```bash
sudo python3 hello.py
```
2. Running ebpf for counting userID in linux
```bash
sudo python3 ebpf.py
```

## Note
I'm using Linux lima-ebpf-lima-vm 5.15.0-72-generic #79-Ubuntu SMP aarch64 aarch64 aarch64 GNU/Linux
