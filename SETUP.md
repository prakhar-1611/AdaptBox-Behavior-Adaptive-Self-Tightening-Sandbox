# Setup (Kali VM)

## 1. Verify the kernel supports what AdaptBox needs

```bash
uname -r                                   # 5.15+ expected
stat -fc %T /sys/fs/cgroup                 # must print: cgroup2fs
cat /sys/fs/cgroup/cgroup.controllers      # want cpu memory pids
ls /sys/kernel/btf/vmlinux                 # BTF present => eBPF is easy
grep SECCOMP /boot/config-$(uname -r)      # want CONFIG_SECCOMP_FILTER=y
python3 --version
```

## 2. Install dependencies

```bash
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r) \
                    strace python3-pip python3-venv libseccomp-dev python3-seccomp

pip install --break-system-packages -r requirements.txt
```

Verify eBPF/BCC (optional — strace is the fallback):

```bash
sudo python3 -c "from bcc import BPF; print('BCC OK')"
```

If BCC fails to compile, the kernel headers probably don't match the running kernel:

```bash
sudo apt full-upgrade && sudo reboot
```

AdaptBox still works with the strace backend if BCC is unavailable.

## 3. VM settings

- 4 GB+ RAM, 2+ vCPUs.
- **Take a snapshot before running any sample under `samples/malicious/`.**
- Network on NAT; malicious samples only touch loopback / a dummy address.

## 4. Editing from Windows

Pick one:

- VS Code Remote-SSH into the VM (`sudo systemctl enable --now ssh`), edit + run on the VM.
- A shared folder (VirtualBox/VMware) so the VM sees changes instantly.
- Git push/pull.
