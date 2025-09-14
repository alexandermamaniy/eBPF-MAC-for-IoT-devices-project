# Evaluating LSM-Based MAC Policies in Kernel Space for IoT Device Protection

This repository contains the MSc research project that evaluates the feasibility of applying **Linux Security Module (LSM) BPF-based Mandatory Access Control (MAC)** in the kernel space to protect IoT devices against malware such as **Mirai**, while reducing system overhead and ensuring high availability in resource-constrained environments.

## Documentation
- 📘 [Research PDF Report](documentation/researchProject.pdf) — Full research report.
- 🛠️ [Configuration Manual Report](documentation/configManual.pdf) — Practical configuration and deployment guide.

## Project Objectives
- Assess the applicability of **LSM BPF** on IoT devices compared to traditional MAC systems (AppArmor, SELinux, TOMOYO, Smack).
- Measure **memory consumption**, **processing delays**, and **file system support** for IoT environments.
- Evaluate effectiveness against real malware through a **simulated Mirai attack**.
- Analyze the adoption of kernel versions in **OpenWrt (2022–2024)** to estimate deployment compatibility.

## Solution Architecture
The proposed solution enforces security policies written in **restricted C**, compiled into **eBPF bytecode**, and attached to **LSM hooks** (e.g., `file_open`, `bprm_check_security`, `inode_setattr`, `socket_connect`).

Key features:
- **Per-file enforcement** even on lightweight IoT file systems without `xattr` support (e.g., Cramfs, romfs).
- **Prevention of Mirai attack vectors**:
    - Block DoS attacks by restricting execution of malware downloaded via `wget`.
    - Deny unauthorized **remote login** by blocking Telnet service.
    - Prevent **propagation/infection** by restricting Telnet client execution.
- **Lightweight footprint**: <5.2% memory overhead on devices with only 128 MB RAM.

## Implementation
- **Development Environment**:
    - Kernel ≥ 5.7 with `CONFIG_BPF` and `CONFIG_BPF_LSM` enabled.
    - Tools: `LLVM/Clang`, `BCC (libbpf)`, `eunomia-bpf`.
- **Evaluation Setup**:
    - Raspberry Pi devices for real-world IoT testing.
    - Virtual machines for **Mirai botnet simulation** in isolated environments.
- **Output Logs**:
    - Security policies produce traces under `/sys/kernel/debug/tracing/trace_pipe`.

## Results Summary
- **Memory Usage**: LSM BPF +5.2% vs. AppArmor +14.2%.
- **Processing Delays**: <7.3% overhead; critical I/O unaffected.
- **File Systems**: LSM BPF maintains per-file control across all tested FS.
- **Protection**: Default policies ineffective, but customized LSM BPF policies successfully blocked **Remote Login, DoS, and Infection** stages of Mirai.
- **Kernel Adoption**: OpenWrt firmware support for LSM BPF rose from 32.5% (2022) to 75% (2024).

## Future Work
- Develop **high-level user-space tools** for policy management.
- Provide **ready-to-use policy sets** for common IoT malware.
- Integrate LSM BPF with **automatic threat detection systems** for scalable IoT protection.

## Citation
If you use this work, please cite:

**Mamani, Alexander.** *Evaluating LSM-Based MAC Policies in Kernel Space for IoT Device Protection.* MSc Research Project, National College of Ireland, 2025.

---

