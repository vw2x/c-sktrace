# sktrace

`sktrace` 是一个基于 Frida Stalker 的 Android 原生指令跟踪工具。它会在目标函数进入时跟踪当前线程，记录目标模块内执行过的指令和寄存器变化，并在函数返回后输出统计结果。

## 支持范围

- ARM32：支持 ARM 和 Thumb 指令，记录 `r0-r12`、`sp`、`lr`、`pc` 和 `cpsr`
- ARM64：记录 `x0-x28`、`fp`、`lr`、`sp` 和 `pc`
- Thumb 指令保留 Capstone 给出的 2 字节或 4 字节长度
- 支持按导出符号或模块内偏移定位目标函数
- 支持 USB 设备和远程 `frida-server`

暂不支持 x86、x86_64 和 MIPS。当前只能附加到已经运行的进程，spawn 模式尚未实现。

ARM64 设备只要保留 32 位 ABI 支持，也可以运行并跟踪 32 位 App。`sktrace` 识别的是目标进程架构，不是设备的主架构。

## 环境准备

需要 Python 3、Frida Python binding，以及设备端可用的 `frida-server` 或 Frida Gadget。客户端与设备端的 Frida 版本应保持一致。

```bash
git clone https://github.com/vw2x/c-sktrace.git
cd c-sktrace
python3 -m pip install frida
```

开始跟踪前，请先确认：

- 目标进程正在运行
- 目标原生库已经加载
- 当前 Frida 连接能够附加到该进程

## 使用方法

按导出符号跟踪：

```bash
python3 sktrace/sktrace.py \
  -m attach \
  -U \
  -l libtarget.so \
  -i target_symbol \
  com.example.app
```

按模块内偏移跟踪：

```bash
python3 sktrace/sktrace.py \
  -m attach \
  -U \
  -l libtarget.so \
  -i 0x1234 \
  com.example.app
```

连接远程 `frida-server` 时，用 `-H` 替换 `-U`：

```bash
python3 sktrace/sktrace.py \
  -m attach \
  -H 127.0.0.1:27042 \
  -l libtarget.so \
  -i target_symbol \
  com.example.app
```

参数说明：

| 参数 | 说明 |
| --- | --- |
| `-m attach` | 附加到已经运行的进程 |
| `-l, --libname` | 目标原生库名称 |
| `-i, --interceptor` | 导出符号或以 `0x` 开头的模块内偏移 |
| `-U, --usb` | 连接 USB 设备，也是默认连接方式 |
| `-H, --host` | 连接远程 `frida-server`，格式如 `127.0.0.1:27042` |
| `-p, --prepend` | 在主跟踪脚本之前加载自定义 Frida 脚本 |
| `-a, --append` | 在主跟踪脚本之后加载自定义 Frida 脚本 |
| `target` | 目标进程名称 |

命令启动后，`sktrace` 会等待目标函数被调用。按回车或 `Ctrl+C` 可以结束当前会话。

## 输出内容

跟踪结果包含：

- 指令地址、长度、助记符和操作数
- 相邻指令快照之间发生变化的寄存器
- 每条指令对应的寄存器变化统计
- 从寄存器变化中识别出的可打印字符串候选

ARM32 和 ARM64 使用各自的 Frida `GumCpuContext` 布局。指令和寄存器数据由 CModule 采集，Python 端负责解析和统计。

## 变更记录

### Unreleased

- 增加 Android ARM32 和 Thumb 跟踪支持
- 根据目标进程自动选择 ARM32 或 ARM64 寄存器布局
- 记录 Capstone 返回的真实指令长度，避免将 Thumb 指令固定为 4 字节

### 2025-10-18

- 指令和寄存器采集改为 CModule 实现
- 增加 `-H` 和 `-U` 连接选项
