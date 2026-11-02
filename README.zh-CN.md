# sktrace

[English](README.md) | [中文](README.zh-CN.md)

基于 Frida Stalker 的 Android 原生指令跟踪工具。目标函数进入后，`sktrace` 会记录当前线程在目标模块内执行过的指令和寄存器变化，并在函数返回时输出统计结果。

## 支持

- Android ARM32、Thumb 和 ARM64
- 按导出符号或模块内偏移定位函数
- USB 设备或远程 `frida-server`
- 指令长度、助记符、操作数和寄存器变化统计

ARM64 设备保留 32 位 ABI 支持时，也可以跟踪 32 位 App。当前仅支持 attach 模式，不支持 x86、x86_64 和 MIPS。

## 使用

需要 Python 3、Frida Python binding，以及设备端可用的 `frida-server` 或 Frida Gadget。客户端与设备端的 Frida 版本需要一致。

```bash
git clone https://github.com/vw2x/c-sktrace.git
cd c-sktrace
python3 -m pip install frida
```

目标进程需要已经运行，并且目标原生库已经加载。按导出符号跟踪：

```bash
python3 sktrace/sktrace.py \
  -m attach \
  -U \
  -l libtarget.so \
  -i target_symbol \
  com.example.app
```

`-i` 也可以传入以 `0x` 开头的模块内偏移：

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

`-p` 和 `-a` 可以在主跟踪脚本前后加载自定义 Frida 脚本。按回车或 `Ctrl+C` 结束会话。
