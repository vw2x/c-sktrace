# sktrace

[English](README.md) | [中文](README.zh-CN.md)

An Android native instruction tracer built on Frida Stalker. When the target function is called, `sktrace` follows the current thread, records instructions executed inside the target module and register changes, then prints statistics when the function returns.

## Support

- Android ARM32, Thumb, and ARM64
- Functions selected by exported symbol or module-relative offset
- USB devices and remote `frida-server` connections
- Instruction length, mnemonic, operands, and register change statistics

An ARM64 device with 32-bit ABI support can also trace 32-bit apps. Only attach mode is available. x86, x86_64, and MIPS are not supported.

## Usage

You need Python 3, the Frida Python bindings, and a working `frida-server` or Frida Gadget on the device. The client and device must use the same Frida version.

```bash
git clone https://github.com/vw2x/c-sktrace.git
cd c-sktrace
python3 -m pip install frida
```

The target process must be running with the native library already loaded. Trace an exported symbol:

```bash
python3 sktrace/sktrace.py \
  -m attach \
  -U \
  -l libtarget.so \
  -i target_symbol \
  com.example.app
```

`-i` also accepts a module-relative offset beginning with `0x`:

```bash
python3 sktrace/sktrace.py \
  -m attach \
  -U \
  -l libtarget.so \
  -i 0x1234 \
  com.example.app
```

For a remote `frida-server`, replace `-U` with `-H`:

```bash
python3 sktrace/sktrace.py \
  -m attach \
  -H 127.0.0.1:27042 \
  -l libtarget.so \
  -i target_symbol \
  com.example.app
```

Use `-p` and `-a` to load custom Frida scripts before or after the main tracer. Press Enter or `Ctrl+C` to end the session.
