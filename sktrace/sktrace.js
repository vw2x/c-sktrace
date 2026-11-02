

if (Process.arch !== 'arm' && Process.arch !== 'arm64') {
    throw new Error(`Unsupported architecture: ${Process.arch}. Expected arm or arm64.`);
}

const traceCM = new CModule(`
#include <gum/gumstalker.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void on_message(const gchar *message);
static void log(const gchar *format, ...);
static void on_trace_after(GumCpuContext *cpu_context, gpointer user_data);
void flush_buffer();  // Export for JS

void hello() {
    on_message("Hello form CModule");
}

static void
log(const gchar *format, ...)
{
    gchar *message;
    va_list args;

    va_start(args, format);
    message = g_strdup_vprintf(format, args);
    va_end(args);

    on_message(message);
    g_free(message);
}

// 空函数
void
flush_buffer()
{
    log("[flush_buffer] Called");
}


void transform(GumStalkerIterator *iterator,
               GumStalkerOutput *output,
               gpointer user_data)
{
    cs_insn *insn;

    gpointer base = *(gpointer *) user_data;
    gpointer end = *(gpointer *) ((guint8 *) user_data + sizeof(gpointer));
    
    while (gum_stalker_iterator_next(iterator, &insn))
    {
        gsize insn_address = (gsize) insn->address;
        gpointer insn_data = GSIZE_TO_POINTER(insn_address);
        gboolean in_target = insn_address >= GPOINTER_TO_SIZE(base) &&
            insn_address < GPOINTER_TO_SIZE(end);
        if(in_target)
        {
            // Include Capstone's size so Thumb instructions keep their 2/4-byte width.
            log("%p\t%u\t%s\t%s", insn_data, insn->size,
                insn->mnemonic, insn->op_str);
        }
        gum_stalker_iterator_keep(iterator);
        if(in_target) 
        {
            gum_stalker_iterator_put_callout(iterator, on_trace_after,
                insn_data, NULL);
        }
    }
}

static void
on_trace_after(GumCpuContext *cpu_context,
        gpointer user_data)
{
    if (cpu_context == NULL)
        return;

#if defined (HAVE_ARM64)
    // addr|arm64|x0|...|x28|fp|lr|sp|pc
    log("%p|arm64|%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|"
            "%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|"
            "%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|"
            "%llx|%llx|%llx|%llx",
            user_data,
            cpu_context->x[0], cpu_context->x[1], cpu_context->x[2], cpu_context->x[3],
            cpu_context->x[4], cpu_context->x[5], cpu_context->x[6], cpu_context->x[7],
            cpu_context->x[8], cpu_context->x[9], cpu_context->x[10], cpu_context->x[11],
            cpu_context->x[12], cpu_context->x[13], cpu_context->x[14], cpu_context->x[15],
            cpu_context->x[16], cpu_context->x[17], cpu_context->x[18], cpu_context->x[19],
            cpu_context->x[20], cpu_context->x[21], cpu_context->x[22], cpu_context->x[23],
            cpu_context->x[24], cpu_context->x[25], cpu_context->x[26], cpu_context->x[27],
            cpu_context->x[28],
            cpu_context->fp, cpu_context->lr, cpu_context->sp, cpu_context->pc);
#elif defined (HAVE_ARM)
    // addr|arm|r0|...|r12|sp|lr|pc|cpsr
    log("%p|arm|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x",
        user_data,
        cpu_context->r[0], cpu_context->r[1], cpu_context->r[2],
        cpu_context->r[3], cpu_context->r[4], cpu_context->r[5],
        cpu_context->r[6], cpu_context->r[7], cpu_context->r8,
        cpu_context->r9, cpu_context->r10, cpu_context->r11,
        cpu_context->r12, cpu_context->sp, cpu_context->lr,
        cpu_context->pc, cpu_context->cpsr);
#else
# error Unsupported architecture
#endif
}

`, {
    on_message: new NativeCallback(messagePtr => {
        const message = messagePtr.readUtf8String();
        // 发送到 Python 端，不在 console 打印（避免重复）
        send({
            type: 'c_output',
            tid: currentTid,
            message: message
        });
      }, 'void', ['pointer'])
});

let currentTid = null;  // 全局变量保存当前 tid

const userData = Memory.alloc(Process.pageSize);
function stalkerTraceRangeC(tid, base, size) {
    currentTid = tid;  // 保存 tid
    
    userData.writePointer(base)
    const pointerSize = Process.pointerSize;
    userData.add(pointerSize).writePointer(base.add(size))
    
    Stalker.follow(tid, {
        transform: traceCM.transform,
        data: userData
    })
}

// 导出 C 的 flush 函数，让 JS 可以调用
function flushCBuffer(tid) {
    const flushBuffer = new NativeFunction(traceCM.flush_buffer, 'void', []);
    flushBuffer();
}


function stalkerTraceRange(tid, base, size) {
    Stalker.follow(tid, {
        transform: (iterator) => {
            const instruction = iterator.next();
            const startAddress = instruction.address;
            const isModuleCode = startAddress.compare(base) >= 0 && 
                startAddress.compare(base.add(size)) < 0;
            // const isModuleCode = true;
            do {
                iterator.keep();
                if (isModuleCode) {
                    send({
                        type: 'inst',
                        tid: tid,
                        block: startAddress,
                        val: JSON.stringify(instruction)
                    })
                    iterator.putCallout((context) => {
                            send({
                                type: 'ctx',
                                tid: tid,
                                val: JSON.stringify(context)
                            })
                    })
                }
            } while (iterator.next() !== null);
        }
    })
}


function traceAddr(addr) {
    let moduleMap = new ModuleMap();    
    let targetModule = moduleMap.find(addr);
    console.log(JSON.stringify(targetModule))
    let exports = targetModule.enumerateExports();
    let symbols = targetModule.enumerateSymbols();
    // send({
    //     type: "module", 
    //     targetModule
    // })
    // send({
    //     type: "sym",
    

    // })
    Interceptor.attach(addr, {
        onEnter: function(args) {
            try {
                this.tid = Process.getCurrentThreadId()
                console.log('[onEnter] Starting C trace for tid:', this.tid);
                stalkerTraceRangeC(this.tid, targetModule.base, targetModule.size);  // 使用 C 版本
                // stalkerTraceRange(this.tid, targetModule.base, targetModule.size)
            } catch (e) {
                console.error('[onEnter] Error:', e.message, e.stack);
            }
        },
        onLeave: function(ret) {
            try {
                console.log('[onLeave] Flushing buffer for tid:', this.tid);
                // 在函数返回时刷新缓冲区
                flushCBuffer(this.tid);
                
                Stalker.unfollow(this.tid);
                Stalker.garbageCollect()
                send({
                    type: "fin",
                    tid: this.tid
                })
            } catch (e) {
                console.error('[onLeave] Error:', e.message, e.stack);
            }
        }
    })
}


function traceSymbol(symbol) {

}

/**
 * from jnitrace-egine
 */
function watcherLib(libname, callback) {
    const dlopenRef = Module.findExportByName(null, "dlopen");
    const dlsymRef = Module.findExportByName(null, "dlsym");
    const dlcloseRef = Module.findExportByName(null, "dlclose");

    if (dlopenRef !== null && dlsymRef !== null && dlcloseRef !== null) {
        const dlopen = new NativeFunction(dlopenRef, "pointer", ["pointer", "int"]);
        Interceptor.replace(dlopen, new NativeCallback((filename, mode) => {
            const path = filename.readCString();
            const retval = dlopen(filename, mode);
    
            if (path !== null) {
                if (checkLibrary(path)) {
                    // eslint-disable-next-line @typescript-eslint/no-base-to-string
                    trackedLibs.set(retval.toString(), true);
                } else {
                    // eslint-disable-next-line @typescript-eslint/no-base-to-string
                    libBlacklist.set(retval.toString(), true);
                }
            }

            return retval;
        }, "pointer", ["pointer", "int"]));
    }
}



(() => {

    console.log(`----- start trace -----`);

    recv("config", (msg) => {
        const payload = msg.payload;
        console.log(JSON.stringify(payload))
        const libname = payload.libname;
        console.log(`libname:${libname}`)
        if(payload.spawn) {
            console.error(`todo: spawn inject not implemented`)
        } else {
            // const modules = Process.enumerateModules();
            const targetModule = Process.getModuleByName(libname);
            let targetAddress = null;
            if("symbol" in payload) {
                targetAddress = targetModule.findExportByName(payload.symbol);
            } else if("offset" in payload) {
                targetAddress = targetModule.base.add(ptr(payload.offset));
            }
            traceAddr(targetAddress)
        }
    })
})()
