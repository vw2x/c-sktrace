
import sys
import json

class Block:
    def __init__(self, addr):
        self.addr = addr
        self.size = -1
        self.insts = []
    
    def append_inst(self, inst):
        self.insts.append(inst)
        self.size += inst.size

    def __str__(self):
        insts_addr = [inst.addr for inst in self.insts]
        insts_addr_str = ",".join(insts_addr)
        block_line = "{}\t{}\t{}".format("block", self.addr, hex(self.size))
        # block_line = "{}\t{}\t{}\t{}".format("block", self.addr, hex(self.size), insts_addr_str)
        return block_line


class Inst:
    def __init__(self, addr, block, size, mnem, op):
        self.addr = addr
        self.block = block
        self.size = size
        self.mnem = mnem
        self.op = op
        self.execed_ctxs = []
        self.changed_regs_dict = {}
        self.try_strings_set = set()
    
    def add_execed_ctx(self, ctx):
        self.execed_ctxs.append(ctx)

    def add_changed_regs(self, changed_regs_arr):
        if changed_regs_arr and len(changed_regs_arr) > 0:
            for reg_val in changed_regs_arr:
                if reg_val.keys[0] in self.changed_regs_dict:
                    self.changed_regs_dict[reg_val.keys[0]].append(reg_val.values[0])
                else:
                    self.changed_regs_dict[reg_val.keys[0]] = (reg_val.values[0])

    def cal_regs_change(self, pre_ctx, ctx):
        print_every_change = True
        eveny_change_str = None
        previous_regs = pre_ctx.registers if pre_ctx else {}

        # PC identifies the instruction and is intentionally not part of the
        # change summary. Register names come from the architecture-specific
        # context, so this works for both ARM32 and ARM64.
        for reg_name, new_value in ctx.registers.items():
            old_value = previous_regs.get(reg_name)
            if old_value == new_value:
                continue

            if reg_name not in self.changed_regs_dict:
                self.changed_regs_dict[reg_name] = []
            self.changed_regs_dict[reg_name].append(new_value)

            if print_every_change and old_value is not None:
                change = "{}={}->{}".format(
                    reg_name, hex(old_value), hex(new_value))
                if eveny_change_str:
                    eveny_change_str += ", " + change
                else:
                    eveny_change_str = "{}\t; {}".format(
                        self.simple_str(), change)

        if print_every_change and eveny_change_str:
            print(eveny_change_str)
        pass

    def try_strings(self):
        if not self.changed_regs_dict:
            return
        # 等于多于4个字符
        char_time_threshold = 4
        for reg in self.changed_regs_dict:
            try_str = ""
            change_val_arr = self.changed_regs_dict[reg]
            # 确保是列表
            if not isinstance(change_val_arr, list):
                change_val_arr = [change_val_arr]
            
            for val in change_val_arr:
                # 处理 int 或 str 类型
                if isinstance(val, int):
                    val_int = val
                else:
                    val_int = int(val, 16)
                
                if val_int < 0x7f and val_int >= 0x20:
                    try_str += chr(val_int)
                else:
                    if len(try_str) >= 4:
                        self.try_strings_set.add(try_str)
                    try_str = ""
            if len(try_str) >= char_time_threshold:
                self.try_strings_set.add(try_str)

        if self.try_strings_set:
            # print("strs\t" + str(self.try_strings_set))
            print("strings\t" + ",".join(self.try_strings_set))

    def statistics_changed_regs(self):
        if self.changed_regs_dict:
            change_line = "statistics"
            for reg in self.changed_regs_dict:
                # 将 int 值转换为 hex 字符串
                vals = self.changed_regs_dict[reg]
                if isinstance(vals, list):
                    val_strs = [hex(v) if isinstance(v, int) else v for v in vals]
                else:
                    val_strs = [hex(vals) if isinstance(vals, int) else vals]
                change_reg = "\t{}:{}".format(reg, ",".join(val_strs))
                change_line += change_reg
            print(change_line)
    
    def simple_str(self):
        inst_line = "{}\t{}\t{}".format(self.addr, self.mnem, self.op)
        return inst_line

    def __str__(self):
        inst_line = "{}\t{}\t{}\t{}\t{}\t{}".format("instruction", self.addr, self.block, self.size, self.mnem, self.op)
        return inst_line

class CpuCtx:
    def __init__(self, arch, pc, registers):
        self.arch = arch
        self.pc = pc
        self.registers = registers
        self.sp = registers["sp"]
        self.general_regs = list(registers.values())

    def __str__(self):
        return ",".join(
            "{}={}".format(name, hex(value))
            for name, value in self.registers.items())


class Arm64Ctx(CpuCtx):
    def __init__(self, pc, sp, x_regs, fp, lr):
        registers = {
            "x{}".format(index): value
            for index, value in enumerate(x_regs)
        }
        registers.update({"fp": fp, "lr": lr, "sp": sp})
        super().__init__("arm64", pc, registers)


class Arm32Ctx(CpuCtx):
    def __init__(self, pc, sp, r_regs, lr, cpsr):
        registers = {
            "r{}".format(index): value
            for index, value in enumerate(r_regs)
        }
        registers.update({"sp": sp, "lr": lr, "cpsr": cpsr})
        super().__init__("arm", pc, registers)




class TraceMgr:

    def __init__(self):
        self.tid_trace_dict = {}
        pass

    def trace_symbol(self, lib, symbol):
        pass

    def trace_offset(self, lib, offset):
        pass

    def on_message(self, msg, data):
        if msg['type'] == 'error':
            print(msg)
            return
        if msg['type'] == 'send':
            payload = msg['payload']
            tid = payload.get('tid')
            if tid is None:
                # 忽略没有 tid 的消息
                return
            if tid not in self.tid_trace_dict:
                self.tid_trace_dict[tid] = TraceLog(tid)
    
            self.tid_trace_dict[tid].on_message(payload)


class TraceLog:
    def __init__(self, tid):
        self.tid = tid
        self.block_dict = {}
        self.inst_dict = {}
        self.pre_ctx = None

    @staticmethod
    def _as_int(value):
        if isinstance(value, int):
            return value
        return int(value, 0)

    @staticmethod
    def _address_key(value):
        if isinstance(value, int):
            return hex(value)
        return str(value)

    def _record_context(self, addr, ctx):
        addr = self._address_key(addr)
        if addr not in self.inst_dict:
            inst = Inst(addr, addr, 4, "unknown", "")
            self.inst_dict[addr] = inst
            if addr not in self.block_dict:
                self.block_dict[addr] = Block(addr)
            self.block_dict[addr].append_inst(inst)

        self.inst_dict[addr].add_execed_ctx(ctx)
        self.inst_dict[addr].cal_regs_change(self.pre_ctx, ctx)
        self.pre_ctx = ctx

    def _parse_c_context(self, parts):
        addr = parts[0]

        if len(parts) == 35 and parts[1] == "arm64":
            x_regs = [int(value, 16) for value in parts[2:31]]
            ctx = Arm64Ctx(
                int(parts[34], 16), int(parts[33], 16), x_regs,
                int(parts[31], 16), int(parts[32], 16))
        elif len(parts) == 19 and parts[1] == "arm":
            r_regs = [int(value, 16) for value in parts[2:15]]
            ctx = Arm32Ctx(
                int(parts[17], 16), int(parts[15], 16), r_regs,
                int(parts[16], 16), int(parts[18], 16))
        elif len(parts) == 34:
            # Compatibility with logs emitted by the previous ARM64 CModule.
            x_regs = [int(value, 16) for value in parts[1:30]]
            ctx = Arm64Ctx(
                int(parts[33], 16), int(parts[32], 16), x_regs,
                int(parts[30], 16), int(parts[31], 16))
        else:
            raise ValueError("unsupported register record")

        return addr, ctx

    def on_message(self, payload):
        # tid = payload['tid']
        type = payload['type']
        if type == 'inst':
            # print(payload)
            val = json.loads(payload['val'])
            inst = Inst(val["address"], payload["block"], val["size"], val["mnemonic"], val["opStr"])
            if inst.block not in self.block_dict:
                self.block_dict[inst.block] = Block(inst.block)
            self.block_dict[inst.block].append_inst(inst)
            self.inst_dict[inst.addr] = inst
            # print(inst)
            pass
        elif type == 'ctx':
            val = json.loads(payload['val'])
            pc = self._as_int(val["pc"])
            sp = self._as_int(val["sp"])

            if "x0" in val:
                x_regs = [self._as_int(val["x{}".format(index)])
                          for index in range(29)]
                ctx = Arm64Ctx(
                    pc, sp, x_regs, self._as_int(val["fp"]),
                    self._as_int(val["lr"]))
            elif "r0" in val:
                r_regs = [self._as_int(val["r{}".format(index)])
                          for index in range(13)]
                ctx = Arm32Ctx(
                    pc, sp, r_regs, self._as_int(val["lr"]),
                    self._as_int(val["cpsr"]))
            else:
                raise ValueError("Unsupported CPU context: {}".format(val))

            self._record_context(pc, ctx)
        elif type == 'c_output':
            # 处理 C 版本输出
            message = payload['message']
            
            # Two formats are emitted by the CModule:
            # 1. addr\tsize\tmnemonic\top_str
            # 2. architecture-tagged register records separated by pipes.
            
            if '|' in message:
                try:
                    addr, ctx = self._parse_c_context(message.split('|'))
                    self._record_context(addr, ctx)
                except Exception as e:
                    print(f"Error parsing c_output register: {e}, message: {message}")
            elif '\t' in message:
                parts = message.split('\t')
                if len(parts) in (3, 4):
                    try:
                        addr = parts[0]
                        if len(parts) == 4:
                            size = int(parts[1], 10)
                            mnem = parts[2]
                            op = parts[3]
                        else:
                            size = 4
                            mnem = parts[1]
                            op = parts[2]

                        inst = Inst(addr, addr, size, mnem, op)
                        
                        # 如果已经存在，更新信息
                        if addr in self.inst_dict:
                            # 更新已存在的临时指令
                            self.inst_dict[addr].size = size
                            self.inst_dict[addr].mnem = mnem
                            self.inst_dict[addr].op = op
                        else:
                            # 创建新的
                            if addr not in self.block_dict:
                                self.block_dict[addr] = Block(addr)
                            self.block_dict[addr].append_inst(inst)
                            self.inst_dict[addr] = inst
                    except Exception as e:
                        print(f"Error parsing c_output inst: {e}, message: {message}")
        elif type == "fin":
            self.statistics()
            pass

# statistics
# '''
# tid  block  addr   size   inst_addrs
# tid  inst   block  size   mnemonic  op
# tid  chng   {reg:val_list}
# tid  strs   (guess_strs_set)
# '''
    def statistics(self):
        print('''==================== Statistic Start =====================''')
        for block_addr in self.block_dict:
            block = self.block_dict[block_addr]
            print(block)
            for inst in block.insts:
                print(inst)
                inst.statistics_changed_regs()
                inst.try_strings()
        print('''==================== Statistic End =====================''')
            

