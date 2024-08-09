from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

import importlib
from typing import List, Tuple
from dataclasses import dataclass

class Emulator:
    """用于模拟执行基类
    存在一些公共方法
    """
    @dataclass
    class MemMap:
        """存放映射的内存信息
        """
        mem_start: int
        mem_size: int
        mem_end: int

    def __init__(self, arch, mode) -> None:
        """创建模拟执行引擎

        Args:
            arch : 模拟器架构x86|arm|arm64
            mode : 模拟器模式32/64|arm/thumb
        """   
        #private
        self.__m_uc = None
        self.__m_mems: List[Emulator.MemMap] = []   #所有mem_map的内存起始地址和内存大小 

        #protected
        self._m_arch = None
        self._m_mode = None

        self._m_arch = arch
        self._m_mode = mode
        self.__m_uc = Uc(arch, mode)
    
    def __del__(self):
        for mem_info in self.__m_mems:
            self.unmap_mem(mem_info.mem_start, mem_info.mem_size)
        #我也不知道映射的内存需不需要手动释放, Uc是不需要手动释放的
    
    def _is_arch32(self) -> bool:
        is32 = False
        if (self._m_mode == UC_MODE_32) or (self._m_arch == UC_ARCH_ARM):
            is32 = True
        return is32

    def __reg2uc(self, reg : str):
        """将reg名转为uc常量

        Args:
            reg : 寄存器名
        
        Returns:
            int : 失败返回None
        """
        attr_name = ""
        arch_name = ""
        module_name = "unicorn."
        reg_name = reg.upper()
        if (self._m_arch == UC_ARCH_X86):
            arch_name = "X86"
            module_name += "x86_const"
        elif (self._m_arch == UC_ARCH_ARM):
            arch_name = "ARM"
            module_name += "arm_const"
        elif (self._m_arch == UC_ARCH_ARM64):
            arch_name = "ARM64"
            module_name += "arm64_const"
        attr_name = f"UC_{arch_name}_REG_{reg_name}"
        
        try:
            arch_const_module = importlib.import_module(module_name)
            return getattr(arch_const_module, attr_name)
        except (ModuleNotFoundError, AttributeError):
            return None
            
    def set_reg(self, reg : str, value = 0):
        reg_id = self.__reg2uc(reg)
        self.__m_uc.reg_write(reg_id, value)

    def get_reg(self, reg : str):
        reg_id = self.__reg2uc(reg)
        return self.__m_uc.reg_read(reg_id)

    def map_mem(self, addr:int, size: int) -> Tuple[int, int]:
        """映射内存

        Args:
            addr (int): 地址
            size (int): 大小

        Returns:
            Tuple[int, int]: (真正的地址, 真正的大小) 因为API要求是4k对齐的
        """
        #不是4k对齐的 则往前进行4k对齐 预留一段空间
        mem_4k_addr = (addr & ~(4095))
        mem_4k_num = ((size + addr - mem_4k_addr) // 4096) + 1 # mem要是4kb的倍数
        mem_4k_size = mem_4k_num * 4 * 1024
        mem_4k_end = mem_4k_addr + mem_4k_size

        new_mem = True
        for mem_info in self.__m_mems: #判断是否已经在mems中, 进行合并
            index = self.__m_mems.index(mem_info)
            if (mem_4k_addr >= mem_info.mem_start) and (mem_4k_end <= mem_info.mem_end):
                return mem_4k_addr, mem_4k_size #已经存在
            elif (mem_4k_addr <= mem_info.mem_start) and ((mem_4k_end >= mem_info.mem_start) and (mem_4k_end <= mem_info.mem_end)):
                new_size = mem_info.mem_size + (mem_info.mem_start - mem_4k_addr)
                self.__m_mems[index].mem_start = mem_4k_addr
                self.__m_mems[index].mem_size = new_size
                new_mem = False
                break
            elif ((mem_4k_addr >= mem_info.mem_start) and (mem_4k_addr <= mem_info.mem_end)) and (mem_4k_end >= mem_info.mem_end):
                new_size = mem_info.mem_size + (mem_4k_end - mem_info.mem_end)
                self.__m_mems[index].mem_end = mem_4k_end
                self.__m_mems[index].mem_size = new_size
                new_mem = False
                break
            elif (mem_4k_addr <= mem_info.mem_start) and (mem_4k_end >= mem_info.mem_end):
                self.__m_mems[index].mem_start = mem_4k_addr
                self.__m_mems[index].mem_size = mem_4k_size
                self.__m_mems[index].mem_end = mem_4k_end
                new_mem = False
                break

        self.__m_uc.mem_map(mem_4k_addr, mem_4k_size)

        if new_mem:
            mem_info = Emulator.MemMap(mem_start=mem_4k_addr, mem_size=mem_4k_size, mem_end=mem_4k_end)
            self.__m_mems.append(mem_info) #添加到__m_mems中
        return mem_4k_addr, mem_4k_size

    def unmap_mem(self, addr: int, size: int) -> bool:
        """取消内存映射

        Args:
            addr (int): 起始地址
            size (int): 大小 会自动4k对齐

        Returns:
            bool: 是否成功
        """
        mem_4k_addr = (addr & ~(4095))
        mem_4k_num = ((size + addr - mem_4k_addr) // 4096) + 1 # mem要是4kb的倍数
        mem_4k_size = mem_4k_num * 4 * 1024
        mem_4k_end = mem_4k_addr + mem_4k_size

        find_mem_info = None
        for mem_info in self.__m_mems:
            if (mem_4k_addr >= mem_info.mem_start) and (mem_4k_end <= mem_info.mem_end):
                find_mem_info = mem_info
                break
        if find_mem_info == None:
            return False
        else:
            if (mem_4k_addr == find_mem_info.mem_start) and (mem_4k_end == find_mem_info.mem_end):
                self.__m_mems.remove(find_mem_info)
            elif (mem_4k_addr > find_mem_info.mem_start) and (mem_4k_end < find_mem_info.mem_end):                
                block1_start = find_mem_info.mem_start
                block1_size = mem_4k_addr - find_mem_info.mem_start
                new_mem_block1 = Emulator.MemMap(mem_start=block1_start, mem_size=block1_size, mem_end=mem_4k_addr)
                block2_start = mem_4k_end
                block2_size = find_mem_info.mem_end - mem_4k_end
                new_mem_block2 = Emulator.MemMap(mem_start=block2_start, mem_size=block2_size, mem_end=find_mem_info.mem_end)
                self.__m_mems.remove(find_mem_info)
                self.__m_mems.append(new_mem_block1)
                self.__m_mems.append(new_mem_block2)

            self.__m_uc.mem_unmap(mem_4k_addr, mem_4k_size)
        return True

    def is_inmem(self, addr: int, size: int = 0) -> bool:
        """判断给定的内存块是否已经映射

        Args:
            addr (int): 地址
            size (int): 大小

        Returns:
            bool: 已经映射返回True
        """
        mem_start = addr
        mem_end = addr + size

        in_mem = False
        for mem_info in self.__m_mems:
            if (mem_start >= mem_info.mem_start) and (mem_end <= mem_info.mem_end):
                in_mem = True
                break
        return in_mem

    def write_mem(self, addr, wbytes) -> bool:
        """将bytes写入内存

        Args:
            addr : 要写入的地址
            wbytes : 要写入的数据
        
        Returns:
            bool: 是否成功
        """
        #print(f"[write_mem] addr:{hex(addr)} | byte_len:{len(bytes)}")
        
        if self.is_inmem(addr, len(wbytes)):
            self.__m_uc.mem_write(addr, wbytes)
            return True
        return False
    
    def read_mem(self, addr, size) -> bytes:
        """读取内存的值

        Args:
            addr : 地址
            size : 大小
        
        Returns:
            bytes: 读取的值
        """
        if self.is_inmem(addr, size):
           return self.__m_uc.mem_read(addr, size)
        return b''

    def add_hook(self, hook_type, func, usr_data = None):
        """添加一个钩子

        Args:
            hook_type : UC_HOOK_*
            func : 回调函数
            usr_data : 用户数据
        """
        self.__m_uc.hook_add(hook_type, func, usr_data)

    def start_emu(self, start_addr: int, end_addr: int) -> bool:
        """开始模拟执行

        Args:
            start_addr : 开始执行的地址(ip)
            end_addr : 结束地址

        Returns:
            bool: 是否开始成功
        """
        try:
            self.__m_uc.emu_start(start_addr, end_addr)
        except UcError as e:
            print(f"Emu Err: {e}")
            return False
        
        return True

class FuncEmulate(Emulator):
    def __init__(self, arch, mode) -> None:
        #protected
        self._m_code_size = 0       #机器码大小
        self._m_code_start = 0      #start是机器码起始地址
        self._m_stack_size = 0
        self._m_stack_base = 0
        super().__init__(arch, mode)
    
    def init_func_emu(self, code_addr, code_size):
        """初始化.text段等信息

        Args:
            code_addr: 机器码开始地址
            code_size (int): 机器码大小.

        Returns:
            bool: 是否初始化成功
        """

        self._m_code_start = code_addr
        self._m_code_size = code_size
        self.map_mem(code_addr, code_size)
        
        high_base = 0x0
        if (self._m_mode == UC_MODE_64) or (self._m_arch == UC_ARCH_ARM64):
            high_base = 0xDE60000000
        self._m_stack_base = high_base + 0x11B0000
        self._m_stack_size = 1 * 1024 * 1024 #1MB
        self.map_mem(self._m_stack_base, self._m_stack_size)

        # 离栈底预留0x100的空间
        sp = self._m_stack_base + self._m_stack_size - 0x100
        bp = sp
        #if self._is_arch32() :
        sp -= 0x100 #32位下的栈帧结构 再把sp往上提 预留变量的空间

        if self._m_arch == UC_ARCH_X86:
            if self._m_mode == UC_MODE_32:
                super().set_reg('ebp', bp)
                super().set_reg('esp', sp)
            elif self._m_mode == UC_MODE_64:
                super().set_reg('rsp', sp)
                super().set_reg('rbp', bp)
        elif self._m_arch == UC_ARCH_ARM:
            super().set_reg('sp', sp) #R13
            super().set_reg('fp', bp) #R11
        elif self._m_arch == UC_ARCH_ARM64:
            super().set_reg('sp', sp)
            super().set_reg('fp', bp) #X29
        return True

    def write_func_opcode(self, opcodes) -> bool:
        """从函数起始地址处写入机器码

        Args:
            opcodes (bytes): 机器码

        Returns:
            bool: 是否成功
        """
        write_addr = self._m_code_start
        return super().write_mem(write_addr, opcodes)

    def reg_value(self, reg, value = None):
        """设置/获取 寄存器的值

        Args:
            reg : 寄存器
            value (optional): 当此值为None时则获取寄存器值. Defaults to None.
        """
        ret_value = 0
        if value == None:
            ret_value = super().get_reg(reg)
        else:
            super().set_reg(reg, value)
        return ret_value

    def stack_value(self, reg, offset, size = None, value = None):
        """设置/获取 栈值

        Args:
            reg : 寄存器
            offset : 偏移
            size : 写入大小 4或者8 为None则按当前架构大小
            value (optional): 当此值为None时则获取栈值. Defaults to None.
        """
        ret_value = None
        rw_addr = super().get_reg(reg) + offset

        rw_size = size #自动识别size
        if rw_size is None:
            rw_size = 4 if super()._is_arch32() else 8

        if (value is not None): #写入
            value_bytes = value.to_bytes(16, 'little', signed=True) #先转到16个字节再截取rw_size个字节
            super().write_mem(rw_addr, value_bytes[:rw_size])
        else: #读取
            read_bytes = super().read_mem(rw_addr, rw_size)
            if (len(read_bytes) == rw_size):
                ret_value = int.from_bytes(read_bytes, byteorder='little', signed=True)
        return ret_value

    def add_code_hook(self, func, usr_data = None):
        """添加代码钩子

        Args:
            func: 回调函数
            usr_data (optional): 用户数据. Defaults to None.
        """
        super().add_hook(UC_HOOK_CODE, func, usr_data)
    
    def start_func_emu(self, start_addr: int, end_addr = None) -> bool:
        """开始模拟执行Func

        Args:
            start_addr : 开始执行的地址(ip)
            end_addr : 结束地址如果为None则一直执行到函数末

        Returns:
            bool: 是否开始成功
        """
        until_addr = None

        code_begin = self._m_code_start
        code_end = self._m_code_start + self._m_code_size
        if end_addr == None:
            until_addr = code_end
        else:
            until_addr = end_addr
        return super().start_emu(start_addr, until_addr)

class DeflatEmulate(FuncEmulate):
    """用于设置deflat相关的模拟执行

    Args:
        FuncEmulate: 父类
    """
    def __init__(self, arch, mode) -> None:
        #private
        self.__m_switch_info = {'begin_addr' : 0, 'var_reg' : '', 'var_offset' : 0, 'init_value' : 0}
        run_info = {'stops': [], 'begin': 0, 'loop_count': 0, 'last': 0, 'insn_size': 0} #1. 需要停止模拟的地址 2. 主分发器开始地址 3. 循环了分发逻辑的次数 4. 最后模拟的一条指令的地址 5. 指令长度
        super().__init__(arch, mode)

        self.run_info_var = run_info
        super().add_code_hook(DeflatEmulate.hook_code_callback, run_info)
        
    def init_reg_stack(self, start_addr: int, end_addr: int):
        """运行entry bb的指令 初始化寄存器和栈的值

        Args:
            start_addr (int): 从哪里开始运行
            end_addr (int): 运行到哪里结束
        """
        result = False
        run_addr = start_addr
        while result != True:
            result = self.start_emu(run_addr, end_addr)
            if result != True:
                ip = self.run_info_var['last']
                opsize = self.run_info_var['insn_size']
                run_addr = ip + opsize #遇到发生错误的指令则跳过并继续执行        

    def set_stop_addrs(self, addrs : list):
        """设置停止仿真地址

        Args:
            addrs (_type_): 停止地址
        """
        for addr in addrs:
            self.run_info_var['stops'].append(addr)

    def set_switch_begin_addr(self, addr : int):
        self.__m_switch_info['begin_addr'] = addr
        self.run_info_var['begin'] = addr

    def set_switch_var(self, reg, offset = None , init_value = None, size = None):
        """设置使用哪个作为switch的判断变量

        Args:
            reg : 寄存器
            offset : 偏移 如果offset=None则使用寄存器作为switch var否则使用栈
            init_value : 初始值
            size : value是4位还是8位 为None则按32/64大小
        """
        self.__m_switch_info['var_reg'] = reg
        self.__m_switch_info['var_offset'] = offset
        if (init_value is not None):
            self.__m_switch_info['init_value'] = init_value
            if offset == None:
                super().reg_value(reg, init_value)
            else:
                super().stack_value(reg, offset, size, init_value)

    def set_switch_var_value(self, value : int, size = None):
        """设置switch变量的值

        Args:
            value (int): 值
        """
        reg = self.__m_switch_info['var_reg']
        offset = self.__m_switch_info['var_offset']
        if (offset == None):
            super().reg_value(reg, value)
        else:
            super().stack_value(reg, offset, size, value)

    def start_until_stop(self) -> int:
        """开始模拟执行直到遇到设置的停止地址

        Returns:
            int: 停止在哪个地址处
        """
        if len(self.run_info_var['stops']) == 0:
            return 0
        
        begin_addr = self.__m_switch_info['begin_addr']
        if (begin_addr == 0):
            return 0
        
        #print(f"[Debug] emu_start: {hex(begin_addr)} | user_data : {self.stop_info_var}")
        super().start_func_emu(begin_addr)
        #print(f"[Debug] emu_end user_data : {self.stop_info_var}")
        return self.run_info_var['last']

    @staticmethod
    def hook_code_callback(uc : Uc, address, size, user_data):
        #print(f"[Debug] cur_rip: {hex(address)} | {uc.mem_read(address, size)}")
        user_data['last'] = address
        user_data['insn_size'] = size
        if address in user_data['stops']:
            uc.emu_stop()
        
        if (address == user_data['begin']):
            user_data['loop_count'] += 1
        
        if user_data['loop_count'] > 3000:
            uc.emu_stop() #循环次数太多了, 说明switch变量或者其他地方出了问题
    

class x86DeflatEmulate(DeflatEmulate):
    def __init__(self, is32 = False) -> None:
        """x86架构

        Args:
            is32 (bool, optional): 是否是32位的. Defaults to False.
        """
        arch = UC_ARCH_X86
        mode = UC_MODE_32 if is32 else UC_MODE_64
        super().__init__(arch, mode)

class armDeflatEmulate(DeflatEmulate):
    def __init__(self, is64 = True, isThumb = False, isEB = False) -> None:
        """arm架构

        Args:
            is64 (bool, optional): 是否是aarch64. Defaults to True.
            isThumb (bool, optional): 是否是Thumb指令集. Defaults to False.
            isEB (bool, optional): 是否是大端序. Defaults to False.
        """
        arch = UC_ARCH_ARM64 if is64 else UC_ARCH_ARM
        if arch == UC_ARCH_ARM64:
            mode = UC_MODE_ARM
        else:
            mode = UC_MODE_THUMB if isThumb else UC_MODE_ARM
        if isEB:
            mode |= UC_MODE_BIG_ENDIAN
        super().__init__(arch, mode)


class DeJmpRegEmulate(FuncEmulate):
    def __init__(self, arch, mode) -> None:
        super().__init__(arch, mode)

    def write_code_part(self, opcodes: bytes, start_addr: int) -> bool:
        """写入一块指令

        Args:
            opcodes (bytes): 机器码
            start_addr (int): 要写入的地址
        
        Returns:
            bool: 是否成功
        """
        #先映射一下内存
        if super().is_inmem(start_addr, len(opcodes)) != True:
            super().map_mem(start_addr, len(opcodes))

        return super().write_mem(start_addr, opcodes)

    def change_select(self, cs_insn_addr: int, cs_insn_len: int, opcode: bytes) -> bool:
        """将csel/cset指令转为其他指令(mov), 用于设置固定的值

        Args:
            cs_insn_addr (int): csel/cset指令起始地址
            cs_insn_len (int): 指令长度
            opcode (bytes): 要替换的opcode
        
        Returns:
            bool: 是否成功
        """
        if (cs_insn_addr + cs_insn_len) < len(opcode):
            return False
        return super().write_mem(cs_insn_addr, opcode)

    def run_specific_opcodes(self, opinfos: list, rreg: str):
        """执行特定的机器码

        Args:
            opinfos (list): [(addr, len), ...] 起始地址和长度
            rreg (str): 执行结束后需要返回哪个寄存器的值
        """
        sorted_opinfos = sorted(opinfos, key=lambda x: x[0]) #按照addr从小到大排序
        for opinfo in sorted_opinfos:
            start_addr = opinfo[0]
            end_addr = start_addr + opinfo[1]
            super().start_emu(start_addr, end_addr)
        return super().reg_value(rreg)

class armDeJmpRegEmulate(DeJmpRegEmulate):
    def __init__(self, is64 = True, isThumb = False, isEB = False) -> None:
        """arm架构

        Args:
            is64 (bool, optional): 是否是aarch64. Defaults to True.
            isThumb (bool, optional): 是否是Thumb指令集. Defaults to False.
            isEB (bool, optional): 是否是大端序. Defaults to False.
        """
        arch = UC_ARCH_ARM64 if is64 else UC_ARCH_ARM
        if arch == UC_ARCH_ARM64:
            mode = UC_MODE_ARM
        else:
            mode = UC_MODE_THUMB if isThumb else UC_MODE_ARM
        if isEB:
            mode |= UC_MODE_BIG_ENDIAN
        super().__init__(arch, mode)