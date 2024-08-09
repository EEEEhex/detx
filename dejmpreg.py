from binaryninja import *
from binaryninja.log import Logger
from .emulate import armDeJmpRegEmulate

import time

logger = Logger(0, "dejmpreg_log")

#递归通过搜索变量的def_site来拿到所有涉及到的指令
def get_involve_insns(jmp_insn: MediumLevelILJump):
    def get_right_ssa_var(expr, vars: list):
        if isinstance(expr, SSAVariable):
            vars.append(expr)
            return
        elif isinstance(expr, list):
            for ope in expr:
                if isinstance(ope, SSAVariable):
                    vars.append(ope)
            return

        if hasattr(expr, 'operands'):
            for ope in expr.operands:
                get_right_ssa_var(ope, vars)
        return

    involve_insns = [] #涉及到的指令
    jmp_var = jmp_insn.dest.var
    var_stack = []
    var_stack.append(jmp_var)
    while len(var_stack) != 0: #拿到一次寄存器间接跳转混淆涉及到的所有指令
        cur_ssa_var = var_stack.pop()
        insn_ = cur_ssa_var.def_site #一条指令 应该是MediumLevelILSetVarSsa或MediumLevelILVarPhi
        if insn_ == None:
            break

        if insn_ in involve_insns:
            break #如果拿到的指令已经在之前获取到的指令中了, 说明遇到循环了
        else:
            involve_insns.append(insn_) #添加涉及到的指令

        if 'cond' in insn_.dest.name:#遇到cond:20#1 = x8#2 == 0x586b6221这种就不再继续了 要不然有可能遇到phi节点导致死循环
            break

        insn_right = insn_.src #这条指令=右边的表达式
        get_right_ssa_var(insn_right, var_stack) #拿到表达式中的变量             
    
    return involve_insns

# 这种混淆就是把跳转改为了jmp(var2)
# 其中var2 = mem[var1 (<< num)] + const 这些值其实都是可以确定的, 例如:
# if (Cond)
#   var1 = 0;
# else 
#   var1 = 1;
# var2 = data_1fd630[var1];
# var3 = var2 - 0x7218df2;
# jump(var3); 

# 反混淆的话, 我的思路是静态分析+模拟执行:
# 从mlil ssa层面, 可以获取到jump变量var的指令
# 然后层层向上找, 找到所有涉及到的指令,
# 然后拿到这些指令对应的汇编指令模拟执行.
def dejmpreg(bv: BinaryView, func: Function, jmp_insn: MediumLevelILJump, emulator: armDeJmpRegEmulate, manual_value = None):
    mlil_ssa_func = func.mlil.ssa_form
    mlil_ssa_bb = jmp_insn.il_basic_block
    jmp_dest_var = jmp_insn.dest.var.var
    jmp_reg = bv.arch.get_reg_name(jmp_dest_var.storage)
    jmp_insn_addr = jmp_insn.address
    logger.log_info(f"开始分析 {hex(jmp_insn_addr)}...")

    #拿到涉及到的所有指令
    involve_insns = get_involve_insns(jmp_insn)
    # 判断指令中是否有arg字样, 有则说明有大概率是分析错了(可能是ninja把不该识别成函数的地址识别成函数了, 也可能是脚本分析错了), 需要手动分析
    if manual_value == None:
        arg_insn = None
        for insn in involve_insns:
            insn_token = insn.tokens
            for t in insn_token: #InstructionTextToken
                if 'arg' in t.text:
                    arg_insn = insn
                    break
            if arg_insn != None:
                break
        if arg_insn != None:
            result = interaction.show_message_box("提示", f"发现参数传值:{arg_insn}, 可能分析错误, 是否停止分析?", MessageBoxButtonSet.YesNoButtonSet, MessageBoxIcon.QuestionIcon)
            if result == MessageBoxButtonResult.YesButton:
                logger.log_warn("停止自动分析, 可手动设置条件选择指令设置的值(dejmpreg_manual)...")
                return None, None

    involve_asm_addrs = [] #涉及到的汇编指令的地址 可能少csx赋值指令 后面补上
    for mlssa_insn in involve_insns:
        llil_insns = mlssa_insn.llils
        for insn_ in llil_insns:
            if insn_.address not in involve_asm_addrs:
                involve_asm_addrs.append(insn_.address)
    logger.log_debug(f"involve_asm_addrs: {[hex(x) for x in involve_asm_addrs]}")

    #找到csel/cset/csinc指令以及指令地址
    condition_insn_names = ['csel', 'cset', 'csinc', 'cinc', 'csetm', 'csinv', 'csneg']
    condition_insn_addr = 0
    insn_token = None
    for addr in involve_asm_addrs:
        tmp_token = (bv.get_disassembly(addr)).split()
        if tmp_token[0] in condition_insn_names:
            insn_token = tmp_token
            condition_insn_addr = addr
            break
    if insn_token == None:
        logger.log_error(f"未找到{condition_insn_names}指令!")
        return None, None
    # 拿到csel/cset/csinc/cinc等指令设置的三个寄存器
    cond_set_value = []#true和false分支 要设置的值/寄存器
    cond_set_reg = insn_token[1][:-1] #去掉,
    if insn_token[0] == 'cset':
        cond_set_value = [1, 0]
    elif insn_token[0] == 'cinc':
        cond_set_value = [insn_token[2][:-1], insn_token[2][:-1]]
    elif insn_token[0] == 'csetm':
        cond_set_value = [-1, 0]
    else:
        cond_set_value = [insn_token[2][:-1], insn_token[3][:-1]]
    logger.log_debug(f"csx:{insn_token[0]} | csx addr: {hex(condition_insn_addr)} | csx value: {cond_set_value}")

    #拿到给csx的两个变量赋值的指令地址
    csx_var_addrs = []
    tmp_addrs = []
    for insn in involve_insns:
        if isinstance(insn, MediumLevelILVarPhi) and (len(insn.src) == 2):
            phi_var1 = insn.src[0].def_site
            phi_var2 = insn.src[1].def_site
            for llil in phi_var1.llils:
                tmp_addrs.append(llil.address)
            for llil in phi_var2.llils:
                tmp_addrs.append(llil.address)
            break
    for addr in tmp_addrs:
        token = (bv.get_disassembly(addr)).split()
        if (token[0] == 'mov') and (addr not in csx_var_addrs):
            csx_var_addrs.append(addr)
    # 如果csx赋值指令为空, 可能是cset, 也可能是某些原因(比如entry块复制)导致拿到的地址不全
    if (len(csx_var_addrs) == 0) and (insn_token[0] != 'cset'): 
        find_over = False
        pre_bb = mlil_ssa_bb.source_block #从前继块中搜索'mov x9, #..'这种指令, 找不到就只能手动分析了
        if (cond_set_value[0] == cond_set_value[1]) or ('xzr' in [cond_set_value[0], cond_set_value[1]]):
            search_count = 1 #如果两个寄存器相同, 或者有一个是xzr寄存器, 则只用搜索一个
        else:
            search_count = 2
        csx_value_reg = ['w' + cond_set_value[0][1:], 'w' + cond_set_value[1][1:]] 
        found_bbs = [pre_bb]
        while True:
            incomes = pre_bb.incoming_edges
            if (len(incomes) == 0):
                break #没有前继了
            if (len(incomes) == 1):
                pre_bb = pre_bb.incoming_edges[0].source
            else: #如果有多个income, 找地址最小的那一个
                min_bb = incomes[0].source
                for edge in incomes:
                    if (edge.source.start < min_bb.start):
                        min_bb = edge.source
                pre_bb = min_bb
            if pre_bb in found_bbs:
                logger.log_debug("已搜索过的块 可能遇到循环...")
                break
            else:
                found_bbs.append(pre_bb)
            
            cur_find_addr = pre_bb.end - pre_bb[-1][-1] #从后往前搜索
            while cur_find_addr >= pre_bb.start:
                insn_txt = bv.get_disassembly(cur_find_addr)
                token = insn_txt.split()
                if (token[0] == 'mov') and ((csx_value_reg[0] == token[1][:-1]) or (csx_value_reg[1] == token[1][:-1])):
                    csx_var_addrs.append(cur_find_addr)
                    logger.log_warn(f"使用可能的csx赋值指令 {hex(cur_find_addr)}: {insn_txt}")
                cur_find_addr -= bv.get_instruction_length(cur_find_addr)
                if len(csx_var_addrs) >= search_count:
                    find_over = True
                    break
            if find_over:
                break
        if find_over == False:
            logger.log_warn("未能自动搜索到csx赋值指令 分析可能出错...")
    if len(csx_var_addrs) > 2:
        logger.log_error(f"搜索到过多的csx赋值变量: {[hex(x) for x in csx_var_addrs]}")
        return None, None
    logger.log_debug(f"csx_var_addrs: {[hex(x) for x in csx_var_addrs]}")

    #补全涉及的指令
    for addr in csx_var_addrs:
        if addr not in involve_asm_addrs:
            involve_asm_addrs.append(addr)

    #把涉及到的指令的整个bb都写入
    involve_bbs = []
    for addr in involve_asm_addrs:
        bb = func.get_basic_block_at(addr)
        if bb not in involve_bbs:
            involve_bbs.append(bb)
    for bb in involve_bbs:
        bb_size = bb.end - bb.start
        opcodes =  bv.read(bb.start, bb_size)
        emulator.write_code_part(opcodes, bb.start)

    #找到本次混淆对应的cmp指令地址, cmp指令肯定在条件选择指令附近
    cmp_insn_addr = 0
    find_bb = func.get_basic_block_at(condition_insn_addr)
    find_addr = condition_insn_addr #先从当前bb找, 当前bb没有就往前继bb找
    while cmp_insn_addr == 0:
        find_token = (bv.get_disassembly(find_addr)).split()
        if find_token[0] == 'cmp':
            cmp_insn_addr = find_addr
            break

        if find_addr <= find_bb.start: #更新bb
            pre_edge = find_bb.incoming_edges
            if len(pre_edge) != 1:
                break #只能有一个前继
            find_bb = pre_edge[0].source
            find_addr = find_bb.end - find_bb[-1][-1] #[-1]是(token, size)
            continue

        op_len = bv.get_instruction_length(find_addr)
        find_addr -= op_len

    if cmp_insn_addr == 0:
        logger.log_error("未找到cmp指令!")
        return None, None
    else:
        verify_token = (bv.get_disassembly(cmp_insn_addr)).split()
        if verify_token[0] != 'cmp':
            logger.log_error(f"搜索到错误的cmp指令地址:{hex(cmp_insn_addr)}!")
            return  None, None
    logger.log_debug(f"cmp_insn_addr: {hex(cmp_insn_addr)}")

    #获取jmp表的地址并写入这块内存
    jmp_table_addr = 0
    for insn in involve_insns:
        if isinstance(insn, MediumLevelILSetVarSsa) and isinstance(insn.src, MediumLevelILLoadSsa):
            add_insn = insn.src.src
            for ope in add_insn.operands:
                if isinstance(ope, MediumLevelILConstPtr) or isinstance(ope, MediumLevelILConst):
                    jmp_table_addr = ope.constant
                    break
        if jmp_table_addr != 0:
            break
    if jmp_table_addr == 0:
        logger.log_error("未找到跳转表地址!")
        return cmp_insn_addr, None
    hex_bytes = bv.read(jmp_table_addr, 1024)
    emulator.write_code_part(hex_bytes, jmp_table_addr)
    logger.log_debug(f"jmp_table_addr: {hex(jmp_table_addr)}")
    
    #设置需要模拟执行的指令
    opinfos = []
    for addr in involve_asm_addrs:
        oplen = bv.get_instruction_length(addr)
        opinfos.append((addr, oplen))

    #分别模拟执行不同的值获取对应的跳转地址
    jmp_values = []
    if manual_value != None:
        cond_set_value = manual_value #手动设置的值
    index = 0 
    for value in cond_set_value:
        mov_opcode = b''
        if manual_value != None:
            mov_opcode = bv.arch.assemble(f"mov {cond_set_reg}, {value}", condition_insn_addr)
        else:
            #如果是csinc指令, 不满足条件应该改为add x24, x1, #1 | csinc是条件不满足则xd=xm+1, cinc是条件满足则xd=xn+1
            if ((insn_token[0] == 'csinc' ) and (index == 1)) or ((insn_token[0] == 'cinc') and (index == 0)): 
                if value == 'xzr':#如果是xzr寄存器就不能用add, 相当于赋值为了1
                    mov_opcode = bv.arch.assemble(f"mov {cond_set_reg}, #1", condition_insn_addr) 
                else:
                    mov_opcode = bv.arch.assemble(f"add {cond_set_reg}, {value}, #1", condition_insn_addr) 
            elif (insn_token[0] == 'csinv') and (index == 1): 
                mov_opcode = bv.arch.assemble(f"mvn {cond_set_reg}, {value}", condition_insn_addr) #按位取反
            elif (insn_token[0] == 'sneg') and (index == 1):
                mov_opcode = bv.arch.assemble(f"neg {cond_set_reg}, {value}", condition_insn_addr) #取负值
            else:
                mov_opcode = bv.arch.assemble(f"mov {cond_set_reg}, {value}", condition_insn_addr) #汇编mov x4, x9
        #将csx reg指令改为mov reg指令
        cs_insn_len = bv.get_instruction_length(condition_insn_addr)
        emulator.change_select(condition_insn_addr, cs_insn_len, mov_opcode)
        reg_value = emulator.run_specific_opcodes(opinfos, jmp_reg)
        jmp_values.append(reg_value)
        index += 1
    logger.log_info(f"{insn_token[0]}->jmp_values: True:{hex(jmp_values[0])}, False:{hex(jmp_values[1])}")
    if jmp_values[0] == jmp_values[1]:
        logger.log_warn(f"本次分析{hex(jmp_insn_addr)}结果可能出错! 请检查涉及到的地址中是否遗漏了指令:{[hex(x) for x in involve_asm_addrs]}")

    #开始Patch!!
    addr_info = {'cmp':cmp_insn_addr, 'cond': condition_insn_addr, 'jmp': jmp_insn_addr, 'involves': involve_asm_addrs}
    patch_addr_info = PatchSelect(bv, addr_info, jmp_values[0], jmp_values[1])

    need_nop_addrs = csx_var_addrs
    need_nop_addrs.append(cmp_insn_addr)
    return need_nop_addrs, patch_addr_info

def PatchSelect(bv: BinaryView, patch_info: dict, tbr_addr: int, fbr_addr: int):
    """不能直接patch csel和br指令为b.cond tbr_addr/b fbr_addr
    因为原逻辑是cmp之后, 还会执行其他指令(因为编译的时候穿插在一块了), 最后再br reg, 
    如果直接patch的话逻辑就改成了cmp之后直接跳了, 逻辑就不正确了, 所以将从cmp到br的指令重新移动构造
    
    Args:
        bv (BinaryView): bv
        patch_info (dict): 各种指令地址
        tbr_addr (int): 满足cmp条件的跳转地址
        fbr_addr (int): 不满足条件的跳转地址
    Returns:
        dict: 所有写入新数据的地址和长度
    """

    """
    具体做法为:
    1. 一次混淆至少涉及以下7个指令(中间穿插着其他逻辑的指令):
        mov     w10, #0x60
        ...
        mov     w11, #0x58
        ...
        cmp     w7, w22
        ...
        csel    x23, x11, x10, lt
        ...
        ldr     x25, [x12, x23]
        ...
        add     x7, x25, x13
        ...
        br      x7
    2. 改为如下:
        mov     w10, #0x60      <- 可以nop掉 不nop也不影响结果
        ...
        mov     w11, #0x58     
        ...
        nop                     <-  cmp     w7, w22 [cmp语句要最后统一nop 因为会可能有多个逻辑共用同一个cmp]
        ...
        nop                     <-  csel    x23, x11, x10, lt
        ...
        nop                     <-  其他涉及到的指令
        ...
        cmp     w7, w22         <-  ldr     x25, [x12, x23]
        b.lt    ...             <-  add     x7, x25, x13
        b       ...             <-  br      x7
    大多只有第一次混淆的时候这些混淆指令会穿插在一起, 之后基本都是ldr+add+br一个整体了
    """
    ret_dict = {} #{地址: 长度}
    cmp_addr = patch_info['cmp']
    cond_addr = patch_info['cond']
    jmp_addr = patch_info['jmp']
    involve_addrs = patch_info['involves']
    #从csx到br可以存放多少个字节(包括br)
    insn_space = jmp_addr - cond_addr + bv.get_instruction_length(jmp_addr)
    
    #0. 拿到所有要操作的指令
    obf_insns_index = [] #指在csx2br_insns_text中的index
    csx2br_insns_text = [] #从csx到br中的所有指令文本 (包含csx不包含br)
    read_addr = cond_addr
    index = 0
    while read_addr < jmp_addr:
        op_text = bv.get_disassembly(read_addr)        
        csx2br_insns_text.append(op_text)
        
        if read_addr in involve_addrs:
            obf_insns_index.append(index)

        op_len = bv.get_instruction_length(read_addr)
        read_addr += op_len

        index += 1
    logger.log_debug(f"cmp2br_insns_text: {csx2br_insns_text}")
    #1. 将混淆指令全转为nop, 并删除最后两个nop(一个nop改bcc, 一个nop改cmp)
    for i in obf_insns_index:
        csx2br_insns_text[i] = 'nop'
    csx2br_insns_text.pop(obf_insns_index[-1])
    csx2br_insns_text.pop(obf_insns_index[-2]) #index本身就是从小到大排序的, 所以直接pop不影响

    #2. 下沉cmp
    cmp_txt = bv.get_disassembly(cmp_addr)
    csx2br_insns_text.append(cmp_txt)

    #3. 获取select指令的寄存器 并添加跳转
    csx_tokens = (bv.get_disassembly(cond_addr)).split() #获取csel/cset/csinc等的token
    csx_cond = csx_tokens[-1] #条件eq/lt等
    bcc_cond = 'b.' + csx_cond
    bcc_txt = f"{bcc_cond} {hex(tbr_addr)}"
    csx2br_insns_text.append(bcc_txt)
    b_txt = f"b {hex(fbr_addr)}"
    csx2br_insns_text.append(b_txt)
    logger.log_info(f"csx2br_insns_text: {csx2br_insns_text}")

    #4. 将重新构造的指令从sex指令开始写入
    if (bv.arch.name == "aarch64"): #64位下指令长度固定为4, 对比哪些指令发生了变化再写哪些指令
        changed_insns = {}#{地址:opcode}
        index = 0
        for insn_txt in csx2br_insns_text:
            cmp_addr = cond_addr + 4 * index
            org_insn_txt = bv.get_disassembly(cmp_addr)
            if (org_insn_txt != insn_txt):
                opcode = None
                insn_tokens = insn_txt.split()
                if (insn_tokens[0][0] == 'b') and (insn_tokens[1][0] == '0'): #跳转指令需要写相对地址
                    bcc_type = insn_tokens[0]
                    bcc_addr = int(insn_tokens[1], 16)
                    bcc_opcode = bv.arch.assemble(f"{bcc_type} {hex(bcc_addr - cmp_addr)}", cmp_addr)
                    opcode = bcc_opcode
                else:
                    opcode = bv.arch.assemble(insn_txt)
                changed_insns[cmp_addr] = opcode
            index += 1
        logger.log_info(f"开始对比写入:{hex(cond_addr)}...")
        state = bv.begin_undo_actions()
        for addr in changed_insns.keys():
            bv.write(addr, changed_insns[addr])
            ret_dict[addr] = len(changed_insns[addr])
        bv.commit_undo_actions(state)
    else:
        new_opcodes = b''
        begin_addr = cond_addr #开始写的地址
        for insn_txt in csx2br_insns_text: #跳转指令需要单独汇编
            insn_tokens = insn_txt.split()
            if (insn_tokens[0][0] == 'b') and (insn_tokens[1][0] == '0'): #跳转指令需要写相对地址
                bcc_type = insn_tokens[0]
                bcc_addr = int(insn_tokens[1], 16)
                bcc_begin_addr = begin_addr + len(new_opcodes)
                bcc_opcode = bv.arch.assemble(f"{bcc_type} {hex(bcc_addr - bcc_begin_addr)}", bcc_begin_addr)
                new_opcodes += bcc_opcode
            else:
                new_opcodes += bv.arch.assemble(insn_txt)

        new_space = len(new_opcodes)
        if new_space != insn_space:
            logger.log_warn(f"前后机器码大小不一致: {insn_space} -> {new_space} 分析可能出错!")
        logger.log_debug(f"space cmp: {insn_space} -> {new_space}")
        if new_space > insn_space:
            logger.log_error(f"新产生的机器码数量{new_space} > 原先的大小{insn_space}")
            return
        elif new_space < insn_space:
            nop_bytes = b'\x00' * (insn_space - new_space)
            nop_bytes = bv.arch.convert_to_nop(nop_bytes, begin_addr + new_space)
            new_opcodes += nop_bytes
        logger.log_info(f"开始全部写入:{hex(begin_addr)}...")
        state = bv.begin_undo_actions()
        bv.write(begin_addr, new_opcodes)
        ret_dict[begin_addr] = len(new_opcodes)
        bv.commit_undo_actions(state)
    return ret_dict
    
# 循环去混淆
def dejmpreg_auto(bv: BinaryView, func: Function):

    dejmpreg_emu = armDeJmpRegEmulate() #模拟执行器
    dejmpreg_emu.init_func_emu(func.start, 4 * 1024) #小于4k都是4k

    deobf_ok = True
    patch_infos = {} #{addr: len}被写入的地址信息
    need_nop_addrs = [] #被编译优化提前的cmp指令和csx赋值的指令(都有可能被共用), 需要在去混淆完毕后统一nop
    #耗时操作弹出进度dialog
    def loop_dejmpreg(progress_callback):
        nonlocal deobf_ok #外部变量

        progress_total = 45 #给个初始值 动态更新
        cur_deobf_count = 0

        last_insn_addr = 0
        while True:
            mlil_ssa_func = func.mlil.ssa_form

            find_insn = None
            #找每一个块的最后一个指令
            for bb in mlil_ssa_func:
                ssa_insn = bb[-1]
                if isinstance(ssa_insn, MediumLevelILJump):
                    find_insn = ssa_insn
                    break
            if (find_insn != None) and (find_insn.address == last_insn_addr):
                deobf_ok = False
                break #如果这次找到的指令和上次的一样 说明去混淆失败

            if find_insn != None:
                last_insn_addr = find_insn.address #记录指令地址
                try: #异常则退出
                    nop_info, patch_info = dejmpreg(bv, func, find_insn, dejmpreg_emu)
                    if (nop_info == None) or (patch_info == None):
                        deobf_ok = False
                        break
    
                    need_nop_addrs.extend(nop_info)
                    patch_infos.update(patch_info)
                    func.reanalyze() # 重新分析函数，以便更新SSA形式
                    while True: #reanalyze是异步的 不会等待重新分析完毕 我没找到同步的API 先这样写吧
                        time.sleep(0.2)  # 等待一段时间再检查
                        if func.mlil.ssa_form is not None:
                            break
    
                    cur_deobf_count += 1 #去除一次
                    if cur_deobf_count >= progress_total:
                        progress_total += 20
                except Exception as e:
                    deobf_ok = False
                    logger.log_error(f"发生异常: {e}")
                    break
            else:
                break
            
            # 调用进度回调函数，参数为已完成和总量
            if not progress_callback(cur_deobf_count, progress_total):
                return
        # 完成
        logger.log_info(f"共去除[寄存器间接跳转]混淆[{cur_deobf_count}]次...")
        progress_callback(progress_total, progress_total)

    start_time = time.time()
    progress_result = interaction.run_progress_dialog("正在去除[寄存器间接跳转]混淆...", True, loop_dejmpreg)
    end_time = time.time()

    # 检查任务是否成功完成
    if progress_result:
        if deobf_ok:
            logger.log_debug(f"patch_infos: { {hex(addr): length for addr, length in patch_infos.items()} }")
            state = bv.begin_undo_actions() #nop cmp指令
            nop_addrs = []
            for addr in need_nop_addrs:
                in_patch = False #如果地址在我们写入的新patch地址中, 就不要去nop它
                for paddr in patch_infos.keys(): 
                    if (addr >= paddr) and (addr < paddr + patch_infos[paddr]):
                        in_patch = True
                        break 

                if not in_patch:
                    op_len = bv.get_instruction_length(addr)
                    nop_bytes = b'\x00' * op_len
                    nop_bytes = bv.arch.convert_to_nop(nop_bytes, addr)
                    bv.write(addr, nop_bytes)
                    nop_addrs.append(addr)
            logger.log_info(f"nop掉无用指令: {[hex(x) for x in nop_addrs]}")
            bv.commit_undo_actions(state)
            logger.log_info(f"去除[寄存器间接跳转]混淆完毕! 共耗时 {end_time - start_time} 秒...")
        else:
            logger.log_error("去除[寄存器间接跳转]混淆失败!...")
    else:
        logger.log_error("用户取消去除[寄存器间接跳转]操作!...")

# 去混淆一次
def dejmpreg_cursor(bv: BinaryView, address: int):
    target_func = (bv.get_functions_containing(address))[0]
    target_mlil_ssa_func = target_func.mlil.ssa_form

    #找到包含该地址的bb
    find_bb = None
    for mlssa_bb in target_mlil_ssa_func:
        start_addr = mlssa_bb[0].address
        end_addr = mlssa_bb[-1].address
        if (address >= start_addr) and (address <= end_addr):
            find_bb = mlssa_bb
            break
    if (find_bb != None) and (isinstance(find_bb[-1], MediumLevelILJump)):
        dejmpreg_emu = armDeJmpRegEmulate() #模拟执行器
        dejmpreg_emu.init_func_emu(target_func.start, 4 * 1024) #小于4k都是4k

        find_insn = find_bb[-1]
        dejmpreg(bv, target_func, find_insn, dejmpreg_emu)
    else:
        logger.log_error(f"{hex(address)}: 该地址处未找到jump指令!")

# 手动设置条件选择指令的值 用于调试
def dejmpreg_manual(bv: BinaryView, address: int):
    target_func = (bv.get_functions_containing(address))[0]
    target_mlil_ssa_func = target_func.mlil.ssa_form

    #找到包含该地址的bb
    find_bb = None
    for mlssa_bb in target_mlil_ssa_func:
        start_addr = mlssa_bb[0].address
        end_addr = mlssa_bb[-1].address
        if (address >= start_addr) and (address <= end_addr):
            find_bb = mlssa_bb
            break
    if (find_bb != None) and (isinstance(find_bb[-1], MediumLevelILJump)):
        true_res = interaction.get_int_input("输入满足条件时的值:", "手动设置csx指令的值")
        false_res = interaction.get_int_input("输入不满足条件时的值:", "手动设置csx指令的值")
        if (true_res == None) or (false_res == None):
            interaction.show_message_box("提示", "未输入值, 取消执行")
            return

        manual_value = [true_res, false_res]
        logger.log_info(f"使用手动值: True:{hex(true_res)} False:{hex(false_res)}")
        dejmpreg_emu = armDeJmpRegEmulate() #模拟执行器
        dejmpreg_emu.init_func_emu(target_func.start, 4 * 1024) #小于4k都是4k

        find_insn = find_bb[-1]
        dejmpreg(bv, target_func, find_insn, dejmpreg_emu, manual_value)
    else:
        logger.log_error(f"{hex(address)}: 该地址处未找到jump指令!")