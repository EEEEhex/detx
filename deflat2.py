from binaryninja import *
from binaryninja.log import Logger
from .emulate import armDeflatEmulate

from typing import List, Union
from dataclasses import dataclass

logger = Logger(0, "deflat2_log")

@dataclass
class PatchInfo:
    """一次patch信息
    """
    start: Optional[int] = None         #patch起始地址
    pbytes: Optional[bytes] = None      #要改成什么字节
    next: Optional['PatchInfo'] = None  #下一个要改的信息 前向引用

@dataclass
class AssignBBInfo:
    """赋值块信息
    包含块起始地址,
    块对应switch变量值等
    """
    @dataclass
    class VarValueInfoTF:
        t_value: int
        f_value: int
        v_type:  int        #类型 0正常类型 1判断提前
    @dataclass
    class VarValueInfoU:
        u_value: int

    bb_start: Optional[int] = None                                       #当前块起始地址
    set_var_addr: Optional[int] = None                                   #当前块改变switch变量的指令的地址
    var_value: Optional[Union[VarValueInfoTF, VarValueInfoU]] = None     #switch变量
    real_suc: Optional[List[int]]  = None                                #真实后继地址信息 0是True 1是False分支

#拿到[判断提前]类型的值
def get_ahead_phi_value(arg_insn: MediumLevelILVarPhi):
    t_value_ = None
    f_value_ = None
    phi_insn = arg_insn
    while True:
        phi_insn_src = phi_insn.src
        if not hasattr(phi_insn_src, "src"):
            break
        phi_insn_src_var = phi_insn_src.src
        if not hasattr(phi_insn_src_var, "def_site"):
            break
        phi_insn = phi_insn_src_var.def_site
        if isinstance(phi_insn, MediumLevelILVarPhi) and (len(phi_insn.src) == 2):
            for phi_var in phi_insn.src:
                phivar_ainsn = phi_var.def_site
                branch_type = True if phivar_ainsn.il_basic_block.incoming_edges[0].type == BranchType.TrueBranch else False
                if branch_type == True:
                    t_value_ = phivar_ainsn.src.constant
                else:
                    f_value_ = phivar_ainsn.src.constant
            break
    return t_value_, f_value_

#拿到[判断提前]类型的csel指令地址
def get_ahead_csel_addr(func, arg_addr):
    csel_addr = None

    assign_insn_index = func.mlil.ssa_form.get_instruction_start(arg_addr)
    assign_insn = func.mlil.ssa_form[assign_insn_index]
    logger.log_debug(f"[判断提前]: {hex(arg_addr)} => {assign_insn}")

    use_insn_ = assign_insn
    if isinstance(use_insn_.il_basic_block[-1], MediumLevelILIf):
        use_insn_ = use_insn_.il_basic_block[-1]

    if isinstance(use_insn_, MediumLevelILIf):
        insn_index  = use_insn_.true
        insn_ = func.mlil.ssa_form[insn_index]
        if insn_.dest.name == insn_.src.var.name:
            insn_index = use_insn_.false 
            insn_ = func.mlil.ssa_form[insn_index]
        use_insn_ = insn_

    phi_insn = use_insn_
    while True:
        phi_insn_src = phi_insn.src
        if not hasattr(phi_insn_src, "src"):
            break
        phi_insn_src_var = phi_insn_src.src
        if not hasattr(phi_insn_src_var, "def_site"):
            break
        phi_insn = phi_insn_src_var.def_site
        if isinstance(phi_insn, MediumLevelILVarPhi) and (len(phi_insn.src) == 2):
            csel_addr = phi_insn.src[0].def_site.address
            break
    return csel_addr

"""
腾讯的控制流平坦化也是while(true) + switch(var)结构,  
那么流程的分发一定是通过var这个switch变量, 因此反混淆逻辑是:  
通过mlil层面拿到所有给var赋值的语句, 该语句所在的块就是真实块, 
然后获取到当前块把var改成什么值了, 通过模拟执行该值会到达哪个块来确定后继块
"""
def deflat2(bv: BinaryView, func: Function, switch_var_ssa: SSAVariable, extra_real_addr = None, manual_value = None, witch_check = False): 
    #从mlil层面或者mlil ssa层面分析都可以, 我感觉ssa层面更方便一点
    loop_phi_var_insn = switch_var_ssa.def_site #循环分发开始的那个获取var值的指令
    if not isinstance(loop_phi_var_insn, MediumLevelILVarPhi):
        logger.log_error(f"错误的变量{switch_var_ssa}...")
        return
    
    init_sbb = []       #汇编层面的初始化块 初始化块就是初始化分发变量值的块 比如cmp w9, w22中的w22就是在初始化块中分配的值
    real_sbb = []       #汇编层面的真实块
    ret_sbb = []        #汇编层面的ret块
    dispatch_sbb = []   #汇编层面的分发块 (可能的 而且不一定全) 只是patch用
    loopEntry_sbb = loop_phi_var_insn.il_basic_block.source_block #汇编层面的循环分发开始的块
    assign_bb_infos: List[AssignBBInfo] = [] #存放赋值块对应的switch变量信息

    logger.log_info("[0] 开始获取真实块/初始化块/分发块等信息...")
    #用到了switch_var_ssa的if语句就是分发块
    for insn in switch_var_ssa.use_sites:
        if isinstance(insn, MediumLevelILIf):
            cur_mlil_ssa_bb = insn.il_basic_block
            dispatch_sbb.append(cur_mlil_ssa_bb.source_block)
    b_bb = []
    for bb in dispatch_sbb:
        for edge in bb.outgoing_edges:
            suc_bb = edge.target
            if (suc_bb.instruction_count == 1):
                insn_token = suc_bb[0][0] #bb的后继块指令
                if (insn_token[0].text)[0] == 'b': #如果是一个单独的b(.cc)的话
                    b_bb.append(suc_bb)
    dispatch_sbb.extend(b_bb) #cmp块的下一个块 如果是b(.cc)的话也是分发块

    #循环分发开始块的前继块都是初始化块
    pre_bb = loopEntry_sbb
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

        if pre_bb in dispatch_sbb:
            break

        last_insn_type = pre_bb[-1][0][0].text
        if last_insn_type[0] == 'b': #跳过的来 不是
            break

        init_sbb.append(pre_bb)
    if len(init_sbb) == 0:
        logger.log_error("未搜索到初始化块 分析出错!...")
        return 
    elif len(init_sbb) >= 5:
        logger.log_warn(f"搜索到过多的初始化块{[hex(bb.start) for bb in init_sbb]} 分析可能出错!...")
    entry_bb = func.basic_blocks[0] #未防止意外情况 把entry块也加上
    if entry_bb not in init_sbb:
        init_sbb.append(entry_bb)
    init_sbb.reverse() #逆序 就是按地址从小到大排序的了
    
    #当前平坦化可能是嵌套的或者平行的 可能不具有ret块, 这里获取的ret块是全局的, 不影响, 只是为了当作一个可能的真实块
    for bb in func.basic_blocks:
        if len(bb.outgoing_edges) == 0:
            ret_sbb.append(bb) #没有后继就是ret块
    
    #获取获取赋值块 同时获取真实块的信息
    switch_vars = loop_phi_var_insn.src #所有用到的var的ssa变量
    logger.log_debug(f"switch变量赋值指令: {[var.def_site for var in switch_vars]}")
    for svar in switch_vars:
        assign_insn = svar.def_site #给当前ssa变量赋值的指令
        if assign_insn == loop_phi_var_insn:
            continue
        cur_ssa_bb = assign_insn.il_basic_block
        disasm_bb = cur_ssa_bb.source_block
        real_sbb.append(disasm_bb)
        #如果一个赋值块有两个(两个以上的情况还没遇到过)直接前继, 且其前继块不是分发块, 则其前继块也是真实块, 该赋值块是共用的
        if (len(disasm_bb.incoming_edges) == 2): #>2块共用也有可能 遇到再改
            pre_edge1 = disasm_bb.incoming_edges[0]
            pre_edge2 = disasm_bb.incoming_edges[1]
            if (pre_edge1.type == BranchType.UnconditionalBranch) and (pre_edge2.type == BranchType.UnconditionalBranch):
                pre_bb1 = pre_edge1.source
                pre_bb2 = pre_edge2.source
                if (pre_bb1 not in dispatch_sbb) and (pre_bb2 not in dispatch_sbb):
                    real_sbb.append(pre_bb1)
                    real_sbb.append(pre_bb2)
        
        cur_bb_info = AssignBBInfo()
        cur_bb_info.bb_start = cur_ssa_bb.source_block.start    #赋值块起始地址
        cur_bb_info.set_var_addr = assign_insn.address          #改变var值的指令的地址
        if isinstance(assign_insn, MediumLevelILSetVarSsa): #说明不是分支
            value_ = None
            var_value_info = None
            if isinstance(assign_insn.src, MediumLevelILVarSsa): #x9_2 = x9_1; 判断提前
                t_value_ = None #需要拿到真正的var值
                f_value_ = None
                t_value_, f_value_ = get_ahead_phi_value(assign_insn)
                if None in [t_value_, f_value_]:
                    logger.log_error(f"[判断提前]类型指令分析失败:{hex(assign_insn.address)} => {assign_insn}")
                    return
                var_value_info = AssignBBInfo.VarValueInfoTF(t_value=t_value_, f_value=f_value_, v_type=1)
            elif isinstance(assign_insn.src, MediumLevelILConst):
                value_ = assign_insn.src.constant
                var_value_info = AssignBBInfo.VarValueInfoU(u_value=value_)
            cur_bb_info.var_value = var_value_info

        elif isinstance(assign_insn, MediumLevelILVarPhi) and (len(assign_insn.src) == 2):#x9_2#20 = ϕ(x9_2#18, x9_2#19)
            t_value_ = None
            f_value_ = None
            var_value_info = None
            for phi_var in assign_insn.src:
                phivar_ainsn = phi_var.def_site
                cur_bb_info.set_var_addr = phivar_ainsn.address          #更新改变var值的指令的地址 phi指令用这个地址才是对应的汇编层面的csel或者其他赋值指令
                branch_type = True if phivar_ainsn.il_basic_block.incoming_edges[0].type == BranchType.TrueBranch else False
                ainsn_src_ope = phivar_ainsn.src.operands[0]
                if isinstance(ainsn_src_ope, SSAVariable): #这种类型: [x9#3 = 0x2e3a7efe |  x9#4 = x9#2] -> csel w9, w24, w9, eq相当于mov w9, w24
                    if (phivar_ainsn.dest.name == ainsn_src_ope.name):
                        continue
                    else: #这种类型 [x14_1#8 = x15_1#5 | x14_1#9 = x14_1#3] -> csel w14, w15, w14, eq 还是判断提前
                        t_value_, f_value_ = get_ahead_phi_value(phivar_ainsn)
                        if None in [t_value_, f_value_]:
                            logger.log_error(f"[判断提前]类型指令分析失败:{hex(assign_insn.address)} => {assign_insn}")
                            return
                        var_value_info = AssignBBInfo.VarValueInfoTF(t_value=t_value_, f_value=f_value_, v_type=1)
                        break
                elif isinstance(ainsn_src_ope, int):
                    if branch_type == True:
                        t_value_ = ainsn_src_ope
                    else:
                        f_value_ = ainsn_src_ope
            if var_value_info == None:
                if None in [t_value_, f_value_]: #存在None则说明是直接类型
                    value_ = t_value_ if t_value_ != None else f_value_
                    var_value_info = AssignBBInfo.VarValueInfoU(u_value=value_)
                else:
                    var_value_info = AssignBBInfo.VarValueInfoTF(t_value=t_value_, f_value=f_value_, v_type=0)
            cur_bb_info.var_value = var_value_info
        else:
            logger.log_error("未知switch变量赋值指令类型...")
            return
        assign_bb_infos.append(cur_bb_info)
    if (extra_real_addr != None): #添加用户额外设置的真实块地址
        extra_sbb = func.get_basic_block_at(extra_real_addr)
        real_sbb.append(extra_sbb)

    
    #可选 把分发块的后继块当作真实块(如果一个函数有多个平坦化的话就需要这样 但这样获取的信息不一定是正确的)
    if witch_check:
        for bb in dispatch_sbb:
            for edge in bb.outgoing_edges:
                suc_bb = edge.target
                if (suc_bb not in dispatch_sbb) and (suc_bb not in init_sbb):
                    if (suc_bb not in real_sbb) and (suc_bb not in ret_sbb):
                        if (suc_bb != loopEntry_sbb): #且如果是b.ne/b.eq的话 则必须分别是false/true分支
                            correct_bb = None
                            bcc_type = dispatch_sbb[-1][0][0]
                            if bcc_type == 'b.ne':
                                correct_bb = dispatch_sbb.outgoing_edges[1].target #FalseBranch
                            elif bcc_type == 'b.eq':
                                correct_bb = dispatch_sbb.outgoing_edges[0].target #TrueBranch
                            if (correct_bb == None) or (correct_bb == suc_bb):
                                real_sbb.append(suc_bb)
        logger.log_warn("[!] 当前会使用分发块的后继块当作真实块 此行为可能导致分析错误!")
    
    logger.log_info("[0] 获取信息完毕!")
    logger.log_debug(f"init_sbb: {init_sbb}")
    logger.log_debug(f"real_sbb: {real_sbb}")
    logger.log_debug(f"ret_sbb: {ret_sbb}")
    logger.log_debug(f"dispatch_sbb: {dispatch_sbb}")
    logger.log_debug(f"loopEntry_sbb: {loopEntry_sbb}")
    logger.log_debug(f"assign_bb_infos: {assign_bb_infos}")
    common_sbb = []
    for bb in real_sbb:
        if bb in dispatch_sbb:
            common_sbb.append(bb)
    logger.log_debug(f"common_sbb: {common_sbb}")

    i = 0
    log_msg_ = ""
    for info in assign_bb_infos:
        log_msg_ += f"({i:02d}) {hex(info.bb_start)}"
        if isinstance(info.var_value, AssignBBInfo.VarValueInfoU):
            log_msg_ += f" ---> {hex(info.var_value.u_value)}"
        elif isinstance(info.var_value, AssignBBInfo.VarValueInfoTF):
            log_msg_ += f" --t-> {hex(info.var_value.t_value)}\n"
            log_msg_ += f"({i:02d}) \t╰--f-> {hex(info.var_value.f_value)}"
        log_msg_ += "\n"
        i += 1
    logger.log_debug(f"真实块的switch值:\n{log_msg_}")

    logger.log_info("[1] 开始模拟执行获取块之间后继关系...")
    #开始模拟执行!
    deflat_emu = armDeflatEmulate() #模拟执行器
    # 0. 写入机器码 同时调用init块中的指令进行初始化
    func_start_addr = func.start
    func_end_addr = func.highest_address + 1
    func_bytes = bv.read(func_start_addr, func_end_addr - func_start_addr) #读取当前函数的机器码
    asm_bytes_noped = bytearray(func_bytes) #把init块机器码中的call都nop掉
    for bb in init_sbb:
        insn_addr = bb.start
        for insn in bb:
            insn_len = insn[-1]
            insn_type = insn[0][0].text
            if insn_type == 'bl':
                offset_in_bytes = insn_addr - func_start_addr
                nop_bytes = '\x00' * insn_len
                nop_bytes = bv.arch.convert_to_nop(nop_bytes, insn_addr)
                i = 0
                for b in nop_bytes:
                    asm_bytes_noped[offset_in_bytes + i] = b
                    i += 1
            insn_addr += insn_len
    func_bytes = bytes(asm_bytes_noped)
    deflat_emu.init_func_emu(func_start_addr, func_end_addr - func_start_addr)
    deflat_emu.write_func_opcode(func_bytes) # 写入到emu内存中

    for bb in init_sbb:#执行init块的指令 (去掉了call)
        end_addr = bb.end
        last_insn_type = (bb[-1][0][0].text)[0]
        if last_insn_type == 'b':
            end_addr -= bb[-1][-1]
        deflat_emu.init_reg_stack(bb.start, end_addr)

    # 1. 设置分发寄存器 (一般来讲是寄存器, 腾讯这个用的都是cmp w9, w22这种, 没见过用栈的)
    mlil_var = switch_var_ssa.var
    if (mlil_var.source_type != VariableSourceType.RegisterVariableSourceType):
        logger.log_error("未处理的情况{mlil_var}, 分发变量不是寄存器!")
        return
    dispatch_reg = bv.arch.get_reg_name(mlil_var.storage)
    deflat_emu.set_switch_var(dispatch_reg)
    
    # 2. 设置模拟执行循环开始地址
    loopEntry_begin = loopEntry_sbb.start #分发开始的地址
    deflat_emu.set_switch_begin_addr(loopEntry_begin) #每次模拟都从此地址开始模拟执行
    
    # 3. 设置模拟停止地址(真实块地址)
    stop_addrs = []
    for bb in real_sbb:
        stop_addrs.append(bb.start)
    for bb in ret_sbb:
        stop_addrs.append(bb.start)
    deflat_emu.set_stop_addrs(stop_addrs)

    # 4. 获取赋值块的真实后继地址
    if (manual_value != None):
        deflat_emu.set_switch_var_value(manual_value)
        logger.log_info(f"[*] 已设置{dispatch_reg}为: {hex(deflat_emu.reg_value(dispatch_reg))}")
        suc_addr = deflat_emu.start_until_stop()
        logger.log_info(f"[*] 当值为 {hex(manual_value)} 时 会到达---> {hex(suc_addr)}")
        return
    else:
        cmp_regs = {}
        if witch_check: #获取各个分发寄存器的初始值
            for bb in dispatch_sbb:
                index = 0
                for insn_info in bb:
                    if insn_info[0][0].text == 'cmp':
                        wreg_name = insn_info[0][-2].text
                        if (bb[index - 1][0][0].text == 'movk') and (bb[index - 1][0][2].text == wreg_name):
                            pass #当前分发寄存器的初始值不是在init块中初始化的 是在当前块中赋值的
                        else:
                            xreg_name = 'x' + wreg_name[1:]
                            cmp_regs[xreg_name] = 0
                    index += 1
            for reg in cmp_regs:
                cmp_regs[reg] = deflat_emu.reg_value(reg)
                logger.log_info(f"[C] {reg} 初始值: {hex(cmp_regs[reg])}")

        for info in assign_bb_infos:
            if witch_check: #每次进入分发逻辑之前初始化分发寄存器的值
                for reg in cmp_regs:
                    cur_value = deflat_emu.reg_value(reg)
                    if cur_value != cmp_regs[reg]:
                        logger.log_warn(f"[C] 当前分发寄存器{reg}的值为 {hex(cur_value)} =将改为初始值=> {hex(cmp_regs[reg])}")
                        deflat_emu.reg_value(reg, cmp_regs[reg])

            var_value = info.var_value
            real_sucs_ = []
            #logger.log_warn(f"在 {hex(info.bb_start)} 前 w10: {hex(deflat_emu.reg_value('w10'))}")
            if isinstance(var_value, AssignBBInfo.VarValueInfoU): #只有一条赋值语句
                deflat_emu.set_switch_var_value(var_value.u_value)
                suc_addr = deflat_emu.start_until_stop()
                real_sucs_.append(suc_addr)

            elif isinstance(var_value, AssignBBInfo.VarValueInfoTF): #有两个赋值语句
                deflat_emu.set_switch_var_value(var_value.t_value)
                suc_addr = deflat_emu.start_until_stop()
                real_sucs_.append(suc_addr)

                deflat_emu.set_switch_var_value(var_value.f_value)
                suc_addr = deflat_emu.start_until_stop()
                real_sucs_.append(suc_addr)
            #logger.log_warn(f"在 {hex(info.bb_start)} 后 w10: {hex(deflat_emu.reg_value('w10'))}")
            info.real_suc = real_sucs_
        # 5. 打印输出
        i = 0
        log_msg_ = ""
        for info in assign_bb_infos:
            log_msg_ += f"({i:02d}) {hex(info.bb_start)}"
            if isinstance(info.var_value, AssignBBInfo.VarValueInfoU):
                log_msg_ += f" ---> {hex(info.real_suc[0])}"
            elif isinstance(info.var_value, AssignBBInfo.VarValueInfoTF):
                log_msg_ += f" --t-> {hex(info.real_suc[0])}\n"
                log_msg_ += f"({i:02d}) \t╰--f-> {hex(info.real_suc[1])}"
            log_msg_ += "\n"
            i += 1
        logger.log_info(f"[1] 模拟执行结束, 块之间后继关系:\n{log_msg_}")

        #如果有后继是loopEntry的 则说明分析失败
        for info in assign_bb_infos:
            for suc in info.real_suc:
                if suc == loopEntry_begin:
                    logger.log_error(f"[!] 地址: {hex(info.bb_start)} 处后继分析失败! {hex(loopEntry_begin)}")
                    return

        #开始Patch!
        PatchAssignBB(bv, func, assign_bb_infos, real_sbb, dispatch_sbb)


def PatchAssignBB(bv: BinaryView, func: Function, abb_infos: List[AssignBBInfo], real_bb, dispatch_bb):
    logger.log_info("[2] 开始获取Patch信息...")
    #可用的无用块, 可用于提供额外的patch空间
    useless_bb = []
    for bb in dispatch_bb:    #防止分发块和真实块共用的情况
        if bb not in real_bb: 
            useless_bb.append(bb)
    
    #因为patch会改变CFG图 所以先记录要patch的信息 再统一patch
    patch_infos = []
    for info in abb_infos:
        cur_bb = bv.get_basic_blocks_at(info.bb_start)[0]
        suc_addrs = info.real_suc #后继地址 
        patch_info = PatchInfo()
        last_insn_addr = cur_bb.end - cur_bb[-1][-1] #当前块最后一个指令的起始地址
        pbytes = b'' #要patch成的字节
        if len(suc_addrs) == 1:#一个就直接把末尾的b指令改了
            patch_start_addr = None
            insn_type = cur_bb[-1][0][0].text
            if (insn_type != 'b'): #末尾指令不是跳转指令
                next_bb = cur_bb.outgoing_edges[0].target #看看紧邻的后继块是不是在useless块中
                if next_bb in useless_bb: #将后继块patch成b ... + nop
                    relative_addr = suc_addrs[0] - next_bb.start
                    pbytes = bv.arch.assemble(f"b {hex(relative_addr)}", next_bb.start)
                    nop_bytes = b'\x00' * (next_bb.length - len(pbytes))
                    nop_bytes = bv.arch.convert_to_nop(nop_bytes, next_bb.start + len(pbytes))
                    pbytes += nop_bytes

                    useless_bb.remove(next_bb) #删除
                else:
                    logger.log_error(f"未处理情况, 赋值块{cur_bb}的后继{next_bb}不是uesless块, 无法patch!")
                    return
                patch_start_addr = next_bb.start
            else:
                relative_addr = suc_addrs[0] - last_insn_addr
                pbytes = bv.arch.assemble(f"b {hex(relative_addr)}", last_insn_addr)
                patch_start_addr = last_insn_addr
            patch_info.start = patch_start_addr
            patch_info.pbytes = pbytes
        elif len(suc_addrs) == 2: #两个要分情况
            if (info.var_value.v_type == 0): #正常类型
                csel_token = bv.get_disassembly(info.set_var_addr).split() #例如['csel', 'w20,', 'w8,', 'w10,', 'eq']
                if csel_token[0] != 'csel': #不是csel的情况还没遇到过
                    logger.log_error(f"未处理的patch情况!{hex(info.set_var_addr)} => {csel_token}")
                    return
                llast_insn_addr = last_insn_addr - cur_bb[-2][-1] #倒数第二个指令地址
                if llast_insn_addr != info.set_var_addr:#如果不是倒数第二个的话就要去移动
                    logger.log_warn(f"csel指令不是当前块的倒数第二个指令!{hex(info.set_var_addr)} != {hex(llast_insn_addr)}")
                    logger.log_warn(f"[!] 将会重新移动构造对应指令, 结果可能出错!...")
                    #拿到csel到b的指令(不包括这两个指令) 相当于把csel-b之间的指令提前了: insns csel b
                    mid_insn_start = info.set_var_addr + bv.get_instruction_length(info.set_var_addr)
                    block_insn_bytes = bv.read(mid_insn_start, last_insn_addr - mid_insn_start)
                    pbytes = block_insn_bytes
                bcc_type = "b." + csel_token[-1]
                relative_addr = suc_addrs[0] - info.set_var_addr #b.cc t_addr
                bcc_insn_bytes = bv.arch.assemble(f"{bcc_type} {hex(relative_addr)}", info.set_var_addr)
                relative_addr = suc_addrs[1] - last_insn_addr #b f_addr
                b_insn_bytes = bv.arch.assemble(f"b {hex(relative_addr)}", last_insn_addr)
                pbytes += bcc_insn_bytes + b_insn_bytes
                patch_info.start = info.set_var_addr
                patch_info.pbytes = pbytes
            elif (info.var_value.v_type == 1): #判断提前
                #我的思路是 条件传递:csel改为cset 后面判断01
                # 1. 拿到提前的csel指令地址 并改为cset
                csel_addr = get_ahead_csel_addr(func, info.set_var_addr)
                ahead_csel_token = bv.get_disassembly(csel_addr).split()
                ahead_csel_cond = ahead_csel_token[-1]    #csel的最后的条件
                ahead_csel_reg = ahead_csel_token[1][:-1] #csel设置的寄存器
                if ahead_csel_token[0] != 'csel':
                    logger.log_error(f"分析错误, {hex(csel_addr)}并不是提前的csel指令!")
                    return
                new_cset_bytes = bv.arch.assemble(f"cset {ahead_csel_reg}, {ahead_csel_cond}")
                # 2. 找分发块(因为分发块已经无用了) 存放(cmp ahead_csel_reg, #0x1) + (b.ahead_csel_cond t_addr) + (b f_addr)
                chain_bb = None
                for bb in useless_bb: #先找能存放3个指令的分发块
                    if bb.instruction_count >= 3:
                        chain_bb = bb
                        break
                if chain_bb == None:   #如果没有的话, 就随便找三个能存放2个指令的分发快(最后一个块可以只存放一个指令)
                    chain_bb = []
                    for bb in useless_bb:
                        if bb.instruction_count >= 2:
                            chain_bb.append(bb)
                            if len(chain_bb) == 2:
                                break
                    useless_bb = [bb for bb in useless_bb if bb not in chain_bb]#删除对应元素
                    for bb in useless_bb:
                        if bb.instruction_count >= 1:
                            chain_bb.append(bb)
                            useless_bb.remove(bb)
                            break
                # 3. 获取patch分发块信息
                patch_info.start = csel_addr        #第一个patch
                patch_info.pbytes = new_cset_bytes
                if isinstance(chain_bb, list): #一个块放不下就分成三个块
                    if len(chain_bb) < 3:
                        logger.log_error(f"分发块的数量不足以提供足够的Patch空间!:{useless_bb}")
                        return 
                    logger.log_debug(f"[判断提前] 将拆成三个块{[hex(bb.start) for bb in chain_bb]}写入Patch信息...")
                    chain_bb1 = chain_bb[0]
                    first_patch = PatchInfo()
                    first_patch.start = last_insn_addr
                    first_patch.pbytes = bv.arch.assemble(f"b {hex(chain_bb1.start - last_insn_addr)}", last_insn_addr)
                    patch_info.next = first_patch

                    chain_bb2 = chain_bb[1]
                    second_patch = PatchInfo()
                    second_patch.start = chain_bb1.start
                    new_insn_cur_addr = chain_bb1.start
                    second_bytes = bv.arch.assemble(f"cmp {ahead_csel_reg}, #0x1", new_insn_cur_addr)
                    new_insn_cur_addr += len(second_bytes)
                    second_bytes += bv.arch.assemble(f"b {chain_bb2.start - new_insn_cur_addr}", new_insn_cur_addr)
                    second_patch.pbytes = second_bytes
                    first_patch.next = second_patch

                    chain_bb3 = chain_bb[2]
                    third_patch = PatchInfo()
                    third_patch.start = chain_bb2.start
                    new_insn_cur_addr = chain_bb2.start
                    third_bytes = bv.arch.assemble(f"b.{ahead_csel_cond} {hex(suc_addrs[0] - new_insn_cur_addr)}", new_insn_cur_addr)
                    new_insn_cur_addr += len(third_bytes)
                    third_bytes += bv.arch.assemble(f"b {chain_bb3.start - new_insn_cur_addr}", new_insn_cur_addr)
                    third_patch.pbytes = third_bytes
                    second_patch.next = third_patch

                    fourth_patch = PatchInfo()
                    fourth_patch.start = chain_bb3.start
                    new_insn_cur_addr = chain_bb3.start
                    fourth_bytes = bv.arch.assemble(f"b {hex(suc_addrs[1] - new_insn_cur_addr)}", new_insn_cur_addr)
                    new_insn_cur_addr += len(fourth_bytes)
                    nop_len = chain_bb3.length - len(fourth_bytes)
                    nop_bytes = b'\x00' * nop_len
                    nop_bytes = bv.arch.convert_to_nop(nop_bytes, new_insn_cur_addr)
                    if nop_bytes != None:
                        fourth_bytes += nop_bytes
                    fourth_patch.pbytes = fourth_bytes
                    third_patch.next = fourth_patch
                    
                else:#一个块就放得下
                    first_patch = PatchInfo()
                    first_patch.start = last_insn_addr
                    first_patch.pbytes = bv.arch.assemble(f"b {hex(chain_bb.start - last_insn_addr)}", last_insn_addr)
                    patch_info.next = first_patch

                    new_insn_cur_addr = chain_bb.start
                    new_insn = bv.arch.assemble(f"cmp {ahead_csel_reg}, #0x1", new_insn_cur_addr)
                    new_insn_cur_addr += len(new_insn)
                    new_insn += bv.arch.assemble(f"b.{ahead_csel_cond} {hex(suc_addrs[0] - new_insn_cur_addr)}", new_insn_cur_addr)
                    new_insn_cur_addr += len(new_insn)
                    new_insn += bv.arch.assemble(f"b {hex(suc_addrs[1] - new_insn_cur_addr)}", new_insn_cur_addr)
                    second_patch = PatchInfo()
                    second_patch.start = chain_bb.start
                    second_patch.pbytes = new_insn
                    first_patch.next = second_patch

        patch_infos.append(patch_info)
    #打印输出
    i = 0
    log_msg_ = ""
    for patch_info in patch_infos:
        one_patch = f"({i:02d}) [addr: {hex(patch_info.start)} patch: ({patch_info.pbytes})]"
        next_info = patch_info.next
        while next_info != None:
            one_patch += f" --> [addr: {hex(next_info.start)} patch: ({next_info.pbytes})]"
            next_info = next_info.next
        log_msg_ += (one_patch + "\n")
        i += 1
    logger.log_info(f"[2] Patch信息获取完毕:\n{log_msg_}")


    #开始写入!
    logger.log_info("[3] 开始写入Patch数据...")
    state = bv.begin_undo_actions()
    for patch_info in patch_infos:
        cur_patch = patch_info
        while cur_patch != None:
            bv.write(cur_patch.start, cur_patch.pbytes)
            cur_patch = cur_patch.next
    bv.commit_undo_actions(state)
    logger.log_info("[3] 写入Patch数据完成!")

    #以下可写可不写 不影响分析
    """
    logger.log_info("开始Patch无用块为nop...")
    state = bv.begin_undo_actions()
    for ubb in useless_bb:
        start_addr = ubb.start
        nop_bytes = b'\x00' * (ubb.length)
        nop_bytes = bv.arch.convert_to_nop(nop_bytes, start_addr)
        bv.write(start_addr,nop_bytes)
    bv.commit_undo_actions(state)
    logger.log_info("Patch无用块为nop完成!")
    """

def get_address_switch_var(func: Function, address: int):
    cursor_mlil_ssa_bb = None #当前的mlil ssa视图中的bb
    mlil_ssa_func = func.mlil.ssa_form
    for bb in mlil_ssa_func.basic_blocks:
        bb_addrs = [insn.address for insn in bb]
        if address in bb_addrs:
            cursor_mlil_ssa_bb = bb
            break
    if cursor_mlil_ssa_bb != None:
        if_insn = None
        for insn in cursor_mlil_ssa_bb:#找if指令
            if isinstance(insn, MediumLevelILIf):
                if_insn = insn
                break
        if if_insn != None:
            ssa_var = None
            cond_ = if_insn.condition
            if isinstance(cond_, MediumLevelILComparisonBase):#if (x9#2 s>= 0x2e3a7efe) 
                ssa_var = cond_.vars_read[0]
            elif isinstance(cond_, MediumLevelILVarSsa): #if (cond:1#1)
                cond_insn = cond_.src.def_site
                ssa_var = cond_insn.src.vars_read[0]
            if ssa_var !=  None:
                return ssa_var
    return None

def deflat_cursor(bv: BinaryView, address: int):
    target_func = bv.get_functions_containing(address)[0]#获取当前用户点击的函数
    swtich_ssa_var = get_address_switch_var(target_func, address)
    if swtich_ssa_var != None:
        deflat2(bv, target_func, swtich_ssa_var)
    else:
        interaction.show_message_box("提示", "当前位置不存在switch var变量!\n请在Medium Level IL SSA视图中查找")

# 去除嵌套平坦化 需要手动设置出口地址
def deflat_nested(bv: BinaryView, address: int):
    target_func = bv.get_functions_containing(address)[0]#获取当前用户点击的函数
    swtich_ssa_var = get_address_switch_var(target_func, address)
    if swtich_ssa_var != None:
        usr_input = interaction.get_address_input("请在下方输入当前平坦化循环的出口地址:", "输入出口地址")
        if usr_input != None:
            extra_sbb = target_func.get_basic_block_at(usr_input)
            if (extra_sbb != None):
                logger.log_info(f"使用用户输入的出口地址: {hex(usr_input)}")
                deflat2(bv, target_func, swtich_ssa_var, usr_input)
            else:
                logger.log_error(f"用户输入{hex(usr_input)}无效 不是一个basicblock")
        else:
            logger.log_warn("用户取消输入")
    else:
        interaction.show_message_box("提示", "当前位置不存在switch var变量!\n请在Medium Level IL SSA视图中查找")

# 每次循环都会将分发变量设置为初始值 且会将分发块的后继块当作真实块
def deflat_with_check(bv: BinaryView, address: int):
    target_func = bv.get_functions_containing(address)[0]#获取当前用户点击的函数
    swtich_ssa_var = get_address_switch_var(target_func, address)
    if swtich_ssa_var != None:
        deflat2(bv, target_func, swtich_ssa_var, None, None, True)
    else:
        interaction.show_message_box("提示", "当前位置不存在switch var变量!\n请在Medium Level IL SSA视图中查找")

# 手动设置switch变量的值 用于调试
def deflat_manual(bv: BinaryView, address: int):
    target_func = bv.get_functions_containing(address)[0]#获取当前用户点击的函数
    swtich_ssa_var = get_address_switch_var(target_func, address)
    if swtich_ssa_var != None:
        switch_var_value = interaction.get_int_input("输入要设置的switch变量的值:", "手动设置switch变量值")
        if (switch_var_value == None):
            logger.log_error("未输入值 取消执行...")
            return

        deflat2(bv, target_func, swtich_ssa_var, None, switch_var_value)
    else:
        interaction.show_message_box("提示", "当前位置不存在switch var变量!\n请在Medium Level IL SSA视图中查找")
        