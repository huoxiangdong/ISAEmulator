//
//文件名称：        src/ISA/Intel_x86/Instructions/jmp.c
//文件描述：        Intel x86下jmp指令仿真
//创建人：          劳生(laosheng@ptwy.cn)
//创建日期：        2009年8月14日
//
//公司名称：        北京普天网怡科技有限公司
//项目组名：
//保密级别：
//版权声明：
//
//主项目名称：      基于虚拟机的漏洞挖掘平台
//主项目描述：
//主项目启动时间：  2009年6月X日
//
//子项目名称：      虚拟机及环境仿真器
//子项目描述：
//子项目启动时间：  2009年6月X日
//
//模块名称：        指令仿真器
//子项目描述：
//子项目启动时间：  2009年6月X日

//
//更新日志：
//2009年8月14日，劳生(laosheng@ptwy.cn)，创建


#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/jmp.h"
#include "ISA/Intel_x86/Instructions/common.h"

//E9 cw   jmp rel16     Jump near , relative , displacement relative to next instruction Not support in 64-bit mode
//E9 cd   jmp rel32     Jump near , relative , RIP = RIP + 32 bit 
VM_INSTRUCTION_ERR_CODE jmp_e9(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xffffffff);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            ACCESS_GEN_EIP(*pX86) += (INT16)pInstruction->uImmediate;
            break;

        case OT_d:
            ACCESS_GEN_EIP(*pX86) += (INT32)pInstruction->uImmediate;
            break;
    }
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//EA cd   jmp ptr16:16   Jump far , absolute, address given in operand
//EA cp   jmp ptr16:32   Jump far , absolute, address given in operand
VM_INSTRUCTION_ERR_CODE jmp_ea(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //没有实现
    return VM_INSTRUCTION_ERR_NOT_IMPLEMENTED;
}


//EB cb  jmp  rel8      Jump short , RIP=RIP + 8bit displacement 
VM_INSTRUCTION_ERR_CODE jmp_eb(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    ACCESS_GEN_EIP(*pX86) += (INT8)pInstruction->uImmediate;

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//FF /4  jmp   r/m16   Jump near , absolute indirect , address = sign-extended r/m16  Not supported in 64-bit mode
//FF /4  jmp   r/m32   Jump near , absolute indirect , address = sign-extended r/m16. Not supported in 64-bit mode
VM_INSTRUCTION_ERR_CODE inc_dec_grp5_ff_4_jmp(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT Op0;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//FF /5  jmp   m16:16  Jump far , absolute indirect , address given in m16:16
//FF /5  jmp   m16:32  Jump far , absolute indirect , address given in m16:32
VM_INSTRUCTION_ERR_CODE inc_dec_grp5_ff_5_jmp(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

