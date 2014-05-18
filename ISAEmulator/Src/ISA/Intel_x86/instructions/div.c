//
//文件名称：        src/ISA/Intel_x86/Instructions/div.c
//文件描述：        Intel x86下div指令仿真
//创建人：          劳生(laosheng@ptwy.cn)
//创建日期：        2009年8月7日
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
//2009年8月12日，劳生(laosheng@ptwy.cn)，创建

//
//更新日志：
//2009年9月29日，劳生(laosheng@ptwy.cn)，修改指令对EFLAGS的影响

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/div.h"
#include "ISA/Intel_x86/Instructions/common.h"

//f6 /6 div r/m8   unsigned divide AX by r/m8 , with result stored in AL <- Quotient , AH <- Remainder
VM_INSTRUCTION_ERR_CODE unary_grp3_f6_div(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp1;
    UINT uTemp;
    UINT uAH;

    assert(pInstruction);
    
    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else {
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);  
    }

    if (0 == uOp1){
        return VM_INSTRUCTION_ERR_DIVIDE_BY_ZERO;
    }

    uAH  = ACCESS_GEN_AX(*pX86) ;
    uTemp = ACCESS_GEN_AX(*pX86) / uOp1 ;
    if (0xff<uTemp){
        return VM_INSTRUCTION_ERR_INTEGER_OVERFLOW;
    }
    ACCESS_GEN_AL(*pX86) = (UINT8)uTemp;
    ACCESS_GEN_AH(*pX86) = uAH % uOp1;

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//f7 /6 div r/m16   unsigned divide DX:AX by r/m16 , with result stored in AX <- Quotient , DX <- Remainder
//f7 /6 div r/m32   unsigned divide DX:AX by r/m32 , with result stored in EAX <- Quotient , EDX <- Remainder
VM_INSTRUCTION_ERR_CODE unary_grp3_f7_div(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT64 uOp1;
    UINT64 Op0;
    UINT uTemp;
 
    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_z, pInstruction->dwFlags);;
    }
    else {
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_z, pInstruction->dwFlags);  
    }

    if (0 == uOp1){
        return VM_INSTRUCTION_ERR_DIVIDE_BY_ZERO;
    }

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        Op0 = ACCESS_GEN_DX(*pX86);
        Op0 = (Op0 << 16) + ACCESS_GEN_AX(*pX86);

        uTemp = Op0 / uOp1;
        if (0xffff < uTemp){
            return  VM_INSTRUCTION_ERR_INTEGER_OVERFLOW;
        }

        ACCESS_GEN_AX(*pX86) = (UINT16)uTemp;
        ACCESS_GEN_DX(*pX86) = (UINT16)(Op0 % uOp1);
    }
    else{
        Op0 = ACCESS_GEN_EDX(*pX86);
        Op0 = (Op0 << 32) + ACCESS_GEN_EAX(*pX86);

        uTemp = Op0 / uOp1;
        if (0xffffffff < uTemp){
            return  VM_INSTRUCTION_ERR_INTEGER_OVERFLOW;
        }

        ACCESS_GEN_EAX(*pX86) = uTemp;
        ACCESS_GEN_EDX(*pX86) = (UINT32)(Op0 % uOp1);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
