//
//文件名称：        src/ISA/Intel_x86/Instructions/sub.c
//文件描述：        Intel x86下sub指令仿真
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
//2009年8月7日，劳生(laosheng@ptwy.cn)，创建

//
//更新日志：
//2009年10月12日，劳生(laosheng@ptwy.cn),修改： 指令对寄存器EFLAGS的影响

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/sub.h"
#include "ISA/Intel_x86/Instructions/common.h"

//28 /r     sub r/m8, r8
VM_INSTRUCTION_ERR_CODE sub_28(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    uOp1 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    //Set Flags
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);  

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//29 /r     sub r/m16, r16
//29 /r     sub r/m32, r32
VM_INSTRUCTION_ERR_CODE sub_29(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    uOp1 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
			EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);  
            break;

        case OT_d:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);  
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//2A /r     sub r/8, r/m8
VM_INSTRUCTION_ERR_CODE sub_2a(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    uOp0 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);  

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//2B /r     sub r16, r/m16
//2B /r     sub r32, r/m32
VM_INSTRUCTION_ERR_CODE sub_2b(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    uOp0 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
			EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);  
            break;

        case OT_d:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);  
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//2C ib     sub al, imm8
VM_INSTRUCTION_ERR_CODE sub_2c(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uResult;
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp0 = (UINT)pInstruction->uImmediate;
    uOp1 = ACCESS_GEN_AL(*pX86);
    uResult = uOp1 - uOp0;
    ACCESS_GEN_AL(*pX86) = uResult;

    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);  

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//2D iw     sub ax, imm16
//2D iw     sub eax, imm32
VM_INSTRUCTION_ERR_CODE sub_2d(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);

    uOp1 = (UINT)pInstruction->uImmediate;
   
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOp0 = ACCESS_GEN_AX(*pX86);
            uResult = uOp0 - uOp1;
            ACCESS_GEN_EAX(*pX86) = uResult;

            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
			EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);  
            break;

        case OT_d:
            uOp0 = ACCESS_GEN_EAX(*pX86);
            uResult = uOp0 - uOp1;
            ACCESS_GEN_EAX(*pX86) = uResult;

            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);  
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//80 sub r/m8 , imm8
VM_INSTRUCTION_ERR_CODE immediate_grp1_80_sub(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp1 = (UINT)pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);  

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//81 /5 iw sub r/m16 , imm16
//81 /5 id sub r/m32 , imm32
VM_INSTRUCTION_ERR_CODE immediate_grp1_81_sub(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    uOp1 = (UINT)pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
			EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);  
            break;

        case OT_d:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);  
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//83 /5 ib sub r/m8 , imm8
//note: 2010年3月26日 杨鸿博， 未测试
VM_INSTRUCTION_ERR_CODE immediate_grp1_82_sub(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);
    uOp1 = (UINT)pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//83 /5 ib sub r/m16 , imm8
//83 /5 ib sub r/m32 , imm8
VM_INSTRUCTION_ERR_CODE immediate_grp1_83_sub(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);
    uOp1 = (UINT)pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
			EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);  
            break;

        case OT_d:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);  
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}