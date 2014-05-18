//
//文件名称：        src/ISA/Intel_x86/Instructions/add.c
//文件描述：        Intel x86下add指令仿真
//创建人：          杨鸿博(yanghongbo@ptwy.cn)
//创建日期：        2009年8月3日
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
//2009年8月3日，杨鸿博(yanghongbo@ptwy.cn)，创建

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/add.h"
#include "ISA/Intel_x86/Instructions/common.h"

//00 /r      add r/m8, r8                                                                                                                                                                                                                                     add r/m8, r8
VM_INSTRUCTION_ERR_CODE add_00(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uSum;

    assert(pInstruction);

    uOp1 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uSum & 0xff, OT_b, pInstruction->dwFlags);
    }
    else {
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uSum & 0xff, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    //Set Flags
    EVAL_EFLAGS_ZF(*pX86, (INT8)uSum);
    EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uSum, _8_BITS);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);
    EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//01 /r     add r/m16, r16
//01 /r     add r/m32, r32
VM_INSTRUCTION_ERR_CODE add_01(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uSum;

    assert(pInstruction);

    uOp1 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uSum, OT_v, pInstruction->dwFlags);
    }
    else {
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);
            EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);
            break;
        case OT_d:
            EVAL_EFLAGS_ZF(*pX86, uSum);
            EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//02 /r     add r8, r/m8
VM_INSTRUCTION_ERR_CODE add_02(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uSum;

    assert(pInstruction);

    uOp0 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    else {
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    EVAL_EFLAGS_ZF(*pX86, (INT8)uSum);
    EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uSum, _8_BITS);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);
    EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//03 /r     add r32, r/m32
//REX.W + 03 /r     add r64, r/m64
VM_INSTRUCTION_ERR_CODE add_03(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uSum;

    assert(pInstruction);

    uOp0 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    else {
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);
            EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);
            break;
        case OT_d:
            EVAL_EFLAGS_ZF(*pX86, uSum);
            EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//04 ib     add al, imm8
VM_INSTRUCTION_ERR_CODE add_04(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp0 = (UINT)pInstruction->uImmediate;
    uOp1 = ACCESS_GEN_AL(*pX86);
    uSum = uOp0 + uOp1;
    ACCESS_GEN_AL(*pX86) = uSum;

    EVAL_EFLAGS_ZF(*pX86, (INT8)uSum);
    EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uSum, _8_BITS);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
    EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//05 iw     add ax, imm16; 
//05 id     add eax, imm32; 
VM_INSTRUCTION_ERR_CODE add_05(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;

    assert(pInstruction);

    uOp0 = (UINT)pInstruction->uImmediate;
    uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    uSum = uOp0 + uOp1;
    SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);
            EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);
            break;
        case OT_d:
            EVAL_EFLAGS_ZF(*pX86, uSum);
            EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//add r/m8 , imm8
VM_INSTRUCTION_ERR_CODE immediate_grp1_80_add(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uSum;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp1 = (UINT)pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uSum & 0xff, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    
    
   EVAL_EFLAGS_ZF(*pX86, (INT8)uSum);
   EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);
   EVAL_EFLAGS_SF(*pX86, uSum, _8_BITS);
   EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
   EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//add r/m16 , imm16
//add r/m32 , imm32
VM_INSTRUCTION_ERR_CODE immediate_grp1_81_add(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uSum;

    assert(pInstruction);
    uOp1 = (UINT)pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uSum, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);
            EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);
            break;
        case OT_d:
            EVAL_EFLAGS_ZF(*pX86, uSum);
            EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//add r/m8 , imm8
//note: 2010年3月26日 杨鸿博， 未测试
VM_INSTRUCTION_ERR_CODE immediate_grp1_82_add(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uSum;

    assert(pInstruction);
    uOp1 = (UINT)pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uSum, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    EVAL_EFLAGS_ZF(*pX86, (INT8)uSum);
    EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uSum, _8_BITS);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
    EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//add r/m16 , imm8
//add r/m32 , imm8
VM_INSTRUCTION_ERR_CODE immediate_grp1_83_add(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uSum;

    assert(pInstruction);
    uOp1 = (UINT)pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uSum, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);
            EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);
            break;
        case OT_d:
            EVAL_EFLAGS_ZF(*pX86, uSum);
            EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
