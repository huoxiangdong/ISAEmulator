//
//文件名称：        src/ISA/Intel_x86/Instructions/sbb.c
//文件描述：        Intel x86下sbb指令仿真
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

#include "ISA/Intel_x86/Instructions/sbb.h"
#include "ISA/Intel_x86/Instructions/common.h"

//18 /r     sbb r/m8, r8
VM_INSTRUCTION_ERR_CODE sbb_18(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;
    UINT uCF;

    assert(pInstruction);
    uOp1 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    uCF = GET_EFLAGS_CF_BIT(*pX86);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 + uCF);
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1+ uCF);
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    //Set Flags
    //DEST<-(DEST- (SRC+CF))有优先级
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1 + uCF, uResult);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _8_BITS);  

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//19 /r     sbb r/m16, r16
//19 /r     sbb r/m32, r32
VM_INSTRUCTION_ERR_CODE sbb_19(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;
    UINT uCF;

    assert(pInstruction);
    uOp1 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    uCF = GET_EFLAGS_CF_BIT(*pX86);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 + uCF);
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 + uCF);
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1+ uCF, uResult, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
			EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1 + uCF, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1+ uCF, uResult, _16_BITS);  
            break;

        case OT_d:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1 + uCF, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _32_BITS);  
            break;
    }


    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//1A /r     sbb r/8, r/m8
VM_INSTRUCTION_ERR_CODE sbb_1a(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;
    UINT uCF;

    assert(pInstruction);
    uOp0 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    uCF = GET_EFLAGS_CF_BIT(*pX86);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 + uCF);
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 + uCF);
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    
    //Set Flags
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1 + uCF, uResult);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _8_BITS);  

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//1B /r     sbb r16, r/m16
//1B /r     sbb r32, r/m32
VM_INSTRUCTION_ERR_CODE sbb_1b(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;
    UINT uCF;

    assert(pInstruction);
    uOp0 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    uCF = GET_EFLAGS_CF_BIT(*pX86);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 + uCF);
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 + uCF);;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
			EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1 + uCF, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _16_BITS);  
            break;

        case OT_d:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1 + uCF, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _32_BITS);  
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//1C ib     sbb al, imm8
VM_INSTRUCTION_ERR_CODE sbb_1c(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uResult;
    UINT uCF;
    
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uCF = GET_EFLAGS_CF_BIT(*pX86);
    uOp1 = (UINT)pInstruction->uImmediate;
    uOp0 = ACCESS_GEN_AL(*pX86);
    uResult = uOp0 - (uOp1 + uCF);
    ACCESS_GEN_AL(*pX86) = uResult;

    //Set Flags
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1+ uCF, uResult, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1 + uCF, uResult);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1+ uCF, uResult, _8_BITS);  

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//1D iw     sbb ax, imm16
//1D iw     sbb eax,imm32
VM_INSTRUCTION_ERR_CODE sbb_1d(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uResult;
    UINT uCF;

    assert(pInstruction);

    uCF = GET_EFLAGS_CF_BIT(*pX86);
    uOp1 = (UINT)pInstruction->uImmediate;
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOp0 = ACCESS_GEN_AX(*pX86);
            uResult = uOp0 - (uOp1 + uCF);
            ACCESS_GEN_EAX(*pX86) = uResult;

            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1+ uCF, uResult, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
			EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1+ uCF, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1+ uCF, uResult, _16_BITS);  
            break;

        case OT_d:
            uOp0 = ACCESS_GEN_EAX(*pX86);
            uResult = uOp0 - (uOp1 + uCF);
            ACCESS_GEN_EAX(*pX86) = uResult;

            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1 + uCF, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _32_BITS);  
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//80 sbb r/m8 , imm8
VM_INSTRUCTION_ERR_CODE immediate_grp1_80_sbb(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;
    UINT uCF;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp1 = (UINT)pInstruction->uImmediate;
    uCF = GET_EFLAGS_CF_BIT(*pX86);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 + uCF);
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 + uCF);
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    
    //Set Flags
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1 + uCF, uResult);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1+ uCF, uResult, _8_BITS);  

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//81 /5 iw sbb r/m16 , imm16
//81 /5 id sbb r/m32 , imm32
VM_INSTRUCTION_ERR_CODE immediate_grp1_81_sbb(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;
    UINT uCF;
    assert(pInstruction);
    uOp1 = (UINT)pInstruction->uImmediate;
    uCF = GET_EFLAGS_CF_BIT(*pX86);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 + uCF);
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 + uCF);
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
			EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1 + uCF, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _16_BITS);  
            break;

        case OT_d:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1 + uCF, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _32_BITS);  
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//83 /5 ib sbb r/m8 , imm8
//note: 2010年3月26日 杨鸿博， 未测试
VM_INSTRUCTION_ERR_CODE immediate_grp1_82_sbb(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;
    UINT uCF;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp1 = (UINT)pInstruction->uImmediate;
    uCF = GET_EFLAGS_CF_BIT(*pX86);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 + uCF);
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 +uCF);
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1 + uCF, uResult);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _8_BITS); 

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//83 /5 ib sbb r/m16 , imm8
//83 /5 ib sbb r/m32 , imm8
VM_INSTRUCTION_ERR_CODE immediate_grp1_83_sbb(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;
    UINT uCF;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp1 = (UINT)pInstruction->uImmediate;
    uCF = GET_EFLAGS_CF_BIT(*pX86);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 + uCF);
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - (uOp1 +uCF);
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
			EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1 + uCF, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _16_BITS);  
            break;

        case OT_d:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1 + uCF, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1 + uCF, uResult, _32_BITS);  
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}