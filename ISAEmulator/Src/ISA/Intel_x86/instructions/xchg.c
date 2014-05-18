//
//文件名称：        src/ISA/Intel_x86/Instructions/xchg.c
//文件描述：        Intel x86下xchg指令仿真
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
//2009年8月13日，劳生(laosheng@ptwy.cn)，创建

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/xchg.h"
#include "ISA/Intel_x86/Instructions/common.h"


//86 /r xchg  r/m8,r8
//86 /r xchg  r8,r/m8
VM_INSTRUCTION_ERR_CODE xchg_86(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT8 uOp0;
    UINT8 uOp1;

    assert(pInstruction);
    uOp0 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        SetMemoryValue(pX86, pMemory, uEA, uOp0, OT_b, pInstruction->dwFlags);
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp1, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp1, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//87 /r xchg  r/m16,r16
//87 /r xchg  r16,r/m16
//87 /r xchg  r/m32,r32
//87 /r xchg  r32,r/m32
VM_INSTRUCTION_ERR_CODE xchg_87(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
	 
    assert(pInstruction);
    uOp0 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        SetMemoryValue(pX86, pMemory, uEA, uOp0, OT_v, pInstruction->dwFlags);
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp1, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp1, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

VM_INSTRUCTION_ERR_CODE xchg_90(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    //XCHG r8 , rAX,  R8-R15 available when using REX.R and 64-bit mode
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//91 rCx /r9
VM_INSTRUCTION_ERR_CODE xchg_91(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOp0 = ACCESS_GEN_AX(*pX86);
            ACCESS_GEN_AX(*pX86) = ACCESS_GEN_CX(*pX86);
            ACCESS_GEN_CX(*pX86) = uOp0;
            break;

        case OT_d:
            uOp0 = ACCESS_GEN_EAX(*pX86);
            ACCESS_GEN_EAX(*pX86) = ACCESS_GEN_ECX(*pX86);
            ACCESS_GEN_ECX(*pX86) = uOp0;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//92 rDx/r10
VM_INSTRUCTION_ERR_CODE xchg_92(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOp0 = ACCESS_GEN_AX(*pX86);
            ACCESS_GEN_AX(*pX86) = ACCESS_GEN_DX(*pX86);
            ACCESS_GEN_DX(*pX86) = uOp0;
            break;

        case OT_d:
            uOp0 = ACCESS_GEN_EAX(*pX86);
            ACCESS_GEN_EAX(*pX86) = ACCESS_GEN_EDX(*pX86);
            ACCESS_GEN_EDX(*pX86) = uOp0;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//93 rBX/r11
VM_INSTRUCTION_ERR_CODE xchg_93(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOp0 = ACCESS_GEN_AX(*pX86);
            ACCESS_GEN_AX(*pX86) = ACCESS_GEN_BX(*pX86);
            ACCESS_GEN_BX(*pX86) = uOp0;
            break;

        case OT_d:
            uOp0 = ACCESS_GEN_EAX(*pX86);
            ACCESS_GEN_EAX(*pX86) = ACCESS_GEN_EBX(*pX86);
            ACCESS_GEN_EBX(*pX86) = uOp0;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//94 rSP/r12
VM_INSTRUCTION_ERR_CODE xchg_94(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOp0 = ACCESS_GEN_AX(*pX86);
            ACCESS_GEN_AX(*pX86) = ACCESS_GEN_SP(*pX86);
            ACCESS_GEN_SP(*pX86) = uOp0;
            break;

        case OT_d:
            uOp0 = ACCESS_GEN_EAX(*pX86);
            ACCESS_GEN_EAX(*pX86) = ACCESS_GEN_ESP(*pX86);
            ACCESS_GEN_ESP(*pX86) = uOp0;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//95 rBP/r13
VM_INSTRUCTION_ERR_CODE xchg_95(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOp0 = ACCESS_GEN_AX(*pX86);
            ACCESS_GEN_AX(*pX86) = ACCESS_GEN_BP(*pX86);
            ACCESS_GEN_BP(*pX86) = uOp0;
            break;

        case OT_d:
            uOp0 = ACCESS_GEN_EAX(*pX86);
            ACCESS_GEN_EAX(*pX86) = ACCESS_GEN_EBP(*pX86);
            ACCESS_GEN_EBP(*pX86) = uOp0;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//96 rSi/r14
VM_INSTRUCTION_ERR_CODE xchg_96(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOp0 = ACCESS_GEN_AX(*pX86);
            ACCESS_GEN_AX(*pX86) = ACCESS_GEN_SI(*pX86);
            ACCESS_GEN_SI(*pX86) = uOp0;
            break;

        case OT_d:
            uOp0 = ACCESS_GEN_EAX(*pX86);
            ACCESS_GEN_EAX(*pX86) = ACCESS_GEN_ESI(*pX86);
            ACCESS_GEN_ESI(*pX86) = uOp0;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//97 rDi/r15
VM_INSTRUCTION_ERR_CODE xchg_97(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOp0 = ACCESS_GEN_AX(*pX86);
            ACCESS_GEN_AX(*pX86) = ACCESS_GEN_DI(*pX86);
            ACCESS_GEN_DI(*pX86) = uOp0;
            break;

        case OT_d:
            uOp0 = ACCESS_GEN_EAX(*pX86);
            ACCESS_GEN_EAX(*pX86) = ACCESS_GEN_EDI(*pX86);
            ACCESS_GEN_EDI(*pX86) = uOp0;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}