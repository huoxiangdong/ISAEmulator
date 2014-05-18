//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/and.c
//�ļ�������        Intel x86��andָ�����
//�����ˣ�          ����(laosheng@ptwy.cn)
//�������ڣ�        2009��8��7��
//
//��˾���ƣ�        �������������Ƽ����޹�˾
//��Ŀ������
//���ܼ���
//��Ȩ������
//
//����Ŀ���ƣ�      �����������©���ھ�ƽ̨
//����Ŀ������
//����Ŀ����ʱ�䣺  2009��6��X��
//
//����Ŀ���ƣ�      �����������������
//����Ŀ������
//����Ŀ����ʱ�䣺  2009��6��X��
//
//ģ�����ƣ�        ָ�������
//����Ŀ������
//����Ŀ����ʱ�䣺  20009��6��X��

//
//������־��
//2009��8��7�գ�����(laosheng@ptwy.cn)������

//
//������־��
//2009��10��10�գ�����(laosheng@ptwy.cn),�޸ģ�ָ��Ķ�EFLAGS�Ĵ�����Ӱ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/or.h"
#include "ISA/Intel_x86/Instructions/common.h"

//08 /r     or r/m8, r8
VM_INSTRUCTION_ERR_CODE or_08(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
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
        uResult = uOp0 | uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uOp0, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 | uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    //Set Flags
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    SET_EFLAGS_OF(*pX86, 0);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    //EFLAGS_AF Undefined
    SET_EFLAGS_CF(*pX86, 0);
    //SET_EFLAGS_PF(*pX86,);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//09 /r     or r/m16, r16
//09 /r     or r/m32, r32
VM_INSTRUCTION_ERR_CODE or_09(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
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
        uResult = uOp0 | uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uOp0, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 | uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
            //EFLAGS_AF Undefined
            SET_EFLAGS_CF(*pX86, 0);
            //SET_EFLAGS_PF(*pX86,);
            break;

        case OT_d:
            EVAL_EFLAGS_ZF(*pX86, uResult);
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            //EFLAGS_AF Undefined
            SET_EFLAGS_CF(*pX86, 0);
            //SET_EFLAGS_PF(*pX86,);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//0A /r     or r/8, r/m8
VM_INSTRUCTION_ERR_CODE or_0a(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
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
        uResult = uOp0 | uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 | uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    
    //Set Flags
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    SET_EFLAGS_OF(*pX86, 0);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    //EFLAGS_AF Undefined
    SET_EFLAGS_CF(*pX86, 0);
    //SET_EFLAGS_PF(*pX86,);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//0B /r     or r16, r/m16
//0B /r     or r32, r/m32
VM_INSTRUCTION_ERR_CODE or_0b(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
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
        uResult = uOp0 | uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 | uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
            //EFLAGS_AF Undefined
            SET_EFLAGS_CF(*pX86, 0);
            //SET_EFLAGS_PF(*pX86,);
            break;

        case OT_d:
            EVAL_EFLAGS_ZF(*pX86, uResult);
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            //EFLAGS_AF Undefined
            SET_EFLAGS_CF(*pX86, 0);
            //SET_EFLAGS_PF(*pX86,);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//0C ib     or al, imm8
VM_INSTRUCTION_ERR_CODE or_0c(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp0 = (UINT)pInstruction->uImmediate;
    uOp1 = ACCESS_GEN_AL(*pX86);
    uResult = uOp0 | uOp1;
    ACCESS_GEN_AL(*pX86) = uResult;

    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    SET_EFLAGS_OF(*pX86, 0);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    //EFLAGS_AF Undefined
    SET_EFLAGS_CF(*pX86, 0);
    //SET_EFLAGS_PF(*pX86,);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//0D iw     or ax, imm16
//0D id     or eax, imm32
VM_INSTRUCTION_ERR_CODE or_0d(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);

    uOp0 = (UINT)pInstruction->uImmediate;

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOp1 = ACCESS_GEN_AX(*pX86);
            uResult = uOp0 | uOp1;
            ACCESS_GEN_AL(*pX86) = uResult;

            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
            //EFLAGS_AF Undefined
            SET_EFLAGS_CF(*pX86, 0);
            //SET_EFLAGS_PF(*pX86,);
            break;

        case OT_d:
            uOp1 = ACCESS_GEN_EAX(*pX86);
            uResult = uOp0 | uOp1;
            ACCESS_GEN_AL(*pX86) = uResult;

            EVAL_EFLAGS_ZF(*pX86, uResult);
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            //EFLAGS_AF Undefined
            SET_EFLAGS_CF(*pX86, 0);
            //SET_EFLAGS_PF(*pX86,);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//or /4 ib r/m8 , imm8
VM_INSTRUCTION_ERR_CODE immediate_grp1_80_or(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
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
        uResult = uOp0 | uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uOp0, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 | uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    SET_EFLAGS_OF(*pX86, 0);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    //EFLAGS_AF Undefined
    SET_EFLAGS_CF(*pX86, 0);
    //SET_EFLAGS_PF(*pX86,);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//or r/m16 , imm16
//or r/m32 , imm32
VM_INSTRUCTION_ERR_CODE immediate_grp1_81_or(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
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
        uResult = uOp0 | uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uOp0, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 | uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_ZF(*pX86,(INT16)uResult);
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
            //EFLAGS_AF Undefined
            SET_EFLAGS_CF(*pX86, 0);
            //SET_EFLAGS_PF(*pX86,);
            break;

        case OT_d:
            EVAL_EFLAGS_ZF(*pX86, uResult);
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            //EFLAGS_AF Undefined
            SET_EFLAGS_CF(*pX86, 0);
            //SET_EFLAGS_PF(*pX86,);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//or r/m8 , imm8
//note: 2010��3��26�� ��販�� δ����
VM_INSTRUCTION_ERR_CODE immediate_grp1_82_or(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
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
        uResult = uOp0 | uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uOp0, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 | uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    SET_EFLAGS_OF(*pX86, 0);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    //EFLAGS_AF Undefined
    SET_EFLAGS_CF(*pX86, 0);
    //SET_EFLAGS_PF(*pX86,);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//or r/m16 , imm8
//or r/m32 , imm8
VM_INSTRUCTION_ERR_CODE immediate_grp1_83_or(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
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
        uResult = uOp0 | uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uOp0, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 | uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    // r/m32 
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
            //EFLAGS_AF Undefined
            SET_EFLAGS_CF(*pX86, 0);
            //SET_EFLAGS_PF(*pX86,);
            break;

        case OT_d:
            EVAL_EFLAGS_ZF(*pX86, uResult);
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            //EFLAGS_AF Undefined
            SET_EFLAGS_CF(*pX86, 0);
            //SET_EFLAGS_PF(*pX86,);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

