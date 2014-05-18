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
//����Ŀ����ʱ�䣺  2009��6��X��

//
//������־��
//2009��8��7�գ�����(laosheng@ptwy.cn)������

//
//������־��
//2009��9��28�գ�����(laosheng@ptwy.cn)���޸�ָ���EFLAGS��Ӱ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/and.h"
#include "ISA/Intel_x86/Instructions/common.h"

//20 /r     and r/m8, r8
VM_INSTRUCTION_ERR_CODE and_20(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
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
        uResult = uOp0 & uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 & uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    //Set Flags
    SET_EFLAGS_OF(*pX86, 0);    
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    //SET_EFLAGS_PF
    SET_EFLAGS_CF(*pX86, 0);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//21 /r     and r/m16, r16
//21 /r     and r/m32, r32
VM_INSTRUCTION_ERR_CODE and_21(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
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
        uResult = uOp0 & uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 & uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    //Set Flags
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            //Set Flags
            SET_EFLAGS_OF(*pX86, 0);    
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            //SET_EFLAGS_PF
            SET_EFLAGS_CF(*pX86, 0);
            break;
        case OT_d:
            //Set Flags
            SET_EFLAGS_OF(*pX86, 0);    
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            //SET_EFLAGS_PF
            SET_EFLAGS_CF(*pX86, 0);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

 //22 /r     and r8, r/m8   Gb,Eb
VM_INSTRUCTION_ERR_CODE and_22(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
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
        uResult = uOp0 & uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 & uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    
    //Set Flags
    SET_EFLAGS_OF(*pX86, 0);    
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    //SET_EFLAGS_PF
    SET_EFLAGS_CF(*pX86, 0);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//23 /r     and r16, r/m16
//23 /r     and r32, r/m32
VM_INSTRUCTION_ERR_CODE and_23(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
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
        uResult = uOp0 & uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 & uOp1;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    
    //Set Flags
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            //Set Flags
            SET_EFLAGS_OF(*pX86, 0);    
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            //SET_EFLAGS_PF
            SET_EFLAGS_CF(*pX86, 0);
            break;
        case OT_d:
            //Set Flags
            SET_EFLAGS_OF(*pX86, 0);    
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            //SET_EFLAGS_PF
            SET_EFLAGS_CF(*pX86, 0);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//24 ib     and al, imm8
VM_INSTRUCTION_ERR_CODE and_24(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uResult;
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp0 = ACCESS_GEN_AL(*pX86);
    uOp1 = (UINT)pInstruction->uImmediate;
    uResult = uOp0 & uOp1;
    ACCESS_GEN_AL(*pX86) = uResult;

    //Set Flags
    SET_EFLAGS_OF(*pX86, 0);    
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    //SET_EFLAGS_PF
    SET_EFLAGS_CF(*pX86, 0);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//25 iw     and ax, imm16; 
//25 id     and eax, imm32; 
VM_INSTRUCTION_ERR_CODE and_25(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    uOp1 = (UINT)pInstruction->uImmediate;

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOp0 = ACCESS_GEN_AX(*pX86);
            uResult = uOp0 & uOp1;
            ACCESS_GEN_AX(*pX86) = uResult;
            //Set Flags
            SET_EFLAGS_OF(*pX86, 0);    
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            //SET_EFLAGS_PF
            SET_EFLAGS_CF(*pX86, 0);
            break;

        case OT_d:
            uOp0 = ACCESS_GEN_EAX(*pX86);
            uResult = uOp0 & uOp1;
            ACCESS_GEN_EAX(*pX86) = uResult;
            //Set Flags
            SET_EFLAGS_OF(*pX86, 0);    
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            //SET_EFLAGS_PF
            SET_EFLAGS_CF(*pX86, 0);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//and /4 ib r/m8 , imm8
VM_INSTRUCTION_ERR_CODE immediate_grp1_80_and(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
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
        uResult = uOp0 & uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 & uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    
    //Set Flags
    SET_EFLAGS_OF(*pX86, 0);    
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    //SET_EFLAGS_PF
    SET_EFLAGS_CF(*pX86, 0);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//add r/m16 , imm16
//add r/m32 , imm32
VM_INSTRUCTION_ERR_CODE immediate_grp1_81_and(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //uOp0 ��ΪĿ�Ĳ�����
    //uOp1 ��ΪԴ������
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
        uResult = uOp0 & uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 & uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            //Set Flags
            SET_EFLAGS_OF(*pX86, 0);    
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            //SET_EFLAGS_PF
            SET_EFLAGS_CF(*pX86, 0);
            break;

        case OT_d:
            //Set Flags
            SET_EFLAGS_OF(*pX86, 0);    
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            //SET_EFLAGS_PF
            SET_EFLAGS_CF(*pX86, 0);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//83 /5 ib and r/m8 , imm8
//note: 2010��3��26�� ��販�� δ����
VM_INSTRUCTION_ERR_CODE immediate_grp1_82_and(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);
    uOp1 = (UINT)pInstruction->uImmediate;

    // 16bit & 8bit or 32bit & 8 bit   Signextended
    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uResult = uOp0 & uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 & uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    SET_EFLAGS_OF(*pX86, 0);    
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    //SET_EFLAGS_PF
    SET_EFLAGS_CF(*pX86, 0);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//83 /5 ib and r/m16 , imm8
//83 /5 ib and r/m32 , imm8
VM_INSTRUCTION_ERR_CODE immediate_grp1_83_and(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);
    uOp1 = (UINT)pInstruction->uImmediate;

    // 16bit & 8bit or 32bit & 8 bit   Signextended
    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uResult = uOp0 & uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 & uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            //Set Flags
            SET_EFLAGS_OF(*pX86, 0);    
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            //SET_EFLAGS_PF
            SET_EFLAGS_CF(*pX86, 0);
            break;

        case OT_d:
            //Set Flags
            SET_EFLAGS_OF(*pX86, 0);    
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            //SET_EFLAGS_PF
            SET_EFLAGS_CF(*pX86, 0);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
