//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/add.c
//�ļ�������        Intel x86��addָ�����
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2009��8��3��
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
//2009��8��3�գ���販(yanghongbo@ptwy.cn)������

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
//note: 2010��3��26�� ��販�� δ����
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
