//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/adc.c
//�ļ�������        Intel x86��adcָ�����
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
//2009��9��28�գ�����(laosheng@ptwy.cn)�����ָ���־λ

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/adc.h"
#include "ISA/Intel_x86/Instructions/common.h"


//10 /r     adc r/m8, r8
VM_INSTRUCTION_ERR_CODE adc_10(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uCf;
    UINT uSum;

    assert(pInstruction);

    uOp1 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);

    uCf = GET_EFLAGS_CF_BIT(*pX86);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetMemoryValue(pX86, pMemory, uEA, uSum & 0xff, OT_b, pInstruction->dwFlags);
    }
    else {
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uSum & 0xff, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    EVAL_EFLAGS_OF_ADD(*pX86,uOp0,uOp1,uSum, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uSum);
    EVAL_EFLAGS_SF(*pX86, uSum, _8_BITS);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);
    EVAL_EFLAGS_CF_ADD(*pX86,uOp0,uOp1,uSum, _8_BITS);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//11 /r     adc r/m16, r16
//11 /r     adc r/m32, r32
VM_INSTRUCTION_ERR_CODE adc_11(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uCf;
    UINT uSum;

    assert(pInstruction);

    uOp1 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    uCf = GET_EFLAGS_CF_BIT(*pX86);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetMemoryValue(pX86, pMemory, uEA, uSum, OT_v, pInstruction->dwFlags);
    }
    else {
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    //Set Flags
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_OF_ADD(*pX86,uOp0,uOp1,uSum, _16_BITS);
            EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);
            EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
            EVAL_EFLAGS_CF_ADD(*pX86,uOp0,uOp1,uSum, _16_BITS);
            break;
        case OT_d:
            EVAL_EFLAGS_ZF(*pX86, uSum);
            EVAL_EFLAGS_OF_ADD(*pX86,uOp0,uOp1,uSum, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
            EVAL_EFLAGS_CF_ADD(*pX86,uOp0,uOp1,uSum, _32_BITS);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//12 /r     adc r8, r/m8
VM_INSTRUCTION_ERR_CODE adc_12(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uCf;
    UINT uSum;

    assert(pInstruction);

    uOp0 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    uCf = GET_EFLAGS_CF_BIT(*pX86);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    else {
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);
    EVAL_EFLAGS_OF_ADD(*pX86,uOp0,uOp1,uSum, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uSum, _8_BITS);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);
    EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1,uSum,_8_BITS);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//13 /r     adc r16, r/m16
//13 /r     adc r32, r/m32
VM_INSTRUCTION_ERR_CODE adc_13(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uCf;
    UINT uSum;

    assert(pInstruction);

    uOp0 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    uCf = GET_EFLAGS_CF_BIT(*pX86);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    else {
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    
    //Set Flags
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);
            EVAL_EFLAGS_OF_ADD(*pX86,uOp0,uOp1,uSum, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1,uSum,_16_BITS);
            break;
        case OT_d:
            EVAL_EFLAGS_ZF(*pX86, uSum);
            EVAL_EFLAGS_OF_ADD(*pX86,uOp0,uOp1,uSum, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1,uSum,_32_BITS);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//14 ib     adc al, imm8
VM_INSTRUCTION_ERR_CODE adc_14(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uSum;
    UINT uCf;
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uCf = GET_EFLAGS_CF_BIT(*pX86);
    uOp0 = ACCESS_GEN_AL(*pX86);
    uSum  = uOp0 + uCf + (UINT)pInstruction->uImmediate;

    ACCESS_GEN_AL(*pX86) = uSum;

    EVAL_EFLAGS_ZF(*pX86, (INT8)uSum);
    EVAL_EFLAGS_OF_ADD(*pX86, uOp0, (UINT)pInstruction->uImmediate, uSum, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uSum, _8_BITS);
    EVAL_EFLAGS_AF(*pX86, uOp0, pInstruction->uImmediate, uSum);
    EVAL_EFLAGS_CF_ADD(*pX86, uOp0, (UINT)pInstruction->uImmediate, uSum, _8_BITS);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//15 iw     adc ax, imm16;
//15 id     adc eax, imm32; 
VM_INSTRUCTION_ERR_CODE adc_15(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uCf;
    UINT uSum;

    assert(pInstruction);

    uOp1 = (UINT)pInstruction->uImmediate;
    uCf = GET_EFLAGS_CF_BIT(*pX86);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOp0 = ACCESS_GEN_AX(*pX86);
            uSum = uOp0 + uOp1 + uCf;
            SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
            EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);
            EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            break;
        case OT_d:
            uOp0 = ACCESS_GEN_EAX(*pX86);
            uSum = uOp0 + uOp1 + uCf;
            SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
            EVAL_EFLAGS_ZF(*pX86, uSum)
            EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//80 /2 ib ADC r/m8 imm8
VM_INSTRUCTION_ERR_CODE immediate_grp1_80_adc(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uCf;
    UINT uSum;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp1 = (UINT)pInstruction->uImmediate;
    uCf = GET_EFLAGS_CF_BIT(*pX86);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetMemoryValue(pX86, pMemory, uEA, uSum & 0xff, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    
    //Set Flags
    EVAL_EFLAGS_ZF(*pX86, (INT8)uSum);
    EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uSum, _8_BITS);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
    EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//81 /2 iw ADC r/m16, imm16
//81 /2 id ADC r/m32, imm32
VM_INSTRUCTION_ERR_CODE immediate_grp1_81_adc(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uCf;
    UINT uSum;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xffffffff);
    uOp1 = (UINT)pInstruction->uImmediate;
    uCf = GET_EFLAGS_CF_BIT(*pX86);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetMemoryValue(pX86, pMemory, uEA, uSum, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    //Set Flags
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);
            EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1 , uSum, _16_BITS);
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

//83 /2 ADC r/m8, imm8
//note: 2010��3��26�� ��販�� δ����
VM_INSTRUCTION_ERR_CODE immediate_grp1_82_adc(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uCf;
    UINT uSum;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp1 = (UINT)pInstruction->uImmediate;
    uCf = GET_EFLAGS_CF_BIT(*pX86);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetMemoryValue(pX86, pMemory, uEA, uSum, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);
    EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uSum, _8_BITS);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum); 
    EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//83 /2 ADC r/m16, imm8
//83 /2 ADC r/m32, imm8
VM_INSTRUCTION_ERR_CODE immediate_grp1_83_adc(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uCf;
    UINT uSum;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp1 = (UINT)pInstruction->uImmediate;
    uCf = GET_EFLAGS_CF_BIT(*pX86);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetMemoryValue(pX86, pMemory, uEA, uSum, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uSum = uOp0 + uOp1 + uCf;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    //Set Flags
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
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}