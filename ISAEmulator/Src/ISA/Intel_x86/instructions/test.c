//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/test.c
//�ļ�������        Intel x86��testָ�����
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
//2009��8��13�գ�����(laosheng@ptwy.cn)������

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/test.h"
#include "ISA/Intel_x86/Instructions/common.h"


//84 /r     test r/m8, r8
VM_INSTRUCTION_ERR_CODE test_84(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);

    uOp1 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else {
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    uResult = uOp0 & uOp1;

    SET_EFLAGS_OF(*pX86, 0);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);
    SET_EFLAGS_CF(*pX86, 0); 

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//85 /r     test r/m16, r16
//85 /r     test r/m32, r32
VM_INSTRUCTION_ERR_CODE test_85(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);

    uOp1 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
    }
    else {
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    
    uResult = uOp0 & uOp1;

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
			EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            SET_EFLAGS_CF(*pX86, 0); 
            break;

        case OT_d:
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            SET_EFLAGS_CF(*pX86, 0); 
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//A8 ib    test al, imm8
VM_INSTRUCTION_ERR_CODE test_a8(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp1 = pInstruction->uImmediate;
    uOp0 = ACCESS_GEN_AL(*pX86) ;

    uResult = uOp0 & uOp1;

    SET_EFLAGS_OF(*pX86, 0);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);
    SET_EFLAGS_CF(*pX86, 0); 

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//A9 iw    test ax, imm16
//A9 id    test eax, imm32
VM_INSTRUCTION_ERR_CODE test_a9(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xffffffff);

    uOp1 = pInstruction->uImmediate;

    if (1 /* 66 ǰ׺*/){
        uOp0 = ACCESS_GEN_AX(*pX86) ;
    }
    else{
        uOp0 = ACCESS_GEN_EAX(*pX86) ;
    }
    
    uResult = uOp0 & uOp1;

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
			EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            SET_EFLAGS_CF(*pX86, 0); 
            break;

        case OT_d:
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            SET_EFLAGS_CF(*pX86, 0); 
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//F6 /0 /ib test r/m8,imm8
VM_INSTRUCTION_ERR_CODE unary_grp3_f6_test(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp1 = pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
    }
    else {
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    
    uResult = uOp0 & uOp1;

    SET_EFLAGS_OF(*pX86, 0);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    //SET_EFLAGS_PF(*pX86, 0 == uSum);
    SET_EFLAGS_CF(*pX86, 0); 

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//F7 /0 /ib test r/m16,imm16
//F7 /0 /ib test r/m32,imm32
VM_INSTRUCTION_ERR_CODE unary_grp3_f7_test(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xffffffff);

    uOp1 = pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
    }
    else {
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    uResult = uOp0 & uOp1;

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
			EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            SET_EFLAGS_CF(*pX86, 0); 
            break;

        case OT_d:
            SET_EFLAGS_OF(*pX86, 0);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_ZF(*pX86, uResult);
            //SET_EFLAGS_PF(*pX86, 0 == uSum);
            SET_EFLAGS_CF(*pX86, 0); 
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}