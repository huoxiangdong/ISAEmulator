//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/neg.c
//�ļ�������        Intel x86��negָ�����
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
//2009��8��12�գ�����(laosheng@ptwy.cn)������

//
//������־��
//2009��10��9�գ�����(laosheng@ptwy.cn),�޸ģ�ָ��Ķ�EFLAGS�Ĵ�����Ӱ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/neg.h"
#include "ISA/Intel_x86/Instructions/common.h"

//f6 /3 neg r/m8
VM_INSTRUCTION_ERR_CODE unary_grp3_f6_neg(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //F6 DB     neg    bl  �����룺neg bl 
    //DB : 1101 1011
    //Mod/RM == 11 011 -> bl

    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uOp1 = 0;
        uResult = uOp1 - uOp0;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    else {
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uOp1 = 0;
        uResult = uOp1 - uOp0;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    if (0 ==uOp0){
        SET_EFLAGS_CF(*pX86 , 0);
    }
    else{
        SET_EFLAGS_CF(*pX86 , 1);
    }

    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult); 

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//f7 /3 neg r/m16
//f7 /3 neg r/m32
VM_INSTRUCTION_ERR_CODE unary_grp3_f7_neg(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uOp1 = 0;
        uResult = uOp1 - uOp0;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    else {
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uOp1 = 0;
        uResult = uOp1 - uOp0;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    //Set Flags
    if (0 ==uOp0){
        SET_EFLAGS_CF(*pX86 , 0);
    }
    else{
        SET_EFLAGS_CF(*pX86 , 1);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult); 
            break;

        case OT_d:
            EVAL_EFLAGS_ZF(*pX86, uResult);
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult); 
            break;
    }
    
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
