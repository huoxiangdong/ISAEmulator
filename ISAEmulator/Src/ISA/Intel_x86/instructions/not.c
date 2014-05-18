//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/not.c
//�ļ�������        Intel x86��notָ�����
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
//2009��10��10�գ�����(laosheng@ptwy.cn),�޸ģ�ָ��Ķ�EFLAGS�Ĵ�����Ӱ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/not.h"
#include "ISA/Intel_x86/Instructions/common.h"

//f6 /2 not r/m8 
VM_INSTRUCTION_ERR_CODE unary_grp3_f6_not(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT8 Op0;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        Op0 = ~Op0;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    else {
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        Op0 = ~Op0;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//f7 /2 not r/m16
//f7 /2 not r/m32
VM_INSTRUCTION_ERR_CODE unary_grp3_f7_not(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT Op0;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        Op0 = ~Op0;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_z, pInstruction->dwFlags);
    }
    else {
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_z, pInstruction->dwFlags);
        Op0 = ~Op0;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_z, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
