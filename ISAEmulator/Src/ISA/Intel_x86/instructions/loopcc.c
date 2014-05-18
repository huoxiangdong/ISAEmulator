//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/loopcc.c
//�ļ�������        loopccָ��ʵ��
//�����ˣ�          ����(laosheng@ptwy.cn)
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
//2009��8��13�գ�����(laosheng@ptwy.cn)������

//
//������־��
//2009��10��9�գ�����(laosheng@ptwy.cn)���޸�:ָ����ʹ��EFLAGS��ֵ

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/loopcc.h"
#include "ISA/Intel_x86/Instructions/common.h"

//e0 cb  loopne rel8    Decrement count; jump short if count !=0 and ZF =0
VM_INSTRUCTION_ERR_CODE loopcc_e0(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        ACCESS_GEN_CX(*pX86) -= 1;
        if (0 != ACCESS_GEN_CX(*pX86) && 0==GET_EFLAGS_ZF_BIT(*pX86)){
            ACCESS_GEN_EIP(*pX86) += (INT8)pInstruction->uImmediate; 
        }
    }else{
        ACCESS_GEN_ECX(*pX86) -= 1;
        if (0 != ACCESS_GEN_ECX(*pX86) && 0==GET_EFLAGS_ZF_BIT(*pX86)){
            ACCESS_GEN_EIP(*pX86) += (INT8)pInstruction->uImmediate; 
        }
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//e1 cb  loope rel8    Decrement count; jump short if count !=0 and ZF =1
VM_INSTRUCTION_ERR_CODE loopcc_e1(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        ACCESS_GEN_CX(*pX86) -= 1;
        if (0 != ACCESS_GEN_CX(*pX86) && 1==GET_EFLAGS_ZF_BIT(*pX86)){
            ACCESS_GEN_EIP(*pX86) += (INT8)pInstruction->uImmediate; 
        }
    }else{
        ACCESS_GEN_ECX(*pX86) -= 1;
        if (0 != ACCESS_GEN_ECX(*pX86) && 1==GET_EFLAGS_ZF_BIT(*pX86)){
            ACCESS_GEN_EIP(*pX86) += (INT8)pInstruction->uImmediate; 
        }
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//e2 cb  loop rel8    Decrement count; jump short if count !=0 
VM_INSTRUCTION_ERR_CODE loopcc_e2(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        ACCESS_GEN_CX(*pX86) -= 1;
        if (0 != ACCESS_GEN_CX(*pX86)){
            ACCESS_GEN_EIP(*pX86) += (INT8)pInstruction->uImmediate; 
        }
    }else{
        ACCESS_GEN_ECX(*pX86) -= 1;
        if (0 != ACCESS_GEN_ECX(*pX86)){
            ACCESS_GEN_EIP(*pX86) += (INT8)pInstruction->uImmediate; 
        }
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
