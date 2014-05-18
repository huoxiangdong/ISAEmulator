//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/leave.c
//�ļ�������        Intel x86��leaveָ�����
//�����ˣ�          ����(laosheng@ptwy.cn)
//�������ڣ�        2009��8��19��
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
//2009��8��19�գ�����(laosheng@ptwy.cn)������

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/leave.h"
#include "ISA/Intel_x86/Instructions/common.h"

//c9  leave     Set SP to BP , then pop BP
//c9  leave     Set SP to EBP , then pop EBP
VM_INSTRUCTION_ERR_CODE leave_c9(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uEA;

    assert(pInstruction);

    uEA = ACCESS_GEN_SS(*pX86) + ACCESS_GEN_ESP(*pX86);
    if (pMemory->StackSegment.uSegmentDescriptor[1] & SEGMENT_DESCRIPTOR_MASK_DB){
        /*Stack size : 32bit*/
        ACCESS_GEN_ESP(*pX86) = ACCESS_GEN_EBP(*pX86);
    }
    else{
        ACCESS_GEN_SP(*pX86) = ACCESS_GEN_BP(*pX86);
    }

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        ACCESS_GEN_BP(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
    }
    else{
        ACCESS_GEN_EBP(*pX86) = ACCESS_GEN_BP(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}