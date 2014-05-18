//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/popf.c
//�ļ�������        Intel x86��popfָ�����
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

//
//������־��
//2009��10��10�գ�����(laosheng@ptwy.cn),�޸ģ����Բ������Ĵ�С

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/popf.h"
#include "ISA/Intel_x86/Instructions/common.h"

//
//������־��
//2009��10��10�գ�����(laosheng@ptwy.cn),�޸ģ��������Ĵ�С��ջ��ַ��С�ļ��


//9d  popf      pop top of stack into lower 16 bits of EFLAGS
//9d  popfd     pop top of stack into EFLAGS
VM_INSTRUCTION_ERR_CODE popf_9d(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{

    assert(pInstruction);

    ACCESS_GEN_EFLAGS_LOWER_HALF_VALUE(*pX86)= (UINT16)PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
    
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}