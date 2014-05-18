//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/aam.c
//�ļ�������        Intel x86��aamָ�����
//�����ˣ�          ����(laosheng@ptwy.cn)
//�������ڣ�        2009��8��18��
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
//2009��8��18�գ�����(laosheng@ptwy.cn)������

//
//������־��
//2009��9��28�գ�����(laosheng@ptwy.cn)���޸�ָ���EFLAGS��Ӱ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/aam.h"
#include "ISA/Intel_x86/Instructions/common.h"


//D4 0A aam       ASCII adjust AX after multiply
//D4 ib (No mnemonic)   adjust AX after multiply to number base imm8
VM_INSTRUCTION_ERR_CODE aam_d4(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uAL;

    assert(pInstruction);
 
    uAL = ACCESS_GEN_AL(*pX86);  

	if(0 == pInstruction->uImmediate)
		return VM_INSTRUCTION_ERR_DIVIDE_BY_ZERO;

    ACCESS_GEN_AH(*pX86) = (UINT8) (uAL / pInstruction->uImmediate);
    ACCESS_GEN_AL(*pX86) = (UINT8) (uAL % pInstruction->uImmediate);

    EVAL_EFLAGS_ZF(*pX86, (INT8)ACCESS_GEN_AL(*pX86));
    EVAL_EFLAGS_SF(*pX86, ACCESS_GEN_AL(*pX86), _8_BITS);
    //EVAL_EFLAGS_PF

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}