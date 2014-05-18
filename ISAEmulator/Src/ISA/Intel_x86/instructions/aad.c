//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/aad.c
//�ļ�������        Intel x86��aadָ�����
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

#include "ISA/Intel_x86/Instructions/aad.h"
#include "ISA/Intel_x86/Instructions/common.h"

//d5 0A aad     ASCII adjust AX before division
//d5 ib (No mnemonic)    adjust AX before division to number base imm8
VM_INSTRUCTION_ERR_CODE aad_d5(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uAH;
    UINT uAL;

    assert(pInstruction);
    uAL = ACCESS_GEN_AL(*pX86);    
    uAH = ACCESS_GEN_AH(*pX86);  

    ACCESS_GEN_AL(*pX86) = (UINT8) ((uAL + uAH * pInstruction->uImmediate) & 0xff);
    ACCESS_GEN_AH(*pX86) = 0;

    EVAL_EFLAGS_ZF(*pX86, (INT8)uAL);
    EVAL_EFLAGS_SF(*pX86, uAL, _8_BITS);
    //EVAL_EFLAGS_PF

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}