//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/das.c
//�ļ�������        Intel x86��dasָ�����
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
//2009��9��29�գ�����(laosheng@ptwy.cn)���޸�ָ���EFLAGS��Ӱ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/das.h"
#include "ISA/Intel_x86/Instructions/common.h"

VM_INSTRUCTION_ERR_CODE das_2f(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOldAL;
    UINT uOldCF;
    UINT uOp0;
    UINT uResult;

    assert(pInstruction);

    uOldAL = ACCESS_GEN_AL(*pX86);
    uOldCF = GET_EFLAGS_CF_BIT(*pX86);
    SET_EFLAGS_CF(*pX86 ,0);


    if ((ACCESS_GEN_AL(*pX86) & 0x0f) > 9 ||  1 == GET_EFLAGS_AF_BIT(*pX86)){
        uOp0 = ACCESS_GEN_AL(*pX86);
        uResult = uOp0 - 6;
        ACCESS_GEN_AL(*pX86) = uResult;

        //CF <- old_CF or Borrow from AL<- AL + 6
        SET_EFLAGS_CF(*pX86, uOldCF);
        if (1 != GET_EFLAGS_CF_BIT(*pX86)){
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 6, uResult, _8_BITS);
        }

        SET_EFLAGS_AF(*pX86, 1);
    }
    else{
        SET_EFLAGS_AF(*pX86, 0);
    }

    if (uOldAL > 0x99 || 1 == uOldCF /* old_CF = 1*/){
        ACCESS_GEN_AL(*pX86) -= 0x60;
        SET_EFLAGS_CF(*pX86, 1);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}