//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/daa.c
//�ļ�������        Intel x86��daaָ�����
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
//2009��9��29�գ�����(laosheng@ptwy.cn)���޸�ָ���EFLAGS��Ӱ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/daa.h"
#include "ISA/Intel_x86/Instructions/common.h"

//2f  daa      Decimal adjust AL after subtraction
VM_INSTRUCTION_ERR_CODE daa_27(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOldAL;
    UINT uOldCF;
    UINT uOp0;
    UINT uSum;

    assert(pInstruction);

    uOldAL = ACCESS_GEN_AL(*pX86);
    uOldCF = GET_EFLAGS_CF_BIT(*pX86);
    SET_EFLAGS_CF(*pX86 ,0);


    if ((ACCESS_GEN_AL(*pX86) & 0x0f) > 9 ||  1 == GET_EFLAGS_AF_BIT(*pX86)){
        uOp0 = ACCESS_GEN_AL(*pX86);
        uSum = uOp0 + 6;
        ACCESS_GEN_AL(*pX86) = uSum;

        //CF <- old_CF or Carry from AL<- AL + 6
        SET_EFLAGS_CF(*pX86, uOldCF);
        if (1 != GET_EFLAGS_CF_BIT(*pX86)){
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, 6, uSum, _8_BITS);
        }
        
        SET_EFLAGS_AF(*pX86, 1);
    }
    else{
        SET_EFLAGS_AF(*pX86, 0);
    }

    if (uOldAL > 0x99 || 1 == uOldCF /* old_CF = 1*/){
        ACCESS_GEN_AL(*pX86) += 0x60;
        SET_EFLAGS_CF(*pX86, 1);
        //ACCESS_GEN_AL(*pX86)  &= 0x0f; ʹ����λΪ0 (unpacked BCD)
    }
    else{
        SET_EFLAGS_CF(*pX86, 0);
        //ACCESS_GEN_AL(*pX86)  &= 0x0f; ʹ����λΪ0 (unpacked BCD)
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}