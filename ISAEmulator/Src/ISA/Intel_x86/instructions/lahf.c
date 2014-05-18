//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/lahf.c
//�ļ�������        Intel x86��lahfָ�����
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

#include "ISA/Intel_x86/Instructions/lahf.h"
#include "ISA/Intel_x86/Instructions/common.h"

//9f  lahf     Load:AH <- EFLAGS(SF:ZF:0:AF:0:PF:1:CF)
VM_INSTRUCTION_ERR_CODE lahf_9f(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    INT  Op0;
    assert(pInstruction);

    Op0 = ACCESS_GEN_EFLAGS(*pX86);
    /*
    */
    // bit:2 of EFLAGS    PF
    if (Op0 & 0x2){
        ACCESS_GEN_AH(*pX86) |= 0x2;
    }
    else{
        ACCESS_GEN_AH(*pX86) &=  (~0x2);
    }

    // bit:4 of EFLAGS    AF
    if (Op0 & 0x8){
        ACCESS_GEN_AH(*pX86) |= 0x8;
    }
    else{
        ACCESS_GEN_AH(*pX86) &=  (~0x8);
    }

    // bit:6 of EFLAGS    ZF
    if (Op0 & 0x20){
        ACCESS_GEN_AH(*pX86) |= 0x20;
    }
    else{
        ACCESS_GEN_AH(*pX86) &=  (~0x20);
    }

    // bit:7 of EFLAGS    SF
    if (Op0 & 0x40){
        ACCESS_GEN_AH(*pX86) |= 0x40;
    }
    else{
        ACCESS_GEN_AH(*pX86) &=  (~0x40);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}