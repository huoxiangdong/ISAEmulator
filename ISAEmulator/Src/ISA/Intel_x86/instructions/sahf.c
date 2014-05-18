//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/sahf.c
//�ļ�������        Intel x86��sahfָ�����
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

#include "ISA/Intel_x86/Instructions/sahf.h"
#include "ISA/Intel_x86/Instructions/common.h"

//9e   sahf   loads SF,ZF,AF,PF,and CF from AH into EFLAGS register
VM_INSTRUCTION_ERR_CODE sahf_9e(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    INT  Op0;
    assert(pInstruction);

    Op0 = ACCESS_GEN_AH(*pX86);
/*
*/
    //bit:0 of AH     CF
    if (Op0 & 0x1){
        SET_EFLAGS_CF(*pX86, 1);
    }
    // bit:2 of AH    PF
    if (Op0 & 0x4){
        //
    }

    // bit:4 of AH    AF
    if (Op0 & 0x10){
        SET_EFLAGS_AF(*pX86, 1);
    }

    // bit:6 of AH    ZF
    if (Op0 & 0x40){
        SET_EFLAGS_ZF(*pX86, 1);
    }

    // bit:7 of AH    SF
    if (Op0 & 0x80){
        SET_EFLAGS_SF(*pX86, 1);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}