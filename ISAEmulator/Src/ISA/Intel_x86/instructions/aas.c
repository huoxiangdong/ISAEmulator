//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/aas.c
//�ļ�������        Intel x86��aasָ�����
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

#include "ISA/Intel_x86/Instructions/aas.h"
#include "ISA/Intel_x86/Instructions/common.h"


//37  aas    ASCII adjust AL after subtraction
VM_INSTRUCTION_ERR_CODE aas_3f(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uAL;

    assert(pInstruction);
    uAL = ACCESS_GEN_AL(*pX86);

    if ((uAL & 0xf) > 9  || (1 == GET_EFLAGS_AF_BIT(*pX86))){
        ACCESS_GEN_AL(*pX86) -= 6;
        ACCESS_GEN_AH(*pX86) -= 1;
        SET_EFLAGS_AF(*pX86, 1);    //AF <- 1
        SET_EFLAGS_CF(*pX86, 1);    //CF <- 1
        ACCESS_GEN_AL(*pX86) &= 0xf;
    } 
    else{
        SET_EFLAGS_AF(*pX86, 0);    //AF <- 0
        SET_EFLAGS_CF(*pX86, 0);    //CF <- 0
        ACCESS_GEN_AL(*pX86) &= 0xf;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}