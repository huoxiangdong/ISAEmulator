//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/aaa.c
//�ļ�������        Intel x86��aaaָ�����
//�����ˣ�          ����(laosheng@ptwy.cn)
//�������ڣ�        2009��8��7��
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
//2009��8��7�գ�����(laosheng@ptwy.cn)������

//
//������־��
//2009��9��28�գ�����(laosheng@ptwy.cn)���޸�ָ���EFLAGS��Ӱ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/aaa.h"
#include "ISA/Intel_x86/Instructions/common.h"

//37  aaa  ASCII adjust AL after addition
VM_INSTRUCTION_ERR_CODE aaa_37(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    if ((ACCESS_GEN_AL(*pX86) & 0x0f) > 9 || GET_EFLAGS_AF_BIT(*pX86)){
        ACCESS_GEN_AL(*pX86) += 6;
        ACCESS_GEN_AH(*pX86) += 1;
        SET_EFLAGS_AF(*pX86, 1);
        SET_EFLAGS_CF(*pX86, 1);
        ACCESS_GEN_AL(*pX86)  &= 0x0f; //ʹ����λΪ0 (unpacked BCD)
    }
    else{
        SET_EFLAGS_AF(*pX86, 0);
        SET_EFLAGS_CF(*pX86, 0);
        ACCESS_GEN_AL(*pX86)  &= 0x0f; //ʹ����λΪ0 (unpacked BCD)
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}