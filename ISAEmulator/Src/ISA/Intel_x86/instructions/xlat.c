//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/xlat.c
//�ļ�������        Intel x86��xlatָ�����
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
//2009��10��12�գ�����(laosheng@ptwy.cn),�޸ģ��Ե�ַλ�����м��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/xlat.h"
#include "ISA/Intel_x86/Instructions/common.h"


//D7 xlat m8  set AL to memory byte DS:[(E)BX+unsigned AL]
//D7 xlat     set AL to memory byte DS:[(E)BX+unsigned AL]
VM_INSTRUCTION_ERR_CODE xlat_d7(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uEA;
    UINT uAL; 

    assert(pInstruction);
    uAL = ACCESS_GEN_AL(*pX86);

    switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
        case OPCODE_FLAG_PREFIX_ES:
            uEA = ACCESS_GEN_ES(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_FS:
            uEA = ACCESS_GEN_FS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_GS:
            uEA = ACCESS_GEN_GS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_DS:
        default :
            uEA = ACCESS_GEN_DS(*pX86);
            break;
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
        uEA = ACCESS_GEN_BX(*pX86) + uAL;
        ACCESS_GEN_AL(*pX86) = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        break;

        case OT_d:
        uEA = ACCESS_GEN_EBX(*pX86) + uAL;
        ACCESS_GEN_AL(*pX86) = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}