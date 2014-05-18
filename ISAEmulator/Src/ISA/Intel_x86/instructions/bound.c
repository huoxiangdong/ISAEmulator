//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/bound.c
//�ļ�������        Intel x86��boundָ�����
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

#include "ISA/Intel_x86/Instructions/bound.h"
#include "ISA/Intel_x86/Instructions/common.h"


//62 /r bound r16,m16&16         Check if r16(array index) is within bounds specified by m16&16
//62 /r bound r32,m32&32
VM_INSTRUCTION_ERR_CODE bound_62(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uBound;
    UINT uLower;
    UINT uUpper;
    UINT uEA;

    assert(pInstruction);
    uBound = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;

    uLower = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uEA += 2;
            break;
        case OT_d:
            uEA += 4;
            break;
    }

    uUpper = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);

    if (uBound < uLower || uBound > uUpper){
        //���� �쳣��#BR
        return VM_INSTRUCTION_ERR_NOT_IMPLEMENTED;
    }
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}