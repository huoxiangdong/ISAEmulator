//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/les.c
//�ļ�������        Intel x86��lesָ�����
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

#include "ISA/Intel_x86/Instructions/les.h"
#include "ISA/Intel_x86/Instructions/common.h"

//c4 /r les r16,m16:16   load ES:r16 with far pointer from memory
//c4 /r les r32,m16:32   load ES:r32 with far pointer from memory
VM_INSTRUCTION_ERR_CODE les_c4(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //û�����쳣�����
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT64  Op0;

    assert(pInstruction);

        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
    Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_p, pInstruction->dwFlags);  // 48 or 32

    SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM),(UINT)Op0, GENERAL_REGISTER, OT_p, pInstruction->dwFlags);
    ACCESS_GEN_ES(*pX86) =(UINT16) (Op0 >> 32);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}