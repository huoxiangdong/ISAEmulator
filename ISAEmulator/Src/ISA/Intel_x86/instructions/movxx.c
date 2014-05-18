//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/movxx.c
//�ļ�������        Intel x86��movzx/movsxָ�����
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2010��4��8��
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
//Update Log:
//������־��
//2010��4��8�գ���販(yanghongbo@ptwy.cn)������

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/movxx.h"
#include "ISA/Intel_x86/Instructions/common.h"

//0F B6 /r  MOVZX r16, r/m8
//0F B6 /r  MOVZX r32, r/m8
//MOVZX Gv, Eb
VM_INSTRUCTION_ERR_CODE movzx_0F_B6(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    VM_INSTRUCTION_ERR_CODE vm_err;
    UINT32 Op0 = 0;
    UINT uEA = 0;
    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;

        Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    //����չ�����INT8ֱ����չΪUINT32����λ��0
    vm_err = SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    return vm_err;
}

//0F B7 /r  MOVZX r32, r/m16
VM_INSTRUCTION_ERR_CODE movzx_0F_B7(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    VM_INSTRUCTION_ERR_CODE vm_err;
    UINT32 Op0;
    UINT uEA = 0;
    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;

        Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_w, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_w, pInstruction->dwFlags);
    }

    //����չ�����INT8ֱ����չΪUINT32����λ��0
    vm_err = SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);

    return vm_err;
}

//0F BE /r  movsx r16, r/m8
//0F BE /r  movsx r32, r/m8
//MOVSX Gv, Eb
VM_INSTRUCTION_ERR_CODE movsx_0F_BE(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    VM_INSTRUCTION_ERR_CODE vm_err;
    INT8 Op0;
    INT32 iResult;
    UINT uEA = 0;
    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;

        //������չ����0b00000000 00000000 00000000 sxxxxxxx��ת��Ϊ0b sxxxxxxx
        Op0 = (INT8)GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else{
        Op0 = (INT8)GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    //������չ�����INT8��չΪINT32����λ������s��
    iResult = (INT32)Op0;
    vm_err = SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), (UINT)iResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);

    return vm_err;
}

//0F BF /r  movsx r16, r/m16
//MOVSX Gv, Ew
VM_INSTRUCTION_ERR_CODE movsx_0F_BF(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    VM_INSTRUCTION_ERR_CODE vm_err;
    INT16 Op0;
    INT32 iResult;
    UINT uEA = 0;
    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;

        //������չ����0b00000000 00000000 00000000 sxxxxxxx��ת��Ϊ0b sxxxxxxx
        Op0 = (INT16)GetMemoryValue(pX86, pMemory, uEA, OT_w, pInstruction->dwFlags);
    }
    else{
        Op0 = (INT16)GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_w, pInstruction->dwFlags);
    }

    //������չ�����INT8��չΪINT32����λ������s��
    iResult = (INT32)Op0;
    vm_err = SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), (UINT)iResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    return vm_err;
}