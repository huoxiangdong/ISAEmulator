//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/misc.c
//�ļ�������        Intel x86��CMC/CLC/STC/CLI/STI/CLD/STD/LEA/CBW/CWDָ�����
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
//2009��8��13�գ�����(laosheng@ptwy.cn)������

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/misc.h"
#include "ISA/Intel_x86/Instructions/common.h"

//8d /r lea r16,m
//8d /r lea r32,m
VM_INSTRUCTION_ERR_CODE lea_8d(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{   
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;

    assert(pInstruction);

        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
    SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uEA, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//98   cbw         AX <- sign-extend of AL
//98   cwde        EAX <- sign-extend of AX
VM_INSTRUCTION_ERR_CODE cbw_98(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    //66 ǰ׺��OperSize
    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        ACCESS_GEN_AX(*pX86) = ACCESS_GEN_AL(*pX86);
    }
    else{
        ACCESS_GEN_EAX(*pX86) = ACCESS_GEN_AX(*pX86);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//99 cwd     DX:AX <- sign-extend of AX
//99 cdq     EDX:EAX <- sign-extend of EAX
VM_INSTRUCTION_ERR_CODE cwd_99(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT64  Op0;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        Op0 = ACCESS_GEN_AX(*pX86);
        ACCESS_GEN_AX(*pX86) = (UINT16)Op0;
        ACCESS_GEN_DX(*pX86) = (UINT16)((Op0 >> 16));
    }
    else{
        Op0 = ACCESS_GEN_EAX(*pX86);
        ACCESS_GEN_EAX(*pX86) = (UINT32)Op0;
        ACCESS_GEN_EDX(*pX86) = (UINT32)((Op0 >> 32));
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//f5 cmc    complement CF flag
VM_INSTRUCTION_ERR_CODE cmc_f5(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pX86);

    SET_EFLAGS_CF(*pX86, ~GET_EFLAGS_CF_BIT(*pX86));
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//f8 cle    clear CF flag
VM_INSTRUCTION_ERR_CODE clc_f8(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{    
    assert(pX86);

    SET_EFLAGS_CF(*pX86, 0);
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//f9 stc  set CF flag
VM_INSTRUCTION_ERR_CODE stc_f9(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pX86);

    SET_EFLAGS_CF(*pX86, 1);
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//fa cli   clear interrupt flag,interrupts disabled when interrupt flag cleared
VM_INSTRUCTION_ERR_CODE cli_fa(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pX86);

    //��ϵͳ�������нϴ���Ӱ�죬δ����
    //SET_EFLAGS_IF(*pX86, 0);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//fb sti set interrupt flag,maskable interrupts enabled at the end of the next instruction
VM_INSTRUCTION_ERR_CODE sti_fb(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pX86);
    //��ϵͳ�������нϴ���Ӱ�죬δ����
    //SET_EFLAGS_IF(*pX86, 1);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//fc cld  clear DF flag
VM_INSTRUCTION_ERR_CODE cld_fc(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pX86);

    SET_EFLAGS_DF(*pX86, 0);
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//fd std set DF flag
VM_INSTRUCTION_ERR_CODE std_fd(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pX86);

    SET_EFLAGS_DF(*pX86, 1);
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
