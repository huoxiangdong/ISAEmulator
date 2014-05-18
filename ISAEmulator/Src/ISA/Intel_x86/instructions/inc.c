//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/cmp.c
//�ļ�������        Intel x86��cmpָ�����
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
//2009��10��9�գ�����(laosheng@ptwy.cn)���޸�ָ���EFLAGS��Ӱ��


#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/inc.h"
#include "ISA/Intel_x86/Instructions/common.h"

//inc ax
//inc eax
VM_INSTRUCTION_ERR_CODE inc_40(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    //����ǰ׺ 66 ѡ�� ex ,eax 
    //���ܲ�����ǰ׺��ͳһ�� eax += 1; ��Ϊ ax += 1 �����ʱ�� ���λ ��ʧ������ʱ��eaxʱ����λ�ڵ�17λ
    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_AX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_AX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                      //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_EAX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_AX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//inc cx
//inc ecx
VM_INSTRUCTION_ERR_CODE inc_41(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_CX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_CX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                      //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_ECX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_ECX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//inc dx
//inc edx
VM_INSTRUCTION_ERR_CODE inc_42(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_DX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_DX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                      //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_EDX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_EDX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//inc bx
//inc ebx
VM_INSTRUCTION_ERR_CODE inc_43(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_BX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_BX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_EBX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_EBX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//inc sp
//inc esp
VM_INSTRUCTION_ERR_CODE inc_44(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_SP(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_SP(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_ESP(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_ESP(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//inc bp
//inc ebp
VM_INSTRUCTION_ERR_CODE inc_45(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_BP(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_BP(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_EBP(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_EBP(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//inc si
//inc esi
VM_INSTRUCTION_ERR_CODE inc_46(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_SI(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_SI(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_ESI(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_ESI(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//inc di
//inc edi
VM_INSTRUCTION_ERR_CODE inc_47(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_DI(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_DI(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_EDI(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_EDI(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//fe /1 inc r/m8
VM_INSTRUCTION_ERR_CODE inc_dec_grp4_fe_inc(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //FE C2       inc   dl   
    //C2 : 1100 0010
    //Mod/RM == 11 010 -> dl , 

    //FE C4       inc   ah 
    //C2 : 1100 0100
    //Mod/RM == 11 100 -> ah , 

    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uSum & 0xff, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);; 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    //set Flag 
    EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);   //OF
    EVAL_EFLAGS_SF(*pX86, uSum, _8_BITS);                   //SF
    EVAL_EFLAGS_ZF(*pX86, (INT8)uSum);                             //ZF
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
    //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
 
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//ff/1 inc r/m16
//ff/1 inc r/m32
VM_INSTRUCTION_ERR_CODE inc_dec_grp5_ff_inc(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uSum, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);; 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
