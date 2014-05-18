//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/div.c
//�ļ�������        Intel x86��divָ�����
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
//2009��8��12�գ�����(laosheng@ptwy.cn)������

//
//������־��
//2009��9��29�գ�����(laosheng@ptwy.cn)���޸�ָ���EFLAGS��Ӱ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/div.h"
#include "ISA/Intel_x86/Instructions/common.h"

//f6 /6 div r/m8   unsigned divide AX by r/m8 , with result stored in AL <- Quotient , AH <- Remainder
VM_INSTRUCTION_ERR_CODE unary_grp3_f6_div(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp1;
    UINT uTemp;
    UINT uAH;

    assert(pInstruction);
    
    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else {
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);  
    }

    if (0 == uOp1){
        return VM_INSTRUCTION_ERR_DIVIDE_BY_ZERO;
    }

    uAH  = ACCESS_GEN_AX(*pX86) ;
    uTemp = ACCESS_GEN_AX(*pX86) / uOp1 ;
    if (0xff<uTemp){
        return VM_INSTRUCTION_ERR_INTEGER_OVERFLOW;
    }
    ACCESS_GEN_AL(*pX86) = (UINT8)uTemp;
    ACCESS_GEN_AH(*pX86) = uAH % uOp1;

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//f7 /6 div r/m16   unsigned divide DX:AX by r/m16 , with result stored in AX <- Quotient , DX <- Remainder
//f7 /6 div r/m32   unsigned divide DX:AX by r/m32 , with result stored in EAX <- Quotient , EDX <- Remainder
VM_INSTRUCTION_ERR_CODE unary_grp3_f7_div(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT64 uOp1;
    UINT64 Op0;
    UINT uTemp;
 
    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_z, pInstruction->dwFlags);;
    }
    else {
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_z, pInstruction->dwFlags);  
    }

    if (0 == uOp1){
        return VM_INSTRUCTION_ERR_DIVIDE_BY_ZERO;
    }

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        Op0 = ACCESS_GEN_DX(*pX86);
        Op0 = (Op0 << 16) + ACCESS_GEN_AX(*pX86);

        uTemp = Op0 / uOp1;
        if (0xffff < uTemp){
            return  VM_INSTRUCTION_ERR_INTEGER_OVERFLOW;
        }

        ACCESS_GEN_AX(*pX86) = (UINT16)uTemp;
        ACCESS_GEN_DX(*pX86) = (UINT16)(Op0 % uOp1);
    }
    else{
        Op0 = ACCESS_GEN_EDX(*pX86);
        Op0 = (Op0 << 32) + ACCESS_GEN_EAX(*pX86);

        uTemp = Op0 / uOp1;
        if (0xffffffff < uTemp){
            return  VM_INSTRUCTION_ERR_INTEGER_OVERFLOW;
        }

        ACCESS_GEN_EAX(*pX86) = uTemp;
        ACCESS_GEN_EDX(*pX86) = (UINT32)(Op0 % uOp1);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
