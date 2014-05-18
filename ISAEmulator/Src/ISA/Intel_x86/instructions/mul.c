//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/mul.c
//�ļ�������        Intel x86��mulָ�����
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
//2009��10��9�գ�����(laosheng@ptwy.cn),�޸ģ�ָ��Ķ�EFLAGS�Ĵ�����Ӱ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/mul.h"
#include "ISA/Intel_x86/Instructions/common.h"


//f6 /4 mul r/m8 unsigned multiply(AX <- AL * r/m8)
VM_INSTRUCTION_ERR_CODE unary_grp3_f6_mul(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //66 F7 E1    mul    ax,cx   �����룺mul cx  ������ax= ax * cx
    //E1 : 1110 0001
    //Mod/RM == 11 001 -> cx ,

    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT Op1;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op1 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else {
        Op1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);  
    }

    ACCESS_GEN_AX(*pX86) = ACCESS_GEN_AL(*pX86) * Op1;
    //Set Flags
    if (0 ==ACCESS_GEN_AH(*pX86)){
        SET_EFLAGS_OF(*pX86, 0);
        SET_EFLAGS_CF(*pX86, 0);
    }
    else{
        SET_EFLAGS_OF(*pX86, 1);
        SET_EFLAGS_CF(*pX86, 1);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//f7 /4 mul r/m16  unsigned multiply(DX:AX <- AX * rm16)
//f7 /4 mul r/m32  unsigned multiply(EDX:EAX <- EAX * rm32)
VM_INSTRUCTION_ERR_CODE unary_grp3_f7_mul(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT64 Op1;
//    UINT64 Op2;
    UINT64 Op0;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op1 = GetMemoryValue(pX86, pMemory, uEA, OT_z, pInstruction->dwFlags);;
    }
    else {
        Op1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_z, pInstruction->dwFlags);  
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            Op0 = ACCESS_GEN_AX(*pX86)  * Op1;
            ACCESS_GEN_AX(*pX86) = Op0;
            ACCESS_GEN_DX(*pX86) = Op0 >>16;

            //If the upper half of the result is 0 then CF=OF = 0 ;otherwise CF=1 F =1
            if (0 ==ACCESS_GEN_DX(*pX86)){
                SET_EFLAGS_OF(*pX86, 0);
                SET_EFLAGS_CF(*pX86, 0);
            }
            else{
                SET_EFLAGS_OF(*pX86, 1);
                SET_EFLAGS_CF(*pX86, 1);
            }
            break;

        case OT_d:
            Op0 = ACCESS_GEN_EAX(*pX86)  * Op1;  //ACCESS_GEN_EAX(*pX86)��ȡ��������Ϊ32λ(union)�����Կ��԰ѿ��ɶ������ͣ� 
            //32*32 ���Ϊ32λ����ʱ����,�� 32*64 ��������ʱ����Ϊ64λ
            ACCESS_GEN_EAX(*pX86) = Op0;
            ACCESS_GEN_EDX(*pX86) = (UINT32)Op0 >>32;

            //If the upper half of the result is 0 then CF=OF = 0 ;otherwise CF=1 F =1
            if (0 ==ACCESS_GEN_EDX(*pX86)){
                SET_EFLAGS_OF(*pX86, 0);
                SET_EFLAGS_CF(*pX86, 0);
            }
            else{
                SET_EFLAGS_OF(*pX86, 1);
                SET_EFLAGS_CF(*pX86, 1);
            }
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
