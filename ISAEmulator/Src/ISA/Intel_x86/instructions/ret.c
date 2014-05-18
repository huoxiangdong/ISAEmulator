//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/ret.c
//�ļ�������        Intel x86��retָ�����
//�����ˣ�          ����(laosheng@ptwy.cn)
//�������ڣ�        2009��8��17��
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
//2009��10��13�գ�����(laosheng@ptwy.cn)���޸ģ����ƣ�ret ��ʵ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/ret.h"
#include "ISA/Intel_x86/Instructions/common.h"


//c2 iw  ret imm16  Near return to calling procedure and pop imm16 bytes from stack
VM_INSTRUCTION_ERR_CODE ret_c2(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    INT  iSrc;
    UINT uEip;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xffff);

    iSrc = pInstruction->uImmediate;

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uEip = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            uEip &= 0xffff;     //low-16bits

            //if uEip not within code segment limits
            //    then #GP(0);fi;
            ACCESS_GEN_EIP(*pX86) = uEip;
            break;

        case OT_d:
            ACCESS_GEN_EIP(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }

    //has immediate operand, Release parameters from stack
    if(pMemory->StackSegment.uSegmentDescriptor[1] & SEGMENT_DESCRIPTOR_MASK_DB){
        //StackAddressSize = 32
        ACCESS_GEN_ESP(*pX86) += iSrc ;
    }
    else{
        //StackAddressSize = 16
        ACCESS_GEN_SP(*pX86) += iSrc;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//c3  ret Near return to calling procedure
//within the current code segment(near call)
VM_INSTRUCTION_ERR_CODE ret_c3(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uEip;

    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uEip = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            uEip &= 0xffff;     //low-16bits

            //if uEip not within code segment limits
            //    then #GP(0);fi;
            ACCESS_GEN_EIP(*pX86) = uEip;
            break;

        case OT_d:
            uEip = ACCESS_GEN_EIP(*pX86);
            uEip = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            ACCESS_GEN_EIP(*pX86) = uEip;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//CA and CB return-same-privilege-level:4-328 Vol. 28 RETURN-SAME-PRIVILEGE-LEVEL

//ca iw  ret imm16  Far return to calling procedure and pop imm16 bytes from stack
VM_INSTRUCTION_ERR_CODE ret_ca(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uEip;
    INT  iSrc;
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xffff);
    iSrc = pInstruction->uImmediate;

    //if the return instruction pointer is not within the return code segment limit
    //    then #GP(0) ; fi
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uEip = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            uEip &= 0xffff;     //low-16bits
            ACCESS_GEN_EIP(*pX86) = uEip;

            ACCESS_GEN_CS(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;

        case OT_d:
            ACCESS_GEN_CS(*pX86) = (UINT16) PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            ACCESS_GEN_EIP(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }

    ACCESS_GEN_ESP(*pX86) += iSrc;

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//cb  ret Far return to calling procedure
VM_INSTRUCTION_ERR_CODE ret_cb(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uEip;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xffff);


    //if the return instruction pointer is not within the return code segment limit
    //    then #GP(0) ; fi
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uEip = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            uEip &= 0xffff;     //low-16bits
            ACCESS_GEN_EIP(*pX86) = uEip;

            ACCESS_GEN_CS(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;

        case OT_d:
            ACCESS_GEN_CS(*pX86) = (UINT16) PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            ACCESS_GEN_EIP(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
