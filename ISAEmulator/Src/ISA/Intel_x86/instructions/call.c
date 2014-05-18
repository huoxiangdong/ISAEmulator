//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/call.c
//�ļ�������        Intel x86��callָ�����
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
//2009��8��17�գ�����(laosheng@ptwy.cn)������

//
//������־��
//2009��10��13�գ�����(laosheng@ptwy.cn)���޸ģ����ƣ�call ��ʵ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/call.h"
#include "ISA/Intel_x86/Instructions/common.h"


//CALL  ֻ��ring3 ���ĺ������ã�û��ʵ����Ȩ���ı仯

//9a and ff /3 CONFORMING-CODE-SEGMENT

//9a cd call ptr16:16
//9a cd call ptr16:32
VM_INSTRUCTION_ERR_CODE call_9a(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //Debug : 		_emit 0x9a   //9A 11 12 13 14 15 16    call  1615:14131211 
    //              _emit 0x11
    //              _emit 0x12
    //              _emit 0x13
    //              _emit 0x14
    //              _emit 0x15
    //              _emit 0x16
    //in pInstruction : uImmediate	0x14131211	unsigned long
    //but No Prt16:, In the same segment.so not ues this value

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_ES(*pX86), OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_IP(*pX86), OPERAND_SIZE_16BIT);
            ACCESS_GEN_IP(*pX86) = (INT16)pInstruction->uImmediate;
            break;

        case OT_d:
            //PUSH CS , cs padded with 16 high-order bits ( ����Ϊ0 ��Ҳ���Բ�Ϊ 0)
            PushStack(pX86, pMemory,(UINT)ACCESS_GEN_CS(*pX86), OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_EIP(*pX86), OPERAND_SIZE_32BIT);

            //CS not change! prt16 , not use to select a segment descriptor
            ACCESS_GEN_EIP(*pX86) = pInstruction->uImmediate;
            break;
        default:
            assert(0);//should not be here;
            break;
    }
    //��ָ���ڱ���ģʽ�����ر�ָ�����ʵ��ͬ��Ȩ��������ͬ��Ȩ��֮���ת����
    return VM_INSTRUCTION_ERR_NOT_IMPLEMENTED;
}


//e8 cw  call rel16   , call near , relative
//e8 cd  call rel32
VM_INSTRUCTION_ERR_CODE call_e8(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_IP(*pX86), OPERAND_SIZE_16BIT);
            ACCESS_GEN_IP(*pX86) += (INT)pInstruction->uImmediate;
            break;

        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_EIP(*pX86), OPERAND_SIZE_32BIT);
            ACCESS_GEN_EIP(*pX86) += (INT)pInstruction->uImmediate;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//ff /2 call r/m16
//ff /2 call r/m32
VM_INSTRUCTION_ERR_CODE inc_dec_grp5_ff_2_call(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uEA1;
    INT Op0;

    assert(pInstruction);

    uEA = ACCESS_GEN_SS(*pX86) + ACCESS_GEN_ESP(*pX86);
    //push EIP
    ACCESS_GEN_ESP(*pX86) -= 4;
    uEA -= 4;
    SetMemoryValue(pX86, pMemory, uEA, ACCESS_GEN_EIP(*pX86) , OT_v, pInstruction->dwFlags);
    
    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA1);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_IP(*pX86), OPERAND_SIZE_16BIT);
            ACCESS_GEN_IP(*pX86) += (INT)pInstruction->uImmediate;
            break;

        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_EIP(*pX86), OPERAND_SIZE_32BIT);
            ACCESS_GEN_EIP(*pX86) += (INT)pInstruction->uImmediate;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//Memory operand:
//m16:16, m16:32 & m16:64 - A memory operand containing a far pointer composed of two numbers.
//The number to the left of the colon corresponds to the pointer's segment selector.The number to
//the right corresponds to its offset.
//ff /3 call m16:16
//ff /3 call m16:32
VM_INSTRUCTION_ERR_CODE inc_dec_grp5_ff_3_call(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT  uEA;
    INT  iM32;

    //004411DD: 64 FF 35 00 00 00 00  push        dword ptr fs:[0]
    assert(pInstruction);

        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
    iM32 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);  //get the EIP value from the memory, double word 

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_ES(*pX86), OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_IP(*pX86), OPERAND_SIZE_16BIT);

            ACCESS_GEN_IP(*pX86) += iM32;
            break;

        case OT_d:
            //PUSH CS , cs padded with 16 high-order bits ( ����Ϊ0 ��Ҳ���Բ�Ϊ 0)
            PushStack(pX86, pMemory,(UINT)ACCESS_GEN_CS(*pX86), OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_EIP(*pX86), OPERAND_SIZE_32BIT);

            ACCESS_GEN_EIP(*pX86) += iM32;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}