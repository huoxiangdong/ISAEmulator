//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/push.c
//�ļ�������        Intel x86��pushָ�����
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
//2009��10��10�գ�����(laosheng@ptwy.cn),�޸ģ��������Ĵ�С��ջ��ַ��С�ļ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/push.h"
#include "ISA/Intel_x86/Instructions/common.h"


//06, push es.
VM_INSTRUCTION_ERR_CODE push_06(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_ES(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_ES(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//0E        push cs
VM_INSTRUCTION_ERR_CODE push_0e(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_CS(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_CS(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//16, push ss.
VM_INSTRUCTION_ERR_CODE push_16(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_SS(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_SS(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//1E        push ds
VM_INSTRUCTION_ERR_CODE push_1e(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_DS(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_DS(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//50        push rAX/r8, d64
VM_INSTRUCTION_ERR_CODE push_50(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_AX(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_EAX(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//51        push rCX/r9, d64
VM_INSTRUCTION_ERR_CODE push_51(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{

    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_CX(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_ECX(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//52        push rDX/r10, d64
VM_INSTRUCTION_ERR_CODE push_52(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_DX(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_EDX(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//53        push rBX/r11, d64
VM_INSTRUCTION_ERR_CODE push_53(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_BX(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_EBX(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//54        push rSP/r12, d64
VM_INSTRUCTION_ERR_CODE push_54(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{

    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_SP(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_ESP(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//55        push rBP, d64
VM_INSTRUCTION_ERR_CODE push_55(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_BP(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_EBP(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//56        push rSI, d64
VM_INSTRUCTION_ERR_CODE push_56(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_SI(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_ESI(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//57        push rDI, d64
VM_INSTRUCTION_ERR_CODE push_57(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_DI(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_EDI(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//68       push imm32, d64
VM_INSTRUCTION_ERR_CODE push_68(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //UINT uEA;
    INT  Op1;

    assert(pInstruction);

    Op1 = pInstruction->uImmediate;

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,Op1, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,Op1, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//6A       push imm8, d64
VM_INSTRUCTION_ERR_CODE push_6a(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //UINT uEA;
    INT  Op1;

    assert(pInstruction);
   
    Op1 = pInstruction->uImmediate;

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,Op1, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,Op1, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//60  pusha in 16-bit mode, pushad when the operand-size attribute is 16
VM_INSTRUCTION_ERR_CODE pusha_60(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_AX(*pX86), OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_CX(*pX86), OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_DX(*pX86), OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_BX(*pX86), OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,0xcc, OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_BP(*pX86), OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_SI(*pX86), OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_DI(*pX86), OPERAND_SIZE_16BIT);
            break;

        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_EAX(*pX86), OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_ECX(*pX86), OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_EDX(*pX86), OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_EBX(*pX86), OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,0xcccccccc, OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_EBP(*pX86), OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_ESI(*pX86), OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_EDI(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;

}

//GS FS ZeroExtend  
//ff /6 r/m16
//ff /6 r/m32
VM_INSTRUCTION_ERR_CODE inc_dec_grp5_ff_push(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uEA1;
    INT  Op0;

    assert(pInstruction);

    //ȡ��Ҫѹջ������
    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA1);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetMemoryValue(pX86, pMemory, uEA1, OT_b, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,Op0, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,Op0, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
