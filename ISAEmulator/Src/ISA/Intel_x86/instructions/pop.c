//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/pop.c
//�ļ�������        Intel x86��popָ�����
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

#include "ISA/Intel_x86/Instructions/pop.h"
#include "ISA/Intel_x86/Instructions/common.h"

//Intel 64 and IA-32 Architectures Software Developer's Manual - Volume 2B- Instruction Set Reference, N-Z
//Instruction : pop       Page : Vol 2. 4-195
//  If the destination operand is one of the segment registers DS,ES,FS,GS,orSS,the value loaded into the 
//register must be a valid segment selector. In the protected mode, poping a segment selector into a segment
//register automatically causes the descriptor information associated with that segment selector to be loaded
//into the hidden(shadow) part of the segment register and causes the selector and the descriptor information
//to be validated.
//
//A NULL value(0000-0003) may be popped into the DS,ES,FS,or GS register without causing a general protection
//fault. However, any subsequent attempt to reference a segment whose corresponding segment register is loaded
//with a NULL value causes a general protection exception(#GP),

//07, pop es.
VM_INSTRUCTION_ERR_CODE pop_07(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{    
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            ACCESS_GEN_ES(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            ACCESS_GEN_ES(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }
    
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//17, pop ss.
VM_INSTRUCTION_ERR_CODE pop_17(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    //Pop doublewordʱ�������Ǹ�16λ�����ǵ�16λ��ֵ����Ϊ�Ĵ�����ֵ
    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            ACCESS_GEN_SS(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            ACCESS_GEN_SS(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//1F        pop ds
VM_INSTRUCTION_ERR_CODE pop_1f(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    //Pop doublewordʱ�������Ǹ�16λ�����ǵ�16λ��ֵ����Ϊ�Ĵ�����ֵ
    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            ACCESS_GEN_DS(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            ACCESS_GEN_DS(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//58        pop rAX/r8, d64
VM_INSTRUCTION_ERR_CODE pop_58(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            ACCESS_GEN_AX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            ACCESS_GEN_EAX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }
    
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//59        pop rCX/r9, d64
VM_INSTRUCTION_ERR_CODE pop_59(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            ACCESS_GEN_CX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            ACCESS_GEN_ECX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//5A        pop rDX/r10, d64
VM_INSTRUCTION_ERR_CODE pop_5a(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            ACCESS_GEN_DX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            ACCESS_GEN_EDX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//5B        pop rBX/r11, d64
VM_INSTRUCTION_ERR_CODE pop_5b(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            ACCESS_GEN_BX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            ACCESS_GEN_EBX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//5C        pop rSP/r12, d64
//The POP ESP instruction increments the stack pointer(ESP) berfore the data at the old top of stack is written into the destination
//A POP SS instruction inhibits all interrupts , including the NMI interrupt , until after execution of the Next instruction.
//(E)SP ָ��ǰ��ջ�ṹ�������ݽṹ�е�ջ��ջָ�루����ʵ�ֳɣ�ָ����һ�����õĽṹ��ע�ⲻͬ��
VM_INSTRUCTION_ERR_CODE pop_5c(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            ACCESS_GEN_SP(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            ACCESS_GEN_ESP(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//5D        pop rBP, d64
VM_INSTRUCTION_ERR_CODE pop_5d(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            ACCESS_GEN_BP(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            ACCESS_GEN_EBP(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//5E        pop rSI, d64
VM_INSTRUCTION_ERR_CODE pop_5e(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            ACCESS_GEN_SI(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            ACCESS_GEN_ESI(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//5F        pop rDI, d64
VM_INSTRUCTION_ERR_CODE pop_5f(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            ACCESS_GEN_DI(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            ACCESS_GEN_EDI(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//61        popa in 16-bit mode, popad when the operand-size attribute is 32
VM_INSTRUCTION_ERR_CODE popa_61(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{ 
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            ACCESS_GEN_DI(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            ACCESS_GEN_SI(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            ACCESS_GEN_BP(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            ACCESS_GEN_BX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            ACCESS_GEN_DX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            ACCESS_GEN_CX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            ACCESS_GEN_AX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            ACCESS_GEN_EDI(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            ACCESS_GEN_ESI(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            ACCESS_GEN_EBP(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            ACCESS_GEN_EBX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            ACCESS_GEN_EDX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            ACCESS_GEN_ECX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            ACCESS_GEN_EAX(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//8f /0 pop r/m16 pop top of stack into m16; increment stack pointer
//8f /0 pop r/m32 pop top of stack into m32; increment stack pointer
VM_INSTRUCTION_ERR_CODE grp1a_pop_8f_pop(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;

    assert(pInstruction);

    //ȡ��ջ���е�Ԫ��
    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOp0 = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            uOp0 = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
            break;
    } 

    //����Ŀ�굥Ԫ��
    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        //�洢��Ԫ���ڴ�ĵ�ַ
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        SetMemoryValue(pX86, pMemory, uEA, uOp0, OT_v, pInstruction->dwFlags);  
    }
    else {
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags); 
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
