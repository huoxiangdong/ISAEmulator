//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/stos.c
//�ļ�������        Intel x86��stosָ�����
//�����ˣ�          ����(laosheng@ptwy.cn)
//�������ڣ�        2009��8��14��
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
//2009��8��14�գ�����(laosheng@ptwy.cn)������

//
//������־��
//2009��10��12�գ�����(laosheng@ptwy.cn),�޸ģ� ָ��ԼĴ���EFLAGS��Ӱ��
//2010��3��29�գ���販(yanghongbo@ptwy.cn�������¡��޸Ĵ���ʵ�֣���ȥbug��δ���в��ԣ�

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"
#include "VM_Log.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/stoscc.h"
#include "ISA/Intel_x86/Instructions/common.h"


//AD  stos m8  Store  AL at address DS:(E)SI
VM_INSTRUCTION_ERR_CODE stos_aa(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uSegment = 0;
    UINT uSegmentOffset = 0;
    UINT uCount = 0;
    INT  iDecrementFlag = 0;

    UINT uAL;

    VM_ERR_CODE vm_err = VM_ERR_FATAL_UNKNOWN;
    assert(pInstruction);

    uSegment = ACCESS_GEN_ES(*pX86);

 //DS : (E)SI �γɵ�ַ
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        uSegmentOffset = ACCESS_GEN_DI(*pX86); 
        uCount= ACCESS_GEN_CX(*pX86); 
    }
    else{
        uSegmentOffset = ACCESS_GEN_EDI(*pX86);
        //��ADDRESS_SIZE_16BIT��64-bit�¼�rex.wǰ׺�������֮�⣬��ʹ��ECX
        uCount= ACCESS_GEN_ECX(*pX86); 
    }
    if (!(OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))){
        uCount = 1;
    }

    iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(1):(-1);

    uAL = ACCESS_GEN_AL(*pX86);

    while(0 != uCount){
        vm_err = SetMemoryValue(pX86, pMemory, uSegment + uSegmentOffset, uAL, OT_b, pInstruction->dwFlags);
        if(VM_ERR_NO_ERROR != vm_err){
            VM_ErrLog(vm_err);
            return VM_INSTRUCTION_ERR_ERROR_RETURN_BY_VM;
        }
        uSegmentOffset += iDecrementFlag;
        uCount --;
    }



   //���仯ֵ��д���Ĵ���
    //ES : (E)DI �γɵ�ַ
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        ACCESS_GEN_DI(*pX86) = uSegmentOffset ; 
        if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))
            ACCESS_GEN_CX(*pX86) = uCount;
    }
    else{
        ACCESS_GEN_EDI(*pX86) = uSegmentOffset;
        //��ADDRESS_SIZE_16BIT��64-bit�¼�rex.wǰ׺�������֮�⣬��ʹ��ECX
        if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))
            ACCESS_GEN_ECX(*pX86) = uCount; 
        
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//AD  stos m16  Store AX at address DS:(E)SI
//AD  stosw
//AD  stos m32  Store EAX at address DS:(E)SI
//AD  stosd
VM_INSTRUCTION_ERR_CODE stos_ab(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{

    UINT uSegment = 0;
    UINT uSegmentOffset = 0;
    UINT uCount = 0;
    INT  iDecrementFlag = 0;
    UINT uOpType = 0;
    UINT uData = 0;

    VM_ERR_CODE vm_err = VM_ERR_FATAL_UNKNOWN;
    assert(pInstruction);

    //The ES segment may be overridden
    uSegment = ACCESS_GEN_ES(*pX86);
    //DS : (E)SI �γɵ�ַ
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        uSegmentOffset = ACCESS_GEN_DI(*pX86); 
        uCount= ACCESS_GEN_CX(*pX86); 
    }
    else{
        uSegmentOffset = ACCESS_GEN_EDI(*pX86);
        //��ADDRESS_SIZE_16BIT��64-bit�¼�rex.wǰ׺�������֮�⣬��ʹ��ECX
        uCount= ACCESS_GEN_ECX(*pX86); 
    }
    if (!(OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))){
        uCount = 1;
    }

    //F3 REPE ǰ׺
    switch (uOpType = GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
            case OT_w:
                /*Opcode size 16*/
                /*DF == 1, decremented*/
                //note: 2010��3��26�գ���販�� ��ԭ�ȵ�do...while()�޸�Ϊwhile()���Ȳ���uCount != 0��������ܽ�����ѭ��
                //                              ��ԭ�ȵ�if (1 == GET_EFLAGS_DF_BIT(*pX86))���룬����iDecrementFlag
                iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(2):(-2);
                uData = ACCESS_GEN_AX(*pX86);
                break;

            case OT_d:
                /*Opcode size 32*/
                iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(4):(-4);
                uData = ACCESS_GEN_EAX(*pX86);
                break;
            default:
                assert(0);//should not be here
                break;
    }

    while(0 != uCount){
        vm_err = SetMemoryValue(pX86, pMemory, uSegment + uSegmentOffset, uData, uOpType, pInstruction->dwFlags);
        if(VM_ERR_NO_ERROR != vm_err){
            VM_ErrLog(vm_err);
            return VM_INSTRUCTION_ERR_ERROR_RETURN_BY_VM;
        }
        uSegmentOffset += iDecrementFlag;
        uCount --;
    }    

    //���仯ֵ��д���Ĵ���
    //ES : (E)DI �γɵ�ַ
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        ACCESS_GEN_DI(*pX86) = uSegmentOffset ; 
        if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))
            ACCESS_GEN_CX(*pX86) = uCount;
    }
    else{
         ACCESS_GEN_EDI(*pX86) = uSegmentOffset;
        //��ADDRESS_SIZE_16BIT��64-bit�¼�rex.wǰ׺�������֮�⣬��ʹ��ECX
        if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))
            ACCESS_GEN_ECX(*pX86) = uCount; 
        
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
