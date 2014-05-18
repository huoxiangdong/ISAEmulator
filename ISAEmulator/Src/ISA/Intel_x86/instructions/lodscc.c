//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/lodscc.c
//�ļ�������        Intel x86��lodsccָ�����
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
//2010��3��29�գ���販(yanghongbo@ptwy.cn�������¡��޸Ĵ���ʵ�֣���ȥbug��δ���в��ԣ�

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/lodscc.h"
#include "ISA/Intel_x86/Instructions/common.h"

//AC  lods m8  Load byte at address DS:(E)SI into Al
//AC  lodsb
VM_INSTRUCTION_ERR_CODE lodscc_ac(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uSegment = 0;
    UINT uSegmentOffset = 0;
    UINT uCount = 0;
    INT  iDecrementFlag = 0;

    assert(pInstruction);

    //The DS segment may be overridden
    switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
        case OPCODE_FLAG_PREFIX_ES:
            uSegment = ACCESS_GEN_ES(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_FS:
            uSegment = ACCESS_GEN_FS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_GS:
            uSegment = ACCESS_GEN_GS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_DS:
        default :
            uSegment = ACCESS_GEN_DS(*pX86);
            break;
    }

//DS : (E)SI �γɵ�ַ
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        uSegmentOffset = ACCESS_GEN_SI(*pX86); 
        uCount= ACCESS_GEN_CX(*pX86); 
    }
    else{
        uSegmentOffset = ACCESS_GEN_ESI(*pX86);
        //��ADDRESS_SIZE_16BIT��64-bit�¼�rex.wǰ׺�������֮�⣬��ʹ��ECX
        uCount= ACCESS_GEN_ECX(*pX86); 
    }
    if (!(OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))){
        uCount = 1;
    }

    iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(1):(-1);

    while(0 != uCount){
        ACCESS_GEN_AL(*pX86) = GetMemoryValue(pX86, pMemory, uSegment + uSegmentOffset, OT_w, pInstruction->dwFlags);
        uSegmentOffset += iDecrementFlag;
        uCount --;
    }


   //���仯ֵ��д���Ĵ���
    //DS : (E)SI �γɵ�ַ
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        ACCESS_GEN_SI(*pX86) = uSegmentOffset ; 
        if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))
            ACCESS_GEN_CX(*pX86) = uCount;
    }
    else{
        ACCESS_GEN_ESI(*pX86) = uSegmentOffset;
        //��ADDRESS_SIZE_16BIT��64-bit�¼�rex.wǰ׺�������֮�⣬��ʹ��ECX
        if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))
            ACCESS_GEN_ECX(*pX86) = uCount; 
        
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//AD  lods m16  Load byte at address DS:(E)SI into AX
//AD  lodsw
//AD  lods m32  Load byte at address DS:(E)SI into EAX
//AD  lodsd
VM_INSTRUCTION_ERR_CODE lodscc_ad(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uSegment = 0;
    UINT uSegmentOffset = 0;
    UINT uCount = 0;
    INT  iDecrementFlag = 0;
    UINT uOpType = 0;
    assert(pInstruction);

    //The DS segment may be overridden
    switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
        case OPCODE_FLAG_PREFIX_ES:
            uSegment = ACCESS_GEN_ES(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_FS:
            uSegment = ACCESS_GEN_FS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_GS:
            uSegment = ACCESS_GEN_GS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_DS:
        default :
            uSegment = ACCESS_GEN_DS(*pX86);
            break;
    }

    //DS : (E)SI �γɵ�ַ
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        uSegmentOffset = ACCESS_GEN_SI(*pX86); 
        uCount= ACCESS_GEN_CX(*pX86); 
    }
    else{
        uSegmentOffset = ACCESS_GEN_ESI(*pX86);
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
            break;
        case OT_d:
            /*Opcode size 32*/
            iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(4):(-4);
            break;
        default:
            assert(0);//should not be here
            break;
    }
    
    while(0 != uCount){
        ACCESS_GEN_AX(*pX86) = GetMemoryValue(pX86, pMemory, uSegment + uSegmentOffset, uOpType, pInstruction->dwFlags);
        uSegmentOffset += iDecrementFlag;
        uCount --;
    }

    //���仯ֵ��д���Ĵ���
    //DS : (E)SI �γɵ�ַ
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        ACCESS_GEN_SI(*pX86) = uSegmentOffset ; 
        if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))
            ACCESS_GEN_CX(*pX86) = uCount;
    }
    else{
         ACCESS_GEN_ESI(*pX86) = uSegmentOffset;
        //��ADDRESS_SIZE_16BIT��64-bit�¼�rex.wǰ׺�������֮�⣬��ʹ��ECX
        if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))
            ACCESS_GEN_ECX(*pX86) = uCount; 
        
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}