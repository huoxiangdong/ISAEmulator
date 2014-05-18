//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/scas.c
//�ļ�������        Intel x86��scasָ�����
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

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/scas.h"
#include "ISA/Intel_x86/Instructions/common.h"


//AE    scas   m8   Copmare AL with byte at ES:(E)DI or RDI then set status flags
//AE    scasb
VM_INSTRUCTION_ERR_CODE scas_ae(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    
    UINT uSegment = 0;
    UINT uSegmentOffset = 0;
    UINT uCount = 0;
    INT  iDecrementFlag = 0;

    UINT uAL = 0;
    UINT uOp = 0;
    UINT uResult = 0;

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

    switch(OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
        case OPCODE_FLAG_PREFIX_REPE:
        case OPCODE_FLAG_PREFIX_REPNE:
            break;
        default:
            uCount = 1;
            break;
    }

    iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(1):(-1);

    uAL = ACCESS_GEN_AL(*pX86);

//REP prefix        Termination Condition 1     Termination Condition 2
    //REPE/REPZ         RCX or ECX = 0              ZF = 0
    //REPNE/REPNZ       RCX or ECX = 0              ZF = 1
    while(0 != uCount){
        uOp = GetMemoryValue(pX86, pMemory, uSegment + uSegmentOffset, OT_b, pInstruction->dwFlags);
        uResult = uAL - uOp;
        //Set Flags
        EVAL_EFLAGS_OF_SUB(*pX86, uAL, uOp, uResult, _8_BITS);
        EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
        EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
        EVAL_EFLAGS_AF(*pX86, uAL, uOp, uResult);
        //SET_EFLAGS_PF(*pX86, 0 == uSum);
        EVAL_EFLAGS_CF_SUB(*pX86, uAL, uOp, uResult, _8_BITS);  

        uSegmentOffset += iDecrementFlag;
        uCount --;
        if(OPCODE_FLAG_PREFIX_REPE == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
            if(0 == GET_EFLAGS_ZF_BIT(*pX86))
                break;//while
        }
        else if(OPCODE_FLAG_PREFIX_REPNE == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
            if(0 != GET_EFLAGS_ZF_BIT(*pX86))
                break;//while
        }
        else {
            assert( 0 == uCount);//���������Ӧ��ִֻ��һ��ָ��
            break;
        }
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

//AE    scas   m16   Copmare AX with byte at ES:(E)DI or RDI then set status flags
//AE    scasw 
//AE    scas   m32   Copmare EAX with byte at ES:(E)DI or RDI then set status flags
//AE    scasd 
VM_INSTRUCTION_ERR_CODE scas_af(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uSegment = 0;
    UINT uSegmentOffset = 0;
    UINT uCount = 0;
    INT  iDecrementFlag = 0;
    UINT uOpType = 0;
    UINT uEAX_AX = 0;
    UINT uOp = 0;
    UINT uResult = 0;
    UINT uOpBits = 0;

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
    switch(OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
        case OPCODE_FLAG_PREFIX_REPE:
        case OPCODE_FLAG_PREFIX_REPNE:
            break;
        default:
            uCount = 1;
            break;
    }

    //F3 REPE ǰ׺
    switch (uOpType = GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
            case OT_w:
                /*Opcode size 16*/
                /*DF == 1, decremented*/
                //note: 2010��3��26�գ���販�� ��ԭ�ȵ�do...while()�޸�Ϊwhile()���Ȳ���uCount != 0��������ܽ�����ѭ��
                //                              ��ԭ�ȵ�if (1 == GET_EFLAGS_DF_BIT(*pX86))���룬����iDecrementFlag
                iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(2):(-2);
                uEAX_AX = ACCESS_GEN_AX(*pX86);
                uOpBits = _16_BITS;
                break;

            case OT_d:
                /*Opcode size 32*/
                iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(4):(-4);
                uEAX_AX = ACCESS_GEN_EAX(*pX86);
                uOpBits = _32_BITS;
                break;
            default:
                assert(0);//should not be here
                break;
    }

    while(0 != uCount){
        uOp = GetMemoryValue(pX86, pMemory, uSegment + uSegmentOffset, uOpType, pInstruction->dwFlags);
        uResult = uEAX_AX - uOp;

        EVAL_EFLAGS_OF_SUB(*pX86, uEAX_AX, uOp, uResult, uOpBits);   //OF
        EVAL_EFLAGS_SF(*pX86, uResult, uOpBits);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (_16_BITS == uOpBits)?(INT16)uResult:uResult);                      //ZF
        EVAL_EFLAGS_AF(*pX86, uEAX_AX, uOp, uResult);                //AF
        //EVAL_EFLAGS_PF();                                        //PF
        EVAL_EFLAGS_CF_SUB(*pX86, uEAX_AX, uOp, uResult, uOpBits);   //CF

        uSegmentOffset += iDecrementFlag;

        uCount --;
        if(OPCODE_FLAG_PREFIX_REPE == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
            if(0 == GET_EFLAGS_ZF_BIT(*pX86))
                break;//while
        }
        else if(OPCODE_FLAG_PREFIX_REPNE == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
            if(0 != GET_EFLAGS_ZF_BIT(*pX86))
                break;//while
        }
        else {
            assert( 0 == uCount);//���������Ӧ��ִֻ��һ��ָ��
            break;
        }
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