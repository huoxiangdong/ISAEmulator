//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/cmps.c
//�ļ�������        Intel x86��cmpsָ�����
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

//
//������־��
//2009��9��28�գ�����(laosheng@ptwy.cn)���޸�ָ���EFLAGS��Ӱ��
//2010��3��29�գ���販(yanghongbo@ptwy.cn�������¡��޸Ĵ���ʵ�֣���ȥbug��δ���в��ԣ�

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/cmps.h"
#include "ISA/Intel_x86/Instructions/common.h"

//��Intel_x86_ISA.c�ж�ǰ׺��ִ��Ϊ��
//���ã�pInstruction->dwFlags
//Ȼ���ȡ��һ���ֽ�
// ��������ָ��ģ��ڶ����2���ֽ�ʱ����ת������Ӧ�ĺ���
// F3 AB            rep stos    dword ptr es:[edi] 
// F3 A6            repe cmps   byte ptr [esi],byte ptr es:[edi] 
// F3 66 A7         repe cmps   word ptr [esi],word ptr es:[edi] 

//A6    cmps m8, m8
VM_INSTRUCTION_ERR_CODE cmps_a6(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0 = 0;
    UINT uOp1 = 0;
    UINT uResult = 0;

    UINT uSegment0 = 0;
    UINT uSegmentOffset0 = 0;
    UINT uSegment1 = 0;
    UINT uSegmentOffset1 = 0;

    UINT uCount = 0;
    INT  iDecrementFlag = 0;

    assert(pInstruction);

    //DS segment may be overridden with an segment override prefix, 
    switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
        case OPCODE_FLAG_PREFIX_ES:
            uSegment0 = ACCESS_GEN_ES(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_FS:
            uSegment0 = ACCESS_GEN_FS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_GS:
            uSegment0 = ACCESS_GEN_GS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_DS:
        default :
            uSegment0 = ACCESS_GEN_DS(*pX86);
            break;
    }

    uSegment1 = ACCESS_GEN_ES(*pX86);


    //the address-size attribute determinate
    //DS:SI,DS:ESI,DS:RSI  
    //ES:DI,ES:EDI,ES:RDI
    //�γɳ�ʼ��ַ
    //DS:(E)SI , ES:(E)DI
    if(ADDRESS_SIZE_16BIT == pX86->AddrSize){
            uSegmentOffset0 = ACCESS_GEN_SI(*pX86);
            uSegmentOffset1 = ACCESS_GEN_DI(*pX86);
            uCount= ACCESS_GEN_CX(*pX86);
    }
    else {
            uSegmentOffset0 = ACCESS_GEN_ESI(*pX86);
            uSegmentOffset1 = ACCESS_GEN_EDI(*pX86);
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

    //REP prefix        Termination Condition 1     Termination Condition 2
    //REPE/REPZ         RCX or ECX = 0              ZF = 0
    //REPNE/REPNZ       RCX or ECX = 0              ZF = 1
    while(0 != uCount){
        uOp0 = GetMemoryValue(pX86, pMemory, uSegment0 + uSegmentOffset0, OT_b, pInstruction->dwFlags);
        uOp1 = GetMemoryValue(pX86, pMemory, uSegment1 + uSegmentOffset1, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);                      //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                //AF
        //EVAL_EFLAGS_PF();                                        //PF
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);   //CF

        uSegmentOffset0 += iDecrementFlag;
        uSegmentOffset1 += iDecrementFlag;
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
    
    if(ADDRESS_SIZE_16BIT == pX86->AddrSize){
        ACCESS_GEN_SI(*pX86) = uSegmentOffset0;
        ACCESS_GEN_DI(*pX86) = uSegmentOffset1;
        switch(OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
            case OPCODE_FLAG_PREFIX_REPE:
            case OPCODE_FLAG_PREFIX_REPNE:
                ACCESS_GEN_CX(*pX86) = uCount;
                break;
            default:
                break;
        }
    }
    else {
        ACCESS_GEN_ESI(*pX86) = uSegmentOffset0;
        ACCESS_GEN_EDI(*pX86) = uSegmentOffset1;
        switch(OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
            case OPCODE_FLAG_PREFIX_REPE:
            case OPCODE_FLAG_PREFIX_REPNE:
                ACCESS_GEN_ECX(*pX86) = uCount;
                break;
            default:
                break;
        }

    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//A7    cmps m16, m16
//A7    cmps m32, m32
//A7    cmpsw
//A7    cmpsd
//66 ǰ׺�ж���word , or double word
VM_INSTRUCTION_ERR_CODE cmps_a7(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0 = 0;
    UINT uOp1 = 0;
    UINT uResult = 0;
    UINT uOpType = 0;
    UINT uOpBits = 0;

    UINT uSegment0 = 0;
    UINT uSegmentOffset0 = 0;
    UINT uSegment1 = 0;
    UINT uSegmentOffset1 = 0;

    UINT uCount = 0;
    INT  iDecrementFlag = 0;
    
    assert(pInstruction);

    //DS segment may be overridden with an segment override prefix, 
    switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
        case OPCODE_FLAG_PREFIX_ES:
            uSegment0 = ACCESS_GEN_ES(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_FS:
            uSegment0 = ACCESS_GEN_FS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_GS:
            uSegment0 = ACCESS_GEN_GS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_DS:
        default :
            uSegment0 = ACCESS_GEN_DS(*pX86);
            break;
    }

    uSegment1 = ACCESS_GEN_ES(*pX86);


    //the address-size attribute determinate
    //DS:SI,DS:ESI,DS:RSI  
    //ES:DI,ES:EDI,ES:RDI
    //�γɳ�ʼ��ַ
    //DS:(E)SI , ES:(E)DI
    if(ADDRESS_SIZE_16BIT == pX86->AddrSize){
            uSegmentOffset0 = ACCESS_GEN_SI(*pX86);
            uSegmentOffset1 = ACCESS_GEN_DI(*pX86);
            uCount= ACCESS_GEN_CX(*pX86);
    }
    else {
            uSegmentOffset0 = ACCESS_GEN_ESI(*pX86);
            uSegmentOffset1 = ACCESS_GEN_EDI(*pX86);
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

    switch (uOpType = GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOpBits = _16_BITS;
            iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(2):(-2);
            break;
        case OT_d:
            uOpBits = _32_BITS;
            iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(4):(-4);
            break;
        default:
            assert(0);//should not be here
            break;
    }

    //REP prefix        Termination Condition 1     Termination Condition 2
    //REPE/REPZ         RCX or ECX = 0              ZF = 0
    //REPNE/REPNZ       RCX or ECX = 0              ZF = 1
    while(0 != uCount){
        uOp0 = GetMemoryValue(pX86, pMemory, uSegment0 + uSegmentOffset0, uOpType, pInstruction->dwFlags);
        uOp1 = GetMemoryValue(pX86, pMemory, uSegment1 + uSegmentOffset1, uOpType, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, uOpBits);   //OF
        EVAL_EFLAGS_SF(*pX86, uResult, uOpBits);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (_16_BITS == uOpBits)?(INT16)uResult:uResult);                      //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                //AF
        //EVAL_EFLAGS_PF();                                        //PF
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, uOpBits);   //CF

        uSegmentOffset0 += iDecrementFlag;
        uSegmentOffset1 += iDecrementFlag;
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
    
    if(ADDRESS_SIZE_16BIT == pX86->AddrSize){
        ACCESS_GEN_SI(*pX86) = uSegmentOffset0;
        ACCESS_GEN_DI(*pX86) = uSegmentOffset1;
        switch(OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
            case OPCODE_FLAG_PREFIX_REPE:
            case OPCODE_FLAG_PREFIX_REPNE:
                ACCESS_GEN_CX(*pX86) = uCount;
                break;
            default:
                break;
        }
    }
    else {
        ACCESS_GEN_ESI(*pX86) = uSegmentOffset0;
        ACCESS_GEN_EDI(*pX86) = uSegmentOffset1;
        switch(OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
            case OPCODE_FLAG_PREFIX_REPE:
            case OPCODE_FLAG_PREFIX_REPNE:
                ACCESS_GEN_ECX(*pX86) = uCount;
                break;
            default:
                break;
        }

    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
