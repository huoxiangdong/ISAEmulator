//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/movs.c
//�ļ�������        Intel x86��movsָ�����
//�����ˣ�          ����(laosheng@ptwy.cn)
//�������ڣ�        2009��8��19��
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
//2009��8��19�գ�����(laosheng@ptwy.cn)������

//
//������־��
//2009��10��9�գ�����(laosheng@ptwy.cn)���޸�:ָ����ʹ��EFLAGS��ֵ

//
//������־��
//2009��10��9�գ�����(laosheng@ptwy.cn),����ָ���ʵ��
//2010��3��29�գ���販(yanghongbo@ptwy.cn�������¡��޸Ĵ���ʵ�֣���ȥbug��δ���в��ԣ�

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"
#include "VM_Log.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/movs.h"
#include "ISA/Intel_x86/Instructions/common.h"


//A4 movs m8,m8   move byte from address DS:(E)SI to ES(E)DI
//A4 movsb
VM_INSTRUCTION_ERR_CODE movs_a4(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0 = 0;

    UINT uSegmentSrc = 0;
    UINT uSegmentOffsetSrc = 0;
    UINT uSegmentDst = 0;
    UINT uSegmentOffsetDst = 0;

    UINT uCount = 0;
    INT  iDecrementFlag = 0;

    VM_ERR_CODE vm_err = VM_ERR_FATAL_UNKNOWN;

    assert(pInstruction);

    switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
        case OPCODE_FLAG_PREFIX_ES:
            uSegmentSrc = ACCESS_GEN_ES(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_FS:
            uSegmentSrc = ACCESS_GEN_FS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_GS:
            uSegmentSrc = ACCESS_GEN_GS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_DS:
        default :
            uSegmentSrc = ACCESS_GEN_DS(*pX86);
            break;
    }

    uSegmentDst = ACCESS_GEN_ES(*pX86);
    
    //DS:(E)SI , ES:(E)DI
    if(ADDRESS_SIZE_16BIT == pX86->AddrSize){
            uSegmentOffsetSrc = ACCESS_GEN_SI(*pX86);
            uSegmentOffsetDst = ACCESS_GEN_DI(*pX86);
            uCount= ACCESS_GEN_CX(*pX86);
    }
    else {
            uSegmentOffsetSrc = ACCESS_GEN_ESI(*pX86);
            uSegmentOffsetDst = ACCESS_GEN_EDI(*pX86);
            uCount= ACCESS_GEN_ECX(*pX86);
    }

    if (!(OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))){
        uCount = 1;
    }

    iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(1):(-1);

    while(0 != uCount){
            uOp0 = GetMemoryValue(pX86, pMemory, uSegmentSrc + uSegmentOffsetSrc, OT_b, pInstruction->dwFlags);
            vm_err = SetMemoryValue(pX86, pMemory, uSegmentDst + uSegmentOffsetDst, uOp0, OT_b, pInstruction->dwFlags);
            if(VM_ERR_NO_ERROR != vm_err){
                VM_ErrLog(vm_err);
                return VM_INSTRUCTION_ERR_ERROR_RETURN_BY_VM;
            }
            uSegmentOffsetSrc += iDecrementFlag;
            uSegmentOffsetDst += iDecrementFlag;
            uCount --;
        }; 

    if(ADDRESS_SIZE_16BIT == pX86->AddrSize){
            ACCESS_GEN_SI(*pX86) = uSegmentOffsetSrc;
            ACCESS_GEN_DI(*pX86) = uSegmentOffsetDst;
            if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
                ACCESS_GEN_CX(*pX86) = uCount;
            }
    }
    else {
            ACCESS_GEN_ESI(*pX86) = uSegmentOffsetSrc;
            ACCESS_GEN_EDI(*pX86) = uSegmentOffsetDst;
            if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
                ACCESS_GEN_ECX(*pX86) = uCount;
            }
    }
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//A5 movs m16,m16
//A5 movsw
//A5 movs m32,m32
//A5 movsd
VM_INSTRUCTION_ERR_CODE movs_a5(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0 = 0;

    UINT uSegmentSrc = 0;
    UINT uSegmentOffsetSrc = 0;
    UINT uSegmentDst = 0;
    UINT uSegmentOffsetDst = 0;

    UINT uCount = 0;
    INT  iDecrementFlag = 0;

    UINT uOpType = 0;

    VM_ERR_CODE vm_err = VM_ERR_FATAL_UNKNOWN;
    assert(pInstruction);

    switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
        case OPCODE_FLAG_PREFIX_ES:
            uSegmentSrc = ACCESS_GEN_ES(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_FS:
            uSegmentSrc = ACCESS_GEN_FS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_GS:
            uSegmentSrc = ACCESS_GEN_GS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_DS:
        default :
            uSegmentSrc = ACCESS_GEN_DS(*pX86);
            break;
    }
    uSegmentDst = ACCESS_GEN_ES(*pX86);
    
    //DS:(E)SI , ES:(E)DI
    if(ADDRESS_SIZE_16BIT == pX86->AddrSize){
            uSegmentOffsetSrc = ACCESS_GEN_SI(*pX86);
            uSegmentOffsetDst = ACCESS_GEN_DI(*pX86);
            uCount= ACCESS_GEN_CX(*pX86);
    }
    else {
            uSegmentOffsetSrc = ACCESS_GEN_ESI(*pX86);
            uSegmentOffsetDst = ACCESS_GEN_EDI(*pX86);
            uCount= ACCESS_GEN_ECX(*pX86);
    }

    if (!(OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))){
        uCount = 1;
    }

    
    switch (uOpType = GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(2):(-2);
            break;
        case OT_d:
            iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(4):(-4);
            break;
        default:
            assert(0);//should not be here
            break;
    }
    while(0 != uCount){
        uOp0 = GetMemoryValue(pX86, pMemory, uSegmentSrc + uSegmentOffsetSrc, uOpType, pInstruction->dwFlags);
        vm_err = SetMemoryValue(pX86, pMemory, uSegmentSrc + uSegmentOffsetSrc, uOp0, uOpType, pInstruction->dwFlags);
        if(VM_ERR_NO_ERROR != vm_err){
            VM_ErrLog(vm_err);
            return VM_INSTRUCTION_ERR_ERROR_RETURN_BY_VM;
        }
        uSegmentOffsetSrc += iDecrementFlag;
        uSegmentOffsetDst += iDecrementFlag;
        uCount --;
    }

    if(ADDRESS_SIZE_16BIT == pX86->AddrSize){
            ACCESS_GEN_SI(*pX86) = uSegmentOffsetSrc;
            ACCESS_GEN_DI(*pX86) = uSegmentOffsetDst;
            if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
                ACCESS_GEN_CX(*pX86) = uCount;
            }
    }
    else {
            ACCESS_GEN_ESI(*pX86) = uSegmentOffsetSrc;
            ACCESS_GEN_EDI(*pX86) = uSegmentOffsetDst;
            if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
                ACCESS_GEN_ECX(*pX86) = uCount;
            }
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
