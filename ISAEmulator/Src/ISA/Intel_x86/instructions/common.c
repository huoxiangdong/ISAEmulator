//
//�ļ����ƣ�        src/ISA/Instructions/common.c
//�ļ�������        Intel x86��ָ���������Ҫ�Ĺ�������
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2009��8��4��
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
//2009��8��4�գ���販(yanghongbo@ptwy.cn)������

#include <assert.h>
#include <stdio.h>
#include "VM_Defines.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"
#include "ISA/Intel_x86/Instructions/common.h"

DWORD GetDataType(DWORD dwFlags, Intel_x86_Operand_Size_t OpSize, DWORD dwPrefixes)
{
    DWORD dwOT = 0;
    switch(MASK_OT(dwFlags)){
        case OT_b:
        case OT_w:
        case OT_d:
        case OT_q:
            dwOT = MASK_OT(dwFlags);
            break;
        case OT_c:
            assert(0);
            break;
        case OT_v:
        case OT_p:
            switch(OpSize){
                case OPERAND_SIZE_16BIT:
                    if(!(OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & dwPrefixes))
                        dwOT = OT_w;
                    else
                        dwOT = OT_d;
                    break;
                case OPERAND_SIZE_32BIT:
                    if(!(OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & dwPrefixes))
                        dwOT = OT_d;
                    else
                        dwOT = OT_w;
                    break;
                case OPERAND_SIZE_64BIT:
                    dwOT = OT_q;
                    break;
                default:
                    assert(0);
                    break;
            }
            break;
        case OT_z:
            switch(OpSize){
                case OPERAND_SIZE_16BIT:
                    if(!(OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & dwPrefixes))
                        dwOT = OT_w;
                    else
                        dwOT = OT_d;
                    break;
                case OPERAND_SIZE_32BIT:
                    if(!(OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & dwPrefixes))
                        dwOT = OT_d;
                    else
                        dwOT = OT_w;
                    break;
                case OPERAND_SIZE_64BIT:
                default:
                    assert(0);
                    break;
            }
            break;
    }

    assert(0 != dwOT);
    return dwOT;
}
//�������ƣ�        GetMemoryValue
//����������        �õ�ָ����ַ��ֵ
//����ֵ��          UINT, �ڴ�ֵ
//����������
//������־:         2009��8��4�գ���販(yanghongbo@ptwy.cn)������
UINT    GetMemoryValue(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uEffectiveAddress, DWORD dwFlags, DWORD dwPrefixes)
{
    UINT uValue;
    DWORD dwOT;
    assert(pX86);
    assert(pMemory);
    dwOT = GetDataType(dwFlags, pX86->OpSize, dwPrefixes);
    switch(dwOT){
        case OT_b:
            uValue = VM_MM_ReadOneByte(&pMemory->DataSegment, uEffectiveAddress);
            break;
        case OT_w:
            uValue = VM_MM_ReadOneWord(&pMemory->DataSegment, uEffectiveAddress);
            break;
        case OT_d:
            uValue = VM_MM_ReadOneDWord(&pMemory->DataSegment, uEffectiveAddress);
            break;
        case OT_q:
            assert(0);
            break;
        default:
            assert(0);
            break;
    }
    return uValue;
}

//�������ƣ�        SetMemoryValue
//����������        �趨��ָ����ַ��ֵ
//����ֵ��          VM_ERR_CODE
//����������
//������־:         2009��8��4�գ���販(yanghongbo@ptwy.cn)������
//                  2010��3��29�գ���販(yanghongbo@ptwy.cn)���޸ķ���ֵ����
VM_ERR_CODE SetMemoryValue(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uEffectiveAddress, UINT uValue, DWORD dwFlags, DWORD dwPrefixes)
{
    VM_ERR_CODE vm_err = VM_ERR_FATAL_UNKNOWN;
    DWORD dwOT;
    assert(pX86);
    dwOT = GetDataType(dwFlags, pX86->OpSize, dwPrefixes);
    switch(dwOT){
        case OT_b:
            //assert(uValue <= 0xff);
            //uValue Ϊ��ֵʱ��ͨ��������
            vm_err = VM_MM_WriteOneByte(&pMemory->DataSegment, uEffectiveAddress, uValue & 0xff);
            break;
        case OT_w:
            //assert(uValue <= 0xffff);
            //uValue Ϊ��ֵʱ��ͨ�������ԣ�����û�������з��������޷�����
            vm_err = VM_MM_WriteOneWord(&pMemory->DataSegment, uEffectiveAddress, uValue & 0xffff);
            break;
        case OT_d:
            vm_err = VM_MM_WriteOneDWord(&pMemory->DataSegment, uEffectiveAddress, uValue);
            break;
        case OT_q:
            assert(0);
            break;
        default:
            assert(0);
            break;
    }
    return vm_err;
}

//�������ƣ�        GetDefaultSegmentPrefix
//����������        �õ�Ĭ�ϵĶ�ǰ׺
//����ֵ��          char *
//����������        reg name
//������־:         2010��3��25�գ���販(yanghongbo@ptwy.cn)������
static char * GetDefaultSegmentPrefix(REG_NAME_INDEX_t regname)
{
    switch(regname){
        case REG_NAME_INDEX_EBP:
        case REG_NAME_INDEX_BP:
        case REG_NAME_INDEX_ESP:
        case REG_NAME_INDEX_SP:
            return "ss:";
        default:
            return "ds:";
    }
    
    return "";
}

//�������ƣ�        GetEffectiveAddress
//����������        ����ModR/M�ֽڼ���EA
//����ֵ��          VM_INSTRUCTION_ERR_CODE
//����������        UINT, EAֵ
//������־:         2009��8��4�գ���販(yanghongbo@ptwy.cn)������
//                  2010��3��25�գ���販(yanghongbo@ptwy.cn)���޸ķ���ֵ���ʹ�UINT��VM_INSTRUCTION_ERR_CODE������ִ��״̬
VM_INSTRUCTION_ERR_CODE GetEffectiveAddress(PVM_Intel_x86_ISA_t pX86, PVM_Intel_x86_InstructionData_t pInstruction, UINT * puEA)
{
    BYTE byScale = 1;
    INT iEA = 0;
    UINT uAddr = 0;
    UINT uSegmentOverride = 0;

    assert(ADDRESS_SIZE_32BIT == pX86->AddrSize);
    assert(pX86);
    assert(pInstruction);
    assert(puEA);

    if(3 == GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        return VM_INSTRUCTION_ERR_INVALID_PARAMETER;
    }

    if(4 != GET_RM_FROM_MODRM(pInstruction->byModRM)){
        if(0 == GET_MOD_FROM_MODRM(pInstruction->byModRM) && 5 == GET_RM_FROM_MODRM(pInstruction->byModRM)){
            iEA = pInstruction->iDisplacement;
        }
        else{
            uAddr = ACCESS_GEN_ERX(*pX86, GET_RM_FROM_MODRM(pInstruction->byModRM));
            //Ӧ�����Ե�ַ�Ƿ����
            iEA = (INT)(pInstruction->iDisplacement);
        }

        if(1 == GET_MOD_FROM_MODRM(pInstruction->byModRM)){
            assert(-254 <= pInstruction->iDisplacement && pInstruction->iDisplacement <= 255);
        }
        //Ӧ�����Ե�ַ�Ƿ����
        //iEA += (INT)(pInstruction->iDisplacement);
        //���Ӧ��������ɣ�
    }
    else{//There is a SIB byte
        if(4 != GET_INDEX_FROM_SIB(pInstruction->bySIB)){
            byScale = 1 << (GET_SCALE_FROM_SIB(pInstruction->bySIB));
            iEA = ACCESS_GEN_ERX(*pX86, GET_INDEX_FROM_SIB(pInstruction->bySIB)) * byScale;
        }
        else
            iEA = 0;

        if(5 == GET_BASE_FROM_SIB(pInstruction->bySIB)){
            if(1 == GET_MOD_FROM_MODRM(pInstruction->byModRM)){
                //assert(0 <= pInstruction->iDisplacement && pInstruction->iDisplacement <= 0xff);
                if(NEED_DISPLACEMENT_8BIT != NEED_DISPLACEMENT_MASK(pX86->CurrentInstruction.dwDataBitFlags)){
                    return VM_INSTRUCTION_ERR_INVALID_PARAMETER;
                }
            }
            iEA += pInstruction->iDisplacement;

            if(1 == GET_MOD_FROM_MODRM(pInstruction->byModRM) 
                    || 2 == GET_MOD_FROM_MODRM(pInstruction->byModRM)){
                //assert(EBP == GET_RM_FROM_MODRM(pInstruction->byModRM));
                //return VM_INSTRUCTION_ERR_INVALID_PARAMETER;
                uAddr += ACCESS_GEN_ERX(*pX86, GET_RM_FROM_MODRM(pInstruction->byModRM));
            }
        }
        else{
            iEA += ACCESS_GEN_ERX(*pX86, GET_BASE_FROM_SIB(pInstruction->bySIB));
        }
    }

    uAddr += iEA;
    *puEA = uAddr;
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//�������ƣ�        GetRegValue
//����������        �õ�ָ����ŵļĴ���ֵ������MODR/M�ֽڱ�
//����ֵ��          UINT
//����������
//������־:         2009��8��4�գ���販(yanghongbo@ptwy.cn)������
UINT GetRegisterValue(PVM_Intel_x86_ISA_t pX86, UINT uIndex, REGISTER_TYPE Type, DWORD dwFlags, DWORD dwPrefixes)
{
    DWORD dwOT;
    assert(pX86);

    if(GENERAL_REGISTER == Type){
        assert(uIndex <= 7);

        dwOT = GetDataType(dwFlags, pX86->OpSize, dwPrefixes);

        switch(uIndex){
            case 0:
                switch(dwOT){
                    case OT_b:
                        return ACCESS_GEN_AL(*pX86);
                        break;
                    case OT_w:
                        return ACCESS_GEN_AX(*pX86);
                        break;
                    case OT_d:
                        return ACCESS_GEN_EAX(*pX86);
                        break;
                    default:
                        assert(0);
                        break;
                }

                break;
            case 1:
                switch(dwOT){
                    case OT_b:
                        return ACCESS_GEN_CL(*pX86);
                        break;
                    case OT_w:
                        return ACCESS_GEN_CX(*pX86);
                        break;
                    case OT_d:
                        return ACCESS_GEN_ECX(*pX86);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 2:
                switch(dwOT){
                    case OT_b:
                        return ACCESS_GEN_DL(*pX86);
                        break;
                    case OT_w:
                        return ACCESS_GEN_DX(*pX86);
                        break;
                    case OT_d:
                        return ACCESS_GEN_EDX(*pX86);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 3:
                switch(dwOT){
                    case OT_b:
                        return ACCESS_GEN_BL(*pX86);
                        break;
                    case OT_w:
                        return ACCESS_GEN_BX(*pX86);
                        break;
                    case OT_d:
                        return ACCESS_GEN_EBX(*pX86);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(dwOT){
                    case OT_b:
                        return ACCESS_GEN_AH(*pX86);
                        break;
                    case OT_w:
                        return ACCESS_GEN_SP(*pX86);
                        break;
                    case OT_d:
                        return ACCESS_GEN_ESP(*pX86);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 5:
                switch(dwOT){
                    case OT_b:
                        return ACCESS_GEN_CH(*pX86);
                        break;
                    case OT_w:
                        return ACCESS_GEN_BP(*pX86);
                        break;
                    case OT_d:
                        return ACCESS_GEN_EBP(*pX86);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 6:
                switch(dwOT){
                    case OT_b:
                        return ACCESS_GEN_DH(*pX86);
                        break;
                    case OT_w:
                        return ACCESS_GEN_SI(*pX86);
                        break;
                    case OT_d:
                        return ACCESS_GEN_ESI(*pX86);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 7:
                switch(dwOT){
                    case OT_b:
                        return ACCESS_GEN_BH(*pX86);
                        break;
                    case OT_w:
                        return ACCESS_GEN_DI(*pX86);
                        break;
                    case OT_d:
                        return ACCESS_GEN_EDI(*pX86);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;

        }
    }//if(GENERAL_REGISTER == Type)
    else if(SEGMENT_REGISTER == Type){
        //assert(uIndex <= 5);
        printf("need to modify GetRegisterValue:%s(%d)\n", __FILE__, __LINE__);
        return 0;//ACCESS_GEN_SEG(*pX86, uIndex);
    }
    else{
        VM_NOT_IMPLEMENTED();
    }

    VM_NOT_IMPLEMENTED();//should be here
    return 0;
}

//�������ƣ�        SetRegisterValue
//����������        �趨ָ����ŵļĴ���ֵ������MODR/M�ֽڱ�
//����ֵ��          VM_INSTRUCTION_ERR_CODE
//����������
//������־:         2009��8��4�գ���販(yanghongbo@ptwy.cn)������
//                  2010��3��25�գ���販(yanghongbo@ptwy.cn)���޸ķ���ֵ���ͣ���void��VM_INSTRUCTION_ERR_CODE����������
//                                 �ļ���©��shellcode���ʱ������δ�������ִ�еĳ������⡣����������غ�����Ӧ�ý���
//                                 �����޸ģ�
VM_INSTRUCTION_ERR_CODE SetRegisterValue(PVM_Intel_x86_ISA_t pX86, UINT uIndex, UINT uValue, REGISTER_TYPE Type, DWORD dwFlags, DWORD dwPrefixes)
{
    DWORD dwOT;
    assert(pX86);

    if(GENERAL_REGISTER == Type){
        assert(uIndex <= 7);
        dwOT = GetDataType(dwFlags, pX86->OpSize, dwPrefixes);

        switch(uIndex){
            case 0:
                switch(dwOT){
                    case OT_b:
                        ACCESS_GEN_AL(*pX86) = (BYTE)uValue;
                        break;
                    case OT_w:
                        ACCESS_GEN_AX(*pX86) = (WORD)uValue;
                        break;
                    case OT_d:
                        ACCESS_GEN_EAX(*pX86) = (DWORD)uValue;
                        break;
                    default:
                        return VM_INSTRUCTION_ERR_INVALID_PARAMETER;
                        break;
                }

                break;
            case 1:
                switch(dwOT){
                    case OT_b:
                        ACCESS_GEN_CL(*pX86) = (BYTE)uValue;
                        break;
                    case OT_w:
                        ACCESS_GEN_CX(*pX86) = (WORD)uValue;
                        break;
                    case OT_d:
                        ACCESS_GEN_ECX(*pX86) = (DWORD)uValue;
                        break;
                    default:
                        return VM_INSTRUCTION_ERR_INVALID_PARAMETER;
                        break;
                }
                break;
            case 2:
                switch(dwOT){
                    case OT_b:
                        ACCESS_GEN_DL(*pX86) = (BYTE)uValue;
                        break;
                    case OT_w:
                        ACCESS_GEN_DX(*pX86) = (WORD)uValue;
                        break;
                    case OT_d:
                        ACCESS_GEN_EDX(*pX86) = (DWORD)uValue;
                        break;
                    default:
                        return VM_INSTRUCTION_ERR_INVALID_PARAMETER;
                        break;
                }
                break;
            case 3:
                switch(dwOT){
                    case OT_b:
                        ACCESS_GEN_BL(*pX86) = (BYTE)uValue;
                        break;
                    case OT_w:
                        ACCESS_GEN_BX(*pX86) = (WORD)uValue;
                        break;
                    case OT_d:
                        ACCESS_GEN_EBX(*pX86) = (DWORD)uValue;
                        break;
                    default:
                        return VM_INSTRUCTION_ERR_INVALID_PARAMETER;
                        break;
                }
                break;
            case 4:
                switch(dwOT){
                    case OT_b:
                        ACCESS_GEN_AH(*pX86) = (BYTE)uValue;
                        break;
                    case OT_w:
                        ACCESS_GEN_SP(*pX86) = (WORD)uValue;
                        break;
                    case OT_d:
                        ACCESS_GEN_ESP(*pX86) = (DWORD)uValue;
                        break;
                    default:
                        return VM_INSTRUCTION_ERR_INVALID_PARAMETER;
                        break;
                }
                break;
            case 5:
                switch(dwOT){
                    case OT_b:
                        ACCESS_GEN_CH(*pX86) = (BYTE)uValue;
                        break;
                    case OT_w:
                        ACCESS_GEN_BP(*pX86) = (WORD)uValue;
                        break;
                    case OT_d:
                        ACCESS_GEN_EBP(*pX86) = (DWORD)uValue;
                        break;
                    default:
                        return VM_INSTRUCTION_ERR_INVALID_PARAMETER;
                        break;
                }
                break;
            case 6:
                switch(dwOT){
                    case OT_b:
                        ACCESS_GEN_DH(*pX86) = (BYTE)uValue;
                        break;
                    case OT_w:
                        ACCESS_GEN_SI(*pX86) = (WORD)uValue;
                        break;
                    case OT_d:
                        ACCESS_GEN_ESI(*pX86) = (DWORD)uValue;
                        break;
                    default:
                        return VM_INSTRUCTION_ERR_INVALID_PARAMETER;
                        break;
                }
                break;
            case 7:
                switch(dwOT){
                    case OT_b:
                        ACCESS_GEN_BH(*pX86) = (BYTE)uValue;
                        break;
                    case OT_w:
                        ACCESS_GEN_DI(*pX86) = (WORD)uValue;
                        break;
                    case OT_d:
                        ACCESS_GEN_EDI(*pX86) = (DWORD)uValue;
                        break;
                    default:
                        return VM_INSTRUCTION_ERR_INVALID_PARAMETER;
                        break;
                }
                break;

        }
    }//if(GENERAL_REGISTER == Type){
    else if(SEGMENT_REGISTER == Type){
        if(uIndex <= 5){
            return VM_INSTRUCTION_ERR_INVALID_PARAMETER;
        }

        //assert(uValue <= 0xffff);//����δ֪����ʱ�����ܵ��´���Ĳ���
        if(uValue <= 0xffff){
            ACCESS_GEN_SEG(*pX86, uIndex) = (WORD)uValue;
        }
        else{
            return VM_INSTRUCTION_ERR_INVALID_PARAMETER;
        }
    }
    else{
        return VM_INSTRUCTION_ERR_INVALID_PARAMETER;
    }
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


UINT  GetStackOffset(PVM_MemoryBlock_t pBlock, UINT addr)
{
    assert(pBlock);

    return (pBlock->uStartAddr - addr);
}

//ʵ�ֵ�ַ��ת������
//Intel IA-32 processor are "little endian" machines,
//data : 0x12345678  address:0x1000 0000  
//Addr: 1000 0000  ->  78
//Addr: 1000 0001  ->  56
//Addr: 1000 0002  ->  34
//Addr: 1000 0003  ->  12 
//ESP:ָ��ǰջ����Ԫ�أ�ESP= 0x1000 0000, (ESPָ��ѹ���ַ�����λ)

VM_ERR_CODE PushStack16OneWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, WORD wData)
{
    UINT uOffset;
    UINT uEA;

    assert(pX86);
    assert(pMemory);

     ACCESS_GEN_SP(*pX86) -= 2;
     uEA = ACCESS_GEN_SS(*pX86) + ACCESS_GEN_SP(*pX86);
    
    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //д�뵽�ڴ���ƫ����ΪuOffset�ĵ�ַ��
    //note(2010-Mar-26):ԭ���Ĵ�����������д��ԭ����Ѱַ��ʽ�ǽ��ݼ���Ѱַת��Ϊ������Ѱַ���� 0x6000 0000 - 4 -> 0x6000 0000 + 4
    //VM_MM_WriteOneWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset, wData);  
    //�޸����ڴ����ģ��֮���ڴ�ҳ�����Կռ䣩��ֱ��ʹ��uEA��Ѱַ��
    VM_MM_WriteOneWord(&pMemory->StackSegment, uEA, wData);  

    return VM_ERR_NO_ERROR;
}

VM_ERR_CODE PushStack16OneDWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, DWORD dwData)
{
    UINT uOffset;
    UINT uEA;

    assert(pX86);
    assert(pMemory);

    ACCESS_GEN_SP(*pX86) -= 4;
    uEA = ACCESS_GEN_SS(*pX86) + ACCESS_GEN_SP(*pX86);

    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //д�뵽�ڴ���ƫ����ΪuOffset�ĵ�ַ��
    //��PushStack16OneWord��note
    //VM_MM_WriteOneDWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset, dwData);  
    VM_MM_WriteOneDWord(&pMemory->StackSegment, uEA, dwData);  
    return VM_ERR_NO_ERROR;
}

VM_ERR_CODE PushStack32OneWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, WORD wData)
{
    UINT uOffset;
    UINT uEA;

    assert(pX86);
    assert(pMemory);

    ACCESS_GEN_ESP(*pX86) -= 2;
    uEA = ACCESS_GEN_SS(*pX86) + ACCESS_GEN_ESP(*pX86);

    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //д�뵽�ڴ���ƫ����ΪuOffset�ĵ�ַ��
    //��PushStack16OneWord��note
    //VM_MM_WriteOneWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset, wData);  
    VM_MM_WriteOneWord(&pMemory->StackSegment, uEA, wData);  

    return VM_ERR_NO_ERROR;
}

VM_ERR_CODE PushStack32OneDWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, DWORD dwData)
{
    UINT uOffset;
    UINT uEA;

    assert(pX86);
    assert(pMemory);

    ACCESS_GEN_ESP(*pX86) -= 4;
    uEA = ACCESS_GEN_SS(*pX86) + ACCESS_GEN_ESP(*pX86);

    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //д�뵽�ڴ���ƫ����ΪuOffset�ĵ�ַ��
    //��PushStack16OneWord��note
    //VM_MM_WriteOneDWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset, dwData);  
    VM_MM_WriteOneDWord(&pMemory->StackSegment, uEA, dwData);  

    return VM_ERR_NO_ERROR;
}


UINT PopStack16OneWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory)
{
    UINT uOffset;
    UINT uRet;
    UINT uEA;

    assert(pX86);
    assert(pMemory);
    
    uEA = ACCESS_GEN_SS(*pX86) + ACCESS_GEN_SP(*pX86);

    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //д�뵽�ڴ���ƫ����ΪuOffset�ĵ�ַ��
    //��PushStack16OneWord��note
    //uRet = VM_MM_ReadOneWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset);  
    uRet = VM_MM_ReadOneWord(&pMemory->StackSegment, uEA); 
    ACCESS_GEN_SP(*pX86) += 2;

    return uRet;
}

UINT PopStack16OneDWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory)
{
    UINT uOffset;
    UINT uRet;
    UINT uEA;

    assert(pX86);
    assert(pMemory);

    uEA = ACCESS_GEN_SS(*pX86) + ACCESS_GEN_SP(*pX86);

    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //д�뵽�ڴ���ƫ����ΪuOffset�ĵ�ַ��
    //��PushStack16OneWord��note
    //uRet =  VM_MM_ReadOneDWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset);  
    uRet = VM_MM_ReadOneDWord(&pMemory->StackSegment, uEA); 
    ACCESS_GEN_SP(*pX86) += 4;

    return VM_ERR_NO_ERROR;
}

UINT PopStack32OneWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory)
{
    UINT uOffset;
    UINT uRet;
    UINT uEA;

    assert(pX86);
    assert(pMemory);
    
    uEA = ACCESS_GEN_SS(*pX86) + ACCESS_GEN_ESP(*pX86);

    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //д�뵽�ڴ���ƫ����ΪuOffset�ĵ�ַ��
    //��PushStack16OneWord��note
    //uRet = VM_MM_ReadOneWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset);  
    uRet = VM_MM_ReadOneWord(&pMemory->StackSegment, uEA);
    ACCESS_GEN_ESP(*pX86) += 2;

    return uRet;
}

UINT PopStack32OneDWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory)
{
    UINT uOffset;
    UINT uRet;
    UINT uEA;

    assert(pX86);
    assert(pMemory);

    uEA = ACCESS_GEN_SS(*pX86) + ACCESS_GEN_ESP(*pX86);

    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //д�뵽�ڴ���ƫ����ΪuOffset�ĵ�ַ��
    //��PushStack16OneWord��note
    //uRet = VM_MM_ReadOneDWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset);  
    uRet = VM_MM_ReadOneDWord(&pMemory->StackSegment, uEA);
    ACCESS_GEN_ESP(*pX86) += 4;

    return uRet;
}



//Intel 64 and IA-32 Architectures Software Developer's Manual - Volume 1- Basic Architecture
//Section: 6.2.3 Address-Size Attribute for Stack Accesses  Page: Vol2 . 6-3
//Content: 
//   The default address-size attribute for data segments as stack is controlled by the B flag of
//the segment's descriptor.When this flag is clear, the default address-size attribute is 16; when
//the flag is set the address-size attribute is 32

//Intel 64 and IA-32 Architectures Software Developer's Manual - Volume 3A- System Programming Guide
//Section: 3.4.5 Segment Descriptors     Vol3 3-13
//Content:
//   Bit22,D/B - Default operation size(0=16-bit segment, 1= 32-bit segment)

//�������ƣ�        GetStackAddressType
//����������        ���� Stack Segment �ĵ�ַ���� 
//����ֵ��          Intel_x86_Address_Size_t : OPERAND_SIZE_32BIT -- ��ʾStack Segment ��ַ��32λ,  OPERAND_SIZE_16BIT -- ��ʾStack Segment ��ַ��16λ,
//����������        PVM_Memory_t �� pMemory -- �ڴ��
//������־:         2009��10��20�գ�����(laosheng@ptwy.cn)������
//                  2010��4��8�գ���販(yanghongbo@ptwy.cn), �����޸����ڴ�ģ�ͣ������ջ��صĺ���Ӧ��ֱ�ӱ��ڴ���ʺ����滻
Intel_x86_Address_Size_t GetStackAddressType(PVM_Memory_t pMemory)
{
    if (pMemory->StackSegment.uSegmentDescriptor[1] |= SEGMENT_DESCRIPTOR_MASK_DB){
        return OPERAND_SIZE_32BIT;
    }
    else{
        return OPERAND_SIZE_16BIT;
    }
}

//�������ƣ�        PushStack
//����������        ��ѹջ����
//����ֵ��          void
//����������        
//������־:         2009��10��20�գ�����(laosheng@ptwy.cn)������
void PushStack(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uValue, Intel_x86_Operand_Size_t emuOperandSize)
{
    assert(pX86);
    assert(pMemory);

    switch(GetStackAddressType(pMemory)){
        case ADDRESS_SIZE_16BIT:
            //StackAddrSize = 16
            switch (emuOperandSize){
            case OPERAND_SIZE_16BIT:
                //OperandSize = 16
                PushStack16OneWord(pX86, pMemory, uValue & 0xffff);  
                break;
           
            case OPERAND_SIZE_32BIT:
                //OperandSize = 32
                PushStack16OneDWord(pX86, pMemory, uValue);  
                break;
            }
        break;

        case ADDRESS_SIZE_32BIT:
            //StackAddrSize = 32
            switch (emuOperandSize){
            case OPERAND_SIZE_16BIT:
                //OperandSize =16
                PushStack32OneWord(pX86, pMemory, uValue & 0xffff);     
                break;

            case OPERAND_SIZE_32BIT:
                //OperandSize =32
                PushStack32OneDWord(pX86, pMemory, uValue);  
                break;
            }
        break;
    }
}

//�������ƣ�        PushStack
//����������        �ڳ�ջ����
//����ֵ��          UINT
//����������        
//������־:         2009��10��20�գ�����(laosheng@ptwy.cn)������
UINT PopStack(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, Intel_x86_Operand_Size_t emuOperandSize)
{
    UINT uRetValue;

    assert(pX86);
    assert(pMemory);

    switch(GetStackAddressType(pMemory)){
        case ADDRESS_SIZE_16BIT:
            //StackAddrSize = 16
            switch (emuOperandSize){
                case OPERAND_SIZE_16BIT:
                    //OperandSize = 16
                    uRetValue = PopStack16OneWord(pX86, pMemory);  
                    break;

                case OPERAND_SIZE_32BIT:
                    //OperandSize = 32 
                    uRetValue = PopStack16OneDWord(pX86, pMemory);   
                    break;
            }
            break;

        case ADDRESS_SIZE_32BIT:
            //StackAddrSize = 32
            switch (emuOperandSize){
                case OPERAND_SIZE_16BIT:
                    //OperandSize =16
                    uRetValue = PopStack32OneWord(pX86, pMemory);      
                    break;

                case OPERAND_SIZE_32BIT:
                    //OperandSize =32
                    uRetValue = PopStack32OneDWord(pX86, pMemory);   
                    break;
            }
            break;
    }

    return uRetValue;
}
//�����޸����ڴ�ģ�ͣ������ջ��صĺ���Ӧ��ֱ�ӱ��ڴ���ʺ����滻
UINT GetStackElement16OneWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory ,UINT uStackAddress)
{
    UINT uOffset;
    UINT uRet;


    assert(pX86);
    assert(pMemory);

    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uStackAddress); 

    //�����ڴ���ƫ����ΪuOffset�ĵ�ַ��������
    uRet = VM_MM_ReadOneWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset);  

    return uRet;
}

UINT GetStackElement16OneDWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory,UINT uStackAddress)
{
    UINT uOffset;
    UINT uRet;

    assert(pX86);
    assert(pMemory);


    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uStackAddress); 

    //�����ڴ���ƫ����ΪuOffset�ĵ�ַ��������
    uRet =  VM_MM_ReadOneDWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset); 

    return VM_ERR_NO_ERROR;
}

UINT GetStackElement32OneWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory,UINT uStackAddress)
{
    UINT uOffset;
    UINT uRet;

    assert(pX86);
    assert(pMemory);

    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uStackAddress); 

    //�����ڴ���ƫ����ΪuOffset�ĵ�ַ��������
    uRet = VM_MM_ReadOneWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset);  


    return uRet;
}

UINT GetStackElement32OneDWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory,UINT uStackAddress)
{
    UINT uOffset;
    UINT uRet;

    assert(pX86);
    assert(pMemory);

    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uStackAddress); 

    //�����ڴ���ƫ����ΪuOffset�ĵ�ַ��������
    uRet = VM_MM_ReadOneDWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset);  

    return uRet;
}
//�����޸����ڴ�ģ�ͣ������ջ��صĺ���Ӧ��ֱ�ӱ��ڴ���ʺ����滻
UINT GetStackElement(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uStackAddress ,Intel_x86_Operand_Size_t emuOperandSize)
{
    UINT uRetValue;

    assert(pX86);
    assert(pMemory);

    switch(GetStackAddressType(pMemory)){
        case ADDRESS_SIZE_16BIT:
            //StackAddrSize = 16
            switch (emuOperandSize){
            case OPERAND_SIZE_16BIT:
                //OperandSize = 16
                uRetValue = GetStackElement16OneWord(pX86, pMemory, uStackAddress);  
                break;

            case OPERAND_SIZE_32BIT:
                //OperandSize = 32 
                uRetValue = GetStackElement16OneDWord(pX86, pMemory, uStackAddress);   
                break;
            }
            break;

        case ADDRESS_SIZE_32BIT:
            //StackAddrSize = 32
            switch (emuOperandSize){
            case OPERAND_SIZE_16BIT:
                //OperandSize =16
                uRetValue = GetStackElement32OneWord(pX86, pMemory, uStackAddress);      
                break;

            case OPERAND_SIZE_32BIT:
                //OperandSize =32
                uRetValue = GetStackElement32OneDWord(pX86, pMemory, uStackAddress);   
                break;
            }
            break;
    }

    return uRetValue;
}

void SetStackElementOneByte(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uStackAddress, UINT uValue)
{
    UINT uOffset;

    assert(pX86);
    assert(pMemory);

    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uStackAddress); 

    VM_MM_WriteOneByte(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset, uValue);  
}



void SetStackElementOneWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uStackAddress, UINT uValue)
{
    UINT uOffset;

    assert(pX86);
    assert(pMemory);

    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uStackAddress); 

    VM_MM_WriteOneWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset, uValue);  
}

void SetStackElementOneDWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uStackAddress, UINT uValue)
{
    UINT uOffset;

    assert(pX86);
    assert(pMemory);

    //ѹջ�ĵ�ַ����Զ���ڣ�ջ�εĿ�ʼ��ַ
    uOffset = GetStackOffset(&pMemory->StackSegment, uStackAddress); 

    VM_MM_WriteOneDWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset, uValue);  
}


void SetStackElement(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uStackAddress, UINT uValue, Intel_x86_Operand_Size_t emuOperandSize)
{
    assert(pX86);
    assert(pMemory);

    switch (emuOperandSize){
       case  4:
            SetStackElementOneByte(pX86, pMemory, uStackAddress, uValue);   
            break;
        case OPERAND_SIZE_16BIT:
            //OperandSize = 16
            SetStackElementOneWord(pX86, pMemory, uStackAddress, uValue);  
            break;

        case OPERAND_SIZE_32BIT:
            //OperandSize = 32 
            SetStackElementOneDWord(pX86, pMemory, uStackAddress, uValue);   
            break;
    }
}


