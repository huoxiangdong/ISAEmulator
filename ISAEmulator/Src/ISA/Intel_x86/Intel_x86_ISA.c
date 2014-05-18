//
//�ļ����ƣ�        src/ISA/Intel_x86_ISA.c
//�ļ�������        ����Intel x86��صĺ���
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2009��6��17��
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
//2009��6��5�գ���販(yanghongbo@ptwy.cn)������
//2009��8��3�գ���販(yanghongbo@ptwy.cn)���������������ϲ�����

#define _CRT_SECURE_NO_DEPRECATE 1

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"



#define CHECK_INTEL_X86_STRUCTURE_VALID(p_cpu_structure, p_mem)                                 \
                                            assert(p_cpu_structure);  \
                                            assert(sizeof(VM_Intel_x86_ISA_t) == p_cpu_structure->PointerStructureSize);\
                                            assert(p_mem);\
                                                            \
                                            if(NULL == p_cpu_structure || NULL == p_mem)\
                                                return VM_ERR_FATAL_NULL_POINTER;\
                                            if(sizeof(VM_Intel_x86_ISA_t) != p_cpu_structure->PointerStructureSize)\
                                                return VM_ERR_FATAL_INVALID_POINTER;

#ifdef  __cplusplus
extern "C" {
#endif



//�ֲ���������������
static void GetEffectiveAddressString(char * szString, size_t iLength, DWORD dwArgFlags, PVM_Intel_x86_InstructionData_t pInstruction, Intel_x86_Operand_Size_t OpSize, Intel_x86_Address_Size_t AddrSize);
static size_t GetOperandString(char * szString, size_t iLength, DWORD dwArgFlags, PVM_Intel_x86_InstructionData_t pInstruction, Intel_x86_Operand_Size_t OpSize, Intel_x86_Address_Size_t AddrSize, DWORD * pdwFlags, DWORD addr);
static DWORD CheckModRM(BYTE byModRM, DWORD * puFlags, Intel_x86_Address_Size_t AddrSize);
static DWORD CheckSIB(BYTE byModRM, BYTE bySIB, DWORD * pdwFlags);
static DWORD CheckArg(DWORD uArgFlag, DWORD * puFlags, Intel_x86_Operand_Size_t OpSize);
static void PrintData(void * data, size_t szBytes);
//static size_t FetchOneInstruction(PVM_Intel_x86_InstructionData_t pInstruction, PVM_MemoryBlock_t pBlock, UINT uInstructionBaseAddr, size_t BufferSize, Intel_x86_Operand_Size_t OpSize, Intel_x86_Address_Size_t AddrSize);
static VM_INSTRUCTION_ERR_CODE FetchOneInstruction(PVM_Intel_x86_InstructionData_t pInstruction, PVM_MemoryBlock_t pBlock, UINT uInstructionBaseAddr, size_t BufferSize, Intel_x86_Operand_Size_t OpSize, Intel_x86_Address_Size_t AddrSize, size_t * psiInstructionSize);
static REG_NAME_INDEX_t GetRegIndexName(BYTE byIndex, DWORD dwArgFlags, Intel_x86_Operand_Size_t OpSize, Intel_x86_Address_Size_t AddrSize);


static const REG_NAME_INDEX_t IndexedName[7][8] = {
    {REG_NAME_INDEX_RAX, REG_NAME_INDEX_RCX, REG_NAME_INDEX_RDX, REG_NAME_INDEX_RBX, REG_NAME_INDEX_RSP, REG_NAME_INDEX_RBP, REG_NAME_INDEX_RSI, REG_NAME_INDEX_RDI}, 
    {REG_NAME_INDEX_EAX, REG_NAME_INDEX_ECX, REG_NAME_INDEX_EDX, REG_NAME_INDEX_EBX, REG_NAME_INDEX_ESP, REG_NAME_INDEX_EBP, REG_NAME_INDEX_ESI, REG_NAME_INDEX_EDI}, 
    {REG_NAME_INDEX_AX, REG_NAME_INDEX_CX, REG_NAME_INDEX_DX, REG_NAME_INDEX_BX, REG_NAME_INDEX_SP, REG_NAME_INDEX_BP, REG_NAME_INDEX_SI, REG_NAME_INDEX_DI}, 
    {REG_NAME_INDEX_AL, REG_NAME_INDEX_CL, REG_NAME_INDEX_DL, REG_NAME_INDEX_BL, REG_NAME_INDEX_AH, REG_NAME_INDEX_CH, REG_NAME_INDEX_DH, REG_NAME_INDEX_BH},
    {REG_NAME_INDEX_ES, REG_NAME_INDEX_SS, REG_NAME_INDEX_CS, REG_NAME_INDEX_DS, REG_NAME_INDEX_FS, REG_NAME_INDEX_GS, REG_NAME_INDEX_NO, REG_NAME_INDEX_NO},
    {REG_NAME_INDEX_MM0, REG_NAME_INDEX_MM1, REG_NAME_INDEX_MM2, REG_NAME_INDEX_MM3, REG_NAME_INDEX_MM4, REG_NAME_INDEX_MM5, REG_NAME_INDEX_MM6, REG_NAME_INDEX_MM7},
    {REG_NAME_INDEX_XMM0, REG_NAME_INDEX_XMM1, REG_NAME_INDEX_XMM2, REG_NAME_INDEX_XMM3, REG_NAME_INDEX_XMM4, REG_NAME_INDEX_XMM5, REG_NAME_INDEX_XMM6, REG_NAME_INDEX_XMM7},
};

//�������ƣ�        VM_Intel_x86_InitializeCpuStructure
//����������        ��ʼ��Cpu�ṹ�ṹ��
//����ֵ��          VM_ERR_CODE
//����������
//������־:         2009��8��4�գ���販(yanghongbo@ptwy.cn)������
VM_ERR_CODE VM_Intel_x86_InitializeCpuStructure(PVM_CPUStructure_t pCpu)
{
    PVM_Intel_x86_ISA_t pX86 = NULL;
    assert(pCpu);
    pCpu->PointerStructureSize = sizeof(VM_Intel_x86_ISA_t);
    pCpu->ISAPointer = malloc(pCpu->PointerStructureSize);
    if(NULL == pCpu->ISAPointer){
        return VM_ERR_FATAL_INSUFFICIENT_MEMORY;
    }
    memset(pCpu->ISAPointer, 0, pCpu->PointerStructureSize);

    pX86 = (PVM_Intel_x86_ISA_t) pCpu->ISAPointer;
    
    //ҪEIP��ʼ����������
    //���ƻ���DS,SS�ȶε�����
    ACCESS_GEN_EIP(*pX86) = 0x40000000;

    pX86->OpSize = OPERAND_SIZE_32BIT;
    pX86->AddrSize = ADDRESS_SIZE_32BIT;

    return VM_ERR_NO_ERROR;
}

//�������ƣ�        VM_Intel_x86_UninitializeCpuStructure
//����������        �ͷ�Cpu�ṹ�ṹ��
//����ֵ��          VM_ERR_CODE
//����������
//������־:         2009��8��4�գ���販(yanghongbo@ptwy.cn)������
VM_ERR_CODE VM_Intel_x86_UninitializeCpuStructure(PVM_CPUStructure_t pCpu)
{
    assert(pCpu);
    if(pCpu->ISAPointer){
        free(pCpu->ISAPointer);
        pCpu->ISAPointer = NULL;
        pCpu->PointerStructureSize = 0;

    }

    return VM_ERR_NO_ERROR;


}

//�������ƣ�        VM_Intel_x86_InitializeControlUnit
//����������        ��ʼ�����Ƶ�Ԫ�ĺ���ָ��
//����ֵ��          VM_ERR_CODE
//����������
//������־:         2009��8��3�գ���販(yanghongbo@ptwy.cn)������
VM_ERR_CODE VM_Intel_x86_InitializeControlUnit(struct _VM_ControlUnit_t * pControlUnit)
{
    assert(NULL != pControlUnit);
    if(NULL == pControlUnit){
        return VM_ERR_FATAL_NULL_POINTER;
    }

    pControlUnit->pfnOutputCpuState = VM_Intel_x86_OutputCpuState;
    pControlUnit->pfnFetchOneInstruction = VM_Intel_x86_FetchAndDecodeOneInstruction;
    pControlUnit->pfnExecuteOneInstruction = VM_Intel_x86_ExecuteOneInstruction;

    return VM_ERR_NO_ERROR;
}

//�������ƣ�       VM_Intel_x86_OutputCpuState
//����������       ���CPU״ֵ̬
//����ֵ��         void
//����������
//������־:         2009��8��4�գ���販(yanghongbo@ptwy.cn)������
void VM_Intel_x86_OutputCpuState(struct _VM_CPUStructure_t * pCpuStructure)
{
    PVM_Intel_x86_ISA_t pX86 = NULL;
    assert(pCpuStructure);
    assert(pCpuStructure->ISAPointer);

    pX86 = (PVM_Intel_x86_ISA_t) pCpuStructure->ISAPointer;
    printf("EAX:%08X\tEBX:%08X\tECX:%08X\tEDX:%08X\n", 
        ACCESS_GEN_EAX(*pX86), 
        ACCESS_GEN_EBX(*pX86), 
        ACCESS_GEN_ECX(*pX86), 
        ACCESS_GEN_EDX(*pX86));
    printf("ESI:%08X\tEDI:%08X\tEBP:%08X\tESP:%08X\n", 
        ACCESS_GEN_ESI(*pX86),
        ACCESS_GEN_EDI(*pX86),
        ACCESS_GEN_EBP(*pX86),
        ACCESS_GEN_ESP(*pX86));

    printf("EIP:%08X\t",ACCESS_GEN_EIP(*pX86)); 
    
    //Like Visual Studio Display :
    //OV =  PL =  ZR =  AC =  PE  CY = 
    printf("OV = %d PL = %d ZR = %d AC = %d PE = %d CY = %d \n", 
                                     GET_EFLAGS_OF_BIT(*pX86),     //Overflow
                                     GET_EFLAGS_SF_BIT(*pX86),     //Sign
                                     GET_EFLAGS_ZF_BIT(*pX86),     //Zero
                                     GET_EFLAGS_AF_BIT(*pX86),     //Auxiliary carry
                                     GET_EFLAGS_PF_BIT(*pX86),     //Parity
                                     GET_EFLAGS_CF_BIT(*pX86));    //Carry
}

//�������ƣ�       VM_Intel_x86_FetchAndDecodeOneInstruction
//����������       ����pX86�е�CS:EIP����pVM_MM��ȡ������һ��ָ�������instruction�ṹ��
//����ֵ��         VM_ERR_CODE
//����������
//������־:         2009��6��17�գ���販(yanghongbo@ptwy.cn)������
//                   2009��8��3�գ���販(yanghongbo@ptwy.cn)����д���룬��x86���������ش�����ӽ���
VM_INSTRUCTION_ERR_CODE VM_Intel_x86_FetchAndDecodeOneInstruction(struct _VM_CPUStructure_t * pCpuStructure, PVM_Memory_t pMemory)
{
    PVM_Intel_x86_ISA_t pX86 = NULL;
    size_t SizeOfCode;
    VM_INSTRUCTION_ERR_CODE ErrCodeInstruction = VM_INSTRUCTION_ERR_FATAL_UNKNOWN;

    CHECK_INTEL_X86_STRUCTURE_VALID(pCpuStructure, pMemory);

    pX86 = (PVM_Intel_x86_ISA_t) pCpuStructure->ISAPointer;

    if(ACCESS_GEN_EIP(*pX86) >= (pMemory->CodeSegment.uStartAddr+ pMemory->CodeSegment.uBlockSize))
        return VM_ERR_NO_MORE_INSTRUCTION;

    //pMemory->CodeSegment.pMemoryBlock + ����=// ACCESS_GEN_EIP(*pX86) - pMemory->CodeSegment.uStartAddr �������ָ�����ڴ���е�ƫ����
    //pMemory->CodeSegment.uBlockSize -     ��=//(ACCESS_GEN_EIP(*pX86) - pMemory->CodeSegment.uStartAddr �� ���ж����ֽڵ�ָ����Զ�ȡ
    //Eip ��ʼֵΪ��0 ~~  Error ��Eipû�г�ʼ��Ϊָ������
    ErrCodeInstruction = FetchOneInstruction(&pX86->CurrentInstruction, &pMemory->CodeSegment, ACCESS_GEN_EIP(*pX86), pMemory->CodeSegment.uBlockSize - (ACCESS_GEN_EIP(*pX86) -  pMemory->CodeSegment.uStartAddr), pX86->OpSize, pX86->AddrSize, &SizeOfCode);

    if(VM_INSTRUCTION_ERR_SUCCEEDED == ErrCodeInstruction){
        if(SizeOfCode > 0){
            //ACCESS_ERX(pX86->nextEIP) = ACCESS_GEN_EIP(*pX86) + SizeOfCode;
            ACCESS_GEN_EIP(*pX86) = ACCESS_GEN_EIP(*pX86) + SizeOfCode;
            return VM_ERR_NO_ERROR;
        }
    }
    return VM_ERR_FATAL_UNKNOWN;
}

//�������ƣ�        VM_Intel_x86_ExecuteOneInstruction
//����������        ����pX86�е�CS:IP����pVM_MM��ȡ������һ��ָ�������instruction�ṹ��
//����ֵ��          VM_ERR_CODE
//����������
//������־:          2009��6��17�գ���販(yanghongbo@ptwy.cn)������
//                    2009��8��3�գ���販(yanghongbo@ptwy.cn)����д����
VM_ERR_CODE VM_Intel_x86_ExecuteOneInstruction(struct _VM_CPUStructure_t * pCpuStructure, PVM_Memory_t pMemory)
{
    PVM_Intel_x86_ISA_t pX86 = NULL;
    VM_INSTRUCTION_ERR_CODE InstErr;

    CHECK_INTEL_X86_STRUCTURE_VALID(pCpuStructure, pMemory);

    pX86 = (PVM_Intel_x86_ISA_t) pCpuStructure->ISAPointer;
    if(NULL != pX86->CurrentInstruction.pfnInstructionExec)
        InstErr = pX86->CurrentInstruction.pfnInstructionExec(pX86, pMemory, &pX86->CurrentInstruction);
    else
        InstErr = VM_INSTRUCTION_ERR_NOT_IMPLEMENTED;

    if(VM_INSTRUCTION_ERR_SUCCEEDED == InstErr){
        return VM_ERR_NO_ERROR;
    }
    else
        return VM_ERR_FATAL_CANNOT_EXECUTE_INSTRUCTION;
}

//�������ƣ�        GetRegIndexName
//����������        ��x86�����������ֲ����
//����ֵ��          REG_NAME_INDEX_t
//����������
//������־:         2009��8��3�գ���販(yanghongbo@ptwy.cn)������
static REG_NAME_INDEX_t GetRegIndexName(BYTE byIndex, DWORD dwArgFlags, Intel_x86_Operand_Size_t OpSize, Intel_x86_Address_Size_t AddrSize)
{
    REG_NAME_INDEX_t regname = REG_NAME_INDEX_NO;
    int reg;
    assert(byIndex >= 0);
    assert(byIndex <= 7);
    switch(MASK_AM(dwArgFlags)){
        case AM_E:
        case AM_G:
            switch(MASK_OT(dwArgFlags)){
                case OT_b:
                    regname = IndexedName[3][byIndex];
                    break;
                case OT_v:
                    regname = IndexedName[OpSize][byIndex];
                    break;
                case OT_p:
                    regname = IndexedName[OpSize][byIndex];
                    break;///��Ҫ���ԣ�����
                case OT_w:
                    regname = IndexedName[2][byIndex];
                    break;
                case OT_z:
                    switch(OpSize){
                        case OPERAND_SIZE_16BIT:
                            regname = IndexedName[2][byIndex];
                            break;
                        case OPERAND_SIZE_32BIT:
                            regname = IndexedName[1][byIndex];
                            break;
                    }
                    break;
                default:
                    reg = MASK_OT(dwArgFlags);
                    assert(0);
                    break;
            }//switch(MASK_OT(dwArgFlags))
            break;
        case AM_S:
            regname = IndexedName[4][byIndex];
            break;
        default:
            if(AM_REG_RAX <= MASK_AM(dwArgFlags) && MASK_AM(dwArgFlags) <= AM_REG_XMM7){
                switch(MASK_OT(dwArgFlags)){
                    case OT_b:
                        regname = IndexedName[3][byIndex];
                        break;
                    case OT_v:
                        regname = IndexedName[OpSize][byIndex];
                        break;
                    case OT_seg:
                        regname = IndexedName[4][byIndex];
                        break;
                }//switch(MASK_OT(dwArgFlags))
            }
            else{
                return regname;//assert(0);8d f8 (LEA Gv, M)��������Чָ��
            }
    }//switch(MASK_AM(dwArgFlags))
    //assert(REG_NAME_INDEX_NO != regname);//����ָ����Ե��¶���
    return regname;

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


//�������ƣ�        GetEffectiveAddressString
//����������        ��x86�����������ֲ����
//����ֵ��          void
//����������
//������־:         2009��8��3�գ���販(yanghongbo@ptwy.cn)������
static void GetEffectiveAddressString(char * szString, size_t iLength, DWORD dwArgFlags, PVM_Intel_x86_InstructionData_t pInstruction, Intel_x86_Operand_Size_t OpSize, Intel_x86_Address_Size_t AddrSize)
{
    REG_NAME_INDEX_t regname;
    size_t len = 0;
    char szOther[50];
    char * pszOperandSize = "";
    char * pszSegment = "";

    BYTE byScale = 1;
    assert(ADDRESS_SIZE_32BIT == AddrSize);
    assert(pInstruction);
    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        switch(GET_RM_FROM_MODRM(pInstruction->byModRM)){
            case 0:
                regname = REG_NAME_INDEX_EAX;
                break;
            case 1:
                regname = REG_NAME_INDEX_ECX;
                break;
            case 2:
                regname = REG_NAME_INDEX_EDX;
                break;
            case 3:
                regname = REG_NAME_INDEX_EBX;
                break;
            case 4:
                regname = REG_NAME_INDEX_SIB;
                break;
            case 5:
                regname = REG_NAME_INDEX_EBP;
                break;
            case 6:
                regname = REG_NAME_INDEX_ESI;
                break;
            case 7:
                regname = REG_NAME_INDEX_EDI;
                break;
        }

        switch(MASK_OT(dwArgFlags)){
            case OT_b:
                pszOperandSize = "byte ptr ";
                break;
            case OT_w:
                pszOperandSize = "word ptr ";
                break;
            case OT_d:
                pszOperandSize = "dword ptr ";
                break;
            case OT_dq:
                pszOperandSize = "dqword ptr ";
                break;
            case OT_v:
                switch(OpSize){
                    case OPERAND_SIZE_16BIT:
                        pszOperandSize = "word ptr ";
                        break;
                    case OPERAND_SIZE_32BIT:
                        pszOperandSize = "dword ptr ";
                        break;
                    case OPERAND_SIZE_64BIT:
                        pszOperandSize = "qword ptr ";
                        break;
                }
                break;
            case OT_z:
                switch(OpSize){
                    case OPERAND_SIZE_16BIT:
                        pszOperandSize = "word ptr ";
                        break;
                    case OPERAND_SIZE_64BIT:
                    case OPERAND_SIZE_32BIT:
                        pszOperandSize = "dword ptr ";
                        break;
                }
                break;
            default:
                break;
        }

        if(0 != *pszOperandSize){//�Ƿ�Ϊ'\0'
            if(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
                switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
                    case OPCODE_FLAG_PREFIX_CS:
                        pszSegment = "cs:";
                        break;
                    case OPCODE_FLAG_PREFIX_SS:
                        pszSegment = "ss:";
                        break;
                    case OPCODE_FLAG_PREFIX_ES:
                        pszSegment = "es:";
                        break;
                    case OPCODE_FLAG_PREFIX_FS:
                        pszSegment = "fs:";
                        break;
                    case OPCODE_FLAG_PREFIX_GS:
                        pszSegment = "gs:";
                        break;
                    case OPCODE_FLAG_PREFIX_DS:
                        pszSegment = "ds:";
                        break;
                    default:
                        assert(0);
                        break;
                }
            }
            else
                pszSegment = "";
        }

        if(REG_NAME_INDEX_SIB != regname){
            //����mov [ecx], 0��������mov [ecx[ecx], 0
			//������00401DEC :C7 45 FC FE FF FF FF mov	 dword ptr ds: +0xfc],0xfffffffe
            if((0 == GET_MOD_FROM_MODRM(pInstruction->byModRM) && 5 != GET_RM_FROM_MODRM(pInstruction->byModRM))
                    ||(0 != GET_MOD_FROM_MODRM(pInstruction->byModRM))){
                len = sprintf(szString, "[%s", Intel_x86_Registers_Names[regname]);
                if(0 == *pszSegment)//δָ����ʹ��Ĭ�϶�
                    pszSegment = GetDefaultSegmentPrefix(regname);
            }
			
        }
        else{//There is a SIB byte
            REG_NAME_INDEX_t BaseRegName = IndexedName[AddrSize][GET_BASE_FROM_SIB(pInstruction->bySIB)];
            REG_NAME_INDEX_t ScaledIndexRegName = IndexedName[AddrSize][GET_INDEX_FROM_SIB(pInstruction->bySIB)];
            if(0 == *pszSegment)//δָ����ʹ��Ĭ�϶�
                pszSegment = GetDefaultSegmentPrefix(BaseRegName);
            if(4 != GET_INDEX_FROM_SIB(pInstruction->bySIB)){
                if(0 != GET_SCALE_FROM_SIB(pInstruction->bySIB)){
                    sprintf(szOther, "%s*%d", Intel_x86_Registers_Names[ScaledIndexRegName], 1 << GET_SCALE_FROM_SIB(pInstruction->bySIB));
                }
                else 
                    sprintf(szOther, "%s", Intel_x86_Registers_Names[ScaledIndexRegName]);
            }
            else{
                memset(szOther, 0, sizeof(szOther));
            }

            if(5 == GET_BASE_FROM_SIB(pInstruction->bySIB)){
                if(0 == GET_MOD_FROM_MODRM(pInstruction->byModRM)){
                    if(4 != GET_INDEX_FROM_SIB(pInstruction->bySIB)){
                        if(pInstruction->iDisplacement > 0)
                            sprintf(szString, "[%s+0x%x]", szOther, pInstruction->iDisplacement);
                        else
                            sprintf(szString, "[%s-0x%x]", szOther, -pInstruction->iDisplacement);
                    }
                    else{
                        if(pInstruction->iDisplacement > 0)
                            sprintf(szString, "[0x%x]", pInstruction->iDisplacement);
                        else
                            sprintf(szString, "[-0x%x]", -pInstruction->iDisplacement);

                        
                    }
                }
                else{
                    sprintf(szString, "[%s+%s", Intel_x86_Registers_Names[BaseRegName], szOther);
                }
            }
            else{
                //����������lea edx, [edi + edi * 2]��8D 14 7F���Լ�lea eax,[eax+ecx+18h](8D 44 08 18)��ʽ�ĸ�ʽ����
                if(4 != GET_INDEX_FROM_SIB(pInstruction->bySIB))
                    len = sprintf(szString, "[%s + %s", Intel_x86_Registers_Names[BaseRegName], szOther);
                else
                    len = sprintf(szString, "[%s", Intel_x86_Registers_Names[BaseRegName]);
            }
        }
        switch(GET_MOD_FROM_MODRM(pInstruction->byModRM)){
            case 0:
                if(5 == GET_RM_FROM_MODRM(pInstruction->byModRM)){
                    if(0 == *pszSegment)//δָ����ʹ��Ĭ�϶�
                        pszSegment = "ds:";
                    if(pInstruction->iDisplacement > 0)
                        len += sprintf(szOther, "[0x%08x]", pInstruction->iDisplacement);
                    else
                        len += sprintf(szOther, "[0x%08x]", -pInstruction->iDisplacement);
                }
				else{
					len += sprintf(szOther, "]");
				}

//                else if(REG_NAME_INDEX_SIB == regname)
//                    len += sprintf(szOther, "]");
//                else
//                    len += sprintf(szOther, "[%s]", Intel_x86_Registers_Names[regname]);
//					//��֮ǰ��len = sprintf(szString, "[%s", Intel_x86_Registers_Names[regname]);���ͻ
				
                break;
            case 1:
            case 2:
                if(0 != pInstruction->iDisplacement){
                    if(pInstruction->iDisplacement > 0)
                        len += sprintf(szOther, "+0x%x]", pInstruction->iDisplacement);
                    else
                        len += sprintf(szOther, "-0x%x]", -pInstruction->iDisplacement);
                }
                else
                    len += sprintf(szOther, "]");
                break;
            default:
                assert(0);//should be proccessed by caller.
                break;
        }
        assert(len < iLength);
        strcat(szString, szOther);
    }
    else{// MOD = 0b11
        switch(MASK_AM(dwArgFlags)){
            case AM_Q:
            case AM_U:
            case AM_W:
                assert(0);//not implemented!
                break;
        }
        regname = GetRegIndexName(GET_RM_FROM_MODRM(pInstruction->byModRM), dwArgFlags, OpSize, AddrSize);
        if(REG_NAME_INDEX_NO == regname)
            len = sprintf(szString, "ERROR reg name");
        else
            len = sprintf(szString, "%s", Intel_x86_Registers_Names[regname]);
    }

    sprintf(szOther, "%s%s%s", pszOperandSize, pszSegment, szString);
    len = ((iLength < sizeof(szOther))?iLength:sizeof(szOther)) - 1;
    strncpy(szString, szOther, len -1);
    *(szString + len) = 0;
}

//�������ƣ�        GetOperandString
//����������        ��x86�����������ֲ����
//����ֵ��          ���������ַ�������
//����������       dwArgFlags:���ڴ��ݲ��������ԣ���־λ����Opcode�����ã���
//                   pdwFlags:
//                   addr:��ǰָ��ĵ�ַ�����ڼ���ƫ�Ƶ�ַ������Jcc, jmp��ƫ�Ƶ�ַ��
//������־:         2009��8��3�գ���販(yanghongbo@ptwy.cn)������
static size_t GetOperandString(char * szString, size_t iLength, DWORD dwArgFlags, PVM_Intel_x86_InstructionData_t pInstruction, Intel_x86_Operand_Size_t OpSize, Intel_x86_Address_Size_t AddrSize, DWORD * pdwFlags, DWORD addr)
{
    char szOperand[50] = {0};
    UINT32 uImmediate;
    Intel_x86_Operand_Size_t RealOpSize = OpSize;
    size_t len;
    int temp = 0;
    assert(NULL != pdwFlags);
    assert(pInstruction);

    if(NO_OPERAND == dwArgFlags){
        memset(szString, 0, iLength);
        return 0;
    }
        
    if(pInstruction->dwFlags & OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE){//�Ƿ�ʹ����OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE
        if(OPERAND_SIZE_16BIT == RealOpSize)
            RealOpSize = OPERAND_SIZE_32BIT;
        else if(OPERAND_SIZE_32BIT == RealOpSize)
            RealOpSize = OPERAND_SIZE_16BIT;
        else
            assert(0);
    }

    switch(MASK_AM(dwArgFlags)){
        case AM_O:
            uImmediate = pInstruction->uImmediate >> (NEED_IMMEDIATE_BYTES(*pdwFlags) * 8);
            switch(RealOpSize){
                case OPERAND_SIZE_16BIT:
                    if(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
                        switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
                            case OPCODE_FLAG_PREFIX_CS:
                                //assert(0);
								sprintf(szOperand, "invalid CS prefix:[0x%x]", (uImmediate & 0xffff));
                                break;
                            case OPCODE_FLAG_PREFIX_SS:
                                sprintf(szOperand, "word ptr ss:[0x%x]", (uImmediate & 0xffff));
                                break;
                            case OPCODE_FLAG_PREFIX_ES:
                                sprintf(szOperand, "word ptr es:[0x%x]", (uImmediate & 0xffff));
                                break;
                            case OPCODE_FLAG_PREFIX_FS:
                                sprintf(szOperand, "word ptr fs:[0x%x]", (uImmediate & 0xffff));
                                break;
                            case OPCODE_FLAG_PREFIX_GS:
                                sprintf(szOperand, "word ptr gs:[0x%x]", (uImmediate & 0xffff));
                                break;
                            case OPCODE_FLAG_PREFIX_DS:
                                sprintf(szOperand, "word ptr ds:[0x%x]", (uImmediate & 0xffff));
                                break;
                            default:
                                assert(0);
                                break;
                        }
                    }
                    else
                        sprintf(szOperand, "word ptr [0x%x]", (uImmediate & 0xffff));

                    ADD_IMMEDIATE_BYTES(*pdwFlags, 2);
                    break;
                case OPERAND_SIZE_32BIT:
                case OPERAND_SIZE_64BIT:
                    if(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
                        switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
                            case OPCODE_FLAG_PREFIX_CS:
                                //assert(0);
								sprintf(szOperand, "invalid CS prefix:[0x%x]", (uImmediate & 0xffff));
                                break;
                            case OPCODE_FLAG_PREFIX_SS:
                                sprintf(szOperand, "dword ptr ss:[0x%x]", (uImmediate & 0xffffffff));
                                break;
                            case OPCODE_FLAG_PREFIX_ES:
                                sprintf(szOperand, "dword ptr es:[0x%x]", (uImmediate & 0xffffffff));
                                break;
                            case OPCODE_FLAG_PREFIX_FS:
                                sprintf(szOperand, "dword ptr fs:[0x%x]", (uImmediate & 0xffffffff));
                                break;
                            case OPCODE_FLAG_PREFIX_GS:
                                sprintf(szOperand, "dword ptr gs:[0x%x]", (uImmediate & 0xffffffff));
                                break;
                            case OPCODE_FLAG_PREFIX_DS:
                                sprintf(szOperand, "dword ptr ds:[0x%x]", (uImmediate & 0xffffffff));
                                break;
                            default:
                                assert(0);
                                break;
                        }
                    }
                    else
                        sprintf(szOperand, "dword ptr [0x%x]", (uImmediate & 0xffffffff));

                    ADD_IMMEDIATE_BYTES(*pdwFlags, 4);
                    break;
            }
            break;
        case AM_I:
        case AM_A:
        case AM_J:
            assert(NEED_IMMEDIATE_BYTES(*pdwFlags) <3);
            uImmediate = pInstruction->uImmediate >> (NEED_IMMEDIATE_BYTES(*pdwFlags) * 8);
            switch(MASK_OT(dwArgFlags)){
                case OT_b:
                    if(AM_J == MASK_AM(dwArgFlags)){
                        sprintf(szOperand, "0x%x", addr + (INT8)(uImmediate & 0xff));
                    }
                    else
                        sprintf(szOperand, "0x%x(%d)", (uImmediate & 0xff), (INT8)(uImmediate & 0xff));
                    ADD_IMMEDIATE_BYTES(*pdwFlags, 1);
                    break;
                case OT_w:
                    if(AM_J == MASK_AM(dwArgFlags))
                        sprintf(szOperand, "0x%x", addr + (INT16)(uImmediate & 0xffff));
                    else{
                        sprintf(szOperand, "0x%x(%d)", (uImmediate & 0xffff), (INT16)(uImmediate & 0xffff));
                    }
                    ADD_IMMEDIATE_BYTES(*pdwFlags, 2);
                    break;
                case OT_v:
                    switch(RealOpSize){
                        case OPERAND_SIZE_16BIT:
                            if(AM_J == MASK_AM(dwArgFlags))
                                sprintf(szOperand, "0x%x", addr + (INT16)(uImmediate & 0xffff));
                            else{
                                sprintf(szOperand, "0x%x(%d)", (uImmediate & 0xffff), (INT16)(uImmediate & 0xffff));
                            }
                            ADD_IMMEDIATE_BYTES(*pdwFlags, 2);
                            break;
                        case OPERAND_SIZE_32BIT:
                            if(AM_J == MASK_AM(dwArgFlags))
                                sprintf(szOperand, "0x%x", addr + (INT32)(uImmediate & 0xffffffff));
                            else{
                                sprintf(szOperand, "0x%x(%d)", (uImmediate & 0xffffffff), (INT32)(uImmediate & 0xffffffff));
                            }
                            ADD_IMMEDIATE_BYTES(*pdwFlags, 4);
                            break;
                        case OPERAND_SIZE_64BIT:
                            assert(0);
                            ADD_IMMEDIATE_BYTES(*pdwFlags, 8);
                            break;
                    }
                    break;
                case OT_z:
                    switch(RealOpSize){
                        case OPERAND_SIZE_16BIT:
                            if(AM_J == MASK_AM(dwArgFlags))
                                sprintf(szOperand, "0x%x", addr + (INT16)(uImmediate & 0xffff));
                            else
                                sprintf(szOperand, "0x%x(%d)", (uImmediate & 0xffff), (INT16)(uImmediate & 0xffff));
                            ADD_IMMEDIATE_BYTES(*pdwFlags, 2);
                            break;
                        case OPERAND_SIZE_32BIT:
                        case OPERAND_SIZE_64BIT:
                            if(AM_J == MASK_AM(dwArgFlags))
                                sprintf(szOperand, "0x%x", addr + (INT32)(uImmediate & 0xffffffff));
                            else
                                sprintf(szOperand, "0x%x(%d)", (uImmediate & 0xffffffff), (INT32)(uImmediate & 0xffffffff));
                            ADD_IMMEDIATE_BYTES(*pdwFlags, 4);
                            break;
                        default:
                            assert(0);
                    }
                    break;
                case OT_p:
                    //assert(0);
                    switch(RealOpSize){
                        case OPERAND_SIZE_16BIT:
                            sprintf(szOperand, "0x%x", (uImmediate & 0xffff));
                            ADD_IMMEDIATE_BYTES(*pdwFlags, 2);
                            break;
                        case OPERAND_SIZE_32BIT:
                        case OPERAND_SIZE_64BIT:
                            sprintf(szOperand, "0x%x(%d)", (uImmediate & 0xffffffff), (INT32)(uImmediate & 0xffffffff));
                            ADD_IMMEDIATE_BYTES(*pdwFlags, 4);
                            break;
                    }
                    break;
                case OT_1:
                    sprintf(szOperand, "1");
                    break;
                default:
                    assert(0);
                    break;
            }
            break;
        case AM_C:
            assert(0);
            break;
        case AM_D:
            assert(0);
            break;
        case AM_E://refer to ModR/M byte
        case AM_M:
        case AM_Q:
        case AM_U:
        case AM_W:
            assert(0 == (*pdwFlags & INSTURCTION_HAS_NO_MODRM));
            GetEffectiveAddressString(szOperand, sizeof(szOperand), dwArgFlags, pInstruction, RealOpSize, AddrSize);
            break;
        case AM_G://refer to reg field of ModR/M byte
        case AM_N:
        case AM_P:
        case AM_R:
        case AM_S:
        case AM_V:
            assert(0 == (*pdwFlags & INSTURCTION_HAS_NO_MODRM));
            {
                REG_NAME_INDEX_t regname = GetRegIndexName(GET_REG_FROM_MODRM(pInstruction->byModRM), dwArgFlags, RealOpSize, AddrSize);
                sprintf(szOperand, "%s", Intel_x86_Registers_Names[regname]);
            }
            break;
        case AM_F:
        case AM_X:
        case AM_Y:
            break;
        default ://there are some AM_ type not be processed;
            if(MASK_AM(dwArgFlags) < AM_I1){
                assert(0);
            }
            else if(AM_REG_RAX <= MASK_AM(dwArgFlags) && MASK_AM(dwArgFlags) <= AM_REG_XMM7){
                 REG_NAME_INDEX_t regname = GetRegIndexName(GET_AM_REG_NAME_INDEX(dwArgFlags), dwArgFlags, RealOpSize, AddrSize);
                 if(REG_NAME_INDEX_NO != regname)
                    sprintf(szOperand, "%s", Intel_x86_Registers_Names[regname]);
                 else
                     strcpy(szOperand, "ERROR reg name");
                    //sprintf(szOperand, "%s");
            }
            break;
    }
    len = (iLength < sizeof(szOperand) ? iLength : sizeof(szOperand)) -1;
    strncpy(szString, szOperand, len-1);
    *(szString + len) = 0;
    return len;
}

//�������ƣ�        GetInstructionMnemonic
//����������        ��x86�����������ֲ����
//����ֵ��          ָ�����Ƿ����ַ�������
//����������
//������־:         2009��8��3�գ���販(yanghongbo@ptwy.cn)������
size_t GetInstructionMnemonic(char * szString, size_t iLength, const PVM_Intel_x86_InstructionData_t pInstruction, Intel_x86_Operand_Size_t OpSize, Intel_x86_Address_Size_t AddrSize, DWORD addr)
{
    char szMnemonic[100];
    char szOperand[50];
    int i;
    DWORD dwFlags = 0;
    DWORD dwArgFlags = 0;
    const Intel_x86_Instruction_Attribute_t * InstructionOpcodeMap = NULL;
    size_t len;

    assert(szString);
    assert(pInstruction);

    memset(szString, 0, iLength);
    memset(szMnemonic, 0, sizeof(szMnemonic));
    InstructionOpcodeMap = Intel_x86_Instruction_Opcode_Map_OneByte;
    for(i = 0; i < pInstruction->byOpcodesNum; i ++){
        switch(OPCODE_FLAG_MASK(InstructionOpcodeMap[pInstruction->byOpcodes[i]].uOpcodeFlag)){
            case OPCODE_FLAG_IS_TWO_BYTES_ESCAPE:
                assert(0 == i);
                InstructionOpcodeMap = Intel_x86_Instruction_Opcode_Map_TwoBytes;
                break;
            case OPCODE_FLAG_IS_THREE_BYTES_ESCAPE:
                assert(1 == i);
                assert(0);
                InstructionOpcodeMap = Intel_x86_Instruction_Opcode_Map_ThreeBytes;
                break;
            case OPCODE_FLAG_IS_OPCODE_EXTENSION:
                if(i != pInstruction->byOpcodesNum - 1){
                    //_asm int 3
                    //assert(0);
                }
                //opcode extension��չ��0xff xx xx
                //assert(NULL != InstructionOpcodeMap[pInstruction->byOpcodes[i]].pPatch[GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM)].szMnemonic_Intel);
                if(NULL == InstructionOpcodeMap[pInstruction->byOpcodes[i]].pPatch[GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM)].szMnemonic_Intel){
                    assert(0);//���ﲻӦ�ñ�ִ�У�֮ǰ��FetchInstructionӦ�ñ���
                    return 0;
                }
                sprintf(szMnemonic, "%s\t", InstructionOpcodeMap[pInstruction->byOpcodes[i]].pPatch[GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM)].szMnemonic_Intel);

                memset(szOperand, 0, sizeof(szOperand));

                dwArgFlags = InstructionOpcodeMap[pInstruction->byOpcodes[i]].pPatch[GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM)].uArg1Flag;
                if(USE_UPPER_OPERAND == dwArgFlags)
                    dwArgFlags = InstructionOpcodeMap[pInstruction->byOpcodes[i]].uArg1Flag;
                if(NO_OPERAND != dwArgFlags){
                    memset(szOperand, 0, sizeof(szOperand));
                    GetOperandString(szOperand, sizeof(szOperand), dwArgFlags, pInstruction, OpSize, AddrSize, &dwFlags, addr);
                    strcat(szMnemonic, " ");
                    strcat(szMnemonic, szOperand);

                    dwArgFlags = InstructionOpcodeMap[pInstruction->byOpcodes[i]].pPatch[GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM)].uArg2Flag;
                    if(USE_UPPER_OPERAND == dwArgFlags)
                        dwArgFlags = InstructionOpcodeMap[pInstruction->byOpcodes[i]].uArg2Flag;
                    if(NO_OPERAND != dwArgFlags){
                        memset(szOperand, 0, sizeof(szOperand));
                        GetOperandString(szOperand, sizeof(szOperand), dwArgFlags, pInstruction, OpSize, AddrSize, &dwFlags, addr);
                        if(strncmp(szOperand, "", sizeof(szOperand))){
                            strcat(szMnemonic, ",");
                            strcat(szMnemonic, szOperand);
                            if(NO_OPERAND != dwArgFlags){
                                dwArgFlags = InstructionOpcodeMap[pInstruction->byOpcodes[i]].pPatch[GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM)].uArg3Flag;
                                if(USE_UPPER_OPERAND == dwArgFlags)
                                    dwArgFlags = InstructionOpcodeMap[pInstruction->byOpcodes[i]].uArg3Flag;
                                if(NO_OPERAND != dwArgFlags){
                                    memset(szOperand, 0, sizeof(szOperand));
                                    GetOperandString(szOperand, sizeof(szOperand), dwArgFlags, pInstruction, OpSize, AddrSize, &dwFlags, addr);

                                    if(strncmp(szOperand, "", sizeof(szOperand))){
                                        strcat(szMnemonic, ",");
                                        strcat(szMnemonic, szOperand);
                                    }
                                }
                            }
                        }
                    }
                }

                break;
            case OPCODE_FLAG_IS_NORMAL_INSTRUCTION:
                if(i != pInstruction->byOpcodesNum - 1){
                    _asm int 3
                    assert(0);
                }
                //if(0x8d == pInstruction->byOpcodes[i])
                    //_asm int 3
                sprintf(szMnemonic, "%s\t", InstructionOpcodeMap[pInstruction->byOpcodes[i]].szMnemonic_Intel);

                if(NO_OPERAND != InstructionOpcodeMap[pInstruction->byOpcodes[i]].uArg1Flag){
                    memset(szOperand, 0, sizeof(szOperand));
                    GetOperandString(szOperand, sizeof(szOperand), InstructionOpcodeMap[pInstruction->byOpcodes[i]].uArg1Flag, pInstruction, OpSize, AddrSize, &dwFlags, addr);
                    strcat(szMnemonic, " ");
                    strcat(szMnemonic, szOperand);

                    if(NO_OPERAND != InstructionOpcodeMap[pInstruction->byOpcodes[i]].uArg2Flag){
                        memset(szOperand, 0, sizeof(szOperand));
                        GetOperandString(szOperand, sizeof(szOperand), InstructionOpcodeMap[pInstruction->byOpcodes[i]].uArg2Flag, pInstruction, OpSize, AddrSize, &dwFlags, addr);
                        if(strncmp(szOperand, "", sizeof(szOperand))){
                            strcat(szMnemonic, ",");
                            strcat(szMnemonic, szOperand);

                            if(NO_OPERAND != InstructionOpcodeMap[pInstruction->byOpcodes[i]].uArg3Flag){
                                memset(szOperand, 0, sizeof(szOperand));
                                GetOperandString(szOperand, sizeof(szOperand), InstructionOpcodeMap[pInstruction->byOpcodes[i]].uArg3Flag, pInstruction, OpSize, AddrSize, &dwFlags, addr);
                                if(strncmp(szOperand, "", sizeof(szOperand))){
                                    strcat(szMnemonic, ",");
                                    strcat(szMnemonic, szOperand);
                                }
                            }
                        }
                    }
                }

                break;
            default:
                assert(0);
                break;
        }
    }

    len = (iLength < sizeof(szMnemonic) ? iLength : sizeof(szMnemonic))-1;
    strncpy(szString, szMnemonic, len-1);
    *(szString + len) = 0;
    return len;
}

//�������ƣ�        FetchOneInstruction
//����������        ��x86�����������ֲ����
//����ֵ��          ��ָ����ֽڳ���
//����������
//������־:         2009��8��3�գ���販(yanghongbo@ptwy.cn)������
static VM_INSTRUCTION_ERR_CODE FetchOneInstruction(PVM_Intel_x86_InstructionData_t pInstruction, PVM_MemoryBlock_t pBlock, UINT uInstructionBaseAddr, size_t BufferSize, Intel_x86_Operand_Size_t OpSize, Intel_x86_Address_Size_t AddrSize, size_t * psiInstructionSize)
{
    const Intel_x86_Instruction_Attribute_t * InstructionOpcodeMap = NULL;
    //PBYTE p = pCodeBuffer;
    BYTE byCode = 0;
    DWORD dwFlags = 0;
    UINT uCodeAddr = uInstructionBaseAddr;
    //const PBYTE pEndOfBuffer = p + BufferSize;  //+ BufferSize���
    int bytes;
    int i;
    assert(pBlock);
    assert(psiInstructionSize);
    //assert(pCodeBuffer);
    assert(pInstruction);

    InstructionOpcodeMap = Intel_x86_Instruction_Opcode_Map_OneByte;
    memset(pInstruction, 0, sizeof(VM_Intel_x86_InstructionData_t));
    while((uCodeAddr - uInstructionBaseAddr) < BufferSize){
        //byCode = *p++;
        byCode = VM_MM_ReadOneByte(pBlock, uCodeAddr);
        uCodeAddr ++;
        //PrintData(&byCode, sizeof(BYTE));

        switch(OPCODE_FLAG_MASK(InstructionOpcodeMap[byCode].uOpcodeFlag)){
            case OPCODE_FLAG_IS_PREFIX:
                //assert(Instruction.byPrefixesNum < 4);
                //Instruction.byPrefixes[Instruction.byPrefixesNum++] = byCode;
                switch(OPCODE_FLAG_MASK_PREFIX_TYPE(InstructionOpcodeMap[byCode].uOpcodeFlag)){
                    //Group 1:
                    case OPCODE_FLAG_PREFIX_LOCK:
                    case OPCODE_FLAG_PREFIX_REPNE:
                    case OPCODE_FLAG_PREFIX_REP://OPCODE_FLAG_PREFIX_REPE
                        //assert(!OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags));
                        if(OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags)){
                            *psiInstructionSize = (size_t)(uCodeAddr - uInstructionBaseAddr);
                            return VM_INSTRUCTION_ERR_INVALID_OPCODE;
                        }
                        break;
                    //Group 2:
                    case OPCODE_FLAG_PREFIX_CS://OPCODE_FLAG_PREFIX_BRANCH_NOT_TAKEN
                    case OPCODE_FLAG_PREFIX_SS:
                    case OPCODE_FLAG_PREFIX_DS://OPCODE_FLAG_PREFIX_BRANCH_TAKEN
                    case OPCODE_FLAG_PREFIX_ES:
                    case OPCODE_FLAG_PREFIX_FS:
                    case OPCODE_FLAG_PREFIX_GS:
                        //assert(!OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags));
                        if(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
                            *psiInstructionSize = (size_t)(uCodeAddr - uInstructionBaseAddr);
                            return VM_INSTRUCTION_ERR_INVALID_OPCODE;
                        }
                        break;
                    case OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE:
                        //assert(!(pInstruction->dwFlags & OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE));
                        if((pInstruction->dwFlags & OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE)){
                            *psiInstructionSize = (size_t)(uCodeAddr - uInstructionBaseAddr);
                            return VM_INSTRUCTION_ERR_INVALID_OPCODE;
                        }
                        dwFlags |= OPERAND_SIZE_OVERRIDE;
                        break;
                    case OPCODE_FLAG_PREFIX_ADDRESS_SIZE_OVERRIDE:
                        //assert(!(pInstruction->dwFlags & OPCODE_FLAG_PREFIX_ADDRESS_SIZE_OVERRIDE));
                        if((pInstruction->dwFlags & OPCODE_FLAG_PREFIX_ADDRESS_SIZE_OVERRIDE)){
                            *psiInstructionSize = (size_t)(uCodeAddr - uInstructionBaseAddr);
                            return VM_INSTRUCTION_ERR_INVALID_OPCODE;
                        }
                        dwFlags |= ADDRESS_SIZE_OVERRIDE;
                        break;
                    default:
                        //printf("\nnot implemented\n");
                        assert(0);
                        break;
                }
                pInstruction->dwFlags |= OPCODE_FLAG_MASK_PREFIX_TYPE(InstructionOpcodeMap[byCode].uOpcodeFlag);
                //sprintf(szMnemonic, "%s%s ",szMnemonic, InstructionOpcodeMap[byCode].szMnemonic_Intel);
                break;
            case OPCODE_FLAG_IS_TWO_BYTES_ESCAPE:
                assert(0 == pInstruction->byOpcodesNum);
                InstructionOpcodeMap = Intel_x86_Instruction_Opcode_Map_TwoBytes;
                pInstruction->byOpcodes[pInstruction->byOpcodesNum++] = byCode;
                break;
            case OPCODE_FLAG_IS_THREE_BYTES_ESCAPE:
                return VM_INSTRUCTION_ERR_NOT_IMPLEMENTED;
                assert(0);
                assert(1 == pInstruction->byOpcodesNum);
                pInstruction->byOpcodes[pInstruction->byOpcodesNum++] = byCode;
                break;
            case OPCODE_FLAG_IS_OPCODE_EXTENSION:
                //if(0x81 == byCode)
                //    _asm int 3;
                assert(pInstruction->byOpcodesNum < 3);//opcode extension0xffӦ������prefix�ĵ�һ��opcode
                pInstruction->byOpcodes[pInstruction->byOpcodesNum++] = byCode;
                assert(InstructionOpcodeMap[byCode].pPatch);
                dwFlags |= NEED_MODRM;
                pInstruction->byModRM = VM_MM_ReadOneByte(pBlock, uCodeAddr);
                uCodeAddr ++;

                //PrintData(&pInstruction->byModRM, sizeof(BYTE));
                assert(InstructionOpcodeMap[byCode].pPatch);
                i = GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM);
                if(NULL == InstructionOpcodeMap[byCode].pPatch[GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM)].szMnemonic_Intel)
                {
                    //δ�ҵ���Ӧ��ָ�룬����Ӧ������Ч��ָ����
                    *psiInstructionSize = (size_t)(uCodeAddr - uInstructionBaseAddr);
                    return VM_INSTRUCTION_ERR_INVALID_OPCODE;
                }
                
                pInstruction->pfnInstructionExec = InstructionOpcodeMap[byCode].pPatch[GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM)].pfnInstructionExec;

                //arg 1
                if(USE_UPPER_OPERAND == InstructionOpcodeMap[byCode].pPatch[GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM)].uArg1Flag){
                    pInstruction->uArg1Flag = InstructionOpcodeMap[byCode].uArg1Flag;
                }
                else{
                    pInstruction->uArg1Flag = InstructionOpcodeMap[byCode].pPatch[GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM)].uArg1Flag;
                }
                CheckArg(pInstruction->uArg1Flag, &dwFlags, OpSize);
                //arg 2
                if(USE_UPPER_OPERAND == InstructionOpcodeMap[byCode].pPatch[GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM)].uArg2Flag){
                    pInstruction->uArg2Flag = InstructionOpcodeMap[byCode].uArg2Flag;
                }
                else{
                    pInstruction->uArg2Flag = InstructionOpcodeMap[byCode].pPatch[GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM)].uArg2Flag;
                }
                CheckArg(pInstruction->uArg2Flag, &dwFlags, OpSize);
                //arg 3
                if(USE_UPPER_OPERAND == InstructionOpcodeMap[byCode].pPatch[GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM)].uArg3Flag){
                    pInstruction->uArg3Flag = InstructionOpcodeMap[byCode].uArg3Flag;
                }
                else{
                    pInstruction->uArg3Flag = InstructionOpcodeMap[byCode].pPatch[GET_OPCODE_EXTENSION_FROM_MODRM(pInstruction->byModRM)].uArg3Flag;
                }
                CheckArg(pInstruction->uArg3Flag, &dwFlags, OpSize);
                goto CHECK_MOD_RM;
               
                break;
            case OPCODE_FLAG_IS_NORMAL_INSTRUCTION:
                assert(0xc0 != byCode);
                if(0xc0 == byCode)
                    _asm int 3;
                assert(pInstruction->byOpcodesNum < 3);
                pInstruction->byOpcodes[pInstruction->byOpcodesNum++] = byCode;
                pInstruction->pfnInstructionExec = InstructionOpcodeMap[byCode].pfnInstructionExec;

                if(NO_OPERAND == InstructionOpcodeMap[byCode].uArg1Flag){
                    assert(NO_OPERAND == InstructionOpcodeMap[byCode].uArg2Flag);
                    assert(NO_OPERAND == InstructionOpcodeMap[byCode].uArg3Flag);
                }
                else{
                    CheckArg(InstructionOpcodeMap[byCode].uArg1Flag, &dwFlags, OpSize);
                    CheckArg(InstructionOpcodeMap[byCode].uArg2Flag, &dwFlags, OpSize);
                    CheckArg(InstructionOpcodeMap[byCode].uArg3Flag, &dwFlags, OpSize);

                    //Get Mod R/M byte, SIB byte, Displacement, if one or more are required.
                    if(dwFlags & NEED_MODRM){
                        pInstruction->byModRM = VM_MM_ReadOneByte(pBlock, uCodeAddr);
                        uCodeAddr ++;

                        //PrintData(&pInstruction->byModRM, sizeof(BYTE));
                        /*if(byCode == 0x8D)
                            _asm int 3;
                        */
CHECK_MOD_RM://ugly goto
                        CheckModRM(pInstruction->byModRM, &dwFlags, AddrSize);
                        

                        if(dwFlags & NEED_SIB){
                            pInstruction->bySIB = VM_MM_ReadOneByte(pBlock, uCodeAddr);
                            uCodeAddr ++;
                            //PrintData(&pInstruction->bySIB, sizeof(BYTE));
                            CheckSIB(pInstruction->byModRM, pInstruction->bySIB, &dwFlags);
                        }

                        //���ñ�־λ���������ʱ��֪��������Щ����λ
                        //pInstruction->dwDataBitFlags |= NEED_MODRM;
                        assert(0 == pInstruction->iDisplacement);
                        switch(NEED_DISPLACEMENT_MASK(dwFlags)){
                            case NEED_DISPLACEMENT_8BIT:
                                //pInstruction->iDisplacement = *((BYTE *)p ++);
                                //pInstruction->iDisplacement = *((BYTE *)p) ++;
                                pInstruction->iDisplacement = (INT32)(INT8)VM_MM_ReadOneByte(pBlock, uCodeAddr);
                                //PrintData(&pInstruction->iDisplacement, sizeof(BYTE));
                                uCodeAddr += sizeof(BYTE);
                                break;
                            case NEED_DISPLACEMENT_16BIT:
                                pInstruction->iDisplacement = (INT32)(INT16)VM_MM_ReadOneWord(pBlock, uCodeAddr);
                                //PrintData(&pInstruction->iDisplacement, sizeof(WORD));
                                //p += sizeof(WORD);
                                uCodeAddr += sizeof(WORD);
                                break;
                            case NEED_DISPLACEMENT_32BIT:
                                pInstruction->iDisplacement = (INT32)VM_MM_ReadOneDWord(pBlock, uCodeAddr);
                                //PrintData(&pInstruction->iDisplacement, sizeof(DWORD));
                                uCodeAddr += sizeof(DWORD);
                                break;
                            default://����Ҫƫ����
                                break;
                        }
                    }
                    assert(0 == pInstruction->uImmediate);
                    if(NEED_IMMEDIATE_BYTES_MASK(dwFlags)){
                        bytes = NEED_IMMEDIATE_BYTES(dwFlags);
                        assert(bytes <= 4);
                        for(i = 0; i < bytes; i ++){
                            pInstruction->uImmediate |= VM_MM_ReadOneByte(pBlock, uCodeAddr) << (i * 8);
                            //PrintData(p, sizeof(BYTE));
                            uCodeAddr += sizeof(BYTE);
                        }
                    }
                }

                pInstruction->dwDataBitFlags |= NEED_DISPLACEMENT_MASK(dwFlags);
                pInstruction->dwDataBitFlags |= NEED_DATA_BYTES_MASK(dwFlags);
                pInstruction->dwDataBitFlags |= NEED_IMMEDIATE_BYTES_MASK(dwFlags);

                *psiInstructionSize = (size_t)(uCodeAddr - uInstructionBaseAddr);
                return VM_INSTRUCTION_ERR_SUCCEEDED;
                break;
            case OPCODE_FLAG_IS_NOT_IMPLEMENTEDED:
                printf("\nOPCODE_FLAG_IS_NOT_IMPLEMENTEDED\n");
                //assert(0);
                *psiInstructionSize = (size_t)(uCodeAddr - uInstructionBaseAddr);
                return VM_INSTRUCTION_ERR_NOT_IMPLEMENTED;
            default://should not reach this line
                assert(0);
                break;
        }
        assert((uCodeAddr - uInstructionBaseAddr)<= BufferSize);//to check 
    }
    *psiInstructionSize = (size_t)(uCodeAddr - uInstructionBaseAddr);
    return VM_INSTRUCTION_ERR_INVALID_OPCODE;
}


//�������ƣ�        PrintData
//����������        ��x86�����������ֲ����
//����ֵ��          void
//����������
//������־:         2009��8��3�գ���販(yanghongbo@ptwy.cn)������
static void PrintData(void * data, size_t szBytes)
{
    BYTE * p = (BYTE *)data;
    size_t i = 0;
    for(i = 0; i < szBytes; i ++){
        printf("%02X ", *p);
        p++;
    }
    //printf("\n");
}

//�������ƣ�        CheckSIB
//����������        ��x86�����������ֲ����
//����ֵ��          
//����������
//������־:         2009��8��3�գ���販(yanghongbo@ptwy.cn)������
//                  2010��3��24�գ���販(yanghongbo@ptwy.cn)������ע�����Ӳ������޸�bug
//according to Vol.2A Table 2-3 footprint.
static DWORD CheckSIB(BYTE byModRM, BYTE bySIB, DWORD * pdwFlags)
{
    if(5 == GET_BASE_FROM_SIB(bySIB))
    {
        switch(GET_MOD_FROM_MODRM(byModRM)){
            case 0:
                //����Ƿ�����ظ�����λ�� ��NEED_DISPLACEMENT_32BIT|NEED_DISPLACEMENT_8BIT
                assert((~NEED_DISPLACEMENT_MASK(*pdwFlags)) & (~NEED_DISPLACEMENT_32BIT));
                *pdwFlags |= NEED_DISPLACEMENT_32BIT;
                break;
            case 1:
                assert((~NEED_DISPLACEMENT_MASK(*pdwFlags)) & (~NEED_DISPLACEMENT_8BIT));
                *pdwFlags |= NEED_DISPLACEMENT_8BIT;
                break;
            case 2:
                assert((~NEED_DISPLACEMENT_MASK(*pdwFlags)) & (~NEED_DISPLACEMENT_32BIT));
                *pdwFlags |= NEED_DISPLACEMENT_32BIT;
                break;
            
            default://��Ӧ��ִ�е�����
                assert(0);
                break;
        }
    }
    return 0;
}

static DWORD CheckModRM(BYTE byModRM, DWORD * pdwFlags, Intel_x86_Address_Size_t AddrSize)
{
    Intel_x86_Address_Size_t RealAddrSize = AddrSize;
    assert(NULL != pdwFlags);
    if(*pdwFlags & ADDRESS_SIZE_OVERRIDE){
        if(ADDRESS_SIZE_16BIT == AddrSize)
            RealAddrSize = ADDRESS_SIZE_32BIT;
        else if(OPERAND_SIZE_32BIT == AddrSize)
            RealAddrSize = ADDRESS_SIZE_16BIT;
        else
            assert(0);
    }
    
    switch(RealAddrSize){
        case ADDRESS_SIZE_16BIT:
            switch(GET_MOD_FROM_MODRM(byModRM)){
                case 0:
                    if(6 == GET_RM_FROM_MODRM(byModRM))
                        *pdwFlags |= NEED_DISPLACEMENT_16BIT;
                    break;
                case 1:
                    *pdwFlags |= NEED_DISPLACEMENT_8BIT;
                    break;
                case 2:
                    *pdwFlags |= NEED_DISPLACEMENT_16BIT;
                    break;
                case 3:
                    break;
                default:
                    assert(0);
                    break;
            }
            break;
        case ADDRESS_SIZE_32BIT:
        case ADDRESS_SIZE_64BIT:
            switch(GET_MOD_FROM_MODRM(byModRM)){
                case 0:
                    if(4 == GET_RM_FROM_MODRM(byModRM))
                        *pdwFlags |= NEED_SIB;
                    else if(5 == GET_RM_FROM_MODRM(byModRM))
                        *pdwFlags |= NEED_DISPLACEMENT_32BIT;
                    break;
                case 1:
                    *pdwFlags |= NEED_DISPLACEMENT_8BIT;
                    if(4 == GET_RM_FROM_MODRM(byModRM))
                        *pdwFlags |= NEED_SIB;
                    break;
                case 2:
                    *pdwFlags |= NEED_DISPLACEMENT_32BIT;
                    if(4 == GET_RM_FROM_MODRM(byModRM))
                        *pdwFlags |= NEED_SIB;
                    break;
                case 3:
                    break;
                default:
                    assert(0);
                    break;
            }
            break;
    }
    return 0;
}
static DWORD CheckArg(DWORD uArgFlag, DWORD * pdwFlags, Intel_x86_Operand_Size_t OpSize)
{
    Intel_x86_Operand_Size_t RealOpSize = OpSize;
    assert(NULL != pdwFlags);
    if(*pdwFlags & OPERAND_SIZE_OVERRIDE){
        if(OPERAND_SIZE_16BIT == RealOpSize)
            RealOpSize = OPERAND_SIZE_32BIT;
        else if(OPERAND_SIZE_32BIT == RealOpSize)
            RealOpSize = OPERAND_SIZE_16BIT;
        else
            assert(0);
    }

    if(NO_OPERAND == uArgFlag)
        return 0;

    switch(MASK_AM(uArgFlag)){
        case AM_O:
            *pdwFlags |= INSTURCTION_HAS_NO_MODRM;
            switch(RealOpSize){
                case OPERAND_SIZE_16BIT:
                    ADD_IMMEDIATE_BYTES(*pdwFlags, 2);
                    break;
                case OPERAND_SIZE_32BIT:
                case OPERAND_SIZE_64BIT:
                    ADD_IMMEDIATE_BYTES(*pdwFlags, 4);
                    break;
            }
            break;
        case AM_A:
        case AM_I:
        case AM_J:
            assert(NEED_IMMEDIATE_BYTES(*pdwFlags) <3);
            switch(MASK_OT(uArgFlag)){
                case OT_b:
                    ADD_IMMEDIATE_BYTES(*pdwFlags, 1);
                    break;
                case OT_w:
                    ADD_IMMEDIATE_BYTES(*pdwFlags, 2);
                    break;
                case OT_v:
                    switch(RealOpSize){
                        case OPERAND_SIZE_16BIT:
                            ADD_IMMEDIATE_BYTES(*pdwFlags, 2);
                            break;
                        case OPERAND_SIZE_32BIT:
                            ADD_IMMEDIATE_BYTES(*pdwFlags, 4);
                            break;
                        case OPERAND_SIZE_64BIT:
                            assert(0);
                            ADD_IMMEDIATE_BYTES(*pdwFlags, 8);
                            break;
                    }
                    break;
                case OT_z:
                    switch(RealOpSize){
                        case OPERAND_SIZE_16BIT:
                            ADD_IMMEDIATE_BYTES(*pdwFlags, 2);
                            break;
                        case OPERAND_SIZE_32BIT:
                        case OPERAND_SIZE_64BIT:
                            ADD_IMMEDIATE_BYTES(*pdwFlags, 4);
                            break;
                        default:
                            assert(0);
                    }
                    break;
                case OT_p:
                    //assert(0);
                    switch(RealOpSize){
                        case OPERAND_SIZE_16BIT:
                            ADD_IMMEDIATE_BYTES(*pdwFlags, 2);
                            break;
                        case OPERAND_SIZE_32BIT:
                        case OPERAND_SIZE_64BIT:
                            ADD_IMMEDIATE_BYTES(*pdwFlags, 4);
                            break;
                    }
                    break;
                case OT_1:
                    *pdwFlags |= NEED_IMMEDIATE_1;
                    break;
                default:
                    assert(0);
                    break;
            }
            break;
        case AM_C:
        case AM_D:
        case AM_E:
        case AM_G:
        case AM_M:
        case AM_N:
        case AM_P:
        case AM_Q:
        case AM_R:
        case AM_S:
        case AM_U:
        case AM_V:
        case AM_W:
            assert(0 == (*pdwFlags & INSTURCTION_HAS_NO_MODRM));
            *pdwFlags |= NEED_MODRM;
            break;
        case AM_F:
        case AM_X:
        case AM_Y:
            break;
        default ://there are some AM_ type not be processed;
            if(MASK_AM(uArgFlag) < AM_I1)
                assert(0);
            break;
    }
    return 0;
}

#ifdef  __cplusplus
}
#endif
