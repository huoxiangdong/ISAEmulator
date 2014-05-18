//
//文件名称：        src/ISA/Instructions/common.c
//文件描述：        Intel x86下指令仿真所需要的公共函数
//创建人：          杨鸿博(yanghongbo@ptwy.cn)
//创建日期：        2009年8月4日
//
//公司名称：        北京普天网怡科技有限公司
//项目组名：
//保密级别：
//版权声明：
//
//主项目名称：      基于虚拟机的漏洞挖掘平台
//主项目描述：
//主项目启动时间：  2009年6月X日
//
//子项目名称：      虚拟机及环境仿真器
//子项目描述：
//子项目启动时间：  2009年6月X日
//
//模块名称：        指令仿真器
//子项目描述：
//子项目启动时间：  2009年6月X日

//
//更新日志：
//2009年8月4日，杨鸿博(yanghongbo@ptwy.cn)，创建

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
//函数名称：        GetMemoryValue
//函数描述：        得到指定地址的值
//返回值：          UINT, 内存值
//参数描述：
//更新日志:         2009年8月4日，杨鸿博(yanghongbo@ptwy.cn)，创建
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

//函数名称：        SetMemoryValue
//函数描述：        设定到指定地址的值
//返回值：          VM_ERR_CODE
//参数描述：
//更新日志:         2009年8月4日，杨鸿博(yanghongbo@ptwy.cn)，创建
//                  2010年3月29日，杨鸿博(yanghongbo@ptwy.cn)，修改返回值类型
VM_ERR_CODE SetMemoryValue(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uEffectiveAddress, UINT uValue, DWORD dwFlags, DWORD dwPrefixes)
{
    VM_ERR_CODE vm_err = VM_ERR_FATAL_UNKNOWN;
    DWORD dwOT;
    assert(pX86);
    dwOT = GetDataType(dwFlags, pX86->OpSize, dwPrefixes);
    switch(dwOT){
        case OT_b:
            //assert(uValue <= 0xff);
            //uValue 为负值时，通不过断言
            vm_err = VM_MM_WriteOneByte(&pMemory->DataSegment, uEffectiveAddress, uValue & 0xff);
            break;
        case OT_w:
            //assert(uValue <= 0xffff);
            //uValue 为负值时，通不过断言，断言没有区分有符号数和无符号数
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

//函数名称：        GetDefaultSegmentPrefix
//函数描述：        得到默认的段前缀
//返回值：          char *
//参数描述：        reg name
//更新日志:         2010年3月25日，杨鸿博(yanghongbo@ptwy.cn)，创建
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

//函数名称：        GetEffectiveAddress
//函数描述：        根据ModR/M字节计算EA
//返回值：          VM_INSTRUCTION_ERR_CODE
//参数描述：        UINT, EA值
//更新日志:         2009年8月4日，杨鸿博(yanghongbo@ptwy.cn)，创建
//                  2010年3月25日，杨鸿博(yanghongbo@ptwy.cn)，修改返回值类型从UINT到VM_INSTRUCTION_ERR_CODE，返回执行状态
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
            //应当测试地址是否溢出
            iEA = (INT)(pInstruction->iDisplacement);
        }

        if(1 == GET_MOD_FROM_MODRM(pInstruction->byModRM)){
            assert(-254 <= pInstruction->iDisplacement && pInstruction->iDisplacement <= 255);
        }
        //应当测试地址是否溢出
        //iEA += (INT)(pInstruction->iDisplacement);
        //这句应该在上面吧？
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


//函数名称：        GetRegValue
//函数描述：        得到指定序号的寄存器值（根据MODR/M字节表）
//返回值：          UINT
//参数描述：
//更新日志:         2009年8月4日，杨鸿博(yanghongbo@ptwy.cn)，创建
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

//函数名称：        SetRegisterValue
//函数描述：        设定指定序号的寄存器值（根据MODR/M字节表）
//返回值：          VM_INSTRUCTION_ERR_CODE
//参数描述：
//更新日志:         2009年8月4日，杨鸿博(yanghongbo@ptwy.cn)，创建
//                  2010年3月25日，杨鸿博(yanghongbo@ptwy.cn)，修改返回值类型，从void到VM_INSTRUCTION_ERR_CODE。以用于作
//                                 文件型漏洞shellcode检测时，对于未审察代码的执行的出错问题。所有其他相关函数都应该进行
//                                 相似修改！
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

        //assert(uValue <= 0xffff);//调试未知程序时，可能导致错误的参数
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

//实现地址，转换机制
//Intel IA-32 processor are "little endian" machines,
//data : 0x12345678  address:0x1000 0000  
//Addr: 1000 0000  ->  78
//Addr: 1000 0001  ->  56
//Addr: 1000 0002  ->  34
//Addr: 1000 0003  ->  12 
//ESP:指向当前栈顶的元素，ESP= 0x1000 0000, (ESP指向压入地址的最低位)

VM_ERR_CODE PushStack16OneWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, WORD wData)
{
    UINT uOffset;
    UINT uEA;

    assert(pX86);
    assert(pMemory);

     ACCESS_GEN_SP(*pX86) -= 2;
     uEA = ACCESS_GEN_SS(*pX86) + ACCESS_GEN_SP(*pX86);
    
    //压栈的地址的永远低于，栈段的开始地址
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //写入到内存中偏移量为uOffset的地址处
    //note(2010-Mar-26):原来的代码由劳生编写。原来的寻址方式是将递减的寻址转换为递增的寻址。如 0x6000 0000 - 4 -> 0x6000 0000 + 4
    //VM_MM_WriteOneWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset, wData);  
    //修改了内存访问模型之后（内存页表，线性空间），直接使用uEA来寻址。
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

    //压栈的地址的永远低于，栈段的开始地址
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //写入到内存中偏移量为uOffset的地址处
    //见PushStack16OneWord的note
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

    //压栈的地址的永远低于，栈段的开始地址
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //写入到内存中偏移量为uOffset的地址处
    //见PushStack16OneWord的note
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

    //压栈的地址的永远低于，栈段的开始地址
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //写入到内存中偏移量为uOffset的地址处
    //见PushStack16OneWord的note
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

    //压栈的地址的永远低于，栈段的开始地址
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //写入到内存中偏移量为uOffset的地址处
    //见PushStack16OneWord的note
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

    //压栈的地址的永远低于，栈段的开始地址
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //写入到内存中偏移量为uOffset的地址处
    //见PushStack16OneWord的note
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

    //压栈的地址的永远低于，栈段的开始地址
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //写入到内存中偏移量为uOffset的地址处
    //见PushStack16OneWord的note
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

    //压栈的地址的永远低于，栈段的开始地址
    uOffset = GetStackOffset(&pMemory->StackSegment, uEA); 

    //写入到内存中偏移量为uOffset的地址处
    //见PushStack16OneWord的note
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

//函数名称：        GetStackAddressType
//函数描述：        返回 Stack Segment 的地址属性 
//返回值：          Intel_x86_Address_Size_t : OPERAND_SIZE_32BIT -- 表示Stack Segment 地址是32位,  OPERAND_SIZE_16BIT -- 表示Stack Segment 地址是16位,
//参数描述：        PVM_Memory_t ： pMemory -- 内存块
//更新日志:         2009年10月20日，劳生(laosheng@ptwy.cn)，创建
//                  2010年4月8日，杨鸿博(yanghongbo@ptwy.cn), 由于修改了内存模型，这里的栈相关的函数应该直接被内存访问函数替换
Intel_x86_Address_Size_t GetStackAddressType(PVM_Memory_t pMemory)
{
    if (pMemory->StackSegment.uSegmentDescriptor[1] |= SEGMENT_DESCRIPTOR_MASK_DB){
        return OPERAND_SIZE_32BIT;
    }
    else{
        return OPERAND_SIZE_16BIT;
    }
}

//函数名称：        PushStack
//函数描述：        在压栈操作
//返回值：          void
//参数描述：        
//更新日志:         2009年10月20日，劳生(laosheng@ptwy.cn)，创建
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

//函数名称：        PushStack
//函数描述：        在出栈操作
//返回值：          UINT
//参数描述：        
//更新日志:         2009年10月20日，劳生(laosheng@ptwy.cn)，创建
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
//由于修改了内存模型，这里的栈相关的函数应该直接被内存访问函数替换
UINT GetStackElement16OneWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory ,UINT uStackAddress)
{
    UINT uOffset;
    UINT uRet;


    assert(pX86);
    assert(pMemory);

    //压栈的地址的永远低于，栈段的开始地址
    uOffset = GetStackOffset(&pMemory->StackSegment, uStackAddress); 

    //读入内存中偏移量为uOffset的地址处的数据
    uRet = VM_MM_ReadOneWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset);  

    return uRet;
}

UINT GetStackElement16OneDWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory,UINT uStackAddress)
{
    UINT uOffset;
    UINT uRet;

    assert(pX86);
    assert(pMemory);


    //压栈的地址的永远低于，栈段的开始地址
    uOffset = GetStackOffset(&pMemory->StackSegment, uStackAddress); 

    //读入内存中偏移量为uOffset的地址处的数据
    uRet =  VM_MM_ReadOneDWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset); 

    return VM_ERR_NO_ERROR;
}

UINT GetStackElement32OneWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory,UINT uStackAddress)
{
    UINT uOffset;
    UINT uRet;

    assert(pX86);
    assert(pMemory);

    //压栈的地址的永远低于，栈段的开始地址
    uOffset = GetStackOffset(&pMemory->StackSegment, uStackAddress); 

    //读入内存中偏移量为uOffset的地址处的数据
    uRet = VM_MM_ReadOneWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset);  


    return uRet;
}

UINT GetStackElement32OneDWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory,UINT uStackAddress)
{
    UINT uOffset;
    UINT uRet;

    assert(pX86);
    assert(pMemory);

    //压栈的地址的永远低于，栈段的开始地址
    uOffset = GetStackOffset(&pMemory->StackSegment, uStackAddress); 

    //读入内存中偏移量为uOffset的地址处的数据
    uRet = VM_MM_ReadOneDWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset);  

    return uRet;
}
//由于修改了内存模型，这里的栈相关的函数应该直接被内存访问函数替换
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

    //压栈的地址的永远低于，栈段的开始地址
    uOffset = GetStackOffset(&pMemory->StackSegment, uStackAddress); 

    VM_MM_WriteOneByte(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset, uValue);  
}



void SetStackElementOneWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uStackAddress, UINT uValue)
{
    UINT uOffset;

    assert(pX86);
    assert(pMemory);

    //压栈的地址的永远低于，栈段的开始地址
    uOffset = GetStackOffset(&pMemory->StackSegment, uStackAddress); 

    VM_MM_WriteOneWord(&pMemory->StackSegment, pMemory->StackSegment.uStartAddr + uOffset, uValue);  
}

void SetStackElementOneDWord(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uStackAddress, UINT uValue)
{
    UINT uOffset;

    assert(pX86);
    assert(pMemory);

    //压栈的地址的永远低于，栈段的开始地址
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


