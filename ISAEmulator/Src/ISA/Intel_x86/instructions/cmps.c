//
//文件名称：        src/ISA/Intel_x86/Instructions/cmps.c
//文件描述：        Intel x86下cmps指令仿真
//创建人：          劳生(laosheng@ptwy.cn)
//创建日期：        2009年8月7日
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
//2009年8月13日，劳生(laosheng@ptwy.cn)，创建

//
//更新日志：
//2009年9月28日，劳生(laosheng@ptwy.cn)，修改指令对EFLAGS的影响
//2010年3月29日，杨鸿博(yanghongbo@ptwy.cn），更新。修改代码实现，除去bug。未进行测试！

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/cmps.h"
#include "ISA/Intel_x86/Instructions/common.h"

//在Intel_x86_ISA.c中对前缀的执行为：
//设置：pInstruction->dwFlags
//然后读取下一个字节
// 因此下面的指令的，在读入第2个字节时才能转跳到相应的函数
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
    //形成初始地址
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
            assert( 0 == uCount);//其他情况，应该只执行一次指令
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
//66 前缀判断是word , or double word
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
    //形成初始地址
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
            assert( 0 == uCount);//其他情况，应该只执行一次指令
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
