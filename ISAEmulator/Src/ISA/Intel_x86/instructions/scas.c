//
//文件名称：        src/ISA/Intel_x86/Instructions/scas.c
//文件描述：        Intel x86下scas指令仿真
//创建人：          劳生(laosheng@ptwy.cn)
//创建日期：        2009年8月14日
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
//2009年8月14日，劳生(laosheng@ptwy.cn)，创建

//
//更新日志：
//2009年10月12日，劳生(laosheng@ptwy.cn),修改： 指令对寄存器EFLAGS的影响
//2010年3月29日，杨鸿博(yanghongbo@ptwy.cn），更新。修改代码实现，除去bug。未进行测试！

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

 //DS : (E)SI 形成地址
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        uSegmentOffset = ACCESS_GEN_DI(*pX86); 
        uCount= ACCESS_GEN_CX(*pX86); 
    }
    else{
        uSegmentOffset = ACCESS_GEN_EDI(*pX86);
        //除ADDRESS_SIZE_16BIT及64-bit下加rex.w前缀两种情况之外，均使用ECX
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
            assert( 0 == uCount);//其他情况，应该只执行一次指令
            break;
        }
    }

    //将变化值回写到寄存器
    //ES : (E)DI 形成地址
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        ACCESS_GEN_DI(*pX86) = uSegmentOffset ; 
        if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))
            ACCESS_GEN_CX(*pX86) = uCount;
    }
    else{
        ACCESS_GEN_EDI(*pX86) = uSegmentOffset;
        //除ADDRESS_SIZE_16BIT及64-bit下加rex.w前缀两种情况之外，均使用ECX
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
    //DS : (E)SI 形成地址
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        uSegmentOffset = ACCESS_GEN_DI(*pX86); 
        uCount= ACCESS_GEN_CX(*pX86); 
    }
    else{
        uSegmentOffset = ACCESS_GEN_EDI(*pX86);
        //除ADDRESS_SIZE_16BIT及64-bit下加rex.w前缀两种情况之外，均使用ECX
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

    //F3 REPE 前缀
    switch (uOpType = GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
            case OT_w:
                /*Opcode size 16*/
                /*DF == 1, decremented*/
                //note: 2010年3月26日，杨鸿博， 将原先的do...while()修改为while()，先测试uCount != 0，否则可能进入死循环
                //                              将原先的if (1 == GET_EFLAGS_DF_BIT(*pX86))分离，增加iDecrementFlag
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
            assert( 0 == uCount);//其他情况，应该只执行一次指令
            break;
        }
    }

        

    //将变化值回写到寄存器
    //ES : (E)DI 形成地址
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        ACCESS_GEN_DI(*pX86) = uSegmentOffset ; 
        if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))
            ACCESS_GEN_CX(*pX86) = uCount;
    }
    else{
         ACCESS_GEN_EDI(*pX86) = uSegmentOffset;
        //除ADDRESS_SIZE_16BIT及64-bit下加rex.w前缀两种情况之外，均使用ECX
        if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))
            ACCESS_GEN_ECX(*pX86) = uCount; 
        
    }
    
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}