//
//文件名称：        src/ISA/Intel_x86/Instructions/lodscc.c
//文件描述：        Intel x86下lodscc指令仿真
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
//2010年3月29日，杨鸿博(yanghongbo@ptwy.cn），更新。修改代码实现，除去bug。未进行测试！

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

//DS : (E)SI 形成地址
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        uSegmentOffset = ACCESS_GEN_SI(*pX86); 
        uCount= ACCESS_GEN_CX(*pX86); 
    }
    else{
        uSegmentOffset = ACCESS_GEN_ESI(*pX86);
        //除ADDRESS_SIZE_16BIT及64-bit下加rex.w前缀两种情况之外，均使用ECX
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


   //将变化值回写到寄存器
    //DS : (E)SI 形成地址
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        ACCESS_GEN_SI(*pX86) = uSegmentOffset ; 
        if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))
            ACCESS_GEN_CX(*pX86) = uCount;
    }
    else{
        ACCESS_GEN_ESI(*pX86) = uSegmentOffset;
        //除ADDRESS_SIZE_16BIT及64-bit下加rex.w前缀两种情况之外，均使用ECX
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

    //DS : (E)SI 形成地址
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        uSegmentOffset = ACCESS_GEN_SI(*pX86); 
        uCount= ACCESS_GEN_CX(*pX86); 
    }
    else{
        uSegmentOffset = ACCESS_GEN_ESI(*pX86);
        //除ADDRESS_SIZE_16BIT及64-bit下加rex.w前缀两种情况之外，均使用ECX
        uCount= ACCESS_GEN_ECX(*pX86); 
    }
    if (!(OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))){
        uCount = 1;
    }

    //F3 REPE 前缀
    switch (uOpType = GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            /*Opcode size 16*/
            /*DF == 1, decremented*/
            //note: 2010年3月26日，杨鸿博， 将原先的do...while()修改为while()，先测试uCount != 0，否则可能进入死循环
            //                              将原先的if (1 == GET_EFLAGS_DF_BIT(*pX86))分离，增加iDecrementFlag
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

    //将变化值回写到寄存器
    //DS : (E)SI 形成地址
    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        ACCESS_GEN_SI(*pX86) = uSegmentOffset ; 
        if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))
            ACCESS_GEN_CX(*pX86) = uCount;
    }
    else{
         ACCESS_GEN_ESI(*pX86) = uSegmentOffset;
        //除ADDRESS_SIZE_16BIT及64-bit下加rex.w前缀两种情况之外，均使用ECX
        if (OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))
            ACCESS_GEN_ECX(*pX86) = uCount; 
        
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}