//
//文件名称：        src/ISA/Intel_x86/Instructions/stos.c
//文件描述：        Intel x86下stos指令仿真
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
#include "VM_Log.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/stoscc.h"
#include "ISA/Intel_x86/Instructions/common.h"


//AD  stos m8  Store  AL at address DS:(E)SI
VM_INSTRUCTION_ERR_CODE stos_aa(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uSegment = 0;
    UINT uSegmentOffset = 0;
    UINT uCount = 0;
    INT  iDecrementFlag = 0;

    UINT uAL;

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
    if (!(OPCODE_FLAG_PREFIX_REP == OPCODE_FLAG_PREFIX_GROUP1_MASK(pInstruction->dwFlags))){
        uCount = 1;
    }

    iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(1):(-1);

    uAL = ACCESS_GEN_AL(*pX86);

    while(0 != uCount){
        vm_err = SetMemoryValue(pX86, pMemory, uSegment + uSegmentOffset, uAL, OT_b, pInstruction->dwFlags);
        if(VM_ERR_NO_ERROR != vm_err){
            VM_ErrLog(vm_err);
            return VM_INSTRUCTION_ERR_ERROR_RETURN_BY_VM;
        }
        uSegmentOffset += iDecrementFlag;
        uCount --;
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


//AD  stos m16  Store AX at address DS:(E)SI
//AD  stosw
//AD  stos m32  Store EAX at address DS:(E)SI
//AD  stosd
VM_INSTRUCTION_ERR_CODE stos_ab(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{

    UINT uSegment = 0;
    UINT uSegmentOffset = 0;
    UINT uCount = 0;
    INT  iDecrementFlag = 0;
    UINT uOpType = 0;
    UINT uData = 0;

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
                uData = ACCESS_GEN_AX(*pX86);
                break;

            case OT_d:
                /*Opcode size 32*/
                iDecrementFlag = (0 == GET_EFLAGS_DF_BIT(*pX86))?(4):(-4);
                uData = ACCESS_GEN_EAX(*pX86);
                break;
            default:
                assert(0);//should not be here
                break;
    }

    while(0 != uCount){
        vm_err = SetMemoryValue(pX86, pMemory, uSegment + uSegmentOffset, uData, uOpType, pInstruction->dwFlags);
        if(VM_ERR_NO_ERROR != vm_err){
            VM_ErrLog(vm_err);
            return VM_INSTRUCTION_ERR_ERROR_RETURN_BY_VM;
        }
        uSegmentOffset += iDecrementFlag;
        uCount --;
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
