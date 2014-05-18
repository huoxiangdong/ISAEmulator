//
//文件名称：        src/ISA/Intel_x86/Instructions/leave.c
//文件描述：        Intel x86下leave指令仿真
//创建人：          劳生(laosheng@ptwy.cn)
//创建日期：        2009年8月19日
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
//2009年8月19日，劳生(laosheng@ptwy.cn)，创建

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/leave.h"
#include "ISA/Intel_x86/Instructions/common.h"

//c9  leave     Set SP to BP , then pop BP
//c9  leave     Set SP to EBP , then pop EBP
VM_INSTRUCTION_ERR_CODE leave_c9(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uEA;

    assert(pInstruction);

    uEA = ACCESS_GEN_SS(*pX86) + ACCESS_GEN_ESP(*pX86);
    if (pMemory->StackSegment.uSegmentDescriptor[1] & SEGMENT_DESCRIPTOR_MASK_DB){
        /*Stack size : 32bit*/
        ACCESS_GEN_ESP(*pX86) = ACCESS_GEN_EBP(*pX86);
    }
    else{
        ACCESS_GEN_SP(*pX86) = ACCESS_GEN_BP(*pX86);
    }

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        ACCESS_GEN_BP(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
    }
    else{
        ACCESS_GEN_EBP(*pX86) = ACCESS_GEN_BP(*pX86) = PopStack(pX86, pMemory, OPERAND_SIZE_32BIT);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}