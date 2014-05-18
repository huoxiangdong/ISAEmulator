//
//文件名称：        src/ISA/Intel_x86/Instructions/popf.c
//文件描述：        Intel x86下popf指令仿真
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

//
//更新日志：
//2009年10月10日，劳生(laosheng@ptwy.cn),修改：检测对操作数的大小

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/popf.h"
#include "ISA/Intel_x86/Instructions/common.h"

//
//更新日志：
//2009年10月10日，劳生(laosheng@ptwy.cn),修改：操作数的大小、栈地址大小的检测


//9d  popf      pop top of stack into lower 16 bits of EFLAGS
//9d  popfd     pop top of stack into EFLAGS
VM_INSTRUCTION_ERR_CODE popf_9d(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{

    assert(pInstruction);

    ACCESS_GEN_EFLAGS_LOWER_HALF_VALUE(*pX86)= (UINT16)PopStack(pX86, pMemory, OPERAND_SIZE_16BIT);
    
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}