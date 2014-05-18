//
//文件名称：        src/ISA/Intel_x86/Instructions/aad.c
//文件描述：        Intel x86下aad指令仿真
//创建人：          劳生(laosheng@ptwy.cn)
//创建日期：        2009年8月18日
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
//2009年8月18日，劳生(laosheng@ptwy.cn)，创建

//
//更新日志：
//2009年9月28日，劳生(laosheng@ptwy.cn)，修改指令对EFLAGS的影响

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/aad.h"
#include "ISA/Intel_x86/Instructions/common.h"

//d5 0A aad     ASCII adjust AX before division
//d5 ib (No mnemonic)    adjust AX before division to number base imm8
VM_INSTRUCTION_ERR_CODE aad_d5(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uAH;
    UINT uAL;

    assert(pInstruction);
    uAL = ACCESS_GEN_AL(*pX86);    
    uAH = ACCESS_GEN_AH(*pX86);  

    ACCESS_GEN_AL(*pX86) = (UINT8) ((uAL + uAH * pInstruction->uImmediate) & 0xff);
    ACCESS_GEN_AH(*pX86) = 0;

    EVAL_EFLAGS_ZF(*pX86, (INT8)uAL);
    EVAL_EFLAGS_SF(*pX86, uAL, _8_BITS);
    //EVAL_EFLAGS_PF

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}