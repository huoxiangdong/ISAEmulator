//
//文件名称：        src/ISA/Intel_x86/Instructions/das.c
//文件描述：        Intel x86下das指令仿真
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
//2009年9月29日，劳生(laosheng@ptwy.cn)，修改指令对EFLAGS的影响

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/das.h"
#include "ISA/Intel_x86/Instructions/common.h"

VM_INSTRUCTION_ERR_CODE das_2f(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOldAL;
    UINT uOldCF;
    UINT uOp0;
    UINT uResult;

    assert(pInstruction);

    uOldAL = ACCESS_GEN_AL(*pX86);
    uOldCF = GET_EFLAGS_CF_BIT(*pX86);
    SET_EFLAGS_CF(*pX86 ,0);


    if ((ACCESS_GEN_AL(*pX86) & 0x0f) > 9 ||  1 == GET_EFLAGS_AF_BIT(*pX86)){
        uOp0 = ACCESS_GEN_AL(*pX86);
        uResult = uOp0 - 6;
        ACCESS_GEN_AL(*pX86) = uResult;

        //CF <- old_CF or Borrow from AL<- AL + 6
        SET_EFLAGS_CF(*pX86, uOldCF);
        if (1 != GET_EFLAGS_CF_BIT(*pX86)){
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 6, uResult, _8_BITS);
        }

        SET_EFLAGS_AF(*pX86, 1);
    }
    else{
        SET_EFLAGS_AF(*pX86, 0);
    }

    if (uOldAL > 0x99 || 1 == uOldCF /* old_CF = 1*/){
        ACCESS_GEN_AL(*pX86) -= 0x60;
        SET_EFLAGS_CF(*pX86, 1);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}