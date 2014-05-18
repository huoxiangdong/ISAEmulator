//
//文件名称：        src/ISA/Intel_x86/Instructions/daa.c
//文件描述：        Intel x86下daa指令仿真
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
//2009年9月29日，劳生(laosheng@ptwy.cn)，修改指令对EFLAGS的影响

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/daa.h"
#include "ISA/Intel_x86/Instructions/common.h"

//2f  daa      Decimal adjust AL after subtraction
VM_INSTRUCTION_ERR_CODE daa_27(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOldAL;
    UINT uOldCF;
    UINT uOp0;
    UINT uSum;

    assert(pInstruction);

    uOldAL = ACCESS_GEN_AL(*pX86);
    uOldCF = GET_EFLAGS_CF_BIT(*pX86);
    SET_EFLAGS_CF(*pX86 ,0);


    if ((ACCESS_GEN_AL(*pX86) & 0x0f) > 9 ||  1 == GET_EFLAGS_AF_BIT(*pX86)){
        uOp0 = ACCESS_GEN_AL(*pX86);
        uSum = uOp0 + 6;
        ACCESS_GEN_AL(*pX86) = uSum;

        //CF <- old_CF or Carry from AL<- AL + 6
        SET_EFLAGS_CF(*pX86, uOldCF);
        if (1 != GET_EFLAGS_CF_BIT(*pX86)){
            EVAL_EFLAGS_CF_ADD(*pX86, uOp0, 6, uSum, _8_BITS);
        }
        
        SET_EFLAGS_AF(*pX86, 1);
    }
    else{
        SET_EFLAGS_AF(*pX86, 0);
    }

    if (uOldAL > 0x99 || 1 == uOldCF /* old_CF = 1*/){
        ACCESS_GEN_AL(*pX86) += 0x60;
        SET_EFLAGS_CF(*pX86, 1);
        //ACCESS_GEN_AL(*pX86)  &= 0x0f; 使高四位为0 (unpacked BCD)
    }
    else{
        SET_EFLAGS_CF(*pX86, 0);
        //ACCESS_GEN_AL(*pX86)  &= 0x0f; 使高四位为0 (unpacked BCD)
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}