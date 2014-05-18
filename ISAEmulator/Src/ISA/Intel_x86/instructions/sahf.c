//
//文件名称：        src/ISA/Intel_x86/Instructions/sahf.c
//文件描述：        Intel x86下sahf指令仿真
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

#include "ISA/Intel_x86/Instructions/sahf.h"
#include "ISA/Intel_x86/Instructions/common.h"

//9e   sahf   loads SF,ZF,AF,PF,and CF from AH into EFLAGS register
VM_INSTRUCTION_ERR_CODE sahf_9e(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    INT  Op0;
    assert(pInstruction);

    Op0 = ACCESS_GEN_AH(*pX86);
/*
*/
    //bit:0 of AH     CF
    if (Op0 & 0x1){
        SET_EFLAGS_CF(*pX86, 1);
    }
    // bit:2 of AH    PF
    if (Op0 & 0x4){
        //
    }

    // bit:4 of AH    AF
    if (Op0 & 0x10){
        SET_EFLAGS_AF(*pX86, 1);
    }

    // bit:6 of AH    ZF
    if (Op0 & 0x40){
        SET_EFLAGS_ZF(*pX86, 1);
    }

    // bit:7 of AH    SF
    if (Op0 & 0x80){
        SET_EFLAGS_SF(*pX86, 1);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}