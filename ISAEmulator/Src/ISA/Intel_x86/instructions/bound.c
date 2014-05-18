//
//文件名称：        src/ISA/Intel_x86/Instructions/bound.c
//文件描述：        Intel x86下bound指令仿真
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

#include "ISA/Intel_x86/Instructions/bound.h"
#include "ISA/Intel_x86/Instructions/common.h"


//62 /r bound r16,m16&16         Check if r16(array index) is within bounds specified by m16&16
//62 /r bound r32,m32&32
VM_INSTRUCTION_ERR_CODE bound_62(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uBound;
    UINT uLower;
    UINT uUpper;
    UINT uEA;

    assert(pInstruction);
    uBound = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;

    uLower = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uEA += 2;
            break;
        case OT_d:
            uEA += 4;
            break;
    }

    uUpper = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);

    if (uBound < uLower || uBound > uUpper){
        //产生 异常。#BR
        return VM_INSTRUCTION_ERR_NOT_IMPLEMENTED;
    }
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}