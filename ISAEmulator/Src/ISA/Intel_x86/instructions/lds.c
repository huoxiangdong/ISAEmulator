//
//文件名称：        src/ISA/Intel_x86/Instructions/lds.c
//文件描述：        Intel x86下lds指令仿真
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

#include "ISA/Intel_x86/Instructions/lds.h"
#include "ISA/Intel_x86/Instructions/common.h"

//c5 /r lds r16,m16:16
//c5 /r lds r16,m16:32
VM_INSTRUCTION_ERR_CODE lds_c5(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT64  Op0;

    assert(pInstruction);

        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
    Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_p, pInstruction->dwFlags);  // 48 or 32

    SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM),(UINT)Op0, GENERAL_REGISTER, OT_p, pInstruction->dwFlags);
    ACCESS_GEN_DS(*pX86) =(UINT16) (Op0 >> 32);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
