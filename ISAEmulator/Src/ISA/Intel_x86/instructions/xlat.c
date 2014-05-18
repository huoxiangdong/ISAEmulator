//
//文件名称：        src/ISA/Intel_x86/Instructions/xlat.c
//文件描述：        Intel x86下xlat指令仿真
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
//2009年10月12日，劳生(laosheng@ptwy.cn),修改：对地址位数进行检测

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/xlat.h"
#include "ISA/Intel_x86/Instructions/common.h"


//D7 xlat m8  set AL to memory byte DS:[(E)BX+unsigned AL]
//D7 xlat     set AL to memory byte DS:[(E)BX+unsigned AL]
VM_INSTRUCTION_ERR_CODE xlat_d7(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uEA;
    UINT uAL; 

    assert(pInstruction);
    uAL = ACCESS_GEN_AL(*pX86);

    switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
        case OPCODE_FLAG_PREFIX_ES:
            uEA = ACCESS_GEN_ES(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_FS:
            uEA = ACCESS_GEN_FS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_GS:
            uEA = ACCESS_GEN_GS(*pX86);
            break;
        case OPCODE_FLAG_PREFIX_DS:
        default :
            uEA = ACCESS_GEN_DS(*pX86);
            break;
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
        uEA = ACCESS_GEN_BX(*pX86) + uAL;
        ACCESS_GEN_AL(*pX86) = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        break;

        case OT_d:
        uEA = ACCESS_GEN_EBX(*pX86) + uAL;
        ACCESS_GEN_AL(*pX86) = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}