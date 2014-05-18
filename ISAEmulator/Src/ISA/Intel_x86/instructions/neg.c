//
//文件名称：        src/ISA/Intel_x86/Instructions/neg.c
//文件描述：        Intel x86下neg指令仿真
//创建人：          劳生(laosheng@ptwy.cn)
//创建日期：        2009年8月7日
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
//2009年8月12日，劳生(laosheng@ptwy.cn)，创建

//
//更新日志：
//2009年10月9日，劳生(laosheng@ptwy.cn),修改：指令的对EFLAGS寄存器的影响

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/neg.h"
#include "ISA/Intel_x86/Instructions/common.h"

//f6 /3 neg r/m8
VM_INSTRUCTION_ERR_CODE unary_grp3_f6_neg(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //F6 DB     neg    bl  汇编代码：neg bl 
    //DB : 1101 1011
    //Mod/RM == 11 011 -> bl

    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uOp1 = 0;
        uResult = uOp1 - uOp0;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }
    else {
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uOp1 = 0;
        uResult = uOp1 - uOp0;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    if (0 ==uOp0){
        SET_EFLAGS_CF(*pX86 , 0);
    }
    else{
        SET_EFLAGS_CF(*pX86 , 1);
    }

    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult); 

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//f7 /3 neg r/m16
//f7 /3 neg r/m32
VM_INSTRUCTION_ERR_CODE unary_grp3_f7_neg(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uOp1 = 0;
        uResult = uOp1 - uOp0;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    else {
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uOp1 = 0;
        uResult = uOp1 - uOp0;
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    //Set Flags
    if (0 ==uOp0){
        SET_EFLAGS_CF(*pX86 , 0);
    }
    else{
        SET_EFLAGS_CF(*pX86 , 1);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult); 
            break;

        case OT_d:
            EVAL_EFLAGS_ZF(*pX86, uResult);
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult); 
            break;
    }
    
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
