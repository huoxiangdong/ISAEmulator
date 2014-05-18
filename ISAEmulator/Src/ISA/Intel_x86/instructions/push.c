//
//文件名称：        src/ISA/Intel_x86/Instructions/push.c
//文件描述：        Intel x86下push指令仿真
//创建人：          劳生(laosheng@ptwy.cn)
//创建日期：        2009年8月17日
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
//2009年8月17日，劳生(laosheng@ptwy.cn)，创建

//
//更新日志：
//2009年10月10日，劳生(laosheng@ptwy.cn),修改：操作数的大小、栈地址大小的检测

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/push.h"
#include "ISA/Intel_x86/Instructions/common.h"


//06, push es.
VM_INSTRUCTION_ERR_CODE push_06(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_ES(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_ES(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//0E        push cs
VM_INSTRUCTION_ERR_CODE push_0e(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_CS(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_CS(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//16, push ss.
VM_INSTRUCTION_ERR_CODE push_16(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_SS(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_SS(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//1E        push ds
VM_INSTRUCTION_ERR_CODE push_1e(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_DS(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_DS(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//50        push rAX/r8, d64
VM_INSTRUCTION_ERR_CODE push_50(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_AX(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_EAX(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//51        push rCX/r9, d64
VM_INSTRUCTION_ERR_CODE push_51(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{

    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_CX(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_ECX(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//52        push rDX/r10, d64
VM_INSTRUCTION_ERR_CODE push_52(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_DX(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_EDX(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//53        push rBX/r11, d64
VM_INSTRUCTION_ERR_CODE push_53(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_BX(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_EBX(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//54        push rSP/r12, d64
VM_INSTRUCTION_ERR_CODE push_54(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{

    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_SP(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_ESP(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//55        push rBP, d64
VM_INSTRUCTION_ERR_CODE push_55(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_BP(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_EBP(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//56        push rSI, d64
VM_INSTRUCTION_ERR_CODE push_56(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_SI(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_ESI(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//57        push rDI, d64
VM_INSTRUCTION_ERR_CODE push_57(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_DI(*pX86), OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_EDI(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//68       push imm32, d64
VM_INSTRUCTION_ERR_CODE push_68(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //UINT uEA;
    INT  Op1;

    assert(pInstruction);

    Op1 = pInstruction->uImmediate;

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,Op1, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,Op1, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//6A       push imm8, d64
VM_INSTRUCTION_ERR_CODE push_6a(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //UINT uEA;
    INT  Op1;

    assert(pInstruction);
   
    Op1 = pInstruction->uImmediate;

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,Op1, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,Op1, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//60  pusha in 16-bit mode, pushad when the operand-size attribute is 16
VM_INSTRUCTION_ERR_CODE pusha_60(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,ACCESS_GEN_AX(*pX86), OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_CX(*pX86), OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_DX(*pX86), OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_BX(*pX86), OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,0xcc, OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_BP(*pX86), OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_SI(*pX86), OPERAND_SIZE_16BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_DI(*pX86), OPERAND_SIZE_16BIT);
            break;

        case OT_d:
            PushStack(pX86, pMemory,ACCESS_GEN_EAX(*pX86), OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_ECX(*pX86), OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_EDX(*pX86), OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_EBX(*pX86), OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,0xcccccccc, OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_EBP(*pX86), OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_ESI(*pX86), OPERAND_SIZE_32BIT);
            PushStack(pX86, pMemory,ACCESS_GEN_EDI(*pX86), OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;

}

//GS FS ZeroExtend  
//ff /6 r/m16
//ff /6 r/m32
VM_INSTRUCTION_ERR_CODE inc_dec_grp5_ff_push(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uEA1;
    INT  Op0;

    assert(pInstruction);

    //取得要压栈的数据
    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA1);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetMemoryValue(pX86, pMemory, uEA1, OT_b, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            PushStack(pX86, pMemory,Op0, OPERAND_SIZE_16BIT);
            break;
        case OT_d:
            PushStack(pX86, pMemory,Op0, OPERAND_SIZE_32BIT);
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
