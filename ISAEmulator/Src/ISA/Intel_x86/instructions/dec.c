//
//文件名称：        src/ISA/Intel_x86/Instructions/cmp.c
//文件描述：        Intel x86下cmp指令仿真
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
//2009年8月7日，劳生(laosheng@ptwy.cn)，创建

//
//更新日志：
//2009年9月29日，劳生(laosheng@ptwy.cn)，修改指令对EFLAGS的影响

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/dec.h"
#include "ISA/Intel_x86/Instructions/common.h"

//dec ax
//dec eax
VM_INSTRUCTION_ERR_CODE dec_48(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uResult;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_AX(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_AX(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);                
        EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);
    }
    else{
        uOp0 = ACCESS_GEN_EAX(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_EAX(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);                
        EVAL_EFLAGS_ZF(*pX86, uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//dec cx
//dec ecx
VM_INSTRUCTION_ERR_CODE dec_49(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uResult;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_CX(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_CX(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);                
        EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);
    }
    else{
        uOp0 = ACCESS_GEN_ECX(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_ECX(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);                
        EVAL_EFLAGS_ZF(*pX86, uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//dec dx
//dec edx
VM_INSTRUCTION_ERR_CODE dec_4a(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uResult;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_DX(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_DX(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);                
        EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);
    }
    else{
        uOp0 = ACCESS_GEN_EDX(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_EDX(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);                
        EVAL_EFLAGS_ZF(*pX86, uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//dec bx
//dec ebx
VM_INSTRUCTION_ERR_CODE dec_4b(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uResult;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_BX(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_BX(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);                
        EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);
    }
    else{
        uOp0 = ACCESS_GEN_EBX(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_EBX(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);                
        EVAL_EFLAGS_ZF(*pX86, uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//dec sp
//dec esp
VM_INSTRUCTION_ERR_CODE dec_4c(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uResult;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_SP(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_SP(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);                
        EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);
    }
    else{
        uOp0 = ACCESS_GEN_ESP(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_ESP(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);                
        EVAL_EFLAGS_ZF(*pX86, uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//dec bp
//dec ebp
VM_INSTRUCTION_ERR_CODE dec_4d(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uResult;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_BP(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_BP(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);                
        EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);
    }
    else{
        uOp0 = ACCESS_GEN_EBP(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_EBP(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);                
        EVAL_EFLAGS_ZF(*pX86, uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//dec si
//dec esi
VM_INSTRUCTION_ERR_CODE dec_4e(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uResult;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_SI(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_SI(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);                
        EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);
    }
    else{
        uOp0 = ACCESS_GEN_ESI(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_ESI(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);                
        EVAL_EFLAGS_ZF(*pX86, uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//dec di
//dec edi
VM_INSTRUCTION_ERR_CODE dec_4f(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uResult;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_DI(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_DI(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);                
        EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _16_BITS);
    }
    else{
        uOp0 = ACCESS_GEN_EDI(*pX86); 
        uResult = uOp0 - 1;
        ACCESS_GEN_EDI(*pX86) = uResult;

        EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);   
        EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);                
        EVAL_EFLAGS_ZF(*pX86, uResult);                
        EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
        //EVAL_EFLAGS_PF();                                      
        EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _32_BITS);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//dec r/m8
VM_INSTRUCTION_ERR_CODE inc_dec_grp4_fe_dec(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uResult;

    assert(pInstruction);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - 1;
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - 1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, _8_BITS);   
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);                
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);                
    EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
    //EVAL_EFLAGS_PF();                                      
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, _8_BITS);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//dec r/m16
//dec r/m32
//notes: 2010年3月29日，杨鸿博， 增加：dec r16/32的处理，并修改标志位设置逻辑
VM_INSTRUCTION_ERR_CODE inc_dec_grp5_ff_dec(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uResult;
    UINT uOpBits = 0;

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - 1;
        SetMemoryValue(pX86, pMemory, uEA, uResult, OT_v, pInstruction->dwFlags);
    }
    else{
        //不会执行 dec r16 或者 r32 时 执行 4_X 系列的DEC
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - 1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uResult, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }


    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags)
                uOpBits = _16_BITS;
            else
                uOpBits = _32_BITS;
            break;
        case OT_d:
            if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags)
                uOpBits = _32_BITS;
            else
                uOpBits = _16_BITS;
            break;
        default:
            assert(0);//should not be here
            break;
    }

    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, 1, uResult, uOpBits);   
    EVAL_EFLAGS_SF(*pX86, uResult, uOpBits);                
    EVAL_EFLAGS_ZF(*pX86, (_16_BITS == uOpBits)?((INT16)uResult):uResult);
    EVAL_EFLAGS_AF(*pX86, uOp0, 1, uResult);              
    //EVAL_EFLAGS_PF();                                      
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, 1, uResult, uOpBits);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
