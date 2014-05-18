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
//2009年10月9日，劳生(laosheng@ptwy.cn)，修改指令对EFLAGS的影响


#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/inc.h"
#include "ISA/Intel_x86/Instructions/common.h"

//inc ax
//inc eax
VM_INSTRUCTION_ERR_CODE inc_40(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    //根据前缀 66 选择 ex ,eax 
    //不能不根据前缀，统一用 eax += 1; 因为 ax += 1 有溢出时， 溢出位 丢失。而此时用eax时，进位在第17位
    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_AX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_AX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                      //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_EAX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_AX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//inc cx
//inc ecx
VM_INSTRUCTION_ERR_CODE inc_41(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_CX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_CX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                      //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_ECX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_ECX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//inc dx
//inc edx
VM_INSTRUCTION_ERR_CODE inc_42(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_DX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_DX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                      //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_EDX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_EDX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//inc bx
//inc ebx
VM_INSTRUCTION_ERR_CODE inc_43(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_BX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_BX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_EBX(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_EBX(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//inc sp
//inc esp
VM_INSTRUCTION_ERR_CODE inc_44(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_SP(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_SP(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_ESP(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_ESP(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//inc bp
//inc ebp
VM_INSTRUCTION_ERR_CODE inc_45(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_BP(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_BP(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_EBP(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_EBP(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//inc si
//inc esi
VM_INSTRUCTION_ERR_CODE inc_46(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_SI(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_SI(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_ESI(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_ESI(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//inc di
//inc edi
VM_INSTRUCTION_ERR_CODE inc_47(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        uOp0 = ACCESS_GEN_DI(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_DI(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        uOp0 = ACCESS_GEN_EDI(*pX86); 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        ACCESS_GEN_EDI(*pX86) = uSum;

        //set Flag 
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//fe /1 inc r/m8
VM_INSTRUCTION_ERR_CODE inc_dec_grp4_fe_inc(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //FE C2       inc   dl   
    //C2 : 1100 0010
    //Mod/RM == 11 010 -> dl , 

    //FE C4       inc   ah 
    //C2 : 1100 0100
    //Mod/RM == 11 100 -> ah , 

    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uSum & 0xff, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);; 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    //set Flag 
    EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _8_BITS);   //OF
    EVAL_EFLAGS_SF(*pX86, uSum, _8_BITS);                   //SF
    EVAL_EFLAGS_ZF(*pX86, (INT8)uSum);                             //ZF
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
    //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
 
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//ff/1 inc r/m16
//ff/1 inc r/m32
VM_INSTRUCTION_ERR_CODE inc_dec_grp5_ff_inc(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uSum;
    assert(pInstruction);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        SetMemoryValue(pX86, pMemory, uEA, uSum, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);; 
        uOp1 = 1;
        uSum = uOp0 + uOp1;
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uSum, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _16_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _16_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT16)uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }
    else{
        EVAL_EFLAGS_OF_ADD(*pX86, uOp0, uOp1, uSum, _32_BITS);   //OF
        EVAL_EFLAGS_SF(*pX86, uSum, _32_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, uSum);                             //ZF
        EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uSum);                 //AF
        //SET_EFLAGS_PF(*pX86, 0 == uSum);                       //PF
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
