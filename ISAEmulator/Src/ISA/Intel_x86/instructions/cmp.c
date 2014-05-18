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
//2009年9月28日，劳生(laosheng@ptwy.cn)，修改指令对EFLAGS的影响

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/cmp.h"
#include "ISA/Intel_x86/Instructions/common.h"


//38 /r     cmp r/m8, r8
VM_INSTRUCTION_ERR_CODE cmp_38(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    uOp1 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }

    //Set Flags
    //EFLAGS Cross-Reference : Architectures Software Developer's Manual -Volume 1:Basic Architecture Appendix                                          
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);   //OF
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);                   //SF
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);                   //ZF
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                //AF
    //EVAL_EFLAGS_PF();                                        //PF
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);   //CF

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//39 /r     cmp r/m16, r16
//39 /r     cmp r/m32, r32
VM_INSTRUCTION_ERR_CODE cmp_39(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    uOp1 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }

    //Set Flags
    //EFLAGS Cross-Reference : Architectures Software Developer's Manual -Volume 1:Basic Architecture Appendix     
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);   //OF
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);                   //SF
            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);                   //ZF
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                 //AF
            //EVAL_EFLAGS_PF();                                      //PF
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);   //CF
            break;
        case OT_d:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);   //OF
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);                   //SF
            EVAL_EFLAGS_ZF(*pX86, uResult);                   //ZF
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                 //AF
            //EVAL_EFLAGS_PF();                                      //PF
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);   //CF
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//3A /r     cmp r/8, r/m8
VM_INSTRUCTION_ERR_CODE cmp_3a(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    uOp0 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }
    else{
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }

    //Set Flags                                       
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);   //OF
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);                   //SF
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);                            //ZF
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                //AF
    //EVAL_EFLAGS_PF();                                        //PF
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);   //CF

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//3B /r     cmp r16, r/m16
//3B /r     cmp r32, r/m32
VM_INSTRUCTION_ERR_CODE cmp_3b(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    uOp0 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp1 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }
    else{
        uOp1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }

    //Set Flags
    //EFLAGS Cross-Reference : Architectures Software Developer's Manual -Volume 1:Basic Architecture Appendix     
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);   //OF
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);                   //SF
            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);                             //ZF
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                 //AF
            //EVAL_EFLAGS_PF();                                         //PF
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);   //CF
            break;
        case OT_d:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);   //OF
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);                   //SF
            EVAL_EFLAGS_ZF(*pX86, uResult);                             //ZF
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                 //AF
            //EVAL_EFLAGS_PF();                                         //PF
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);   //CF
            break;
    }

    
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//3C ib     cmp al, imm8
VM_INSTRUCTION_ERR_CODE cmp_3c(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uResult;
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp0 = ACCESS_GEN_AL(*pX86);
    uOp1 = (UINT)pInstruction->uImmediate;
    uResult = uOp0 - uOp1;

    //Set Flags                                       
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);   //OF
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);                   //SF
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);                            //ZF
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                //AF
    //EVAL_EFLAGS_PF();                                        //PF
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);   //CF

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//3D iw     cmp ax, imm16
//3D id     cmp eax, imm32
VM_INSTRUCTION_ERR_CODE cmp_3d(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);

    uOp0 = ACCESS_GEN_AL(*pX86);
    uOp1 = (UINT)pInstruction->uImmediate;
    uResult = uOp0 - uOp1;
    
    //Set Flags
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);   //OF
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);                   //SF
            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);                   //ZF
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                 //AF
            //EVAL_EFLAGS_PF();                                         //PF
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);   //CF
            break;
        case OT_d:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);   //OF
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);                   //SF
            EVAL_EFLAGS_ZF(*pX86, uResult);                   //ZF
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                 //AF
            //EVAL_EFLAGS_PF();                                         //PF
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);   //CF
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//80 /7 ib cmp r/m8,imm8
VM_INSTRUCTION_ERR_CODE immediate_grp1_80_cmp(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    uOp1 = (UINT)pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }
   
    //Set Flags                                       
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);   //OF
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);                   //SF
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);                   //ZF
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                //AF
    //EVAL_EFLAGS_PF();                                        //PF
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);   //CF

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//81 /7 /iw cmp r/m32,imm16
//81 /7 /iw cmp r/m32,imm32
VM_INSTRUCTION_ERR_CODE immediate_grp1_81_cmp(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    uOp1 = (UINT)pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }

    //Set Flags
    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);   //OF
    EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);                   //SF
    EVAL_EFLAGS_ZF(*pX86, uResult);                   //ZF
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                 //AF
    //EVAL_EFLAGS_PF();                                         //PF
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);   //CF

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//83 /7 ib   cmp r/m8, imm8
//note: 2010年3月26日 杨鸿博， 未测试
VM_INSTRUCTION_ERR_CODE immediate_grp1_82_cmp(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //Test Case:
    //cmp  eax , 6
    //Correct: OV(overflow) 0 , PL(Sign) = 1 , ZR(zero) = 0 , AC(Auxiliary carry) =1  PE(parity) = 1 CY(Carry)= 1
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);
    uOp1 = (UINT)pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }

    EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);   //OF
    EVAL_EFLAGS_SF(*pX86, uResult, _8_BITS);                   //SF
    EVAL_EFLAGS_ZF(*pX86, (INT8)uResult);                   //ZF
    EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                 //AF
    //EVAL_EFLAGS_PF();                                         //PF
    EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _8_BITS);   //CF

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

 
VM_INSTRUCTION_ERR_CODE immediate_grp1_83_cmp(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //Test Case:
    //cmp  eax , 6
    //Correct: OV(overflow) 0 , PL(Sign) = 1 , ZR(zero) = 0 , AC(Auxiliary carry) =1  PE(parity) = 1 CY(Carry)= 1
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT uResult;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);
    uOp1 = (UINT)pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        uResult = uOp0 - uOp1;
    }

    //Set Flags
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);   //OF
            EVAL_EFLAGS_SF(*pX86, uResult, _16_BITS);                   //SF
            EVAL_EFLAGS_ZF(*pX86, (INT16)uResult);                   //ZF
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                 //AF
            //EVAL_EFLAGS_PF();                                         //PF
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _16_BITS);   //CF
            break;
        case OT_d:
            EVAL_EFLAGS_OF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);   //OF
            EVAL_EFLAGS_SF(*pX86, uResult, _32_BITS);                   //SF
            EVAL_EFLAGS_ZF(*pX86, uResult);                   //ZF
            EVAL_EFLAGS_AF(*pX86, uOp0, uOp1, uResult);                 //AF
            //EVAL_EFLAGS_PF();                                         //PF
            EVAL_EFLAGS_CF_SUB(*pX86, uOp0, uOp1, uResult, _32_BITS);   //CF
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
