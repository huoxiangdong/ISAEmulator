//
//文件名称：        src/ISA/Intel_x86/Instructions/sar.c
//文件描述：        Intel x86下sar指令仿真
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
//2009年10月10日，劳生(laosheng@ptwy.cn),修改： 指令对寄存器EFLAGS的影响

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/sar.h"
#include "ISA/Intel_x86/Instructions/common.h"

//Intel® 64 and IA-32 Architectures Software Developer's Manual - Volume 1- Basic Architecture
//7.3.6.1(Shift Instructions) Page 205 

//sar 用C">>"运算符实现时，当操作数为正是(0x7f,0x7fff,0x7fffffff),时会在MSB 补0，操作数为负时，会在MSB中补1

#define  GET_THE_N_BIT_VALUE(x,bits)  (((x) >> (bits -1)) & 1)
#define  MSB(x,bits)  GET_THE_N_BIT_VALUE(x,bits)

//c0 /4 ib sar r/m8 , imm8   multiply r/m8 by 2, imm8 times
VM_INSTRUCTION_ERR_CODE shift_grp2_c0_sar(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT8 Op0;
    UINT uOp1;

    assert(pInstruction);

    uOp1 = pInstruction->uImmediate;

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    uOp1 = uOp1 & 0x1f;

    if (0 < uOp1){
        if (Op0 & (1 <<(uOp1-1))){
            SET_EFLAGS_CF(*pX86, 1);
        }
        else{
            SET_EFLAGS_CF(*pX86, 0);
        }

        Op0 = Op0 >> uOp1;

        if (1 == uOp1){
            SET_EFLAGS_OF(*pX86, 0);
        }

        EVAL_EFLAGS_SF(*pX86, Op0, _8_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT8)Op0);                      //ZF
        //EVAL_EFLAGS_PF();                                    //PF
    }

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        SetMemoryValue(pX86, pMemory, uEA, Op0, OT_b, pInstruction->dwFlags);
    }
    else{
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//c1 /4 /ib sar r/m16,imm8  multiply r/m16 by 2, imm8 times
//c1 /4 /ib sar r/m32,imm8  multiply r/m32 by 2, imm8 times
VM_INSTRUCTION_ERR_CODE shift_grp2_c1_sar(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT Op0;
    UINT uOp1;

    assert(pInstruction);

    uOp1 = pInstruction->uImmediate;

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    uOp1 = uOp1 & 0x1f;

    if (0 < uOp1){
        if (Op0 & (1 <<(uOp1-1))){
            SET_EFLAGS_CF(*pX86, 1);
        }
        else{
            SET_EFLAGS_CF(*pX86, 0);
        }

        if (1 == uOp1){
            SET_EFLAGS_OF(*pX86, 0);
        }

        switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
            case OT_w:
                Op0 = (INT16)Op0;
                Op0 = Op0 >> uOp1;
                EVAL_EFLAGS_SF(*pX86, Op0, _16_BITS);                    //SF
                EVAL_EFLAGS_ZF(*pX86, (INT16)Op0);
                //EVAL_EFLAGS_PF();                                     //PF
                break;
            case OT_d:
                Op0 = Op0 >> uOp1;
                EVAL_EFLAGS_SF(*pX86, Op0, _32_BITS);                    //SF
                EVAL_EFLAGS_ZF(*pX86, Op0);
                //EVAL_EFLAGS_PF();                                     //PF
                break;
        }
        
        EVAL_EFLAGS_ZF(*pX86, Op0);                             //ZF
    }

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        SetMemoryValue(pX86, pMemory, uEA, Op0, OT_v, pInstruction->dwFlags);
    }
    else{
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//d0 /4 sar r/m8,1      multiply r/m8 by 2 , once
VM_INSTRUCTION_ERR_CODE shift_grp2_d0_sar(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT8 Op0;

    assert(pInstruction);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    } 

    SET_EFLAGS_CF(*pX86,( Op0 & 1));

    Op0 = Op0 >> 1;
    
    SET_EFLAGS_OF(*pX86, 0);

    EVAL_EFLAGS_SF(*pX86, Op0, _8_BITS);                   //SF
    EVAL_EFLAGS_ZF(*pX86, (INT8)Op0);                      //ZF
    //EVAL_EFLAGS_PF();                                    //PF

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        SetMemoryValue(pX86, pMemory, uEA, Op0 & 0xff, OT_b, pInstruction->dwFlags);
    }
    else{
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), Op0 & 0xff, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//d1 /4 sar r/m16 ,1   multiply r/m16 by 2 , once
//d1 /4 sar r/m32 ,1   multiply r/m32 by 2 , once
VM_INSTRUCTION_ERR_CODE shift_grp2_d1_sar(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT Op0;

    assert(pInstruction);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    SET_EFLAGS_CF(*pX86, (Op0 & 1));

    SET_EFLAGS_OF(*pX86, 0);

    switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
            case OT_w:
                Op0 = (INT16)Op0;
                Op0 = Op0 >> 1;
                EVAL_EFLAGS_SF(*pX86, Op0, _16_BITS);                    //SF
                EVAL_EFLAGS_ZF(*pX86, (INT16)Op0);
                //EVAL_EFLAGS_PF();                                     //PF
                break;
            case OT_d:
                Op0 = Op0 >> 1;
                EVAL_EFLAGS_SF(*pX86, Op0, _32_BITS);                    //SF
                EVAL_EFLAGS_ZF(*pX86, Op0);
                //EVAL_EFLAGS_PF();                                     //PF
                break;
    }

    EVAL_EFLAGS_ZF(*pX86, Op0);         

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        SetMemoryValue(pX86, pMemory, uEA, Op0, OT_v, pInstruction->dwFlags);
    }
    else{
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//d2 /4 sar r/m8, cl   multiply r/m8 by 2, CL times
VM_INSTRUCTION_ERR_CODE shift_grp2_d2_sar(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT8 Op0;
    UINT uOp1;

    assert(pInstruction);

    uOp1 = ACCESS_GEN_CL(*pX86);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    uOp1 = uOp1 & 0x1f;

    if (0 < uOp1){
        if (Op0 & (1 << (uOp1 - 1))){
            SET_EFLAGS_CF(*pX86, 1);
        }
        else{
            SET_EFLAGS_CF(*pX86, 0);
        }

        Op0 = Op0 >> uOp1;

        if (1 == uOp1){
            SET_EFLAGS_OF(*pX86, 0);
        }

        EVAL_EFLAGS_SF(*pX86, Op0, _8_BITS);                   //SF
        EVAL_EFLAGS_ZF(*pX86, (INT8)Op0);                      //ZF
        //EVAL_EFLAGS_PF();                                    //PF
    }

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        SetMemoryValue(pX86, pMemory, uEA, Op0, OT_b, pInstruction->dwFlags);
    }
    else{
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//d3 /4 sar r/m16, cl   multiply r/m16 by 2, CL times
//d3 /4 sar r/m32, cl   multiply r/m328 by 2, CL times
VM_INSTRUCTION_ERR_CODE shift_grp2_d3_sar(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT Op0;
    UINT uOp1;

    assert(pInstruction);

    uOp1 = ACCESS_GEN_CL(*pX86);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    uOp1 = uOp1 & 0x1f;

    if (0 < uOp1){
        if (Op0 & (1 << (uOp1 - 1))){
            SET_EFLAGS_CF(*pX86, 1);
        }
        else{
            SET_EFLAGS_CF(*pX86, 0);
        }

        Op0 = Op0 >> uOp1;

        if (1 == uOp1){
            SET_EFLAGS_OF(*pX86, 0);
        }

        switch(GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
            case OT_w:
                EVAL_EFLAGS_SF(*pX86, Op0, _16_BITS);                    //SF
                EVAL_EFLAGS_ZF(*pX86, (INT16)Op0);
                //EVAL_EFLAGS_PF();                                     //PF
                break;
            case OT_d:
                EVAL_EFLAGS_SF(*pX86, Op0, _32_BITS);                    //SF
                EVAL_EFLAGS_ZF(*pX86, Op0);
                //EVAL_EFLAGS_PF();                                     //PF
                break;
        }         
    }

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        SetMemoryValue(pX86, pMemory, uEA, Op0, OT_v, pInstruction->dwFlags);
    }
    else{
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}