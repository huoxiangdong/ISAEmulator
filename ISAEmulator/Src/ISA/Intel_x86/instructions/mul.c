//
//文件名称：        src/ISA/Intel_x86/Instructions/mul.c
//文件描述：        Intel x86下mul指令仿真
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

#include "ISA/Intel_x86/Instructions/mul.h"
#include "ISA/Intel_x86/Instructions/common.h"


//f6 /4 mul r/m8 unsigned multiply(AX <- AL * r/m8)
VM_INSTRUCTION_ERR_CODE unary_grp3_f6_mul(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //66 F7 E1    mul    ax,cx   汇编代码：mul cx  操作：ax= ax * cx
    //E1 : 1110 0001
    //Mod/RM == 11 001 -> cx ,

    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT Op1;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op1 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else {
        Op1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);  
    }

    ACCESS_GEN_AX(*pX86) = ACCESS_GEN_AL(*pX86) * Op1;
    //Set Flags
    if (0 ==ACCESS_GEN_AH(*pX86)){
        SET_EFLAGS_OF(*pX86, 0);
        SET_EFLAGS_CF(*pX86, 0);
    }
    else{
        SET_EFLAGS_OF(*pX86, 1);
        SET_EFLAGS_CF(*pX86, 1);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//f7 /4 mul r/m16  unsigned multiply(DX:AX <- AX * rm16)
//f7 /4 mul r/m32  unsigned multiply(EDX:EAX <- EAX * rm32)
VM_INSTRUCTION_ERR_CODE unary_grp3_f7_mul(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT64 Op1;
//    UINT64 Op2;
    UINT64 Op0;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op1 = GetMemoryValue(pX86, pMemory, uEA, OT_z, pInstruction->dwFlags);;
    }
    else {
        Op1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_z, pInstruction->dwFlags);  
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            Op0 = ACCESS_GEN_AX(*pX86)  * Op1;
            ACCESS_GEN_AX(*pX86) = Op0;
            ACCESS_GEN_DX(*pX86) = Op0 >>16;

            //If the upper half of the result is 0 then CF=OF = 0 ;otherwise CF=1 F =1
            if (0 ==ACCESS_GEN_DX(*pX86)){
                SET_EFLAGS_OF(*pX86, 0);
                SET_EFLAGS_CF(*pX86, 0);
            }
            else{
                SET_EFLAGS_OF(*pX86, 1);
                SET_EFLAGS_CF(*pX86, 1);
            }
            break;

        case OT_d:
            Op0 = ACCESS_GEN_EAX(*pX86)  * Op1;  //ACCESS_GEN_EAX(*pX86)读取到的数据为32位(union)的特性可以把看成多种类型， 
            //32*32 结果为32位的临时变量,若 32*64 则结果的临时变量为64位
            ACCESS_GEN_EAX(*pX86) = Op0;
            ACCESS_GEN_EDX(*pX86) = (UINT32)Op0 >>32;

            //If the upper half of the result is 0 then CF=OF = 0 ;otherwise CF=1 F =1
            if (0 ==ACCESS_GEN_EDX(*pX86)){
                SET_EFLAGS_OF(*pX86, 0);
                SET_EFLAGS_CF(*pX86, 0);
            }
            else{
                SET_EFLAGS_OF(*pX86, 1);
                SET_EFLAGS_CF(*pX86, 1);
            }
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
