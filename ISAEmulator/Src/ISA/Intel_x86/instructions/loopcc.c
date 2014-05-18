//
//文件名称：        src/ISA/Intel_x86/Instructions/loopcc.c
//文件描述：        loopcc指令实现
//创建人：          劳生(laosheng@ptwy.cn)
//创建日期：        2009年8月3日
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
//2009年8月13日，劳生(laosheng@ptwy.cn)，创建

//
//更新日志：
//2009年10月9日，劳生(laosheng@ptwy.cn)，修改:指令中使用EFLAGS的值

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/loopcc.h"
#include "ISA/Intel_x86/Instructions/common.h"

//e0 cb  loopne rel8    Decrement count; jump short if count !=0 and ZF =0
VM_INSTRUCTION_ERR_CODE loopcc_e0(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        ACCESS_GEN_CX(*pX86) -= 1;
        if (0 != ACCESS_GEN_CX(*pX86) && 0==GET_EFLAGS_ZF_BIT(*pX86)){
            ACCESS_GEN_EIP(*pX86) += (INT8)pInstruction->uImmediate; 
        }
    }else{
        ACCESS_GEN_ECX(*pX86) -= 1;
        if (0 != ACCESS_GEN_ECX(*pX86) && 0==GET_EFLAGS_ZF_BIT(*pX86)){
            ACCESS_GEN_EIP(*pX86) += (INT8)pInstruction->uImmediate; 
        }
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//e1 cb  loope rel8    Decrement count; jump short if count !=0 and ZF =1
VM_INSTRUCTION_ERR_CODE loopcc_e1(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        ACCESS_GEN_CX(*pX86) -= 1;
        if (0 != ACCESS_GEN_CX(*pX86) && 1==GET_EFLAGS_ZF_BIT(*pX86)){
            ACCESS_GEN_EIP(*pX86) += (INT8)pInstruction->uImmediate; 
        }
    }else{
        ACCESS_GEN_ECX(*pX86) -= 1;
        if (0 != ACCESS_GEN_ECX(*pX86) && 1==GET_EFLAGS_ZF_BIT(*pX86)){
            ACCESS_GEN_EIP(*pX86) += (INT8)pInstruction->uImmediate; 
        }
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//e2 cb  loop rel8    Decrement count; jump short if count !=0 
VM_INSTRUCTION_ERR_CODE loopcc_e2(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if (ADDRESS_SIZE_16BIT ==pX86->AddrSize){
        ACCESS_GEN_CX(*pX86) -= 1;
        if (0 != ACCESS_GEN_CX(*pX86)){
            ACCESS_GEN_EIP(*pX86) += (INT8)pInstruction->uImmediate; 
        }
    }else{
        ACCESS_GEN_ECX(*pX86) -= 1;
        if (0 != ACCESS_GEN_ECX(*pX86)){
            ACCESS_GEN_EIP(*pX86) += (INT8)pInstruction->uImmediate; 
        }
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
