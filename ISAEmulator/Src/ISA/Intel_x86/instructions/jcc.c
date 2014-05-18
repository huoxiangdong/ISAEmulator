//
//文件名称：        src/ISA/Intel_x86/Instructions/jcc.c
//文件描述：        Intel x86下jcc指令仿真
//创建人：          劳生(laosheng@ptwy.cn)
//创建日期：        2009年8月14日
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
//2009年10月9日，劳生(laosheng@ptwy.cn)，修改:指令对EFLAGS位的测试

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/jcc.h"
#include "ISA/Intel_x86/Instructions/common.h"


//70 cb  jo rel8     Jump short if overflow(OF=1)
VM_INSTRUCTION_ERR_CODE jo_70(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(1== GET_EFLAGS_OF_BIT(*pX86)){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//71 cb jno rel8    Jump short if not overflow(OF=0)
VM_INSTRUCTION_ERR_CODE jno_71(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(0== GET_EFLAGS_OF_BIT(*pX86)){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//72 cb      jb rel8          Jump short if below(CF=1)
//72 cb      jnae rel8        Jump short if not above or equal(CF=1)
//72 cb      jc rel8          Jump short if carry(CF=1)
VM_INSTRUCTION_ERR_CODE jb_72(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(1== GET_EFLAGS_CF_BIT(*pX86)){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//73 cb      jnb rel8        Jump  short if not below(CF=0)
//73 cb      jae rel8        Jump  short if above or equal(CF=0)
//73 cb      jnc rel8        Jump  short if not  carry(CF=0)
VM_INSTRUCTION_ERR_CODE jnb_73(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(0== GET_EFLAGS_CF_BIT(*pX86)){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//74 cb      jz rel8        Jump short if zero(ZF=1)
//74 cb      je rel8        Jump short if equal(ZF=1)
VM_INSTRUCTION_ERR_CODE jz_74(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(1== GET_EFLAGS_ZF_BIT(*pX86)){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//75 cb     jne  rel8      Jump if not equal(ZF=0) 
//75 cb     jnz  rel8      Jump if not zero(ZF=0)
VM_INSTRUCTION_ERR_CODE jnz_75(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(0== GET_EFLAGS_ZF_BIT(*pX86)){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//76 cb     jbe  rel8     Jump short if below or equal(CF=1 or ZF=1)
//76 cb     jna  rel8     Jump short if not above(CF=1 or ZF=1)
VM_INSTRUCTION_ERR_CODE jbe_76(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(1== GET_EFLAGS_CF_BIT(*pX86) || 1== GET_EFLAGS_ZF_BIT(*pX86)){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//77 cb     ja   rel8     Jump short if above(CF=0 and ZF=0)
//77 cb     jnbe rel8     Jump short if not below or equal(CF=0 or ZF=0)
VM_INSTRUCTION_ERR_CODE jnbe_77(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(0== GET_EFLAGS_CF_BIT(*pX86) || 0== GET_EFLAGS_ZF_BIT(*pX86)){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//78 cb     js   rel8     Jump short if sign(SF=1)
VM_INSTRUCTION_ERR_CODE js_78(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(1== GET_EFLAGS_SF_BIT(*pX86)){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//79 cb    jns  rel8     Jump  short if not sign(SF=0)
VM_INSTRUCTION_ERR_CODE jns_79(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(0== GET_EFLAGS_SF_BIT(*pX86)){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//7a cb    jp   rel8     Jump   short if parity(PF=1)
//7a cb    jpe   rel8     Jump  short if parity even(PF=1)
VM_INSTRUCTION_ERR_CODE jp_7a(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(1== GET_EFLAGS_PF_BIT(*pX86)){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//7b cb    jnp   rel8     Jump  short if not parity(PF=0)
//7a cb    jpo   rel8     Jump  short if parity odd(PF=0)
VM_INSTRUCTION_ERR_CODE jnp_7b(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(0== GET_EFLAGS_PF_BIT(*pX86)){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//7c cb    jl    rel8    Jump  short if less(SF!=OF)
//7c cb    jnge  rel8    Jump  short if not greater or equal(SF!=OF)
VM_INSTRUCTION_ERR_CODE jl_7c(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(GET_EFLAGS_SF_BIT(*pX86)  != GET_EFLAGS_OF_BIT(*pX86)){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//7d cb    jge  rel8     Jump  short if greater or equal(SF=OF)
//7d cb    jnl  rel8     Jump  short if not less(SF=OF)
VM_INSTRUCTION_ERR_CODE jnl_7d(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(GET_EFLAGS_SF_BIT(*pX86)  == GET_EFLAGS_OF_BIT(*pX86)){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//7e cb   jle  rel8      Jump  short if less or equal(ZF=1 or SF!=OF) 
//7e cb   jng  rel8      Jump  short if not greater(ZF=1 or SF!=OF) 
VM_INSTRUCTION_ERR_CODE jle_7e(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(1 == GET_EFLAGS_ZF_BIT(*pX86)|| GET_EFLAGS_SF_BIT(*pX86) != GET_EFLAGS_OF_BIT(*pX86)/*ZF=1 or SF!=OF*/){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//7f cb   jg   rel8       Jump short if greater(ZF=0 and SF=OF)
//7f cb   jnle rel8       Jump short if not less or equal(ZF=0 and SF=OF)
VM_INSTRUCTION_ERR_CODE jg_7f(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(0 == GET_EFLAGS_ZF_BIT(*pX86) && GET_EFLAGS_SF_BIT(*pX86) == GET_EFLAGS_OF_BIT(*pX86)/*ZF=0 and  SF=OF*/){
        ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//e3 cb   jcxz  rel8       Jump short if CX register is 0
//e3 cb   jecxz  rel8      Jump short if ECX register is 0
VM_INSTRUCTION_ERR_CODE jrcxz_e3(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    if(OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        if (0 == ACCESS_GEN_CX(*pX86)){
            ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
        }
        
    }
    else{
        if (0 == ACCESS_GEN_ECX(*pX86)){
            ACCESS_GEN_EIP(*pX86) +=  (INT8)pInstruction->uImmediate;
        }
    }

    //case 1:
    //if(ECX ==0)
    // jump
    //return 
    //
    //case2:
    //if(CX = 0)
    //  jump
    //return 
    //在支路测试时，路径测试会发现错误

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
