//
//文件名称：        src/ISA/Intel_x86/Instructions/idiv.c
//文件描述：        Intel x86下idiv指令仿真
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
//2009年10月28日，劳生(laosheng@ptwy.cn)，修改：idiv指令的Bug

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/idiv.h"
#include "ISA/Intel_x86/Instructions/common.h"


//f6 /7 idiv r/m8 Signed divide Ax by r/m8 , with result stored in:AL <- Quotient , AH <- Remainder
VM_INSTRUCTION_ERR_CODE unary_grp3_f6_idiv(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT8 i8Divisor;
    INT16 i16Dividend;
    INT8 i8Quotient;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        i8Divisor = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else {
        i8Divisor = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);  
    }

    if (0 == i8Divisor){
        // return Error ， Error 没有定义
    }

    i16Dividend = ACCESS_GEN_AX(*pX86);

    if(0 == i8Divisor){
        return VM_INSTRUCTION_ERR_DIVIDE_BY_ZERO;
    }
    i8Quotient = i16Dividend / i8Divisor;
    if (0x7f<i8Quotient || i8Quotient < -128){
        return VM_INSTRUCTION_ERR_INTEGER_OVERFLOW;
    }
    ACCESS_GEN_AL(*pX86) = i8Quotient ; 
    ACCESS_GEN_AH(*pX86) = i16Dividend % i8Divisor;

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//f7 /7   idiv   r/m16
//f7 /7   idiv   r/m32
VM_INSTRUCTION_ERR_CODE unary_grp3_f7_idiv(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT Op1;
    UINT64 u64Dividend;
    INT iQuotient;
    INT16 i16Divisor ;
    INT i31Divisor ;
    INT iINT_MAX = 2147483647;
    INT iINT_MIN = -2147483648;
/*    INT64  iConstant = -2147483647 - 1;*/

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

    if (0 == Op1){
        return VM_INSTRUCTION_ERR_DIVIDE_BY_ZERO;
    }

    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        u64Dividend = ACCESS_GEN_DX(*pX86);
        u64Dividend = (u64Dividend << 16) + ACCESS_GEN_AX(*pX86);
        i16Divisor  = Op1;

        iQuotient = (INT16) ((INT64)u64Dividend / i16Divisor) ;

        if (0x7fff < iQuotient || iQuotient < -32768){
            return VM_INSTRUCTION_ERR_INTEGER_OVERFLOW;
        }

        ACCESS_GEN_AX(*pX86) = (UINT16)iQuotient ;
        ACCESS_GEN_DX(*pX86) = (UINT16)((INT64)u64Dividend % i16Divisor );
    }
    else{
        u64Dividend = ACCESS_GEN_EDX(*pX86);
        u64Dividend = (u64Dividend << 32) + ACCESS_GEN_EAX(*pX86);
        i31Divisor = (INT)Op1;

        iQuotient =(INT) ((INT64)u64Dividend / i31Divisor);

        if (iINT_MAX < iQuotient || iQuotient < iINT_MIN ){
            return VM_INSTRUCTION_ERR_INTEGER_OVERFLOW;
        }

        ACCESS_GEN_EAX(*pX86) = (UINT32)iQuotient ;
        ACCESS_GEN_EDX(*pX86) = (UINT32)((INT64)u64Dividend % i31Divisor);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
