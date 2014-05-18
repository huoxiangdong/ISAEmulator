//
//文件名称：        src/ISA/Intel_x86/Instructions/enter.c
//文件描述：        Intel x86下enter指令仿真
//创建人：          劳生(laosheng@ptwy.cn)
//创建日期：        2009年8月19日
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
//2009年8月19日，劳生(laosheng@ptwy.cn)，创建

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions.h"
#include "ISA/Intel_x86/Instructions/enter.h"
#include "ISA/Intel_x86/Instructions/common.h"


//这种指令的设计方式，对高层的指令，复用支持不好。
//c8 iw 00 enter imm16,0
//c8 iw 01 enter imm16,1
//c8 iw ib enter imm16,imm8
VM_INSTRUCTION_ERR_CODE enter_c8(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //Example :   C8 04 11 22    enter  1104h,22h
    //uImmediate :0x00221104
    UINT16  uImm16;             //0x1104
    UINT16  uNestingLevel;      //0x0022
    UINT    uFremeTemp;
    INT i;

    assert(pInstruction);

    uImm16 = (UINT16)pInstruction->uImmediate;
    uNestingLevel = (UINT16)(pInstruction->uImmediate >>16);
    uNestingLevel = uNestingLevel % 32;

    //SetMemoryValue Bug,
    //没有考虑栈 Stack-size的大小
    if (pMemory->StackSegment.uSegmentDescriptor[1] & SEGMENT_DESCRIPTOR_MASK_DB){
        //StackSize 32bit
        PushStack(pX86, pMemory,ACCESS_GEN_EBP(*pX86), OPERAND_SIZE_32BIT);
        uFremeTemp = ACCESS_GEN_ESP(*pX86);
    }
    else{
        PushStack(pX86, pMemory,ACCESS_GEN_BP(*pX86), OPERAND_SIZE_16BIT);
        uFremeTemp = ACCESS_GEN_SP(*pX86);
    }

    if (0 != uNestingLevel){
        if (1 < uNestingLevel){
            //uNestingLevel = 2 ....都能执行到的语句
            for(i = 1; i <= uNestingLevel - 1; i++){
                if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
                    //Operand-size == 16
                    if (pMemory->StackSegment.uSegmentDescriptor[1] & SEGMENT_DESCRIPTOR_MASK_DB){
                        //StackSize == 32 Bit;
                        ACCESS_GEN_EBP(*pX86) -= 2;
                        PushStack(pX86, pMemory,ACCESS_GEN_EBP(*pX86), OPERAND_SIZE_16BIT);
                    }
                    else{
                        //StackSize == 16 Bit;
                        ACCESS_GEN_BP(*pX86) -= 2;
                        PushStack(pX86, pMemory,ACCESS_GEN_BP(*pX86), OPERAND_SIZE_16BIT);
                    }
                }
                else{
                    //Operand-size == 32
                    if (pMemory->StackSegment.uSegmentDescriptor[1] & SEGMENT_DESCRIPTOR_MASK_DB){
                        //StackSize == 32 Bit;
                        ACCESS_GEN_EBP(*pX86) -= 4;
                        PushStack(pX86, pMemory,ACCESS_GEN_EBP(*pX86), OPERAND_SIZE_32BIT);
                    }
                    else{
                        //StackSize == 16 Bit;
                        ACCESS_GEN_BP(*pX86) -= 4;
                        PushStack(pX86, pMemory,ACCESS_GEN_BP(*pX86), OPERAND_SIZE_32BIT);
                    }
                }
            }
        }

        //uNestingLevel = 1 ,2 ....都能执行到的语句
        //SetMemoryValue Bug ,
        if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
            //OperandSize = 16
            PushStack(pX86, pMemory, uFremeTemp, OPERAND_SIZE_16BIT);
        }
        else{
            //OperandSize = 32
            PushStack(pX86, pMemory, uFremeTemp, OPERAND_SIZE_32BIT);
        }
    }

    //uNestingLevel = 0 ,1 ,2 ....都能执行到的语句
    if (pMemory->StackSegment.uSegmentDescriptor[1] & SEGMENT_DESCRIPTOR_MASK_DB){
        //StackSize = 32
        ACCESS_GEN_EBP(*pX86) = uFremeTemp;
        ACCESS_GEN_ESP(*pX86) -= uImm16;
    }
    else{
        //StackSize = 16
        ACCESS_GEN_BP(*pX86) = (UINT16)uFremeTemp;
        ACCESS_GEN_SP(*pX86) -= uImm16;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}