//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/enter.c
//�ļ�������        Intel x86��enterָ�����
//�����ˣ�          ����(laosheng@ptwy.cn)
//�������ڣ�        2009��8��19��
//
//��˾���ƣ�        �������������Ƽ����޹�˾
//��Ŀ������
//���ܼ���
//��Ȩ������
//
//����Ŀ���ƣ�      �����������©���ھ�ƽ̨
//����Ŀ������
//����Ŀ����ʱ�䣺  2009��6��X��
//
//����Ŀ���ƣ�      �����������������
//����Ŀ������
//����Ŀ����ʱ�䣺  2009��6��X��
//
//ģ�����ƣ�        ָ�������
//����Ŀ������
//����Ŀ����ʱ�䣺  2009��6��X��

//
//������־��
//2009��8��19�գ�����(laosheng@ptwy.cn)������

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions.h"
#include "ISA/Intel_x86/Instructions/enter.h"
#include "ISA/Intel_x86/Instructions/common.h"


//����ָ�����Ʒ�ʽ���Ը߲��ָ�����֧�ֲ��á�
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
    //û�п���ջ Stack-size�Ĵ�С
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
            //uNestingLevel = 2 ....����ִ�е������
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

        //uNestingLevel = 1 ,2 ....����ִ�е������
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

    //uNestingLevel = 0 ,1 ,2 ....����ִ�е������
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