//
//文件名称：        src/ISA/Intel_x86/Instructions/mov.c
//文件描述：        mov指令实现
//创建人：          杨鸿博(yanghongbo@ptwy.cn)
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
//2009年8月3日，杨鸿博(yanghongbo@ptwy.cn)，创建

//
//更新日志：
//2009年10月9日，劳生(laosheng@ptwy.cn)，修改:指令中使用EFLAGS的值

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/mov.h"
#include "ISA/Intel_x86/Instructions/common.h"

//a0    mov al,moffset8                                                                                                                                                                                                                                           add r/m8, r8
VM_INSTRUCTION_ERR_CODE mov_a0(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uEA;
    INT Op1;

    assert(pInstruction);
    Op1 = (INT)pInstruction->uImmediate;

    switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
        case OPCODE_FLAG_PREFIX_ES:
            uEA = ACCESS_GEN_ES(*pX86) + Op1;
            break;
        case OPCODE_FLAG_PREFIX_FS:
            uEA = ACCESS_GEN_FS(*pX86) + Op1;
            break;
        case OPCODE_FLAG_PREFIX_GS:
            uEA = ACCESS_GEN_GS(*pX86) + Op1;
            break;
        case OPCODE_FLAG_PREFIX_DS:
        default :
            uEA = ACCESS_GEN_DS(*pX86) + Op1;
            break;
    }
    
    ACCESS_GEN_AL(*pX86) = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}



//a1    mov ax,moffset16
//a1    mov eax,moffset32
VM_INSTRUCTION_ERR_CODE mov_a1(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uEA;
    INT Op1;

    assert(pInstruction);
    Op1 = (INT)pInstruction->uImmediate;

    switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
        case OPCODE_FLAG_PREFIX_ES:
            uEA = ACCESS_GEN_ES(*pX86) + Op1;
            break;
        case OPCODE_FLAG_PREFIX_FS:
            uEA = ACCESS_GEN_FS(*pX86) + Op1;
            break;
        case OPCODE_FLAG_PREFIX_GS:
            uEA = ACCESS_GEN_GS(*pX86) + Op1;
            break;
        case OPCODE_FLAG_PREFIX_DS:
        default :
            uEA = ACCESS_GEN_DS(*pX86) + Op1;
            break;
    }

    Op1 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            ACCESS_GEN_AX(*pX86) = Op1;
            break;

        case OT_d:
            ACCESS_GEN_EAX(*pX86) = Op1;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//a2    mov moffset8, AL
VM_INSTRUCTION_ERR_CODE mov_a2(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uEA;
    INT Op1;

    assert(pInstruction);
    Op1 = (INT)pInstruction->uImmediate;

    switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
        case OPCODE_FLAG_PREFIX_ES:
            uEA = ACCESS_GEN_ES(*pX86) + Op1;
            break;
        case OPCODE_FLAG_PREFIX_FS:
            uEA = ACCESS_GEN_FS(*pX86) + Op1;
            break;
        case OPCODE_FLAG_PREFIX_GS:
            uEA = ACCESS_GEN_GS(*pX86) + Op1;
            break;
        case OPCODE_FLAG_PREFIX_DS:
        default :
            uEA = ACCESS_GEN_DS(*pX86) + Op1;
            break;
    }

    SetMemoryValue(pX86, pMemory, uEA, ACCESS_GEN_AL(*pX86) , OT_b, pInstruction->dwFlags);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//a3    mov moffset16, ax
//a3    mov moffset32, eax
VM_INSTRUCTION_ERR_CODE mov_a3(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uEA;
    INT Op1;

    assert(pInstruction);
    Op1 = (INT)pInstruction->uImmediate;

    switch(OPCODE_FLAG_PREFIX_GROUP2_MASK(pInstruction->dwFlags)){
        case OPCODE_FLAG_PREFIX_ES:
            uEA = ACCESS_GEN_ES(*pX86) + Op1;
            break;
        case OPCODE_FLAG_PREFIX_FS:
            uEA = ACCESS_GEN_FS(*pX86) + Op1;
            break;
        case OPCODE_FLAG_PREFIX_GS:
            uEA = ACCESS_GEN_GS(*pX86) + Op1;
            break;
        case OPCODE_FLAG_PREFIX_DS:
        default :
            uEA = ACCESS_GEN_DS(*pX86) + Op1;
            break;
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
             Op1 = ACCESS_GEN_AX(*pX86);
            break;

        case OT_d:
            Op1 = ACCESS_GEN_EAX(*pX86);
            break;
    }

    SetMemoryValue(pX86, pMemory, uEA, Op1, OT_v, pInstruction->dwFlags);

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//b0    mov al, imm8     //修改者：劳生  2009年8月5日     //修改注释                                                                                                                                                                                                                                  add r/m8, r8
VM_INSTRUCTION_ERR_CODE mov_b0(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);
    ACCESS_GEN_AL(*pX86) = (BYTE)pInstruction->uImmediate;

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//b1    mov cl, imm8
VM_INSTRUCTION_ERR_CODE mov_b1(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);
    ACCESS_GEN_CL(*pX86) = (BYTE)pInstruction->uImmediate;

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//b2    mov dl, imm8
VM_INSTRUCTION_ERR_CODE mov_b2(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);
    ACCESS_GEN_DL(*pX86) = (BYTE)pInstruction->uImmediate;

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//b3    mov bl, imm8
VM_INSTRUCTION_ERR_CODE mov_b3(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);
    ACCESS_GEN_BL(*pX86) = (BYTE)pInstruction->uImmediate;

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//b4    mov ah, imm8
VM_INSTRUCTION_ERR_CODE mov_b4(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);
    ACCESS_GEN_AH(*pX86) = (BYTE)pInstruction->uImmediate;

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//b5    mov ch, imm8
VM_INSTRUCTION_ERR_CODE mov_b5(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);
    ACCESS_GEN_CH(*pX86) = (BYTE)pInstruction->uImmediate;

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//b6    mov dh, imm8
VM_INSTRUCTION_ERR_CODE mov_b6(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);
    ACCESS_GEN_DH(*pX86) = (BYTE)pInstruction->uImmediate;

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//b7    mov bh, imm8
VM_INSTRUCTION_ERR_CODE mov_b7(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);
    ACCESS_GEN_BH(*pX86) = (BYTE)pInstruction->uImmediate;

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//b8 + rd   eax , ax
//B8 + rd   mov r16, im16
//B8 + rd   mov r32, im32
VM_INSTRUCTION_ERR_CODE mov_b8(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            assert(pInstruction->uImmediate <= 0xffff);
            ACCESS_GEN_AX(*pX86) = (UINT16)pInstruction->uImmediate;
            break;
        case OT_d:
            assert(pInstruction->uImmediate <= 0xffffffff);
            ACCESS_GEN_EAX(*pX86) = pInstruction->uImmediate;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//b9 + rd   ecx , cx 
//B8 + rd   mov r16, im16
//B8 + rd   mov r32, im32
VM_INSTRUCTION_ERR_CODE mov_b9(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            assert(pInstruction->uImmediate <= 0xffff);
            ACCESS_GEN_CX(*pX86) = (UINT16)pInstruction->uImmediate;
            break;
        case OT_d:
            assert(pInstruction->uImmediate <= 0xffffffff);
            ACCESS_GEN_ECX(*pX86) = pInstruction->uImmediate;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//ba + rd   edx , dx
//B8 + rd   mov r16, im16
//B8 + rd   mov r32, im32
VM_INSTRUCTION_ERR_CODE mov_ba(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            assert(pInstruction->uImmediate <= 0xffff);
            ACCESS_GEN_DX(*pX86) = (UINT16)pInstruction->uImmediate;
            break;
        case OT_d:
            assert(pInstruction->uImmediate <= 0xffffffff);
            ACCESS_GEN_EDX(*pX86) = pInstruction->uImmediate;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//bb   EBX , BX
//B8 + rd   mov r16, im16
//B8 + rd   mov r32, im32
VM_INSTRUCTION_ERR_CODE mov_bb(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            assert(pInstruction->uImmediate <= 0xffff);
            ACCESS_GEN_BX(*pX86) = (UINT16)pInstruction->uImmediate;
            break;
        case OT_d:
            assert(pInstruction->uImmediate <= 0xffffffff);
            ACCESS_GEN_EBX(*pX86) = pInstruction->uImmediate;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//bc  ESP , SP
//B8 + rd   mov r16, im16
//B8 + rd   mov r32, im32
VM_INSTRUCTION_ERR_CODE mov_bc(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            assert(pInstruction->uImmediate <= 0xffff);
            ACCESS_GEN_SP(*pX86) = (UINT16)pInstruction->uImmediate;
            break;
        case OT_d:
            assert(pInstruction->uImmediate <= 0xffffffff);
            ACCESS_GEN_ESP(*pX86) = pInstruction->uImmediate;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//bd   mov ebp, imm32
//B8 + rd   mov r16, im16
//B8 + rd   mov r32, im32
VM_INSTRUCTION_ERR_CODE mov_bd(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            assert(pInstruction->uImmediate <= 0xffff);
            ACCESS_GEN_BP(*pX86) = (UINT16)pInstruction->uImmediate;
            break;
        case OT_d:
            assert(pInstruction->uImmediate <= 0xffffffff);
            ACCESS_GEN_EBP(*pX86) = pInstruction->uImmediate;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//be   esi , si
//B8 + rd   mov r16, im16
//B8 + rd   mov r32, im32
VM_INSTRUCTION_ERR_CODE mov_be(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            assert(pInstruction->uImmediate <= 0xffff);
            ACCESS_GEN_SI(*pX86) = (UINT16)pInstruction->uImmediate;
            break;
        case OT_d:
            assert(pInstruction->uImmediate <= 0xffffffff);
            ACCESS_GEN_ESI(*pX86) = pInstruction->uImmediate;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//bf   edi, di
//B8 + rd   mov r16, im16
//B8 + rd   mov r32, im32
VM_INSTRUCTION_ERR_CODE mov_bf(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    assert(pInstruction);

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            assert(pInstruction->uImmediate <= 0xffff);
            ACCESS_GEN_DI(*pX86) = (UINT16)pInstruction->uImmediate;
            break;
        case OT_d:
            assert(pInstruction->uImmediate <= 0xffffffff);
            ACCESS_GEN_EDI(*pX86) = pInstruction->uImmediate;
            break;
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//88    mov r/m8, r8
VM_INSTRUCTION_ERR_CODE mov_88(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uMemAddr;
    INT Op1;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        Op1 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uMemAddr);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        SetMemoryValue(pX86, pMemory, uMemAddr, Op1, OT_b, pInstruction->dwFlags);
    }
    else {
        Op1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), Op1, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//89    mov r/m16, r16
//89    mov r/m32, r32
VM_INSTRUCTION_ERR_CODE mov_89(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT Op0;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        Op0 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        if (((pMemory->StackSegment.uStartAddr - pMemory->StackSegment.uBlockSize) <= uEA) && (uEA <= pMemory->StackSegment.uStartAddr)){
            switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
                case OT_w:
                    SetStackElement(pX86, pMemory, uEA, Op0, OPERAND_SIZE_16BIT);
                    break;
                case OT_d:
                    SetStackElement(pX86, pMemory, uEA, Op0, OPERAND_SIZE_32BIT);
                    break;
            }
        }
        else{
            SetMemoryValue(pX86, pMemory, uEA, Op0, OT_v, pInstruction->dwFlags);
        }
    }
    else {
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//8a  mov r8, r/m8
VM_INSTRUCTION_ERR_CODE mov_8a(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT Op0;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        if (((pMemory->StackSegment.uStartAddr - pMemory->StackSegment.uBlockSize) <= uEA) && (uEA <= pMemory->StackSegment.uStartAddr)){
            SetStackElement(pX86, pMemory, uEA, Op0, 4);
        }else{
            SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        }
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//Intel 64 and IA-32 Architectures Software Developer's Manual - Volume 1- Basic Architecture
//Page: 3-29
//The following default segment selections cannot be overridden:
//    Instruction fetches must be made from the code segment
//    Destination string in string instructions must be stored in the data segment pointed to by the ES register
//    Push and Pop operations must always reference  the SS segment

//Any memory reference which uses the esp or ebp register as a base register

//8b  mov r16, r/m16
//8b  mov r32, r/m32
VM_INSTRUCTION_ERR_CODE mov_8b(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT Op0;


    //Example : 8B 0C 24         mov         ecx,dword ptr [esp]         ModR/M  0000 1100 :  Mod-R/M;00 100 ;->SIB    0x24 :0010 0100  SS;00  Index:100  Base:100   Base -> ESP
    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;

        //栈地址是由高低地址向低地址扩展
        if (((pMemory->StackSegment.uStartAddr - pMemory->StackSegment.uBlockSize) <= uEA) && (uEA <= pMemory->StackSegment.uStartAddr)){
            switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
                case OT_w:
                    Op0 = GetStackElement(pX86, pMemory, uEA,OPERAND_SIZE_16BIT);
                    break;
                case OT_d:
                    Op0 = GetStackElement(pX86, pMemory, uEA,OPERAND_SIZE_32BIT);
                    break;
            }
        }
        else{
            Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        }

        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), Op0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//8c    mov r/m16, Sreg
VM_INSTRUCTION_ERR_CODE mov_8c(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT Op0;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetRegisterValue(pX86,GET_REG_FROM_MODRM(pInstruction->byModRM), SEGMENT_REGISTER,OT_v, pInstruction->dwFlags);
        SetMemoryValue(pX86, pMemory, uEA, Op0, OT_b, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), SEGMENT_REGISTER, OT_v, pInstruction->dwFlags);
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), Op0, SEGMENT_REGISTER, OT_v, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//8e    mov Sreg, r/m16
VM_INSTRUCTION_ERR_CODE mov_8e(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    UINT uEA;
    INT Op0;
    VM_INSTRUCTION_ERR_CODE inst_err = VM_INSTRUCTION_ERR_FATAL_UNKNOWN;
    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
        inst_err = SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM) , Op0, SEGMENT_REGISTER, OT_v, pInstruction->dwFlags);
    }
    else{
        Op0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
        inst_err = SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), Op0, SEGMENT_REGISTER, OT_v, pInstruction->dwFlags);
    }

    return inst_err;
}


//C6 /0 mov r/m8 ,imm8
VM_INSTRUCTION_ERR_CODE grp11_mov_c6_mov(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT8 Op0;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    Op0 = (UINT8)pInstruction->uImmediate ;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        //栈地址是由高低地址向低地址扩展
        if (((pMemory->StackSegment.uStartAddr - pMemory->StackSegment.uBlockSize) <= uEA) && (uEA <= pMemory->StackSegment.uStartAddr)){
             SetStackElement(pX86, pMemory, uEA, Op0, 4);  //Warring OPERAND_SIZE = 8bit
        }
        else{
            SetMemoryValue(pX86, pMemory, uEA, Op0,OT_b, pInstruction->dwFlags);
        }
    }
    else{
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), pInstruction->uImmediate, SEGMENT_REGISTER, OT_b, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//c7 /0 mov r/m16,imm16
//c7 /0 mov r/m32,imm32
VM_INSTRUCTION_ERR_CODE grp11_mov_c7_mov(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT Op0;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xffffffff);

    Op0 = pInstruction->uImmediate;

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;

        //栈地址是由高低地址向低地址扩展
        if (((pMemory->StackSegment.uStartAddr - pMemory->StackSegment.uBlockSize) <= uEA) && (uEA <= pMemory->StackSegment.uStartAddr)){
            switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
                case OT_w:
                    SetStackElement(pX86, pMemory, uEA, Op0, OPERAND_SIZE_16BIT);
                    break;
                case OT_d:
                    SetStackElement(pX86, pMemory, uEA, Op0, OPERAND_SIZE_32BIT);
                    break;
            }
        }
        else{
            SetMemoryValue(pX86, pMemory, uEA, Op0,OT_v, pInstruction->dwFlags);
        }
    }
    else{
        SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), pInstruction->uImmediate, SEGMENT_REGISTER, OT_v, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}
