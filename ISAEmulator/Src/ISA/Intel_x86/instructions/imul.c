//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/imul.c
//�ļ�������        Intel x86��imulָ�����
//�����ˣ�          ����(laosheng@ptwy.cn)
//�������ڣ�        2009��8��7��
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
//2009��8��12�գ�����(laosheng@ptwy.cn)������

//
//������־��
//2009��10��9�գ�����(laosheng@ptwy.cn)���޸�ָ���EFLAGS��Ӱ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/imul.h"
#include "ISA/Intel_x86/Instructions/common.h"

//69 /r /iw imul r16 , r/m16 , imm16  word register <- r/m16 * immediate word
//69 /r /id imul r32 , r/m32 , imm32  doubleword register <- r/m16 * immediate doubleword
//69 /r /iw imul r16 , imm16 (imul r16 , r16 , imm16) word register <- r/m16 * immediate word
//69 /r /id imul r32 , imm32 (imul r32 , r32 , imm32) doubleword register <- r/m16 * immediate doubleword
VM_INSTRUCTION_ERR_CODE imul_69(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    //66 69 C3 14 11   imul        ax,bx,1114h   �����룺imul ax,bx ,0x1114   ������ax= bx * 0x1114
    //C3 : 1100 0011
    //Mod/RM == 11 011 -> bx , Reg 000 -> ax

    //66 69 5D EC 14 11 imul        bx,word ptr [shortIntTest],1114h  �����룺imul bx,shortIntTest ,0x1114   ������bx = shortIntTest * 0x1114
    //5D : 0101 1101
    //Mod/RM == 01 101 -> [EBP]+disp8 ��� shortIntTest��ջ���ڵ�ַ��ƫ���� , Reg 011 -> bx

    //66 69 C0 14 11   imul        ax,ax,1114h   �����룺imul ax,0x1114       ������ax= ax * 0x1114
    //C0 : 1100 0000
    //Mod/RM == 11 000 -> ax , Reg 000 -> ax

    //66 69 DB 14 11   imul        bx,bx,1114h   �����룺imul bx,0x1114       ������bx= bx * 0x1114
    //DB : 1101 1011   
    //Mod/RM == 11 011 -> bx , Reg 011 -> bx

    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;

    INT Op1;
    INT Op2;
    INT16 i16Op1;
    INT16 i16Op2;
    INT16 i16Dest;
    INT32 i32Result;

    INT64 i64Op1;
    INT64 i64Op2;
    INT32 i32Dest;
    INT64 i64Result;

    assert(pInstruction);

    Op2 = pInstruction->uImmediate;

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
          //�������EBP+ ƫ�������ڴ��е����Ե�ַ��
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op1 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags); 
    }
    else{
        Op1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            i16Op1  = Op1;
            i16Op2  = Op2;
            i16Dest = i16Op1 * i16Op2;
            i64Result = i16Op1 * i16Op2;

            if (i64Result != i16Dest){
                SET_EFLAGS_OF(*pX86, 1);
                SET_EFLAGS_CF(*pX86, 1);
            }
            else{
                SET_EFLAGS_OF(*pX86, 0);
                SET_EFLAGS_CF(*pX86, 0);
            }
            break;

        case OT_d:
            i64Op1 = Op1;
            i64Op2 = Op2;
            i32Dest = i64Op1 * i64Op2; 
            i64Result = i64Op1 * i64Op2;
            
            if (i64Result != i32Dest){
                SET_EFLAGS_OF(*pX86, 1);
                SET_EFLAGS_CF(*pX86, 1);
            }
            else{
                SET_EFLAGS_OF(*pX86, 0);
                SET_EFLAGS_CF(*pX86, 0);
            }

            break;
    }

    SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), (UINT)i64Result, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);


    return VM_INSTRUCTION_ERR_SUCCEEDED;
}


//6B /r ib imul r16, r/m16, imm8
//6B /r ib imul r32, r/m32, imm8
//6B /r ib imul r16, imm8
//6B /r ib imul r32, imm8
VM_INSTRUCTION_ERR_CODE imul_6b(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT uOp0;
    INT16 i16Op1;
    UINT16  u16Dest;
    UINT32  u32Dest;
    INT Op1;
    INT8 Op2;
    UINT64 ui64Result;;

    assert(pInstruction);
    assert(pInstruction->uImmediate <= 0xff);

    Op2 = pInstruction->uImmediate;

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op1 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else{
        Op1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            i16Op1 = Op1;
            u16Dest  = Op2 * i16Op1; 
            ui64Result = Op2 * i16Op1; 
            if (ui64Result != (INT16)u16Dest){
                SET_EFLAGS_OF(*pX86, 1);
                SET_EFLAGS_CF(*pX86, 1);
            }
            else{
                SET_EFLAGS_OF(*pX86, 0);
                SET_EFLAGS_CF(*pX86, 0);
            }
            break;
        case OT_d:
            uOp0 = Op1 * Op2; 
            u32Dest = Op1 * Op2;
            ui64Result = Op1 * Op2;
            if (ui64Result != (INT32)u32Dest){
                SET_EFLAGS_OF(*pX86, 1);
                SET_EFLAGS_CF(*pX86, 1);
            }
            else{
                SET_EFLAGS_OF(*pX86, 0);
                SET_EFLAGS_CF(*pX86, 0);
            }
            break;
    }

    SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), ui64Result, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//0F AF /r imul r16 , r/m16
//0F AF /r imul r32 , r/m32
VM_INSTRUCTION_ERR_CODE imul_Of_af(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT uOp0;
    INT Op1;
    UINT64 ui64Result;

    assert(pInstruction);

    uOp0 = GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);;

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op1 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else{
        Op1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    ui64Result = uOp0 * Op1;

    SetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
   
    if (ui64Result != GetRegisterValue(pX86, GET_REG_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags)){
        SET_EFLAGS_OF(*pX86, 1);
        SET_EFLAGS_CF(*pX86, 1);
    }
    else{
        SET_EFLAGS_OF(*pX86, 0);
        SET_EFLAGS_CF(*pX86, 0);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//f6 /5 imul r/m8   AX <- AL * r/m byte
VM_INSTRUCTION_ERR_CODE unary_grp3_f6_imul(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT8 Op1;

    assert(pInstruction);

    if(3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)) {
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        Op1 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
        ACCESS_GEN_AX(*pX86) = (INT8)ACCESS_GEN_AL(*pX86) * Op1;
    }
    else {
        Op1 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);  
        ACCESS_GEN_AX(*pX86) = (INT8)ACCESS_GEN_AL(*pX86) * Op1;
    }
    

    if (ACCESS_GEN_AX(*pX86) == ACCESS_GEN_AL(*pX86)){
        SET_EFLAGS_OF(*pX86, 0);
        SET_EFLAGS_CF(*pX86, 0);
    }
    else{
        SET_EFLAGS_OF(*pX86, 1);
        SET_EFLAGS_CF(*pX86, 1);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//f7 /5 imul r/m16   DX:AX <- AX * r/m    word
//f7 /5 imul r/m32   EDX:EAX <- EAX * r/m 
VM_INSTRUCTION_ERR_CODE unary_grp3_f7_imul(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    INT Op1;
    INT16  i16Temp;
    INT iTemp;

    INT64 i64Op1;
    INT64 i64Op2;
    INT64 i64Result;

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

    //66 ǰ׺
    if (OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE & pInstruction->dwFlags){
        i16Temp = (INT16) Op1 ;
        iTemp = (INT16)ACCESS_GEN_AX(*pX86)  * i16Temp;

        //���´����������ݽض�
        ACCESS_GEN_AX(*pX86) = iTemp;
        ACCESS_GEN_DX(*pX86) = iTemp >>16;

        if (iTemp == (INT16)ACCESS_GEN_AX(*pX86)){
            SET_EFLAGS_OF(*pX86, 0);
            SET_EFLAGS_CF(*pX86, 0);
        }
        else{
            SET_EFLAGS_OF(*pX86, 1);
            SET_EFLAGS_CF(*pX86, 1);
        }
    }
    else{
        i64Op1 = Op1;
        i64Op2 = (INT)ACCESS_GEN_EAX(*pX86);
        i64Result = i64Op1  * i64Op2;

        ACCESS_GEN_EAX(*pX86) = (UINT)i64Result;
        ACCESS_GEN_EDX(*pX86) = (UINT)(i64Result >>32);

        if (i64Result == (INT)ACCESS_GEN_EAX(*pX86)){
            SET_EFLAGS_OF(*pX86, 0);
            SET_EFLAGS_CF(*pX86, 0);
        }
        else{
            SET_EFLAGS_OF(*pX86, 1);
            SET_EFLAGS_CF(*pX86, 1);
        }
    }
    //Set Flags

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

