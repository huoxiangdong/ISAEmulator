//
//�ļ����ƣ�        src/ISA/Intel_x86/Instructions/rcr.c
//�ļ�������        Intel x86��rcrָ�����
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
//2009��10��10�գ�����(laosheng@ptwy.cn),�޸ģ� ָ��ԼĴ���EFLAGS��Ӱ��

#include <assert.h>

#include "VM_Defines.h"
#include "VM_Memory.h"

#include "VM_ISARelated.h"
#include "ISA/Intel_x86/Intel_x86_ISA.h"
#include "ISA/Intel_x86/OpcodeMaps.h"

#include "ISA/Intel_x86/Instructions/rcr.h"
#include "ISA/Intel_x86/Instructions/common.h"

//Intel 64 and IA-32 Architectures Software Developer's Manual - Volume 1- Basic Architecture
//7.3.6.1(Shift Instructions) Vol.1 7-15

//c:carry �� �����ϴν�λ��Ӱ�죬 ��һ��ָ��Ա�ָ���Ӱ��

#define  GET_THE_N_BIT_VALUE(x,bits)  (((x) >> (bits -1)) & 1)
#define  MSB(x,bits)  GET_THE_N_BIT_VALUE(x,bits)

//c0 /4 ib rcr r/m8 , imm8   multiply r/m8 by 2, imm8 times
VM_INSTRUCTION_ERR_CODE shift_grp2_c0_rcr(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT u8CF;

    assert(pInstruction);

    uOp1 = pInstruction->uImmediate;

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    if (1 == uOp1){
        SET_EFLAGS_OF(*pX86, (MSB(uOp0, _8_BITS)  ^ GET_EFLAGS_CF_BIT(*pX86)));
    }

    uOp1 = (uOp1 & 0x1f) % (_8_BITS +1);  //8λ�����λ��Ϊ 8��   �� & 1f ���� 5λ��: 2^5 = 32 ,

    if (GET_THE_N_BIT_VALUE(uOp0, uOp1) && uOp1 >0){
        u8CF = 0x1 ;
    }
    else{
        u8CF = 0x0;
    }
    //Example : 1111 0011(0xf3) CF = 0
    //rotate 1: 0111 1001(0x79) CF = 1
    //rotate 2: 1011 1100(0xbc) CF = 1
    //rotate 3: 1101 1110(0xde) CF = 0     
    //ǰ���֣��ɵ͵� n(λ�ƴ���) -1 λ���ɣ��м� = CF(��ʼֵ) �� �󲿷��ɸߵ�8 -nλ����
    //CF(����ֵ)= ��nλ��ֵ

    uOp0 = uOp0 << (_8_BITS - uOp1 + 1) | uOp0 >> uOp1;

    //ERROR����  uOp0 |= GET_EFLAGS_CF_BIT(*pX86) <<  (8- uOp1);  //0x7f , uOp1=0  CF =1 , Result : 0xff
    if (1==GET_EFLAGS_CF_BIT(*pX86) && uOp1 >0){
        uOp0 |= 1<<  (_8_BITS- uOp1);
    }

    SET_EFLAGS_CF(*pX86 , u8CF);


    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        SetMemoryValue(pX86, pMemory, uEA, uOp0, OT_b, pInstruction->dwFlags);
    }
    else{
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//c1 /4 /ib rcr r/m16,imm8  multiply r/m16 by 2, imm8 times
//c1 /4 /ib rcr r/m32,imm8  multiply r/m32 by 2, imm8 times
VM_INSTRUCTION_ERR_CODE shift_grp2_c1_rcr(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT8 u8CF;

    assert(pInstruction);

    uOp1 = pInstruction->uImmediate;

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }
    

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            if (1 == uOp1){
                SET_EFLAGS_OF(*pX86, (MSB(uOp0, _16_BITS)  ^ GET_EFLAGS_CF_BIT(*pX86)));
            }

            uOp1 = (uOp1 & 0x1f) % (_16_BITS +1);   //16 bits

            if (GET_THE_N_BIT_VALUE(uOp0, uOp1) && uOp1 >0){
                u8CF = 0x1;
            }
            else{
                u8CF = 0x0;
            }

            uOp0 = uOp0 << (_16_BITS - uOp1 + 1) | uOp0 >> uOp1;

            if (1==GET_EFLAGS_CF_BIT(*pX86) && uOp1 >0){
                uOp0 |= 1<<  (_16_BITS- uOp1);
            }

            break;

        case OT_d:
            if (1 == uOp1){
                SET_EFLAGS_OF(*pX86, (MSB(uOp0, _32_BITS)  ^ GET_EFLAGS_CF_BIT(*pX86)));
            }

            uOp1 = (uOp1 & 0x1f) % (_32_BITS +1);   //32 bits

            if (GET_THE_N_BIT_VALUE(uOp0, uOp1) && uOp1 >0){
                u8CF = 0x1;
            }
            else{
                u8CF = 0x0;
            }

            uOp0 = uOp0 << (_32_BITS - uOp1 + 1) | uOp0 >> uOp1;

            if (1==GET_EFLAGS_CF_BIT(*pX86) && uOp1 >0){
                uOp0 |= 1<<  (_32_BITS- uOp1);
            }
            break;
    }

    SET_EFLAGS_CF(*pX86 , u8CF);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        SetMemoryValue(pX86, pMemory, uEA, uOp0, OT_v, pInstruction->dwFlags);
    }
    else{
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//d0 /4 rcr r/m8,1      multiply r/m8 by 2 , once
VM_INSTRUCTION_ERR_CODE shift_grp2_d0_rcr(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT8 uOp0;
    UINT8 u8CF;

    assert(pInstruction);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    SET_EFLAGS_OF(*pX86, (MSB(uOp0, _8_BITS)  ^ GET_EFLAGS_CF_BIT(*pX86)));
    u8CF = GET_THE_N_BIT_VALUE(uOp0, 1);

    uOp0 = uOp0 << _8_BITS  | uOp0 >> 1;

    if (1==GET_EFLAGS_CF_BIT(*pX86)){
        uOp0 |= 1<<  (_8_BITS- 1);
    }

    SET_EFLAGS_CF(*pX86, u8CF);


    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        SetMemoryValue(pX86, pMemory, uEA, uOp0, OT_b, pInstruction->dwFlags);
    }
    else{
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//d1 /4 rcr r/m16 ,1   multiply r/m16 by 2 , once
//d1 /4 rcr r/m32 ,1   multiply r/m32 by 2 , once
VM_INSTRUCTION_ERR_CODE shift_grp2_d1_rcr(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT8 u8CF;

    assert(pInstruction);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    u8CF = GET_THE_N_BIT_VALUE(uOp0, 1);
    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            SET_EFLAGS_OF(*pX86, (MSB(uOp0, _16_BITS)  ^ GET_EFLAGS_CF_BIT(*pX86)));
            uOp0 =  uOp0 >> 1;

            if (1==GET_EFLAGS_CF_BIT(*pX86)){
                uOp0 |= 1<<  (_16_BITS- 1);
            }
            break;

        case OT_d:
            SET_EFLAGS_OF(*pX86, (MSB(uOp0, _32_BITS)  ^ GET_EFLAGS_CF_BIT(*pX86)));
            uOp0 = uOp0 >> 1;  //warning C4293: ��<<��: Shift ����Ϊ�����������Ϊδ����

            if (1==GET_EFLAGS_CF_BIT(*pX86)){
                uOp0 |= 1<<  (_32_BITS- 1);
            }
            break;
    }

    SET_EFLAGS_CF(*pX86, u8CF);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        SetMemoryValue(pX86, pMemory, uEA, uOp0, OT_v, pInstruction->dwFlags);
    }
    else{
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//d2 /4 rcr r/m8, cl   multiply r/m8 by 2, CL times
VM_INSTRUCTION_ERR_CODE shift_grp2_d2_rcr(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT8 u8CF;

    assert(pInstruction);

    uOp1 = ACCESS_GEN_CL(*pX86);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_b, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    if (1 == uOp1){
        SET_EFLAGS_OF(*pX86, (MSB(uOp0, _8_BITS)  ^ GET_EFLAGS_CF_BIT(*pX86)));
    }

    uOp1 = (uOp1 & 0x1f) % 9; 

    if (GET_THE_N_BIT_VALUE(uOp0, uOp1) && uOp1 >0){
        u8CF = 0x1;
    }
    else{
        u8CF = 0x0;
    }

    uOp0 = uOp0 << (_8_BITS - uOp1 + 1) | uOp0 >> uOp1;

    if (1==GET_EFLAGS_CF_BIT(*pX86) && uOp1 >0){
        uOp0 |= 1<<  (_8_BITS- uOp1);
    }

    SET_EFLAGS_CF(*pX86 , u8CF);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        SetMemoryValue(pX86, pMemory, uEA, uOp0 & 0xff, OT_b, pInstruction->dwFlags);
    }
    else{
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_b, pInstruction->dwFlags);
    }

    return VM_INSTRUCTION_ERR_SUCCEEDED;
}

//d3 /4 rcr r/m16, cl   multiply r/m16 by 2, CL times
//d3 /4 rcr r/m32, cl   multiply r/m328 by 2, CL times
VM_INSTRUCTION_ERR_CODE shift_grp2_d3_rcr(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction)
{
    VM_INSTRUCTION_ERR_CODE inst_err;
    UINT uEA;
    UINT uOp0;
    UINT uOp1;
    UINT8 u8CF;

    assert(pInstruction);

    uOp1 = ACCESS_GEN_CL(*pX86);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        inst_err = GetEffectiveAddress(pX86, pInstruction, &uEA);
        if(VM_INSTRUCTION_ERR_SUCCEEDED != inst_err)
            return inst_err;
        uOp0 = GetMemoryValue(pX86, pMemory, uEA, OT_v, pInstruction->dwFlags);
    }
    else{
        uOp0 = GetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }

    if (1 == uOp1){
        SET_EFLAGS_OF(*pX86, (MSB(uOp0, _16_BITS)  ^ GET_EFLAGS_CF_BIT(*pX86)));
    }

    switch (GetDataType(OT_v, pX86->OpSize, pInstruction->dwFlags)){
        case OT_w:
            uOp1 = (uOp1 & 0x1f) % (_16_BITS +1);   //16 bits
            if (GET_THE_N_BIT_VALUE(uOp0, uOp1) && uOp1 >0){
                u8CF = 0x1;
            }
            else{
                u8CF = 0x0;
            }

            uOp0 = uOp0 << (_16_BITS - uOp1 + 1) | uOp0 >> uOp1;

            if (1==GET_EFLAGS_CF_BIT(*pX86) && uOp1 >0){
                uOp0 |= 1<<  (_16_BITS- uOp1);
            }

            uOp0 = uOp0 & 0xffff;
            
            break;

        case OT_d:
            uOp1 = (uOp1 & 0x1f) % (_32_BITS +1);   //32 bits

            if (GET_THE_N_BIT_VALUE(uOp0, uOp1) && uOp1 >0){
                u8CF = 0x1;
            }
            else{
                u8CF = 0x0;
            }

            uOp0 = uOp0 << (_32_BITS - uOp1 + 1) | uOp0 >> uOp1;

            if (1==GET_EFLAGS_CF_BIT(*pX86) && uOp1 >0){
                uOp0 |= 1<<  (_32_BITS- uOp1);
            }
            break;
    }

    SET_EFLAGS_CF(*pX86,u8CF);

    if (3 != GET_MOD_FROM_MODRM(pInstruction->byModRM)){
        SetMemoryValue(pX86, pMemory, uEA, uOp0, OT_v, pInstruction->dwFlags);
    }
    else{
        SetRegisterValue(pX86, GET_RM_FROM_MODRM(pInstruction->byModRM), uOp0, GENERAL_REGISTER, OT_v, pInstruction->dwFlags);
    }


    return VM_INSTRUCTION_ERR_SUCCEEDED;
}