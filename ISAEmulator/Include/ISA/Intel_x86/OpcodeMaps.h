//
//文件名称：        Include/ISA/Intel_x86/OpcodeMaps.h
//文件描述：        Intel x86架构指令编码表(opcode map)
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
//Update Log:
//更新日志：
//2009年8月3日，杨鸿博(yanghongbo@ptwy.cn)，创建

#ifndef _OPCODE_MAPS_H_
#define _OPCODE_MAPS_H_

#include "VM_Defines.h"

#include "ISA/Intel_x86/Intel_x86_ISA.h"

//Operand Macros:
#define NO_OPERAND   0x00000000
#define USE_UPPER_OPERAND   0x80000000
#define NO_PREFIXES  0x00000000

#define MASK_AM(x) ((x) & 0x00ff0000)
#define MASK_OT(x) ((x) & 0xFF000000)

//Codes for Addressing Method from Intel 64 and IA-32 Architectures Software Developer's Manual - Volume 2B Appendix A
//The mask is compatible with libemu projects

#define AM_A         0x00010000    //Direct Address: the instruction has no ModR/M byte; the address of the
                                        //operand is encoded in the instruction. No base 
                                        //register, index register, or scaling factor can be applied (for 
                                        //example, far jmp(EA))
#define AM_C         0x00020000    //The reg field of the ModR/M byte selects a control register (for example,
                                        //mov (0F20, 0F22)).
#define AM_D         0x00030000    //The reg field of the ModR/M byte selects a debgug register (for example,
                                        //mov (0F21, 0F23)).
#define AM_E         0x00040000    //A ModR/M byte follows the opcode and specifies the operand. The operand
                                        //is either a general-purpose register or a memory address. If it is 
                                        //a memory address, the address is computed from a segment register 
                                        //and any of the following values: a base register, an index register, 
                                        //a scaling factor, a dispacement.
#define AM_F         0x00050000    //EFLAGS/RFLAGS Register.
#define AM_G         0x00060000    //The reg field of ModR/M byte selects a general register
#define AM_I         0x00070000    //Immediate data: the operand is encoded in subsquent bytes of the instruction
#define AM_J         0x00080000    //Instruction contains a relative offset to be added to the instruction 
                                        //pointer register (for example, JMP(0E9), LOOP)
#define AM_M         0x00090000    //The ModR/M byte may refer only to memory (for example, BOUND, LES, LDS, LSS
                                        //LFS, LGS, CMPXCHG8B).
#define AM_N         0x000A0000    //The reg field of ModR/M byte selects a packed-quadword, MMX technology 
                                        //register.
#define AM_O         0x000B0000    //The instruction has no ModR/M byte. The offset of the operand is coded as a word
                                        //or double word (depending on address size attribute) in the instruction.
                                        //No base register, index register, or scaling factor can be applied (for 
                                        //example, MOV(A0-A3)).
#define AM_P         0x000C0000    //The reg field of ModR/M byte selects a packed quadword MMX technology register.
#define AM_Q         0x000D0000    //A ModR/M byte follows the opcode and specifies the operand. The operand is either
                                        //an MMX technology register or a memory address. If it is a memory address, 
                                        //the address is computed from segment register and any of the following values:
                                        //a base register, an index register, a scaling factor, a displacement.
#define AM_R         0x000E0000    //The R/M field of the ModR/M byte may refer only to a general register (for example,
                                        //MOV (0F20,0F23)).
#define AM_S         0x000F0000    //The reg field of the ModR/M byte selects a segment register (for example, MOV(8C,8E)).
#define AM_U         0x00110000    //The R/M field of the ModR/M byte selects a 128-bit XMM register.
#define AM_V         0x00120000    //The reg field of the ModR/M byte selects a 128-bit XMM register.
#define AM_W         0x00130000    //A ModR/M byte follows the opcode and specifies the operand. The operand is either
                                        //a 128-bit XMM register, or a memory address. If it is a memory address, the
                                        //address is computed from segment register and any of the following values:
                                        //a base register, an index register, a scaling factor, a displacement.
#define AM_X         0x00140000    //Memory addressed by the DS:rSI register pair (for example, MOVS, CMPS, OUTS, or LODS).
#define AM_Y         0x00150000    //Memory addressed by the DS:rDI register pair (for example, MOVS, CMPS, INS, or SCAS).

#define AM_I1        0x00200000     //Immediate 1 byte?



#define AM_REG_BASE     0x00210000
#define MAKE_AM_REG(base, offset)   ((base) + (offset << 16))
#define GET_AM_REG_NAME_INDEX(x)    ((BYTE)((MASK_AM(x) - AM_REG_BASE) >> 16))

#define AM_REG_RAX  MAKE_AM_REG(AM_REG_BASE, 0)
#define AM_REG_RCX  MAKE_AM_REG(AM_REG_BASE, 1)
#define AM_REG_RDX  MAKE_AM_REG(AM_REG_BASE, 2)
#define AM_REG_RBX  MAKE_AM_REG(AM_REG_BASE, 3)

#define AM_REG_RSP  MAKE_AM_REG(AM_REG_BASE, 4)
#define AM_REG_RBP  MAKE_AM_REG(AM_REG_BASE, 5)
#define AM_REG_RSI  MAKE_AM_REG(AM_REG_BASE, 6)
#define AM_REG_RDI  MAKE_AM_REG(AM_REG_BASE, 7)


#define AM_REG_EAX  MAKE_AM_REG(AM_REG_BASE, 0)
#define AM_REG_ECX  MAKE_AM_REG(AM_REG_BASE, 1)
#define AM_REG_EDX  MAKE_AM_REG(AM_REG_BASE, 2)
#define AM_REG_EBX  MAKE_AM_REG(AM_REG_BASE, 3)

#define AM_REG_ESP  MAKE_AM_REG(AM_REG_BASE, 4)
#define AM_REG_EBP  MAKE_AM_REG(AM_REG_BASE, 5)
#define AM_REG_ESI  MAKE_AM_REG(AM_REG_BASE, 6)
#define AM_REG_EDI  MAKE_AM_REG(AM_REG_BASE, 7)


#define AM_REG_AX  MAKE_AM_REG(AM_REG_BASE, 0)
#define AM_REG_CX  MAKE_AM_REG(AM_REG_BASE, 1)
#define AM_REG_DX  MAKE_AM_REG(AM_REG_BASE, 2)
#define AM_REG_BX  MAKE_AM_REG(AM_REG_BASE, 3)

#define AM_REG_SP  MAKE_AM_REG(AM_REG_BASE, 4)
#define AM_REG_BP  MAKE_AM_REG(AM_REG_BASE, 5)
#define AM_REG_SI  MAKE_AM_REG(AM_REG_BASE, 6)
#define AM_REG_DI  MAKE_AM_REG(AM_REG_BASE, 7)

#define AM_REG_AL  MAKE_AM_REG(AM_REG_BASE, 0)
#define AM_REG_CL  MAKE_AM_REG(AM_REG_BASE, 1)
#define AM_REG_DL  MAKE_AM_REG(AM_REG_BASE, 2)
#define AM_REG_BL  MAKE_AM_REG(AM_REG_BASE, 3)

#define AM_REG_AH  MAKE_AM_REG(AM_REG_BASE, 4)
#define AM_REG_CH  MAKE_AM_REG(AM_REG_BASE, 5)
#define AM_REG_DH  MAKE_AM_REG(AM_REG_BASE, 6)
#define AM_REG_BH  MAKE_AM_REG(AM_REG_BASE, 7)

#define AM_REG_MM0  MAKE_AM_REG(AM_REG_BASE, 0)
#define AM_REG_MM1  MAKE_AM_REG(AM_REG_BASE, 1)
#define AM_REG_MM2  MAKE_AM_REG(AM_REG_BASE, 2)
#define AM_REG_MM3  MAKE_AM_REG(AM_REG_BASE, 3)
#define AM_REG_MM4  MAKE_AM_REG(AM_REG_BASE, 4)
#define AM_REG_MM5  MAKE_AM_REG(AM_REG_BASE, 5)
#define AM_REG_MM6  MAKE_AM_REG(AM_REG_BASE, 6)
#define AM_REG_MM7  MAKE_AM_REG(AM_REG_BASE, 7)

#define AM_REG_XMM0  MAKE_AM_REG(AM_REG_BASE, 0)
#define AM_REG_XMM1  MAKE_AM_REG(AM_REG_BASE, 1)
#define AM_REG_XMM2  MAKE_AM_REG(AM_REG_BASE, 2)
#define AM_REG_XMM3  MAKE_AM_REG(AM_REG_BASE, 3)
#define AM_REG_XMM4  MAKE_AM_REG(AM_REG_BASE, 4)
#define AM_REG_XMM5  MAKE_AM_REG(AM_REG_BASE, 5)
#define AM_REG_XMM6  MAKE_AM_REG(AM_REG_BASE, 6)
#define AM_REG_XMM7  MAKE_AM_REG(AM_REG_BASE, 7)

#define AM_REG_ES  MAKE_AM_REG(AM_REG_BASE, 0)
#define AM_REG_SS  MAKE_AM_REG(AM_REG_BASE, 1)
#define AM_REG_CS  MAKE_AM_REG(AM_REG_BASE, 2)
#define AM_REG_DS  MAKE_AM_REG(AM_REG_BASE, 3)
#define AM_REG_FS  MAKE_AM_REG(AM_REG_BASE, 4)
#define AM_REG_GS  MAKE_AM_REG(AM_REG_BASE, 5)

//Codes for Operand Type from Intel 64 and IA-32 Architectures Software Developer's Manual - Volume 2B Appendix A
//The mask is compatible with libemu projects

#define OT_a         0x01000000     //Two one-word operands in memory or two double-word operands in memory, 
                                        //depending on operand-size attribute (used only by BOUND instruction).
#define OT_b         0x02000000     //Byte, regardless of operand-size attribute.
#define OT_c         0x03000000     //Byte or word, depending on operand-size attribute.
#define OT_d         0x04000000     //Doubleword, regardless of operand-size attribute.
#define OT_dq        0x05000000     //Double-quadword, regardless of operand-size attribute.
#define OT_p         0x06000000     //32-bit, 48-bit, or 80-bit pointer, depending on operand-size attribute.
#define OT_pd        0x07000000     //128-bit packed double-precision floating-point data.
#define OT_pi        0x08000000     //Quadword MMX technology register (for example, mm0).
#define OT_ps        0x09000000     //128-bit packed single-precision floating-point data.
#define OT_q         0x0a000000     //Quadword, regardless of operand-size attribute.
#define OT_s         0x0b000000     //6-byte or 10-byte pseudo-descriptor.
#define OT_ss        0x0c000000     //Scalar element of a 128-bit single-precision floating data.
#define OT_si        0x0d000000     //Double integer register (for example, eax).
#define OT_v         0x0e000000     //Word, doubleword or quadword (in 64-bit mode), depending operand-size attribute.
#define OT_w         0x0f000000     //Word, regardless of operand-size attribute.
#define OT_z         0x10000000     //Word for 16-bit operand-size or doubleword for 32 or 64-bit operand-size
#define OT_1         0x11000000     //Word for 16-bit operand-size or doubleword for 32 or 64-bit operand-size

#define OT_seg       0x12000000     //use a segment register

#define GET_MOD_FROM_MODRM(x)   ((BYTE)(((x) & 0300) >> 6))
#define GET_REG_FROM_MODRM(x)   ((BYTE)(((x) & 070) >> 3))
#define GET_OPCODE_EXTENSION_FROM_MODRM     GET_REG_FROM_MODRM
#define GET_RM_FROM_MODRM(x)    ((BYTE)((x) & 07))

#define GET_INDEX_FROM_SIB(x)  (((x) & 070) >> 3)
#define GET_SCALE_FROM_SIB(x) (((x) & 0300) >> 6)
#define GET_BASE_FROM_SIB(x)   (((x) & 07))

//Opcode Flags
#define OPCODE_FLAG_MASK(x)                         ((x) & 0xff000000)
#define OPCODE_FLAG_IS_NORMAL_INSTRUCTION           0x00000000  //eg, 
#define OPCODE_FLAG_IS_PREFIX                       0x01000000  //eg, 
#define OPCODE_FLAG_IS_TWO_BYTES_ESCAPE              0x02000000  //eg,
#define OPCODE_FLAG_IS_THREE_BYTES_ESCAPE            0x03000000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION             0x04000000  //eg,
#define OPCODE_FLAG_IS_ESCAPE_TO_COPROCESSOR        0x05000000  //eg,
#define OPCODE_FLAG_IS_NOT_IMPLEMENTEDED            0xff000000  //eg,

#define OPCODE_FLAG_MASK_PREFIX_TYPE(x)             ((x) & 0x000fff00)
//Prefix Group1
#define OPCODE_FLAG_PREFIX_GROUP1_MASK(x)           ((x) & 0x00000f00)
#define OPCODE_FLAG_PREFIX_LOCK                     0x00000100  //F0H
#define OPCODE_FLAG_PREFIX_REPNE                    0x00000200  //F2H
#define OPCODE_FLAG_PREFIX_REP                      0x00000300  //F3H
#define OPCODE_FLAG_PREFIX_REPE                     0x00000300  //F3H
//Prefix Group2
#define OPCODE_FLAG_PREFIX_GROUP2_MASK(x)           ((x) & 0x0000f000)
#define OPCODE_FLAG_PREFIX_CS                       0x00001000  //2EH
#define OPCODE_FLAG_PREFIX_BRANCH_NOT_TAKEN         0x00001000  //2EH
#define OPCODE_FLAG_PREFIX_SS                       0x00002000  //36H
#define OPCODE_FLAG_PREFIX_DS                       0x00003000  //3EH
#define OPCODE_FLAG_PREFIX_BRANCH_TAKEN             0x00003000  //3EH
#define OPCODE_FLAG_PREFIX_ES                       0x00004000  //26H
#define OPCODE_FLAG_PREFIX_FS                       0x00005000  //64H
#define OPCODE_FLAG_PREFIX_GS                       0x00006000  //65H

#define OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE    0x00010000  //66H
#define OPCODE_FLAG_PREFIX_ADDRESS_SIZE_OVERRIDE    0x00020000  //67H

#define OPCODE_FLAG_MASK_OPCODE_EXTENSION_GROUP(x)       ((x) & 0x00ff0000)
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_1          0x00010000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_1A         0x00020000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_2          0x00030000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_3          0x00040000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_4          0x00050000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_5          0x00060000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_6          0x00070000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_7          0x00080000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_8          0x00090000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_9          0x000A0000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_10         0x000B0000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_11         0x000C0000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_12         0x000D0000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_13         0x000E0000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_14         0x000F0000  //eg,
#define OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_15         0x00100000  //eg,

#define OPCODE_FLAG_USE_PATCH_MASK(x)                      ((x) & 0x000000ff)
#define OPCODE_FLAG_USE_PATCH_FOR_ALIAS                    0x00000001  //if this bit is set, this patch name is secondary(not shown in default)
#define OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT           0x00000002  //eg, opcode 63H, arpl/movsxd
#define OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT           0x00000004  //eg, opcode 60H, pusha/pushad
#define OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT           0x00000008  //eg
#define OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_8BIT            0x00000010  //eg

#define OPCODE_FLAG_ATTRIBUTE_MASK(x)                      ((x) & 0x0000ff00)
#define OPCODE_FLAG_ATTRIBUTE_USE_WITH_PREFIX_F3H           0x00000100
#define OPCODE_FLAG_ATTRIBUTE_i64                           0x00000200//instruction is invalid or not encodable in 64-bit mode
#define OPCODE_FLAG_ATTRIBUTE_o64                           0x00000400//instruction is only available when in 64-bit mode
#define OPCODE_FLAG_ATTRIBUTE_d64                           0x00000800//when in 64-bit mode, instruction defaults to 64-bit operand size and cannot encode 32-bit operand-size
#define OPCODE_FLAG_ATTRIBUTE_f64                           0x00001000//the operand size is forced to a 64-bit operand size when in 64-bit mode (prefixes that change operand size are ignored for this instruction in 64-bit mode

/*
#define OPCODE_FLAG_USE_PATCH_WITH_PREFIX_F2H                   0x00000100  //eg, 
#define OPCODE_FLAG_USE_PATCH_WITH_PREFIX_REPNE                 0x00000100  //REPNE F2H, eg, 
#define OPCODE_FLAG_USE_PATCH_WITH_PREFIX_F3H                   0x00000400  //eg, 
#define OPCODE_FLAG_USE_PATCH_WITH_PREFIX_REPE                  0x00000400  //REPNE F3H, eg, 
#define OPCODE_FLAG_USE_PATCH_WITH_PREFIX_66H                   0x00001000  //eg, 
#define OPCODE_FLAG_USE_PATCH_WITH_PREFIX_OPERAND_SIZE_OVERRIDE 0x00001000  //eg, 
*/

typedef enum _REG_NAME_INDEX_t {
 REG_NAME_INDEX_RAX  =0,
 REG_NAME_INDEX_RBX  =1,
 REG_NAME_INDEX_RCX  =2,
 REG_NAME_INDEX_RDX  =3,

 REG_NAME_INDEX_RSI  =4,
 REG_NAME_INDEX_RDI  =5,
 REG_NAME_INDEX_RSP  =6,
 REG_NAME_INDEX_RBP  =7,

 REG_NAME_INDEX_EAX  =8,
 REG_NAME_INDEX_EBX  =9,
 REG_NAME_INDEX_ECX  =10,
 REG_NAME_INDEX_EDX  =11,

 REG_NAME_INDEX_ESI  =12,
 REG_NAME_INDEX_EDI  =13,
 REG_NAME_INDEX_ESP  =14,
 REG_NAME_INDEX_EBP  =15,

 REG_NAME_INDEX_AX  =16,
 REG_NAME_INDEX_BX  =17,
 REG_NAME_INDEX_CX  =18,
 REG_NAME_INDEX_DX  =19,

 REG_NAME_INDEX_SI  =20,
 REG_NAME_INDEX_DI  =21,
 REG_NAME_INDEX_SP  =22,
 REG_NAME_INDEX_BP  =23,

 REG_NAME_INDEX_AL  =24,
 REG_NAME_INDEX_BL  =25,
 REG_NAME_INDEX_CL  =26,
 REG_NAME_INDEX_DL  =27,

 REG_NAME_INDEX_AH  =28,
 REG_NAME_INDEX_BH  =29,
 REG_NAME_INDEX_CH  =30,
 REG_NAME_INDEX_DH  =31,

 REG_NAME_INDEX_ES  =32,
 REG_NAME_INDEX_SS  =33,
 REG_NAME_INDEX_CS  =34,
 REG_NAME_INDEX_DS  =35,
 REG_NAME_INDEX_FS  =36,
 REG_NAME_INDEX_GS  =37,

 REG_NAME_INDEX_MM0  =38,
 REG_NAME_INDEX_MM1  =39,
 REG_NAME_INDEX_MM2  =40,
 REG_NAME_INDEX_MM3  =41,
 REG_NAME_INDEX_MM4  =42,
 REG_NAME_INDEX_MM5  =43,
 REG_NAME_INDEX_MM6  =44,
 REG_NAME_INDEX_MM7  =45,

 REG_NAME_INDEX_XMM0  =46,
 REG_NAME_INDEX_XMM1  =47,
 REG_NAME_INDEX_XMM2  =48,
 REG_NAME_INDEX_XMM3  =49,
 REG_NAME_INDEX_XMM4  =50,
 REG_NAME_INDEX_XMM5  =51,
 REG_NAME_INDEX_XMM6  =52,
 REG_NAME_INDEX_XMM7  =53,

 REG_NAME_INDEX_SIB  = 0xfe,
 REG_NAME_INDEX_NO  = 0xff
}REG_NAME_INDEX_t;

typedef struct _Intel_x86_Instruction_Attribute_t {
    char * szMnemonic_Intel;//for Intel syntax
    const UINT uArg1Flag;
    const UINT uArg2Flag;
    const UINT uArg3Flag;
    const UINT uOpcodeFlag;
    const struct _Intel_x86_Instruction_Attribute_t * pPatch;
    const PFN_INSTRUCTION_EXEC pfnInstructionExec;
}Intel_x86_Instruction_Attribute_t;

extern const char * const Intel_x86_Registers_Names[54];
extern const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Opcode_Map_OneByte[256];
extern const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Opcode_Map_TwoBytes[256];
extern const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Opcode_Map_ThreeBytes[256];
#ifdef NDEBUG
void PrintOpcodeTable(void);
#endif
#endif //_OPCODE_MAPS_H_
