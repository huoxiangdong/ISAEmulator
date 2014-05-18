#ifndef _INTEL_X86_ISA_H_
#define _INTEL_X86_ISA_H_
//
//文件名称：        Include/ISA/Intel_x86_ISA.h
//文件描述：        Intel x86 CPU架构（ISA）定义
//创建人：          杨鸿博(yanghongbo@ptwy.cn)
//创建日期：        2009年6月16日
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
//2009年6月16日，杨鸿博(yanghongbo@ptwy.cn)，创建
//2009年9月24日，杨鸿博(yanghongbo@ptwy.cn)，修改标志位运算宏

#include "VM_Config.h"
#include "VM_Defines.h"
#include "VM_ControlUnit.h"

#ifdef  __cplusplus
extern "C" {
#endif


//Configures
#if defined(VM_ISA_INTEL_X86_64_BIT)
# define VM_INTEL_X86_64BIT_SUPPORT 1
#else
# define VM_INTEL_X86_64BIT_SUPPORT 0
#endif

//宏定义
#define NEED_DATA_BYTES_MASK(x)  ((x) & 0x0000000f)
#define NEED_MODRM               0x00000001
#define NEED_SIB                 0x00000002
#define NEED_IMMEDIATE_1         0x00000004//only for opcode d0, d1 

#define NEED_DISPLACEMENT_MASK(x) ((x) & 0x000000f0)
#define NEED_DISPLACEMENT_8BIT   0x00000010
#define NEED_DISPLACEMENT_16BIT  0x00000020
#define NEED_DISPLACEMENT_32BIT  0x00000040
#define INSTURCTION_HAS_NO_MODRM    0x80000000  // for check

#define NEED_IMMEDIATE_BYTES_MASK(x)    ((x) & 0x00000f00)
#define NEED_IMMEDIATE_BYTES(x)         (NEED_IMMEDIATE_BYTES_MASK(x) >> 8)
#define ADD_IMMEDIATE_BYTES(x, n)       ((x) += ((n) << 8))
#define NEED_IMMEDIATE_BYTE             0x00000100
#define NEED_IMMEDIATE_WORD             0x00000200
#define NEED_IMMEDIATE_TWO_BYTES        0x00000200
#define NEED_IMMEDIATE_THREE_BYTES      0x00000300//for enter Iw, Ib
#define NEED_IMMEDIATE_DWORD            0x00000400
#define NEED_IMMEDIATE_FOUR_BYTES       0x00000400
#define NEED_IMMEDIATE_QWORD            0x00000800//? the maximum immediate bytes are 4 bytes!
#define NEED_IMMEDIATE_EIGHT_BYTES      0x00000800//?

#define OPERAND_SIZE_OVERRIDE           0x00001000
#define ADDRESS_SIZE_OVERRIDE           0x00002000


//通用寄存器组
typedef enum _VM_INTEL_X86_GENERAL_REGISTER_32BIT_ERX_INDEX {
    EAX = 0,
    ECX,// = 1,
    EDX,// = 2,
    EBX,// = 3,
    ESP,// = 4,
    EBP,// = 5,
    ESI,// = 6,
    EDI,// = 7,
    EIP,// = 8,
    //EFLAGS, // = 9
    SIB = 0xff,
}VM_INTEL_X86_GENERAL_REGISTER_32BIT_ERX_INDEX;

typedef enum _VM_INTEL_X86_GENERAL_REGISTER_16BIT_RX_INDEX {
    AX = 0,
    CX,// = 1,
    DX,// = 2,
    BX,// = 3,
    SP,// = 4,
    BP,// = 5,
    SI,// = 6,
    DI,// = 7,
    IP,// = 8,
    //FLAGS // = 9
}VM_INTEL_X86_GENERAL_REGISTER_16BIT_RX_INDEX;

typedef enum _VM_INTEL_X86_GENERAL_REGISTER_8BIT_RH_INDEX {
    AH = 0,
    CH,// = 1,
    DH, // = 2,
    BH,// = 3,
}VM_INTEL_X86_GENERAL_REGISTER_8BIT_RH_INDEX;

typedef enum _VM_INTEL_X86_GENERAL_REGISTER_8BIT_RL_INDEX {
    AL = 0,
    CL,// = 1,
    DL, // = 2,
    BL,// = 3,
}VM_INTEL_X86_GENERAL_REGISTER_8BIT_RL_INDEX;

//段寄存器组
typedef enum _VM_INTEL_X86_SEGMENT_REGISTER_INDEX {
    ES = 0,
    CS,//1
    SS,// = 2
    DS,// = 3
    FS,// = 4
    GS,// = 5
}VM_INTEL_X86_SEGMENT_REGISTER_INDEX;

#if VM_INTEL_X86_64BIT_SUPPORT
//
#else
//通用寄存器数量
# define VM_INTEL_X86_GENERAL_REGISTERS 8
# define VM_INTEL_X86_EIP_REGISTER 1
# define VM_INTEL_X86_EFLAGS_REGISTER 0 //改为单独定义
# define VM_INTEL_X86_SEGMENT_REGISTERS 6

# define ACCESS_ERX(reg_struct) ((reg_struct).rrxqword.erx)
# define ACCESS_RX(reg_struct) ((reg_struct).rrxqword.erxdword.rx)
# define ACCESS_RH(reg_struct) ((reg_struct).rrxqword.erxdword.rxword.rh)
# define ACCESS_RL(reg_struct) ((reg_struct).rrxqword.erxdword.rxword.rl)
# define ACCESS_SEG(reg_struct) ((reg_struct).selector)

# define ACCESS_GEN_ERX(cpu_struct, erx_i) ((cpu_struct).GeneralRegisters[erx_i].rrxqword.erx)
# define ACCESS_GEN_RX(cpu_struct, rx_i) ((cpu_struct).GeneralRegisters[rx_i].rrxqword.erxdword.rx)
# define ACCESS_GEN_RH(cpu_struct, rh_i) ((cpu_struct).GeneralRegisters[rh_i].rrxqword.erxdword.rxword.rh)
# define ACCESS_GEN_RL(cpu_struct, rl_i) ((cpu_struct).GeneralRegisters[rl_i].rrxqword.erxdword.rxword.rl)
# define ACCESS_GEN_SEG(cpu_struct, seg_i) ((cpu_struct).SegmentRegisters[seg_i].selector)

# define ACCESS_GEN_EAX(cpu_struct) ACCESS_GEN_ERX(cpu_struct, EAX)
# define ACCESS_GEN_AX(cpu_struct) ACCESS_GEN_RX(cpu_struct, AX)
# define ACCESS_GEN_AH(cpu_struct) ACCESS_GEN_RH(cpu_struct, AH)
# define ACCESS_GEN_AL(cpu_struct) ACCESS_GEN_RL(cpu_struct, AL)

# define ACCESS_GEN_EBX(cpu_struct) ACCESS_GEN_ERX(cpu_struct, EBX)
# define ACCESS_GEN_BX(cpu_struct) ACCESS_GEN_RX(cpu_struct, BX)
# define ACCESS_GEN_BH(cpu_struct) ACCESS_GEN_RH(cpu_struct, BH)
# define ACCESS_GEN_BL(cpu_struct) ACCESS_GEN_RL(cpu_struct, BL)

# define ACCESS_GEN_ECX(cpu_struct) ACCESS_GEN_ERX(cpu_struct, ECX)
# define ACCESS_GEN_CX(cpu_struct) ACCESS_GEN_RX(cpu_struct, CX)
# define ACCESS_GEN_CH(cpu_struct) ACCESS_GEN_RH(cpu_struct, CH)
# define ACCESS_GEN_CL(cpu_struct) ACCESS_GEN_RL(cpu_struct, CL)

# define ACCESS_GEN_EDX(cpu_struct) ACCESS_GEN_ERX(cpu_struct, EDX)
# define ACCESS_GEN_DX(cpu_struct) ACCESS_GEN_RX(cpu_struct, DX)
# define ACCESS_GEN_DH(cpu_struct) ACCESS_GEN_RH(cpu_struct, DH)
# define ACCESS_GEN_DL(cpu_struct) ACCESS_GEN_RL(cpu_struct, DL)

# define ACCESS_GEN_ESI(cpu_struct) ACCESS_GEN_ERX(cpu_struct, ESI)
# define ACCESS_GEN_SI(cpu_struct) ACCESS_GEN_RX(cpu_struct, SI)

# define ACCESS_GEN_EDI(cpu_struct) ACCESS_GEN_ERX(cpu_struct, EDI)
# define ACCESS_GEN_DI(cpu_struct) ACCESS_GEN_RX(cpu_struct, DI)

# define ACCESS_GEN_ESP(cpu_struct) ACCESS_GEN_ERX(cpu_struct, ESP)
# define ACCESS_GEN_SP(cpu_struct) ACCESS_GEN_RX(cpu_struct, SP)

# define ACCESS_GEN_EBP(cpu_struct) ACCESS_GEN_ERX(cpu_struct, EBP)
# define ACCESS_GEN_BP(cpu_struct) ACCESS_GEN_RX(cpu_struct, BP)

# define ACCESS_GEN_EIP(cpu_struct) ACCESS_GEN_ERX(cpu_struct, EIP)
# define ACCESS_GEN_IP(cpu_struct) ACCESS_GEN_RX(cpu_struct, IP)

//# define ACCESS_GEN_EFLAGS(cpu_struct) ACCESS_GEN_ERX(cpu_struct, EFLAGS)
//# define ACCESS_GEN_FLAGS(cpu_struct) ACCESS_GEN_RX(cpu_struct, FLAGS)
#define  ACCESS_GEN_EFLAGS_LOWER_HALF_VALUE(cpu_struct) ((cpu_struct).EFlagsRegister.flag.value) 
# define ACCESS_GEN_EFLAGS(cpu_struct) ((cpu_struct).EFlagsRegister.value)
# define ACCESS_GEN_FLAGS(cpu_struct) ((cpu_struct).EFlagsRegister.flag.value)


# define ACCESS_GEN_CS(cpu_struct) ACCESS_GEN_SEG(cpu_struct, CS)
# define ACCESS_GEN_DS(cpu_struct) ACCESS_GEN_SEG(cpu_struct, DS)
# define ACCESS_GEN_ES(cpu_struct) ACCESS_GEN_SEG(cpu_struct, ES)
# define ACCESS_GEN_FS(cpu_struct) ACCESS_GEN_SEG(cpu_struct, FS)
# define ACCESS_GEN_GS(cpu_struct) ACCESS_GEN_SEG(cpu_struct, GS)
# define ACCESS_GEN_SS(cpu_struct) ACCESS_GEN_SEG(cpu_struct, SS)

#define EFLAGS_CF_BITS  0
#define EFLAGS_PF_BITS  2
#define EFLAGS_AF_BITS  4
#define EFLAGS_ZF_BITS  6
#define EFLAGS_SF_BITS  7
#define EFLAGS_TF_BITS  8
#define EFLAGS_IF_BITS  9
#define EFLAGS_DF_BITS  10
#define EFLAGS_OF_BITS  11
#define EFLAGS_IOPL_BITS  12
#define EFLAGS_NT_BITS  14

#define EFLAGS_CF_MASK  (1 << EFLAGS_CF_BITS)
#define EFLAGS_PF_MASK  (1 << EFLAGS_PF_BITS)
#define EFLAGS_AF_MASK  (1 << EFLAGS_AF_BITS)
#define EFLAGS_ZF_MASK  (1 << EFLAGS_ZF_BITS)
#define EFLAGS_SF_MASK  (1 << EFLAGS_SF_BITS)
#define EFLAGS_TF_MASK  (1 << EFLAGS_TF_BITS)
#define EFLAGS_IF_MASK  (1 << EFLAGS_IF_BITS)
#define EFLAGS_DF_MASK  (1 << EFLAGS_DF_BITS)
#define EFLAGS_OF_MASK  (1 << EFLAGS_OF_BITS)
#define EFLAGS_IOPL_MASK  (2 << EFLAGS_IOPL_BITS)
#define EFLAGS_NT_MASK  (1 << EFLAGS_NT_BITS)

#define SET_EFLAGS_MASK(cpu_struct, val, flag) (ACCESS_GEN_EFLAGS(cpu_struct) = ((ACCESS_GEN_EFLAGS(cpu_struct) & (~flag##_MASK)) | (((UINT32) (val)) << flag##_BITS)))

#define SET_EFLAGS_DF(cpu_struct, val)   SET_EFLAGS_MASK(cpu_struct, (val), EFLAGS_DF)
#define SET_EFLAGS_CF(cpu_struct, val)   SET_EFLAGS_MASK(cpu_struct, (val), EFLAGS_CF)
#define SET_EFLAGS_PF(cpu_struct, val)   SET_EFLAGS_MASK(cpu_struct, (val), EFLAGS_PF)
#define SET_EFLAGS_AF(cpu_struct, val)   SET_EFLAGS_MASK(cpu_struct, (val), EFLAGS_AF)
#define SET_EFLAGS_ZF(cpu_struct, val)   SET_EFLAGS_MASK(cpu_struct, (val), EFLAGS_ZF);  \
                                            assert(1 == (0 == 0));assert(0 == (0 != 0));
#define SET_EFLAGS_SF(cpu_struct, val)   SET_EFLAGS_MASK(cpu_struct, val, EFLAGS_SF)
//#define SET_EFLAGS_TF(cpu_struct, val)   SET_EFLAGS_MASK(cpu_struct, (val), EFLAGS_TF)
//#define SET_EFLAGS_IF(cpu_struct, val)   SET_EFLAGS_MASK(cpu_struct, (val), EFLAGS_IF)
//#define SET_EFLAGS_DF(cpu_struct, val)   SET_EFLAGS_MASK(cpu_struct, (val), EFLAGS_DF)


//Intel 64 and IA-32 Architectures Software Developer's Manual - Volume 1- Basic Architecture.pdf    
//                                                                                      Page:3-21
// Overflow flag — Set if the integer result is too large a positive
// number or too small a negative number (excluding the sign-bit)
// to fit in the destination operand; cleared otherwise. This flag
// indicates an overflow condition for signed-integer (two's complement) arithmetic.
#define SET_EFLAGS_OF(cpu_struct, val)   SET_EFLAGS_MASK(cpu_struct, (val), EFLAGS_OF)

//两个符号位相同的补码相加，如果和的符号位与加数的符号相反，则表明运算结果溢出
//加法溢出真值表
// (~(op1^op2)) & ( op2 & result)   overflow
//     0      0              0          0
//     0      0              1          1
//     0      1              0          0
//     0      1              1          0
//     1      0              0          0
//     1      0              1          0
//     1      1              0          1
//     1      1              1          0
#define GET_OVERFLOW_ADD(op1, op2, result, bits) ((((~((op1) ^ (op2))) & ((op2) ^ (result))) & (1 << (bits-1))) != 0)
//两个符号位相反的补码相减，如果差的符号位与被减数的符号位相反，则表明运算结果溢出。
#define GET_OVERFLOW_SUB(op1, op2, result, bits) (((((op1) ^ (op2)) & ((op1) ^ (result))) & (1 << (bits-1))) != 0)


#define EVAL_EFLAGS_OF_ADD(cpu_struct, op1, op2, result, bits)   SET_EFLAGS_OF(cpu_struct, ((GET_OVERFLOW_ADD(op1, op2, result, bits))))
#define EVAL_EFLAGS_OF_SUB(cpu_struct, op1, op2, result, bits)   SET_EFLAGS_OF(cpu_struct, ((GET_OVERFLOW_SUB(op1, op2, result, bits))))
//#define EVAL_EFLAGS_PF(cpu_struct, val)   SET_EFLAGS_PF(cpu_struct, val(val) EFLAGS_PF)

//针对第5位
//(op1) ^ (op2) ^ (result) 真值表：
//  0      0          0      AF: 0       
//  0      0          1      AF: 1     op1,op2第5位为0，相加结果应为0，但运算结果为1，说明第4位有，进位，其它情况同理
//  0      1          0      AF: 1
//  0      1          1      AF: 0
//  1      0          0      AF: 1
//  1      0          1      AF: 0
//  1      1          0      AF: 0
//  1      1          1      AF: 1  
#define EVAL_EFLAGS_AF(cpu_struct, op1, op2, result)   SET_EFLAGS_AF(cpu_struct, (((op1) ^ (op2) ^ (result)) & 0x10) >> 4)
#define EVAL_EFLAGS_ZF(cpu_struct, result)   SET_EFLAGS_ZF(cpu_struct,(0 == result))

//result 传进来的16位数： bit = 8
//0000 0001 0000 0000
//result >> (bits -1)
//0000 0000 00000 0010
#define EVAL_EFLAGS_SF(cpu_struct, result, bits)   SET_EFLAGS_SF(cpu_struct, ((result &(1<<(bits -1))) != 0))

#define EVAL_EFLAGS_CF_ADD(cpu_struct, op1, op2, result, bits)   SET_EFLAGS_CF(cpu_struct, ((((((op1) ^ (op2)  ^ (result)) &(1<<(bits -1))) >> (bits -1))  ^ (GET_OVERFLOW_ADD(op1, op2, result, bits))) != 0))
#define EVAL_EFLAGS_CF_SUB(cpu_struct, op1, op2, result, bits)   SET_EFLAGS_CF(cpu_struct, ((((((op1) ^ (op2)  ^ (result)) &(1<<(bits -1))) >> (bits -1))  ^ (GET_OVERFLOW_SUB(op1, op2, result, bits))) != 0))


#define GET_EFLAGS_MASK(cpu_struct, flag_mask) (ACCESS_GEN_EFLAGS(cpu_struct) & flag_mask)

#define GET_EFLAGS_CF(cpu_struct)   GET_EFLAGS_MASK(cpu_struct, EFLAGS_CF_MASK)
#define GET_EFLAGS_PF(cpu_struct)   GET_EFLAGS_MASK(cpu_struct, EFLAGS_PF_MASK)
#define GET_EFLAGS_AF(cpu_struct)   GET_EFLAGS_MASK(cpu_struct, EFLAGS_AF_MASK)
#define GET_EFLAGS_ZF(cpu_struct)   GET_EFLAGS_MASK(cpu_struct, EFLAGS_ZF_MASK)
#define GET_EFLAGS_SF(cpu_struct)   GET_EFLAGS_MASK(cpu_struct, EFLAGS_SF_MASK)
#define GET_EFLAGS_TF(cpu_struct)   GET_EFLAGS_MASK(cpu_struct, EFLAGS_TF_MASK)
#define GET_EFLAGS_IF(cpu_struct)   GET_EFLAGS_MASK(cpu_struct, EFLAGS_IF_MASK)
#define GET_EFLAGS_DF(cpu_struct)   GET_EFLAGS_MASK(cpu_struct, EFLAGS_DF_MASK)
#define GET_EFLAGS_OF(cpu_struct)   GET_EFLAGS_MASK(cpu_struct, EFLAGS_OF_MASK)
#define GET_EFLAGS_NT(cpu_struct)   GET_EFLAGS_MASK(cpu_struct, EFLAGS_NT_MASK)

#define GET_EFLAGS_CF_BIT(cpu_struct)   (GET_EFLAGS_MASK(cpu_struct, EFLAGS_CF_MASK) >> EFLAGS_CF_BITS)
#define GET_EFLAGS_PF_BIT(cpu_struct)   (GET_EFLAGS_MASK(cpu_struct, EFLAGS_PF_MASK) >> EFLAGS_PF_BITS)
#define GET_EFLAGS_AF_BIT(cpu_struct)   (GET_EFLAGS_MASK(cpu_struct, EFLAGS_AF_MASK) >> EFLAGS_AF_BITS)
#define GET_EFLAGS_ZF_BIT(cpu_struct)   (GET_EFLAGS_MASK(cpu_struct, EFLAGS_ZF_MASK) >> EFLAGS_ZF_BITS)
#define GET_EFLAGS_SF_BIT(cpu_struct)   (GET_EFLAGS_MASK(cpu_struct, EFLAGS_SF_MASK) >> EFLAGS_SF_BITS)
#define GET_EFLAGS_TF_BIT(cpu_struct)   (GET_EFLAGS_MASK(cpu_struct, EFLAGS_TF_MASK) >> EFLAGS_TF_BITS)
#define GET_EFLAGS_IF_BIT(cpu_struct)   (GET_EFLAGS_MASK(cpu_struct, EFLAGS_IF_MASK) >> EFLAGS_IF_BITS)
#define GET_EFLAGS_DF_BIT(cpu_struct)   (GET_EFLAGS_MASK(cpu_struct, EFLAGS_DF_MASK) >> EFLAGS_DF_BITS)
#define GET_EFLAGS_OF_BIT(cpu_struct)   (GET_EFLAGS_MASK(cpu_struct, EFLAGS_OF_MASK) >> EFLAGS_OF_BITS)
#define GET_EFLAGS_NT_BIT(cpu_struct)   (GET_EFLAGS_MASK(cpu_struct, EFLAGS_NT_MASK) >> EFLAGS_NT_BITS)

#endif

//段描述符掩码(第一字节位)
#define SEGMENT_DESCRIPTOR_MASK_BIT_BASE_15_0  0
#define SEGMENT_DESCRIPTOR_MASK_BIT_LIMIT_15_0 16

#define SEGMENT_DESCRIPTOR_MASK_BASE_15_0  (0xffff << SEGMENT_DESCRIPTOR_MASK_BIT_BASE_15_0)
#define SEGMENT_DESCRIPTOR_MASK_LIMIT_15_0 (0xffff << SEGMENT_DESCRIPTOR_MASK_BIT_LIMIT_15_0)

//段描述符掩码(第二字节位)
#define SEGMENT_DESCRIPTOR_MASK_BIT_BASE_23_16  0
#define SEGMENT_DESCRIPTOR_MASK_BIT_TYPE        8
#define SEGMENT_DESCRIPTOR_MASK_BIT_S           12
#define SEGMENT_DESCRIPTOR_MASK_BIT_DPL         13
#define SEGMENT_DESCRIPTOR_MASK_BIT_P           15
#define SEGMENT_DESCRIPTOR_MASK_BIT_LIMIT_19_16 16
#define SEGMENT_DESCRIPTOR_MASK_BIT_AVL         20
#define SEGMENT_DESCRIPTOR_MASK_BIT_L           21
#define SEGMENT_DESCRIPTOR_MASK_BIT_DB          22
#define SEGMENT_DESCRIPTOR_MASK_BIT_G           23
#define SEGMENT_DESCRIPTOR_MASK_BIT_BASE_31_24  24

#define SEGMENT_DESCRIPTOR_MASK_BASE_23_16  (0xff << SEGMENT_DESCRIPTOR_MASK_BIT_BASE_23_16)
#define SEGMENT_DESCRIPTOR_MASK_TYPE        (0x0f << SEGMENT_DESCRIPTOR_MASK_BIT_TYPE)
#define SEGMENT_DESCRIPTOR_MASK_S           (1 << SEGMENT_DESCRIPTOR_MASK_BIT_S)
#define SEGMENT_DESCRIPTOR_MASK_DPL         (0x3 << SEGMENT_DESCRIPTOR_MASK_BIT_DPL)
#define SEGMENT_DESCRIPTOR_MASK_P           (1 << SEGMENT_DESCRIPTOR_MASK_BIT_P)
#define SEGMENT_DESCRIPTOR_MASK_LIMIT_19_16 (0x0f << SEGMENT_DESCRIPTOR_MASK_BIT_LIMIT_19_16)
#define SEGMENT_DESCRIPTOR_MASK_AVL         (1 << SEGMENT_DESCRIPTOR_MASK_BIT_AVL)
#define SEGMENT_DESCRIPTOR_MASK_L           (1 << SEGMENT_DESCRIPTOR_MASK_BIT_L)
#define SEGMENT_DESCRIPTOR_MASK_DB          (1 << SEGMENT_DESCRIPTOR_MASK_BIT_DB)
#define SEGMENT_DESCRIPTOR_MASK_G           (1 << SEGMENT_DESCRIPTOR_MASK_BIT_G)
#define SEGMENT_DESCRIPTOR_MASK_BASE_31_24  (0xff << SEGMENT_DESCRIPTOR_MASK_BIT_BASE_31_24)

//名称：_VM_Intel_x86_GeneralRegister_t
//描述：结构体，用于描述Intel x86架构下Ring3级CPU使用的通用寄存器定义
//更新日志：2009年6月16日，杨鸿博(yanghongbo@ptwy.cn)，创建
//                 2009年6月19日，杨鸿博(yanghongbo@ptwy.cn)，原先的结构有问题，修改了
//
//#pragma pack(push, 1) //取消编译器的多字节对齐
typedef union _VM_Intel_x86_GeneralRegister_t{
    UINT64 rrx;
    struct {
        union {
            UINT32 erx;
            struct {
                union {
                    UINT16 rx;
                    struct {
                        UINT8 rl;
                        UINT8 rh;
                    }rxword;
                };
                UINT16 word_padding;    //仅用来占位，不应当被使用
            }erxdword;
        };
        UINT32 dword_padding;
    }rrxqword;
}VM_Intel_x86_GeneralRegister_t;
//#pragma pack(pop)

//名称：_VM_Intel_x86_GeneralRegister_t
//描述：结构体，用于描述Intel x86架构下Ring3级CPU使用的通用寄存器定义
//更新日志：2009年6月16日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
//#pragma pack(push, 1) //取消编译器的多字节对齐
# if VM_INTEL_X86_64BIT_SUPPORT
//
# else
typedef struct _VM_Intel_x86_SegmentRegister_t{
    UINT16 selector;
}VM_Intel_x86_SegmentRegister_t;
# endif
//#pragma pack(pop)

//名称：_VM_Intel_x86_SegmentDescriptor_t
//描述：定义段描述符
//更新日志：2009年6月24日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
//#pragma pack(push, 1) //取消编译器的多字节对齐
typedef struct _VM_Intel_x86_SegmentDescriptor_t {
    union {
        UINT32 uDescriptor0;
        struct {
            UINT32 uBase0 : 8;
            UINT32 uSegType : 4;
            UINT32 uDescType : 1;
            UINT32 uDPL : 2;
            UINT32 uPresent : 1;
            UINT32 uSegLimit : 4;
            UINT32 uAVL : 1;
            UINT32 uL : 1;
            UINT32 uDeafultOperationSize : 1;
            UINT32 uGranularity : 1;
            UINT32 uBase1 : 8;
        }Descriptor0;
    };

    union {
        UINT32 uDescriptor1;
        struct {
            UINT16 uSegLimit;
            UINT16 uBaseAddress;
        }Descriptor1;
    };
}VM_Intel_x86_SegmentDescriptor_t , *PVM_Intel_x86_SegmentDescriptor_t;
//#pragma pack(pop)

typedef struct _VM_Intel_x86_ISA_t VM_Intel_x86_ISA_t, *PVM_Intel_x86_ISA_t;
typedef struct _VM_Intel_x86_InstructionData_t VM_Intel_x86_InstructionData_t, * PVM_Intel_x86_InstructionData_t;
typedef VM_INSTRUCTION_ERR_CODE (*PFN_INSTRUCTION_EXEC)(PVM_Intel_x86_ISA_t, PVM_Memory_t, PVM_Intel_x86_InstructionData_t);

//名称：VM_Intel_x86_InstructionData_LastResult_t
//描述：结构体，用于保存上一次运算的操作数及结果，用于在需要时计算标志位
//更新日志：2009年9月25日，杨鸿博(yanghongbo@ptwy.cn)，创建
typedef struct _VM_Intel_x86_InstructionData_LastResult_t {
# if VM_INTEL_X86_64BIT_SUPPORT
//
# else
    UINT32 op2;
    UINT32 uOp2;
    UINT32 uResult;
#endif
}VM_Intel_x86_InstructionData_LastResult_t;

//名称：VM_Intel_x86_InstructionData_t
//描述：结构体，用于描述Intel x86 架构下Ring3指令数据格式
//更新日志：2009年6月19日，杨鸿博(yanghongbo@ptwy.cn)，创建
//           2009年8月3日，杨鸿博(yanghongbo@ptwy.cn)，做反汇编器时将前缀字节数组换成标志位
//#pragma pack(push, 1) //取消编译器的多字节对齐
struct _VM_Intel_x86_InstructionData_t{
    DWORD dwFlags;//指令附加属性标志位，比如各种前缀状态
    DWORD dwDataBitFlags;//设置标志位，用以标记使用的数据位，或者确定立即数/偏移的大小（用于符号位转换）
    BYTE byOpcodesNum;
    BYTE byOpcodes[3];//1-, 2-or 3-BYTE opcode
#ifdef VM_LITTLE_ENDDIAN
    union {
        struct  {//little endian
            BYTE byRm : 3;
            BYTE byReg : 3;
            BYTE byMod : 2;
        }ModRM; //if required
        BYTE byModRM;
    };
#else
#endif

#ifdef VM_LITTLE_ENDDIAN
    union {//little endian
        struct {
            BYTE byBase : 3;
            BYTE byIndex : 3;
            BYTE byScale : 2;
        }SIB; //if required
        BYTE bySIB;
    };
#else
#endif

    INT32 iDisplacement;// 1, 2, or 4 BYTEs or none
    UINT32 uImmediate;// 1, 2, or 4 BYTEs or none

    //2009-9-25, yanghongbo@ptwy.cn, 增加，保存原有的标志位
    UINT uArg1Flag;
    UINT uArg2Flag;
    UINT uArg3Flag;

    PFN_INSTRUCTION_EXEC pfnInstructionExec;
};
//#pragma pack(pop)

//CPU state
typedef enum _Intel_x86_Operand_Size_t {
    OPERAND_SIZE_64BIT = 0,
    OPERAND_SIZE_16BIT = 2,
    OPERAND_SIZE_32BIT = 1,
}Intel_x86_Operand_Size_t;

typedef enum _Intel_x86_Address_Size_t {
    ADDRESS_SIZE_64BIT,
    ADDRESS_SIZE_32BIT,
    ADDRESS_SIZE_16BIT,
}Intel_x86_Address_Size_t;
typedef union _EFLAGS_Register_t {
    DWORD value;
    struct {
        WORD value;
        WORD upper_half_value;
    }flag;
    struct {
#ifdef VM_LITTLE_ENDDIAN
        BYTE CF:1;
        BYTE Reserved0:1;
        BYTE PF:1;
        BYTE Reserved1:1;
        BYTE AF:1;
        BYTE Reserved2:1;
        BYTE ZF:1;
        BYTE SF:1;
        BYTE TF:1;
        BYTE IF:1;
        BYTE DF:1;
        BYTE OF:1;
#else
#endif
    } eflags;
}EFLAGS_Register_t;
//名称：_VM_Intel_x86_ISA_t
//描述：结构体，用于描述Intel x86 架构下Ring3级CPU使用的寄存器定义
//结构体中包含一些与CPU直接相关的执行函数的指针，用以控制单元(Control Unit)来调用
//更新日志：2009年6月16日，杨鸿博(yanghongbo@ptwy.cn)，创建，增加GeneralRegisters及SegmentRegisters
//          2009年9月25日，杨鸿博(yanghongbo@ptwy.cn)，增加LastResult
struct _VM_Intel_x86_ISA_t{
    Intel_x86_Operand_Size_t OpSize;//默认操作数
    Intel_x86_Address_Size_t AddrSize;//默认操作数
    //GeneralRegisters:8个通用寄存器(EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP)及EIP和EFLAGS
    VM_Intel_x86_GeneralRegister_t GeneralRegisters[VM_INTEL_X86_GENERAL_REGISTERS + VM_INTEL_X86_EIP_REGISTER + VM_INTEL_X86_EFLAGS_REGISTER];
    EFLAGS_Register_t   EFlagsRegister;
    //SegmentRegisters:6个段寄存器(CS, DS, ES, FS, SS)
    VM_Intel_x86_SegmentRegister_t SegmentRegisters[VM_INTEL_X86_SEGMENT_REGISTERS];

    VM_Intel_x86_InstructionData_t CurrentInstruction;

    //用于保存最后一次与标志位相关的操作数据
    VM_Intel_x86_InstructionData_LastResult_t LastResult;

};

struct _VM_CPUStructure_t; //defined in Include/VM_CpuStructure.h
struct _VM_ControlUnit_t; //defined in Include/VM_ControlUnit.h

VM_ERR_CODE VM_Intel_x86_InitializeCpuStructure(PVM_CPUStructure_t pCpu);
VM_ERR_CODE VM_Intel_x86_UninitializeCpuStructure(PVM_CPUStructure_t pCpu);
VM_ERR_CODE VM_Intel_x86_InitializeControlUnit(struct _VM_ControlUnit_t * pControlUnit);
void VM_Intel_x86_OutputCpuState(struct _VM_CPUStructure_t * pCpuStructure);
VM_INSTRUCTION_ERR_CODE VM_Intel_x86_FetchAndDecodeOneInstruction(struct _VM_CPUStructure_t * pCpuStructure, PVM_Memory_t pMemory);
VM_ERR_CODE VM_Intel_x86_ExecuteOneInstruction(struct _VM_CPUStructure_t * pCpuStructure, PVM_Memory_t pMemory);


size_t GetInstructionMnemonic(char * szString, size_t iLength, const PVM_Intel_x86_InstructionData_t pInstruction, Intel_x86_Operand_Size_t OpSize, Intel_x86_Address_Size_t AddrSize, DWORD addr);

#ifdef  __cplusplus
}
#endif

#endif//_INTEL_X86_ISA_H_
