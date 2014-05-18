//
//文件名称：        src/ISA/Intel_x86/Intel_x86_ISA.c
//文件描述：        Intel x86架构的编码表
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
//2009年8月3日，杨鸿博(yanghongbo@ptwy.cn)，创建（从另一个工程中迁移过来）

#include "ISA/Intel_x86/OpcodeMaps.h"
#include "ISA/Intel_x86/Instructions.h"

const char * const Intel_x86_Registers_Names[54] = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
                                            "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
                                            "ax", "bx", "cx", "dx", "si", "di", "sp", "bp",
                                            "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
                                            "es", "ss", "cs", "ds", "fs", "gs", 
                                            "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",
                                            "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",};
                                            


const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_movsxd[] = {{"movsxd", AM_G|OT_v, AM_E|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, 0}};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_pushad[] = {{"pushad", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, 0, pusha_60}};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_popad[] = {{"popad", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, 0,popa_61}};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_insb[] = {{"insb", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0}};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_inswd[] = {{"insw", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT|OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0}, 
                                                                                                {"insd", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT|OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
                                                                                              };
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_outsb[] = {{"outsb", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0}};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_outswd[] = {{"outsw", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT|OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0}, 
                                                                                                {"outsd", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT|OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
                                                                                              };
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_for_jb[] = {{"jnae", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, jb_72},
                                                                                            {"jc", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, jb_72}};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_for_jnb[] = {{"jae", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, jnb_73},
                                                                                            {"jnc", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, jnb_73}};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_je[] = {{"je", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, jz_74},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_jne[] = {{"jne", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, jnz_75},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_jna[] = {{"jna", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, jbe_76},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_ja[] = {{"ja", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, jnbe_77},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_jpe[] = {{"jpe", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, jp_7a},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_jpo[] = {{"jpo", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, jnp_7b},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_jnge[] = {{"jnge", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, jl_7c},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_jge[] = {{"jge", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, jnl_7d},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_jng[] = {{"jng", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, jle_7e},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_jg[] = {{"jg", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, jg_7f},};

const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_for_setb[] = {{"setnae", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
                                                                                            {"setc", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0}};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_for_setnb[] = {{"setae", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
                                                                                            {"setnc", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0}};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_sete[] = {{"sete", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_setne[] = {{"setne", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_setna[] = {{"setna", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_seta[] = {{"seta", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_setpe[] = {{"setpe", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_setpo[] = {{"setpo", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_setnge[] = {{"setnge", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_setge[] = {{"setge", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_setng[] = {{"setng", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_setg[] = {{"setg", USE_UPPER_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};

const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_sal[] = {{"sal", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_nop[] = {{"puase", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_USE_WITH_PREFIX_F3H, 0},
                                                                                        {"xchg", AM_REG_RAX|OT_v, AM_REG_RAX|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
                                                                                      };
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_xchg_rcx[] = {{"xchg", AM_REG_RCX|OT_v, AM_REG_RAX|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_xchg_rdx[] = {{"xchg", AM_REG_RDX|OT_v, AM_REG_RAX|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_xchg_rbx[] = {{"xchg", AM_REG_RBX|OT_v, AM_REG_RAX|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_xchg_rsp[] = {{"xchg", AM_REG_RSP|OT_v, AM_REG_RAX|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_xchg_rbp[] = {{"xchg", AM_REG_RBP|OT_v, AM_REG_RAX|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_xchg_rsi[] = {{"xchg", AM_REG_RSI|OT_v, AM_REG_RAX|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_xchg_rdi[] = {{"xchg", AM_REG_RDI|OT_v, AM_REG_RAX|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};

const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_cbw[] = {{"cwde", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, 0},
                                                                                        {"cdqe", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_cwd[] = {{"cdq", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, 0},
                                                                                        {"cqo", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_fwait[] = {{"fwait", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_pushf[] = {{"pushfd", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, 0},
                                                                                        {"pushfq", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_popf[] = {{"popfd", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, 0},
                                                                                        {"popq", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_movsb[] = {{"movsb", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_movs[] = {{"movsw", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT, 0},
                                                                                        {"movsd", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, 0},
                                                                                        {"movsq", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, 0},
                                                                                       };
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_cmpsb[] = {{"cmpsb", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, cmps_a6},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_cmps[] = {{"cmpsw", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT, 0},
                                                                                        {"cmpsd", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, 0},
                                                                                        {"cmpsq", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, 0},
                                                                                       };
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_stosb[] = {{"stosb", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_stos[] = {{"stosw", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT, 0},
                                                                                        {"stosd", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, 0},
                                                                                        {"stosq", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, 0},
                                                                                       };
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_lodsb[] = {{"lodsb", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_lods[] = {{"lodsw", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT, 0},
                                                                                        {"lodsd", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, 0},
                                                                                        {"lodsq", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, 0},
                                                                                       };
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_scasb[] = {{"scasb", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_scas[] = {{"scasw", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT, 0},
                                                                                        {"scasd", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, 0},
                                                                                        {"scasq", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, 0},
                                                                                       };
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_ret[] = {{"ret", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_iret[] = {{"iretd", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, 0},
                                                                                        {"iretq", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, 0},};

const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_xlatb[] = {{"xlatb", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_loopnz[] = {{"loopnz", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, loopcc_e0},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_loopz[] = {{"loopz", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0, loopcc_e1},};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Attribute_Patch_jrcxz[] = {{"jcxz", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT, 0, jrcxz_e3},
                                                                                         {"jecxz", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, 0, jrcxz_e3},
                                                                                         {"jrcxz", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, 0},
                                                                                        };
//Opcode Extension Group
//80
const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp1_Immd0[8] = {{"add", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_80_add},
                                                                                             {"or", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_80_or},
                                                                                             {"adc", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_80_adc},
                                                                                             {"sbb", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_80_sbb},
                                                                                             {"and", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_80_and},
                                                                                             {"sub", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_80_sub},
                                                                                             {"xor", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_80_xor},
                                                                                             {"cmp", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_80_cmp},
                                                                                            };

//Opcode Extension Group
//81
const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp1_Immd1[8] = {{"add", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_81_add},
                                                                                            {"or", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_81_or},
                                                                                            {"adc", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_81_adc},
                                                                                            {"sbb", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_81_sbb},
                                                                                            {"and", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_81_and},
                                                                                            {"sub", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_81_sub},
                                                                                            {"xor", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_81_xor},
                                                                                            {"cmp", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_81_cmp},
                                                                                           };
//Opcode Extension Group
//82
//note: 2010年3月26日杨鸿博
const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp1_Immd2[8] = {{"add", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_82_add},
                                                                                            {"or", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_82_or},
                                                                                            {"adc", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_82_adc},
                                                                                            {"sbb", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_82_sbb},
                                                                                            {"and", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_82_and},
                                                                                            {"sub", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_82_sub},
                                                                                            {"xor", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_82_xor},
                                                                                            {"cmp", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_82_cmp},
                                                                                           };
//Opcode Extension Group
//83
const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp1_Immd3[8] = {{"add", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_83_add},
                                                                                            {"or", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_83_or},
                                                                                            {"adc", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_83_adc},
                                                                                            {"sbb", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_83_sbb},
                                                                                            {"and", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_83_and},
                                                                                            {"sub", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_83_sub},
                                                                                            {"xor", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_83_xor},
                                                                                            {"cmp", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, immediate_grp1_83_cmp},
                                                                                           };
//8F
const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp1A[8] = {{"pop", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, grp1a_pop_8f_pop},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                            };

const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp2_c0[8] = {{"rol", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_c0_rol},
                                                                                             {"ror", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_c0_ror},
                                                                                             {"rcl", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_c0_rcl},
                                                                                             {"rcr", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_c0_rcr},
                                                                                             {"shl", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_sal, shift_grp2_c0_sal},
                                                                                             {"shr", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0,shift_grp2_c0_shr},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                             {"sar", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0,shift_grp2_c0_sar},
                                                                                            };

const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp2_c1[8] = {{"rol", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_c1_rol},
                                                                                            {"ror", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_c1_ror},
                                                                                            {"rcl", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_c1_rcl},
                                                                                            {"rcr", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_c1_rcr},
                                                                                            {"shl", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_sal, shift_grp2_c1_sal},
                                                                                            {"shr", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0,shift_grp2_c1_shr},
                                                                                            {0, 0, 0, 0, 0, 0},
                                                                                            {"sar", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0,shift_grp2_c1_sar},
                                                                                           };

const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp2_d0[8] = {{"rol", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d0_rol},
                                                                                            {"ror", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d0_ror},
                                                                                            {"rcl", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d0_rcl},
                                                                                            {"rcr", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d0_rcr},
                                                                                            {"shl", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_sal, shift_grp2_d0_sal},
                                                                                            {"shr", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0,shift_grp2_d0_shr},
                                                                                            {0, 0, 0, 0, 0, 0},
                                                                                            {"sar", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0,shift_grp2_d0_sar},
                                                                                           };

const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp2_d1[8] = {{"rol", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d1_rol},
                                                                                            {"ror", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d1_ror},
                                                                                            {"rcl", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d1_rcl},
                                                                                            {"rcr", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d1_rcr},
                                                                                            {"shl", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_sal, shift_grp2_d1_sal},
                                                                                            {"shr", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0,shift_grp2_d1_shr},
                                                                                            {0, 0, 0, 0, 0, 0},
                                                                                            {"sar", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0,shift_grp2_d1_sar},
                                                                                            };
const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp2_d2[8] = {{"rol", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d2_rol},
                                                                                            {"ror", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d2_ror},
                                                                                            {"rcl", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d2_rcl},
                                                                                            {"rcr", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d2_rcr},
                                                                                            {"shl", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_sal, shift_grp2_d2_sal},
                                                                                            {"shr", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0,shift_grp2_d2_shr},
                                                                                            {0, 0, 0, 0, 0, 0},
                                                                                            {"sar", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0,shift_grp2_d2_sar},
                                                                                            };

const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp2_d3[8] = {{"rol", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d3_rol},
                                                                                            {"ror", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d3_ror},
                                                                                            {"rcl", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d3_rcl},
                                                                                            {"rcr", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, shift_grp2_d3_rcr},
                                                                                            {"shl", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_sal, shift_grp2_d3_sal},
                                                                                            {"shr", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0,shift_grp2_d3_shr},
                                                                                            {0, 0, 0, 0, 0, 0},
                                                                                            {"sar", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0,shift_grp2_d3_sar},
                                                                                            };


const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp3_F6[8] = {{"test", AM_I|OT_b, NO_OPERAND, NO_OPERAND, 0, 0, unary_grp3_f6_test},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                             {"not", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, unary_grp3_f6_not},
                                                                                             {"neg", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, unary_grp3_f6_neg},
                                                                                             {"mul", AM_REG_AL|OT_b, AM_E|OT_b, NO_OPERAND, 0, 0, unary_grp3_f6_mul},
                                                                                             {"imul", AM_REG_AL|OT_b, AM_E|OT_b, NO_OPERAND, 0, 0, unary_grp3_f6_imul}, 
                                                                                             {"div", AM_REG_AL|OT_b, AM_E|OT_b, NO_OPERAND, 0, 0, unary_grp3_f6_div},
                                                                                             {"idiv", AM_REG_AL|OT_b, AM_E|OT_b, NO_OPERAND, 0, 0, unary_grp3_f6_idiv},                                                                                             
                                                                                            };
const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp3_F7[8] = {{"test", AM_I|OT_z, NO_OPERAND, NO_OPERAND, 0, 0, unary_grp3_f7_test},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                             {"not", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, unary_grp3_f7_not},
                                                                                             {"neg", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, unary_grp3_f7_neg},
                                                                                             {"mul", AM_REG_RAX|OT_b, AM_E|OT_v, NO_OPERAND, 0, 0, unary_grp3_f7_mul},
                                                                                             {"imul", AM_REG_RAX|OT_b, AM_E|OT_v, NO_OPERAND, 0, 0, unary_grp3_f7_imul},
                                                                                             {"div", AM_REG_RAX|OT_b, AM_E|OT_v, NO_OPERAND, 0, 0, unary_grp3_f7_div},
                                                                                             {"idiv", AM_REG_RAX|OT_b, AM_E|OT_v, NO_OPERAND, 0, 0, unary_grp3_f7_idiv},                                                                                             
                                                                                            };
const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp4[8] = {{"inc", AM_E|OT_b, NO_OPERAND, NO_OPERAND, 0, 0, inc_dec_grp4_fe_inc},
                                                                              {"dec", AM_E|OT_b, NO_OPERAND, NO_OPERAND, 0, 0, inc_dec_grp4_fe_dec},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                             {0, 0, 0, 0, 0, 0},
                                                                                            };
const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp5[8] = {{"inc", AM_E|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, inc_dec_grp5_ff_inc},
                                                                              {"dec", AM_E|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, inc_dec_grp5_ff_dec},
                                                                             {"calln", AM_E|OT_v, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_f64, 0,inc_dec_grp5_ff_2_call},
                                                                             {"callf", AM_E|OT_p, NO_OPERAND, NO_OPERAND, 0, 0,inc_dec_grp5_ff_3_call},
                                                                             {"jmpn", AM_E|OT_v, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_f64, 0, inc_dec_grp5_ff_4_jmp},
                                                                             {"jmpf", AM_E|OT_p, NO_OPERAND, NO_OPERAND, 0, 0, inc_dec_grp5_ff_4_jmp},
                                                                             {"push", AM_E|OT_v, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_d64, 0,inc_dec_grp5_ff_push},
                                                                             {0, 0, 0, 0, 0, 0},
                                                                            };

const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp11_c6[1] = {{"mov", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, grp11_mov_c6_mov}//C6
                                                                                };

const Intel_x86_Instruction_Attribute_t Intel_x86_Opcode_Extension_Grp11_c7[8] = {{"mov", USE_UPPER_OPERAND, USE_UPPER_OPERAND, USE_UPPER_OPERAND, 0, 0, grp11_mov_c7_mov},//C7 没有填
                                                                                 {0, 0, 0, 0, 0, 0},
                                                                                 {0, 0, 0, 0, 0, 0},
                                                                                 {0, 0, 0, 0, 0, 0},
                                                                                 {0, 0, 0, 0, 0, 0},
                                                                                 {0, 0, 0, 0, 0, 0},
                                                                                 {0, 0, 0, 0, 0, 0},
                                                                                 {0, 0, 0, 0, 0, 0},
                                                                                };
/*
const Intel_x86_Instruction_Prefix_t Intel_x86_Instruction_Prefix_Map[0x10] = {
//Group 1:
    {PF_LOCK,   0xF0, "lock"},
    {PF_REPNE,  0xF2, "repne"},
    {PF_REPNE,  0xF2, "repnz"},
    {PF_REP,    0xF3, "rep"},
    {PF_REPE,   0xF3, "repe"},
    {PF_REPE,   0xF3, "repz"},
//Group 2:
    {PF_CS,     0x2E, "cs"},
    {PF_SS,     0x36, "ss"},
    {PF_DS,     0x3E, "ds"},
    {PF_ES,     0x26, "es"},
    {PF_FS,     0x64, "fs"},
    {PF_GS,     0x65, "gs"},
    {PF_BRANCH_NOT_TAKEN,   0x2E, 0},
    {PF_BRANCH_TAKEN,     0x3E, 0},
//Group 3:
    {PF_OPERAND_SIZE,     0x66, 0},
//Group 4:
    {PF_ADDRESS_SIZE,     0x67, 0},
};
*/
/*
char * Intel_x86_Instruction_Mnemonics[] = {
    "add",
};
*/

const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Opcode_Map_OneByte[256] = {
//row 0x00
    {"add", AM_E|OT_b, AM_G|OT_b, NO_OPERAND, 0, 0, add_00},          //00 /r     add r/m8, r8
                                                        //REX + 00 /r   add r/m8, r8
    {"add", AM_E|OT_v, AM_G|OT_v, NO_OPERAND, 0, 0, add_01},          //01 /r     add r/m16, r16
                                                        //01 /r     add r/m32, r32
                                                        //REX.W + 01 /r   add r/m64, r64
    {"add", AM_G|OT_b, AM_E|OT_b, NO_OPERAND, 0, 0, add_02},          //02 /r     add r8, r/m8
                                                        //REX + 02 /r   add r/m8, r8
    {"add", AM_G|OT_v, AM_E|OT_v, NO_OPERAND, 0, 0, add_03},          //03 /r     add r16, r/m16
                                                        //03 /r     add r32, r/m32
                                                        //REX.W + 03 /r     add r64, r/m64
    {"add", AM_REG_AL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, add_04},     //04 ib     add al, imm8
    {"add", AM_REG_RAX|OT_v, AM_I|OT_z, NO_OPERAND, 0, 0, add_05},    //05 iw     add ax, imm16; 
                                                        //05 id     add eax, imm32; 
                                                        //REX.W + 05 id     add rax, imm32.
                                                        //libemu here seems wrong with Iv, not Iz type.
    {"push", AM_REG_ES|OT_seg, NO_OPERAND, NO_OPERAND, 0, 0, push_06},   //06, push es.
    {"pop", AM_REG_ES|OT_seg, NO_OPERAND, NO_OPERAND, 0, 0, pop_07},    //07, pop es.
    {"or", AM_E|OT_b, AM_G|OT_b, NO_OPERAND, 0, 0, or_08},           //08 /r     or r/m8, r8
                                                        //REX + 08  or r/m8, r8
    {"or", AM_E|OT_v, AM_G|OT_v, NO_OPERAND, 0, 0, or_09},           //09 /r     or r/m16, r16
                                                        //09 /r     or r/m32, r32
                                                        //REX.W + 09 /r     or r/m64, r64
    {"or", AM_G|OT_b, AM_E|OT_b, NO_OPERAND, 0, 0, or_0a},           //0A /r     or r/8, r/m8
                                                        //REX + 0A /r       or r/8, r/m8
    {"or", AM_G|OT_v, AM_E|OT_v, NO_OPERAND, 0, 0, or_0b},           //0B /r     or r16, r/m16
                                                        //0B /r     or r32, r/m32
                                                        //REX.W + 0B /r     or r64, r/m64
    {"or", AM_REG_AL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, or_0c},      //0C ib     or al, imm8
    {"or", AM_REG_RAX|OT_v, AM_I|OT_z, NO_OPERAND, 0, 0, or_0d},     //0D iw     or ax, imm16
                                                        //0D id     or eax, imm32
                                                        //REX.W + 0D iw     or rax, imm32
    {"push", AM_REG_CS|OT_seg, NO_OPERAND, NO_OPERAND, 0, 0, push_0e},   //0E        push cs
    {"ESC", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_TWO_BYTES_ESCAPE, 0},        //0F        2-byte escape
//row 0x10
    {"adc", AM_E|OT_b, AM_G|OT_b, NO_OPERAND, 0, 0, adc_10},          //10 /r     adc r/m8, r8
                                                        //REX + 10 /r   adc r/m8, r8
    {"adc", AM_E|OT_v, AM_G|OT_v, NO_OPERAND, 0, 0, adc_11},          //11 /r     adc r/m16, r16
                                                        //11 /r     adc r/m32, r32
                                                        //REX.W + 11 /r   adc r/m64, r64
    {"adc", AM_G|OT_b, AM_E|OT_b, NO_OPERAND, 0, 0, adc_12},          //12 /r     adc r8, r/m8
                                                        //REX + 12 /r   adc r/m8, r8
    {"adc", AM_G|OT_v, AM_E|OT_v, NO_OPERAND, 0, 0, adc_13},          //13 /r     adc r16, r/m16
                                                        //13 /r     adc r32, r/m32
                                                        //REX.W + 13 /r     adc r64, r/m64
    {"adc", AM_REG_AL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, adc_14},     //14 ib     adc al, imm8
    {"adc", AM_REG_RAX|OT_v, AM_I|OT_z, NO_OPERAND, 0, 0, adc_15},    //15 iw     adc ax, imm16; 
                                                        //15 id     adc eax, imm32; 
                                                        //REX.W + 15 id     adc rax, imm32.
    {"push", AM_REG_SS|OT_seg, NO_OPERAND, NO_OPERAND, 0, 0, push_16},   //16, push ss.
    {"pop", AM_REG_SS|OT_seg, NO_OPERAND, NO_OPERAND, 0, 0, pop_17},    //17, pop ss.
    {"sbb", AM_E|OT_b, AM_G|OT_b, NO_OPERAND, 0, 0, sbb_18},          //18 /r     sbb r/m8, r8
                                                        //REX + 18  sbb r/m8, r8
    {"sbb", AM_E|OT_v, AM_G|OT_v, NO_OPERAND, 0, 0, sbb_19},           //19 /r     sbb r/m16, r16
                                                        //19 /r     sbb r/m32, r32
                                                        //REX.W + 19 /r     sbb r/m64, r64
    {"sbb", AM_G|OT_b, AM_E|OT_b, NO_OPERAND, 0, 0, sbb_1a},           //1A /r     sbb r/8, r/m8
                                                        //REX + 1A /r       sbb r/8, r/m8
    {"sbb", AM_G|OT_v, AM_E|OT_v, NO_OPERAND, 0, 0, sbb_1b},           //1B /r     sbb r16, r/m16
                                                        //1B /r     sbb r32, r/m32
                                                        //REX.W + 1B /r     sbb r64, r/m64
    {"sbb", AM_REG_AL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, sbb_1c},      //1C ib     sbb al, imm8
    {"sbb", AM_REG_RAX|OT_v, AM_I|OT_z, NO_OPERAND, 0, 0, sbb_1d},     //1D iw     sbb ax, imm16
                                                        //1D id     sbb eax, imm32
                                                        //REX.W + 1D iw     sbb rax, imm32
    {"push", AM_REG_DS|OT_seg, NO_OPERAND, NO_OPERAND, 0, 0, push_1e},   //1E        push ds
    {"pop", AM_REG_DS|OT_seg, NO_OPERAND, NO_OPERAND, 0, 0, pop_1f},    //1F        pop ds
//row 0x20
    {"and", AM_E|OT_b, AM_G|OT_b, NO_OPERAND, 0, 0, and_20},          //20 /r     and r/m8, r8
                                                        //REX + 20 /r   and r/m8, r8
    {"and", AM_E|OT_v, AM_G|OT_v, NO_OPERAND, 0, 0, and_21},          //21 /r     and r/m16, r16
                                                        //21 /r     and r/m32, r32
                                                        //REX.W + 21 /r   and r/m64, r64
    {"and", AM_G|OT_b, AM_E|OT_b, NO_OPERAND, 0, 0, and_22},          //22 /r     and r8, r/m8
                                                        //REX + 22 /r   and r/m8, r8
    {"and", AM_G|OT_v, AM_E|OT_v, NO_OPERAND, 0, 0, and_23},          //23 /r     and r16, r/m16
                                                        //23 /r     and r32, r/m32
                                                        //REX.W + 23 /r     and r64, r/m64
    {"and", AM_REG_AL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, and_24},     //24 ib     and al, imm8
    {"and", AM_REG_RAX|OT_v, AM_I|OT_z, NO_OPERAND, 0, 0, and_25},    //25 iw     and ax, imm16; 
                                                        //25 id     and eax, imm32; 
                                                        //REX.W + 25 id     and rax, imm32.
    {"es:", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_PREFIX|OPCODE_FLAG_PREFIX_ES, 0},        //26, SEG=ES(prefix)
    {"daa", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0, daa_27},        //27, daa
    {"sub", AM_E|OT_b, AM_G|OT_b, NO_OPERAND, 0, 0, sub_28},          //28 /r     sub r/m8, r8
                                                        //REX + 18  sub r/m8, r8
    {"sub", AM_E|OT_v, AM_G|OT_v, NO_OPERAND, 0, 0, sub_29},           //29 /r     sub r/m16, r16
                                                        //29 /r     sub r/m32, r32
                                                        //REX.W + 29 /r     sub r/m64, r64
    {"sub", AM_G|OT_b, AM_E|OT_b, NO_OPERAND, 0, 0, sub_2a},           //2A /r     sub r/8, r/m8
                                                        //REX + 2A /r       sub r/8, r/m8
    {"sub", AM_G|OT_v, AM_E|OT_v, NO_OPERAND, 0, 0, sub_2b},           //2B /r     sub r16, r/m16
                                                        //2B /r     sub r32, r/m32
                                                        //REX.W + 2B /r     sub r64, r/m64
    {"sub", AM_REG_AL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, sub_2c},      //2C ib     sub al, imm8
    {"sub", AM_REG_RAX|OT_v, AM_I|OT_z, NO_OPERAND, 0, 0, sub_2d},     //2D iw     sub ax, imm16
                                                        //2D id     sub eax, imm32
                                                        //REX.W + 2D iw     sub rax, imm32
    {"cs:", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_PREFIX|OPCODE_FLAG_PREFIX_CS, 0},        //2E, SEG=CS(prefix)
    {"das", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0, das_2f},        //2F        das
//row 0x30
    {"xor", AM_E|OT_b, AM_G|OT_b, NO_OPERAND, 0, 0, xor_30},          //30 /r     xor r/m8, r8
                                                        //REX + 30 /r   xor r/m8, r8
    {"xor", AM_E|OT_v, AM_G|OT_v, NO_OPERAND, 0, 0, xor_31},          //31 /r     xor r/m16, r16
                                                        //31 /r     xor r/m32, r32
                                                        //REX.W + 31 /r   xor r/m64, r64
    {"xor", AM_G|OT_b, AM_E|OT_b, NO_OPERAND, 0, 0, xor_32},          //32 /r     xor r8, r/m8
                                                        //REX + 32 /r   xor r/m8, r8
    {"xor", AM_G|OT_v, AM_E|OT_v, NO_OPERAND, 0, 0, xor_33},          //33 /r     xor r16, r/m16
                                                        //33 /r     xor r32, r/m32
                                                        //REX.W + 33 /r     xor r64, r/m64
    {"xor", AM_REG_AL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, xor_34},     //34 ib     xor al, imm8
    {"xor", AM_REG_RAX|OT_v, AM_I|OT_z, NO_OPERAND, 0, 0, xor_35},    //35 iw     xor ax, imm16; 
                                                        //35 id     xor eax, imm32; 
                                                        //REX.W + 35 id     xor rax, imm32.
    {"ss:", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_PREFIX|OPCODE_FLAG_PREFIX_SS, 0},        //36, SEG=SS(prefix)
    {"aaa", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0, aaa_37},        //37, aaa
    {"cmp", AM_E|OT_b, AM_G|OT_b, NO_OPERAND, 0, 0, cmp_38},          //38 /r     cmp r/m8, r8
                                                        //REX + 38  cmp r/m8, r8
    {"cmp", AM_E|OT_v, AM_G|OT_v, NO_OPERAND, 0, 0, cmp_39},          //39 /r     cmp r/m16, r16
                                                        //39 /r     cmp r/m32, r32
                                                        //REX.W + 39 /r     cmp r/m64, r64
    {"cmp", AM_G|OT_b, AM_E|OT_b, NO_OPERAND, 0, 0, cmp_3a},          //3A /r     cmp r/8, r/m8
                                                        //REX + 3A /r       cmp r/8, r/m8
    {"cmp", AM_G|OT_v, AM_E|OT_v, NO_OPERAND, 0, 0, cmp_3b},          //3B /r     cmp r16, r/m16
                                                        //3B /r     cmp r32, r/m32
                                                        //REX.W + 3B /r     cmp r64, r/m64
    {"cmp", AM_REG_AL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, cmp_3c},     //3C ib     cmp al, imm8
    {"cmp", AM_REG_RAX|OT_v, AM_I|OT_z, NO_OPERAND, 0, 0, cmp_3d},    //3D iw     cmp ax, imm16
                                                        //3D id     cmp eax, imm32
                                                        //REX.W + 3D iw     cmp rax, imm32
    {"ds:", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_PREFIX|OPCODE_FLAG_PREFIX_DS, 0},        //3E, SEG=DS(prefix)
    {"aas", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0,aas_3f},        //3F        aas
//row 0x40
    {"inc", AM_REG_EAX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, inc_40},   //40        inc eAX, Warning: REX prefix in 64-bit mode!
    {"inc", AM_REG_ECX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, inc_41},   //41        inc eBX, Warning: REX.B prefix in 64-bit mode!
    {"inc", AM_REG_EDX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, inc_42},   //42        inc eDX, Warning: REX.X prefix in 64-bit mode!
    {"inc", AM_REG_EBX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, inc_43},   //43        inc eBX, Warning: REX.XB prefix in 64-bit mode!
    {"inc", AM_REG_ESP|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, inc_44},   //44        inc eSP, Warning: REX.R prefix in 64-bit mode!
    {"inc", AM_REG_EBP|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, inc_45},   //45        inc eBP, Warning: REX.RB prefix in 64-bit mode!
    {"inc", AM_REG_ESI|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, inc_46},   //46        inc eSI, Warning: REX.RX prefix in 64-bit mode!
    {"inc", AM_REG_EDI|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, inc_47},   //47        inc eDI, Warning: REX.RXB prefix in 64-bit mode!

    {"dec", AM_REG_EAX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, dec_48},   //48        dec eAX, Warning: REX.W prefix in 64-bit mode!
    {"dec", AM_REG_ECX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, dec_49},   //49        dec eBX, Warning: REX.WB prefix in 64-bit mode!
    {"dec", AM_REG_EDX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, dec_4a},   //4A        dec eDX, Warning: REX.WX prefix in 64-bit mode!
    {"dec", AM_REG_EBX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, dec_4b},   //4B        dec eBX, Warning: REX.WXB prefix in 64-bit mode!
    {"dec", AM_REG_ESP|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, dec_4c},   //4C        dec eSP, Warning: REX.WR prefix in 64-bit mode!
    {"dec", AM_REG_EBP|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, dec_4d},   //4D        dec eBP, Warning: REX.WRB prefix in 64-bit mode!
    {"dec", AM_REG_ESI|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, dec_4e},   //4E        dec eSI, Warning: REX.WRX prefix in 64-bit mode!
    {"dec", AM_REG_EDI|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, dec_4f},   //4F        dec eDI, Warning: REX.WRXB prefix in 64-bit mode!
//row 0x50
    {"push", AM_REG_EAX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, push_50},   //50        push rAX/r8, d64
    {"push", AM_REG_ECX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, push_51},   //51        push rCX/r9, d64
    {"push", AM_REG_EDX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, push_52},   //52        push rDX/r10, d64
    {"push", AM_REG_EBX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, push_53},   //53        push rBX/r11, d64
    {"push", AM_REG_ESP|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, push_54},   //54        push rSP/r12, d64
    {"push", AM_REG_EBP|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, push_55},   //55        push rBP, d64
    {"push", AM_REG_ESI|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, push_56},   //56        push rSI, d64
    {"push", AM_REG_EDI|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, push_57},   //57        push rDI, d64

    {"pop", AM_REG_EAX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, pop_58},   //58        pop rAX/r8, d64
    {"pop", AM_REG_ECX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, pop_59},   //59        pop rCX/r9, d64
    {"pop", AM_REG_EDX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, pop_5a},   //5A        pop rDX/r10, d64
    {"pop", AM_REG_EBX|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, pop_5b},   //5B        pop rBX/r11, d64
    {"pop", AM_REG_ESP|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, pop_5c},   //5C        pop rSP/r12, d64
    {"pop", AM_REG_EBP|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, pop_5d},   //5D        pop rBP, d64
    {"pop", AM_REG_ESI|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, pop_5e},   //5E        pop rSI, d64
    {"pop", AM_REG_EDI|OT_v, NO_OPERAND, NO_OPERAND, 0, 0, pop_5f},   //5F        pop rDI, d64
//row 0x60
    {"pusha", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, Intel_x86_Instruction_Attribute_Patch_pushad,pusha_60},      //60        pusha in 16-bit mode, pushad when the operand-size attribute is 16
    {"popa", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, Intel_x86_Instruction_Attribute_Patch_popad, popa_61},       //61        popa in 16-bit mode, popad when the operand-size attribute is 32
    {"bound", AM_G|OT_v, AM_M|OT_a, NO_OPERAND, 0, 0, bound_62},        //62 /r     bound r16, m16&16, when the operand-size attribute is 16
                                                              //62 /r     bound r32, m32&32, when the operand-size attribute is 32
    {"arpl", AM_E|OT_w, AM_G|OT_w, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, Intel_x86_Instruction_Attribute_Patch_movsxd},   //63        push rBX/r11, d64
    {"fs:", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_PREFIX|OPCODE_FLAG_PREFIX_FS, 0},   //64        SEG=FS
    {"gs:", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_PREFIX|OPCODE_FLAG_PREFIX_GS, 0},   //65        SEG=GS
    {"op-size", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_PREFIX|OPCODE_FLAG_PREFIX_OPERAND_SIZE_OVERRIDE, 0},   //66        Operand Size
    {"addr-size", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_PREFIX|OPCODE_FLAG_PREFIX_ADDRESS_SIZE_OVERRIDE, 0},   //67        Address Size

    {"push", AM_I|OT_z, NO_OPERAND, NO_OPERAND, 0, 0, push_68},        //68       push imm32, d64
    {"imul", AM_G|OT_v, AM_E|OT_v, AM_I|OT_z, 0, 0, imul_69},          //69 /r iw imul r16, r/m16, imm16
                                                              //69 /r id imul r32, r/m32, imm32
                                                              //REX.W + 69 /r id  imul r64, r/m64, imm32
                                                              //69 /r iw imul r16, imm16
                                                              //69 /r id imul r32, imm32
                                                              //REX.W + 69 /r id  imul r64, imm32
    {"push", AM_I|OT_b, NO_OPERAND, NO_OPERAND, 0, 0, push_6a},        //6A       push imm8, d64
    {"imul", AM_G|OT_v, AM_E|OT_v, AM_I|OT_b, 0, 0, imul_6b},          //6B /r ib imul r16, r/m16, imm8
                                                              //6B /r ib imul r32, r/m32, imm8
                                                              //REX.W + 6B /r ib  imul r64, r/m64, imm8
                                                              //6B /r ib imul r16, imm8
                                                              //6B /r ib imul r32, imm8
                                                              //REX.W + 6B /r ib  imul r64, imm8
    {"ins", AM_Y|OT_b, AM_REG_DX|OT_w, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_insb},    //6C        ins m8, DX
                                                                                                                                        //6C        insb
    {"ins", AM_Y|OT_z, AM_REG_DX|OT_w, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, Intel_x86_Instruction_Attribute_Patch_inswd},     //6D    ins m16,dx
                                                                                                                                                                                        //6D    ins m32,dx
                                                                                                                                                                                        //6D    insw
                                                                                                                                                                                        //6D    insd
    {"outs", AM_REG_DX|OT_w, AM_X|OT_b,  NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_outsb},  //6E        outs DX, m8
                                                                                                                                         //6E        outsb
    {"outs", AM_REG_DX|OT_w, AM_X|OT_z, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT, Intel_x86_Instruction_Attribute_Patch_outswd},   //6F    outs dx, m16
                                                                                                                                                                                        //6F    outs dx, m32
                                                                                                                                                                                        //6F    insw
                                                                                                                                                                                        //6F    insd
//row 0x70
    {"jo", AM_J|OT_b, NO_OPERAND, NO_OPERAND, 0, 0, jo_70},    //70 cb      jo rel8
    {"jno", AM_J|OT_b, NO_OPERAND, NO_OPERAND, 0, 0, jno_71},   //71 cb      jno rel8
    {"jb", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_for_jb, jb_72},   //72 cb      jb rel8
                                                                                                                                //72 cb      jnae rel8
                                                                                                                                //72 cb      jc rel8
    {"jnb", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_for_jnb, jnb_73}, //73 cb      jnb rel8
                                                                                                                                //73 cb      jae rel8
                                                                                                                                //73 cb      jnc rel8
    {"jz", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_je, jz_74},   //74 cb      jz rel8
                                                                                                                                //74 cb      je rel8
    {"jnz", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_jne, jnz_75}, //75 cb      jnz rel8
                                                                                                                                //75 cb      jne rel8
    {"jbe", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_jna, jbe_76}, //76 cb      jbe rel8
                                                                                                                                //76 cb      jna rel8
    {"jnbe", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_ja, jnbe_77}, //77 cb      jnbe rel8
                                                                                                                                //77 cb      ja rel8
    {"js", AM_J|OT_b, NO_OPERAND, NO_OPERAND, 0, 0 , js_78},    //78 cb      js rel8
    {"jns", AM_J|OT_b, NO_OPERAND, NO_OPERAND, 0, 0, jns_79},   //79 cb      jns rel8
    {"jp", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_jpe, jp_7a}, //7A cb      jp rel8
                                                                                                                                //7A cb      jpe rel8
    {"jnp", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_jpo, jnp_7b}, //7B cb      jnp rel8
                                                                                                                                //7B cb      jpo rel8
    {"jl", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_jnge, jl_7c},   //7C cb      jl rel8
                                                                                                                                //7C cb      jnge rel8
    {"jnl", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_jge, jnl_7d}, //7D cb      jnl rel8
                                                                                                                                //7D cb      jge rel8
    {"jle", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_jng, jle_7e}, //7E cb      jle rel8
                                                                                                                                //7E cb      jng rel8
    {"jnle", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_jg, jg_7f}, //7F cb      jnle rel8
                                                                                                                                //7F cb      jg rel8
//row 0x80
    {"Immediate Grp1", AM_E|OT_b, AM_I|OT_b, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_1|OPCODE_FLAG_IS_OPCODE_EXTENSION, Intel_x86_Opcode_Extension_Grp1_Immd0}, //80 Opcode Extension
    {"Immediate Grp1", AM_E|OT_v, AM_I|OT_z, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_1|OPCODE_FLAG_IS_OPCODE_EXTENSION, Intel_x86_Opcode_Extension_Grp1_Immd1}, //81 Opcode Extension
    {"Immediate Grp1", AM_E|OT_b, AM_I|OT_b, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_1|OPCODE_FLAG_IS_OPCODE_EXTENSION, Intel_x86_Opcode_Extension_Grp1_Immd2}, //82 Opcode Extension, i64
    {"Immediate Grp1", AM_E|OT_v, AM_I|OT_b, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_1|OPCODE_FLAG_IS_OPCODE_EXTENSION, Intel_x86_Opcode_Extension_Grp1_Immd3}, //83 Opcode Extension
    {"test", AM_E|OT_b, AM_G|OT_b, NO_OPERAND, 0, 0, test_84},   //84 /r     test r/m8, r8
                                                        //REX + 84 /r test r/m8, r8
    {"test", AM_E|OT_v, AM_G|OT_v, NO_OPERAND, 0, 0, test_85},   //85 /r     test r/m16, r16
                                                        //85 /r     test r/m32, r32
                                                        //REX.W + 85 /r test r/m64, r64
    {"xchg", AM_E|OT_b, AM_G|OT_b, NO_OPERAND, 0, 0, xchg_86},   //86 /r     xchg r/m8, r8
                                                        //REX + 86 /r xchg r/m8, r8
    {"xchg", AM_E|OT_v, AM_G|OT_v, NO_OPERAND, 0, 0, xchg_87},   //87 /r     xchg r/m16, r16
                                                        //87 /r     xchg r16, r/m16
                                                        //87 /r     xchg r/m32, r32
                                                        //REX.W + 87 /r xchg r/m64, r64
                                                        //87 /r     xchg r32, r/m32
                                                        //REX.W + 87 /r xchg r64, r/m64
    {"mov", AM_E|OT_b, AM_G|OT_b, NO_OPERAND, 0, 0, mov_88},    //88 /r     mov r/m8, r8
                                                        //REX + 88 /r mov r/m8, r8
    {"mov", AM_E|OT_v, AM_G|OT_v, NO_OPERAND, 0, 0, mov_89},    //89 /r     mov r/m16, r16
                                                        //89 /r     mov r/m32, r32
                                                        //REX.W + 89 /r mov r/m64, r64
    {"mov", AM_G|OT_b, AM_E|OT_b, NO_OPERAND, 0, 0, mov_8a},    //8A /r     mov r8, r/m8
                                                        //REX + 8A /r mov r8, r/m8
    {"mov", AM_G|OT_v, AM_E|OT_v, NO_OPERAND, 0, 0, mov_8b},    //8B /r     mov r16, r/m16
                                                        //8B /r     mov r32, r/m32
                                                        //REX.W + 8B /r mov r64, r/m64
    {"mov", AM_E|OT_v, AM_S|OT_w, NO_OPERAND, 0, 0, mov_8c},    //8C /r     mov r/m16, Sreg
                                                        //REX.W + 8C /r mov r64/m, Sreg
    {"lea", AM_G|OT_v, AM_M, NO_OPERAND, 0, 0, lea_8d},         //8D /r     mov r16, m
                                                        //8D /r     mov r32, m
                                                        //REX.W + 8D /r mov r64, m
    {"mov", AM_E|OT_v, AM_S|OT_w, NO_OPERAND, 0, 0, mov_8e},    //8E /r     mov Sreg, r/m16
                                                        //REX.W + 8E /r mov Sreg, r/m64
    {"pop", AM_E|OT_v, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_8BIT, Intel_x86_Opcode_Extension_Grp1A}, //8F /0     pop r/m16
                                                                                                                                                                                                                            //8F /0     pop r/m32
                                                                                                                                                                                                                            //8F /0     pop r/m64
//row 0x90
    {"nop", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_USE_WITH_PREFIX_F3H|OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_nop, nop_90},    //90    nop
                                                                                                                                                                        //F3 90 pause
                                                                                                                                                                        //90    xchg ax, ax
                                                                                                                                                                        //90    xchg eax, eax
                                                                                                                                                                        //REX.W + 90    xchg rax, rax
                                                        //90 + rw   xchg ax, r16
                                                        //90 + rw   xchg r16, ax
                                                        //90 + rd   xchg eax, r32
                                                        //REX.W + 90 + rd   xchg rax, r64
                                                        //90 + rd   xchg r32, eax
                                                        //REX.W + 90 + rd   xchg r64, rax
    {"xchg", AM_REG_RAX|OT_v, AM_REG_RCX|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_xchg_rcx, xchg_91},//91
    {"xchg", AM_REG_RAX|OT_v, AM_REG_RDX|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_xchg_rdx, xchg_92},//92
    {"xchg", AM_REG_RAX|OT_v, AM_REG_RBX|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_xchg_rbx, xchg_93},//93
    {"xchg", AM_REG_RAX|OT_v, AM_REG_RSP|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_xchg_rsp, xchg_94},//94
    {"xchg", AM_REG_RAX|OT_v, AM_REG_RBP|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_xchg_rbp, xchg_95},//95
    {"xchg", AM_REG_RAX|OT_v, AM_REG_RSI|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_xchg_rsi, xchg_96},//96
    {"xchg", AM_REG_RAX|OT_v, AM_REG_RDI|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_xchg_rdi, xchg_97},//97

    {"cbw", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, Intel_x86_Instruction_Attribute_Patch_cbw, cbw_98},  //98    cbw
                                                                                                                                                                                //98    cwde
                                                                                                                                                                                //REX.W + 98    cdqe
    {"cwd", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, Intel_x86_Instruction_Attribute_Patch_cwd, cwd_99},  //99    cwd
                                                                                                                                                                                //99    cdq
                                                                                                                                                                                //REX.W + 99    cqo
    {"call", AM_A|OT_p, NO_OPERAND, NO_OPERAND, 0, 0, call_9a},  //9A cd   call ptr16:16
                                                        //9A cp   call ptr32:32
    {"wait", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_fwait},   //9B     wait
                                                                                            //9B     fwait
    {"pushf", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, Intel_x86_Instruction_Attribute_Patch_pushf, pushf_9c},  //9c    pushf
                                                                                                                                                                                    //9c    pushfd
                                                                                                                                                                                    //REX.W + 9c    pushfq
    {"popf", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, Intel_x86_Instruction_Attribute_Patch_popf, popf_9d},    //9d    popf
                                                                                                                                                                                    //9d    popfd
                                                                                                                                                                                    //REX.W + 9d    popfq
    {"sahf", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0, sahf_9e},   //9E     sahf
    {"lahf", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0, lahf_9f},   //9F     lahf

//row 0xA0
    {"mov", AM_REG_AL|OT_b, AM_O|OT_b, NO_OPERAND, 0, 0, mov_a0},   //A0    mov al, moffset8
                                                            //REX.W + A0 mov al, moffset8
    {"mov", AM_REG_RAX|OT_v, AM_O|OT_v, NO_OPERAND, 0, 0, mov_a1},  //A1    mov ax, moffset16
                                                            //A1    mov eax, moffset32
                                                            //REX.W + A1 mov rax, moffset64
    {"mov", AM_O|OT_b, AM_REG_AL|OT_b, NO_OPERAND, 0, 0, mov_a2},   //A2    mov moffset8, al
                                                            //REX.W + A2 mov moffset8, al
    {"mov", AM_O|OT_v, AM_REG_RAX|OT_v, NO_OPERAND, 0, 0, mov_a3},  //A3    mov moffset16, ax
                                                            //A3    mov moffset32, eax
                                                            //REX.W + A3 mov moffset64, rax
    {"movs", AM_X|OT_b, AM_Y|OT_b, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_movsb, movs_a4},   //A4    movs m8, m8
                                                                                                                                    //A4    movsb
    {"movs", AM_X|OT_v, AM_Y|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, Intel_x86_Instruction_Attribute_Patch_movs, movs_a5},    //A5    movs m16, m16
                                                                                                                                    //A5    movs m32, m32
                                                                                                                                    //REX.W + A5    movs m64, m64
                                                                                                                                    //A5    movsw
                                                                                                                                    //A5    movsd
                                                                                                                                    //REX.W + A5    movsq
    {"cmps", AM_X|OT_b, AM_Y|OT_b, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_cmpsb,cmps_a6},   //A6    cmps m8, m8
                                                                                                                                    //A6    cmpsb
    {"cmps", AM_X|OT_v, AM_Y|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, Intel_x86_Instruction_Attribute_Patch_cmps, cmps_a7},    //A5    cmps m16, m16
                                                                                                                                    //A7    cmps m32, m32
                                                                                                                                    //REX.W + A7    cmps m64, m64
                                                                                                                                    //A7    cmpsw
                                                                                                                                    //A7    cmpsd
                                                                                                                                    //REX.W + A7    cmpsq
    {"test", AM_REG_AL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, test_a8},      //A8 ib    test al, imm8
    {"test", AM_REG_RAX|OT_v, AM_I|OT_z, NO_OPERAND, 0, 0, test_a9},     //A9 iw    test ax, imm16
                                                                //A9 id    test ax, imm32
                                                                //REX.W + A9 id    test ax, imm32
    {"stos", AM_Y|OT_b, AM_REG_AL|OT_b, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_stosb, stos_aa},   //AA    stos m8
                                                                                                                                    //AA    stosb
    {"stos", AM_X|OT_v, AM_REG_RAX|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, Intel_x86_Instruction_Attribute_Patch_stos, stos_ab},    //AB    stos m16
                                                                                                                                    //AB    stos m32
                                                                                                                                    //REX.W + AB    stos m64
                                                                                                                                    //AB    stosw
                                                                                                                                    //AB    stosd
    {"lods", AM_REG_AL|OT_b, AM_X|OT_b, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_lodsb, lodscc_ac},   //AC    lods m8
                                                                                                                                    //AC    lodsb
    {"lods", AM_REG_RAX|OT_v, AM_X|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, Intel_x86_Instruction_Attribute_Patch_lods,lodscc_ad},    //AD    lods m16
                                                                                                                                    //AD    lods m32
                                                                                                                                    //REX.W + AD    lods m64
                                                                                                                                    //AD    lodsw
                                                                                                                                    //AD    lodsd
                                                                                                                                    //REX.W + AD    stosq
    {"scas", AM_REG_AL|OT_b, AM_Y|OT_b, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_scasb, scas_ae},   //AE    scas m8
                                                                                                                                    //AE    scasb
    {"scas", AM_REG_RAX|OT_v, AM_Y|OT_v, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, Intel_x86_Instruction_Attribute_Patch_scas, scas_af},    //AF    scas m16
                                                                                                                                    //AF    scas m32
                                                                                                                                    //REX.W + AF    scas m64
                                                                                                                                    //AF    scasw
                                                                                                                                    //AF    scasd
                                                                                                                                    //REX.W + AF    stosq
//row 0xB0
    {"mov", AM_REG_AL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, mov_b0},   //B0    mov al, imm8
                                                            //REX.W + B0 mov al, imm8
    {"mov", AM_REG_CL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, mov_b1},   //B1    mov cl, imm8
                                                            //REX.W + B1 mov cl, imm8
    {"mov", AM_REG_DL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, mov_b2},   //B2    mov dl, imm8
                                                            //REX.W + B2 mov dl, imm8
    {"mov", AM_REG_BL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, mov_b3},   //B3    mov bl, imm8
                                                            //REX.W + B3 mov bl, imm8
    {"mov", AM_REG_AH|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, mov_b4},   //B4    mov ah, imm8
                                                            //REX.W + B4 mov ah, imm8
    {"mov", AM_REG_CH|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, mov_b5},   //B5    mov ch, imm8
                                                            //REX.W + B5 mov ch, imm8
    {"mov", AM_REG_DH|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, mov_b6},   //B6    mov dh, imm8
                                                            //REX.W + B6 mov dh, imm8
    {"mov", AM_REG_BL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0, mov_b7},   //B7    mov bh, imm8
                                                            //REX.W + B7 mov bh, imm8
    //B8 + rw   mov r16, imm16
    //B8 + rd   mov r32, imm32
    //REX.W + B8 + rd   mov r64, imm64
    {"mov", AM_REG_RAX|OT_v, AM_I|OT_v, NO_OPERAND, 0, 0, mov_b8},
    {"mov", AM_REG_RCX|OT_v, AM_I|OT_v, NO_OPERAND, 0, 0, mov_b9},
    {"mov", AM_REG_RDX|OT_v, AM_I|OT_v, NO_OPERAND, 0, 0, mov_ba},
    {"mov", AM_REG_RBX|OT_v, AM_I|OT_v, NO_OPERAND, 0, 0, mov_bb},
    {"mov", AM_REG_RSP|OT_v, AM_I|OT_v, NO_OPERAND, 0, 0, mov_bc},
    {"mov", AM_REG_RBP|OT_v, AM_I|OT_v, NO_OPERAND, 0, 0, mov_bd},
    {"mov", AM_REG_RSI|OT_v, AM_I|OT_v, NO_OPERAND, 0, 0, mov_be},
    {"mov", AM_REG_RDI|OT_v, AM_I|OT_v, NO_OPERAND, 0, 0, mov_bf},
//row 0xc0
    {"Shift Grp2", AM_E|OT_b, AM_I|OT_b, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION|OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_2, Intel_x86_Opcode_Extension_Grp2_c0}, 
    {"Shift Grp2", AM_E|OT_v, AM_I|OT_b, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION|OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_2, Intel_x86_Opcode_Extension_Grp2_c1}, 
    {"retn", AM_I|OT_w, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_f64, 0, ret_c2},
    {"retn", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_f64, 0, ret_c3},
    {"les", AM_G|OT_z, AM_M|OT_p, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_i64, 0, les_c4},    //C4 /r     les r16, m16:16
                                                                                //C4 /r     lds r32, m16:32
    {"lds", AM_G|OT_z, AM_M|OT_p, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_i64, 0, lds_c5},    //C5 /r     lds r16, m16:16
                                                                                //C5 /r     lds r32, m16:32
    {"Grp 11", AM_E|OT_b, AM_I|OT_b, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION|OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_11, Intel_x86_Opcode_Extension_Grp11_c6},  //C6
    {"Grp 11", AM_E|OT_v, AM_I|OT_z, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION|OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_11, Intel_x86_Opcode_Extension_Grp11_c7},  //C7
    {"enter", AM_I|OT_w, AM_I|OT_b, NO_OPERAND, 0, 0, enter_c8},    //C8 iw 00    enter imm16, 0
                                                          //C8 iw 01    enter imm16, 1
                                                          //C8 iw ib    enter imm16, imm8
    {"leave", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0, leave_c9},  //C9          leave
    {"retf", AM_I|OT_w, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_ret, ret_ca},    //CA iw       retf/ret
    {"retf", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT, Intel_x86_Instruction_Attribute_Patch_ret, ret_ca},    //CB iw       retf/ret
    {"int 3", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0},    //CC         int 3
    {"int", AM_I|OT_b, NO_OPERAND, NO_OPERAND, 0, 0},       //CD ib      int imm8
    {"into", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_i64, 0},     //CE         into
    {"iret", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_iret},     //CF         iret/d/q
//row 0xD0
    {"Shift Grp2", AM_E|OT_b, AM_I|OT_1, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION|OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_2, Intel_x86_Opcode_Extension_Grp2_d0}, 
    {"Shift Grp2", AM_E|OT_v, AM_I|OT_1, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION|OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_2, Intel_x86_Opcode_Extension_Grp2_d1}, 
    {"Shift Grp2", AM_E|OT_b, AM_REG_CL|OT_b, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION|OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_2, Intel_x86_Opcode_Extension_Grp2_d2}, 
    {"Shift Grp2", AM_E|OT_v, AM_REG_CL|OT_b, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION|OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_2, Intel_x86_Opcode_Extension_Grp2_d3}, 
    {"aam", AM_I|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_i64, 0, aam_d4},     //D4 ib   aam imm8?
    {"aad", AM_I|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_i64, 0, aad_d5},     //D5 ib   aad imm8?
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0},
    {"xlat", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_xlatb, xlat_d7},     //D7 ib   aad imm8?
    {"ESC", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED|OPCODE_FLAG_IS_ESCAPE_TO_COPROCESSOR, 0},//D8
    {"ESC", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED|OPCODE_FLAG_IS_ESCAPE_TO_COPROCESSOR, 0},//D9
    {"ESC", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED|OPCODE_FLAG_IS_ESCAPE_TO_COPROCESSOR, 0},//DA
    {"ESC", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED|OPCODE_FLAG_IS_ESCAPE_TO_COPROCESSOR, 0},//DB
    {"ESC", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED|OPCODE_FLAG_IS_ESCAPE_TO_COPROCESSOR, 0},//DC
    {"ESC", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED|OPCODE_FLAG_IS_ESCAPE_TO_COPROCESSOR, 0},//DD
    {"ESC", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED|OPCODE_FLAG_IS_ESCAPE_TO_COPROCESSOR, 0},//DE
    {"ESC", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED|OPCODE_FLAG_IS_ESCAPE_TO_COPROCESSOR, 0},//DF
//row 0xE0
    {"loopne", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_ATTRIBUTE_f64, Intel_x86_Instruction_Attribute_Patch_loopnz, loopcc_e0},//E0 cb  loopne/loopnz rel8
    {"loope", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS|OPCODE_FLAG_ATTRIBUTE_f64, Intel_x86_Instruction_Attribute_Patch_loopz, loopcc_e1},//E1 cb  loope/loopz rel8
    {"loopd", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_f64, 0, loopcc_e2},//E2 cb  loop rel8
    {"jrcxz", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_16BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_32BIT|OPCODE_FLAG_USE_PATCH_OPERAND_SIZE_64BIT|OPCODE_FLAG_ATTRIBUTE_f64, Intel_x86_Instruction_Attribute_Patch_jrcxz, jrcxz_e3},//E3 cb  jcx/jecx/jrcx rel8
    {"in", AM_REG_AL|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0},    //E4 ib     in al, imm8
    {"in", AM_REG_EAX|OT_b, AM_I|OT_b, NO_OPERAND, 0, 0},   //E5 ib     in ax, imm8
                                                            //E5 ib     in eax, imm8
    {"out", AM_I|OT_b, AM_REG_AL|OT_b, NO_OPERAND, 0, 0},   //E6 ib     out imm8, al
    {"out", AM_I|OT_b, AM_REG_EAX|OT_b, NO_OPERAND, 0, 0},  //E7 ib     out imm8, ax
                                                            //E7 ib     out imm8, eax
    {"call", AM_J|OT_z, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_f64, 0, call_e8},  //E8 cw     call rel16
                                                                                //E8 cd     call rel32 (32-bit displacement sign extended to 64bits in 64-bit mode
    {"jmp", AM_J|OT_z, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_f64, 0, jmp_e9},   //E9 cw     jmp rel16
                                                                                //E9 cd     jmp rel32 (32-bit displacement sign extended to 64bits in 64-bit mode
    {"jmp", AM_A|OT_p, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_i64, 0, jmp_ea},   //EA cd     jmp ptr16:16
                                                                                //EA cp     jmp ptr16:32
    {"jmp", AM_J|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_ATTRIBUTE_f64, 0, jmp_eb},   //EB cb     jmp rel8
    {"in", AM_REG_AL|OT_b, AM_REG_DX|OT_w, NO_OPERAND, 0, 0},   //EC      in al, dx
    {"in", AM_REG_EAX|OT_b, AM_REG_DX|OT_w, NO_OPERAND, 0, 0},  //ED      in ax, dx
                                                                //ED      in eax, dx
    {"out", AM_REG_DX|OT_w, AM_REG_AL|OT_b, NO_OPERAND, 0, 0},   //EE      out dx, al
    {"out", AM_REG_DX|OT_w, AM_REG_EAX|OT_b, NO_OPERAND, 0, 0},  //EF      out dx, eax
                                                                 //ED      out dx, eax
//row 0xf0
    {"lock", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_PREFIX|OPCODE_FLAG_PREFIX_LOCK, 0},  //F0
    {0, 0, 0, 0, 0, 0},
    {"repne", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_PREFIX|OPCODE_FLAG_PREFIX_REPNE, 0},  //F2
    {"rep/repe", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_PREFIX|OPCODE_FLAG_PREFIX_REP, 0},  //F3
    {"hlt", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0},  //F4
    {"cmc", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0, cmc_f5},  //F5
    {"Unary Grp3", AM_E|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION|OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_3, Intel_x86_Opcode_Extension_Grp3_F6}, //F6
    {"Unary Grp3", AM_E|OT_v, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION|OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_3, Intel_x86_Opcode_Extension_Grp3_F7}, //F7
    {"clc", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0, clc_f8},  //F8
    {"stc", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0, stc_f9},  //F9
    {"cli", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0, cli_fa},  //FA
    {"sti", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0, sti_fb},  //FB
    {"cld", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0, cld_fc},  //FC
    {"std", NO_OPERAND, NO_OPERAND, NO_OPERAND, 0, 0, std_fd},  //FD
    {"INC/DEC Grp4", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION|OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_4, Intel_x86_Opcode_Extension_Grp4}, //FE
    {"INC/DEC Grp5", NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_OPCODE_EXTENSION|OPCODE_FLAG_IS_OPCODE_EXTENSION_GROUP_5, Intel_x86_Opcode_Extension_Grp5}, //FF
};


const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Opcode_Map_TwoBytes[256] = {
//row 0x00
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x10
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x20
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x30
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x40
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x50
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x60
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x70
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x80
    //0x80
    {"jo", AM_J|OT_z, NO_OPERAND, NO_OPERAND, 0, 0},//0x80
    //0x81
    {"jno", AM_J|OT_z, NO_OPERAND, NO_OPERAND, 0, 0},//0x81
    //0x82
    {"jb", AM_J|OT_z, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
    //0x83
    {"jnb", AM_J|OT_z, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
    //0x84
    {"jz", AM_J|OT_z, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
    //0x85
    {"jnz", AM_J|OT_z, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
    //0x86
    {"jbe", AM_J|OT_z, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
    //0x87
    {"jnbe", AM_J|OT_z, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
    //0x88
    {"js", AM_J|OT_z, NO_OPERAND, NO_OPERAND, 0, 0},
    //0x89
    {"jns", AM_J|OT_z, NO_OPERAND, NO_OPERAND, 0, 0},
    //0x8A
    {"jp", AM_J|OT_z, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
    //0x8B
    {"jnp", AM_J|OT_z, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
    //0x8C
    {"jl", AM_J|OT_z, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
    //0x8D
    {"jnl", AM_J|OT_z, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
    //0x8E
    {"jle", AM_J|OT_z, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
    //0x8F
    {"jnle", AM_J|OT_z, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, 0},
//row 0x90
    //0x90
    {"seto", AM_E|OT_b, NO_OPERAND, NO_OPERAND, 0, 0},
    //0x91
    {"setno", AM_E|OT_b, NO_OPERAND, NO_OPERAND, 0, 0},
    //0x92
    {"setb", AM_E|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_for_setb},
    //0x93
    {"setnb", AM_E|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_for_setnb},
    //0x94
    {"setz", AM_E|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_sete},
    //0x95
    {"setnz", AM_E|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_setne},
    //0x96
    {"setbe", AM_E|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_setna},
    //0x97
    {"setnbe", AM_E|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_seta},
    //0x98
    {"sets", AM_E|OT_b, NO_OPERAND, NO_OPERAND, 0, 0},
    //0x99
    {"setns", AM_E|OT_b, NO_OPERAND, NO_OPERAND, 0, 0},
    //0x9A
    {"setp", AM_E|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_setpe},
    //0x9B
    {"setnp", AM_E|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_setpo},
    //0x9C
    {"setl", AM_E|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_setnge},
    //0x9D
    {"setnl", AM_E|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_setge},
    //0x9E
    {"setle", AM_E|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_setng},
    //0x9F
    {"setnle", AM_E|OT_b, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_USE_PATCH_FOR_ALIAS, Intel_x86_Instruction_Attribute_Patch_setg},
//row 0xA0
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0xB0
    //0xB0
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    //0xB1
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    //0xB2
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    //0xB3
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    //0xB4
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    //0xB5
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    //0xB6
    {"movzx", AM_G|OT_v, AM_E|OT_b, NO_OPERAND, 0, 0, movzx_0F_B6},
    //0xB7
    {"movzx", AM_G|OT_v, AM_E|OT_w, NO_OPERAND, 0, 0, movzx_0F_B7},
    //0xB8
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    //0xB9
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    //0xBA
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    //0xBB
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    //0xBC
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    //0xBD
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    //0xBE
    {"movsx", AM_G|OT_v, AM_E|OT_b, NO_OPERAND, 0, 0, movsx_0F_BE},
    //0xBF
    {"movsx", AM_G|OT_v, AM_E|OT_w, NO_OPERAND, 0, 0, movsx_0F_BF},
//row 0xC0
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0xD0
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0xE0
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0xF0
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
};
const Intel_x86_Instruction_Attribute_t Intel_x86_Instruction_Opcode_Map_ThreeBytes[256] = {
//row 0x00
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x10
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x20
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x30
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x40
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x50
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x60
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x70
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x80
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0x90
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0xA0
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0xB0
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0xC0
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0xD0
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0xE0
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
//row 0xF0
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
    {0, NO_OPERAND, NO_OPERAND, NO_OPERAND, OPCODE_FLAG_IS_NOT_IMPLEMENTEDED, 0},
};

#ifdef NDEBUG
void PrintOpcodeTable(void)
{
    printf("column from 0x0 to 0x7\n");
    for(int j = 0; j < 0x8; j ++){
        printf("\t%3x", j);
    }
    printf("\n");
    for(int i = 0; i < 0x10; i ++){
        printf("%2x", i);
        for(int j = 0x0; j < 0x8; j ++){
            printf("\t%s", Intel_x86_Instruction_Opcode_Map_OneByte[i*0x10 + j].szMnemonic_Intel);
        }
        printf("\n");
    }


    printf("\n");
    printf("column from 0x8 to 0xf\n");
    for(int j = 0x08; j < 0x10; j ++){
        printf("\t%3x", j);
    }
    printf("\n");
    for(int i = 0x0; i < 0x10; i ++){
        printf("%2x", i);
        for(int j = 0x8; j < 0x10; j ++){
            printf("\t%s", Intel_x86_Instruction_Opcode_Map_OneByte[i*0x10 + j].szMnemonic_Intel);
        }
        printf("\n");
    }
    
}
#endif// NDEGUG
