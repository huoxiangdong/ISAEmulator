#ifndef _JMP_H_
#define _JMP_H_
//
//文件名称：        Include/ISA/Intel_x86/Instructions/jmp.h
//文件描述：        jmp指令头文件
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
//Update Log:
//更新日志：
//2009年8月14日，劳生(laosheng@ptwy.cn)，创建


VM_INSTRUCTION_ERR_CODE jmp_e9(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);
VM_INSTRUCTION_ERR_CODE jmp_ea(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);
VM_INSTRUCTION_ERR_CODE jmp_eb(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);
VM_INSTRUCTION_ERR_CODE inc_dec_grp5_ff_4_jmp(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);
VM_INSTRUCTION_ERR_CODE inc_dec_grp5_ff_5_jmp(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);
#endif //_JMP_H_