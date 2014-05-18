#ifndef _MOVXX_H_
#define _MOVXX_H_
//
//文件名称：        Include/ISA/Intel_x86/Instructions/movxx.h
//文件描述：        movzx/movsx指令头文件
//创建人：          杨鸿博(yanghongbo@ptwy.cn)
//创建日期：        2010年4月8日
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
//2010年4月8日，杨鸿博(yanghongbo@ptwy.cn)，创建

VM_INSTRUCTION_ERR_CODE movzx_0F_B6(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);
VM_INSTRUCTION_ERR_CODE movzx_0F_B7(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);

VM_INSTRUCTION_ERR_CODE movsx_0F_BE(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);
VM_INSTRUCTION_ERR_CODE movsx_0F_BF(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);


#endif //_MOVXX_H_