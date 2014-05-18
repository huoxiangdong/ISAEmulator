#ifndef _COMMON_H_
#define _COMMON_H_
//
//文件名称：        Include/ISA/Intel_x86/common.h
//文件描述：        与指令仿真相关的一些通用函数
//创建人：          杨鸿博(yanghongbo@ptwy.cn)
//创建日期：        2009年8月4日
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
//2009年8月4日，杨鸿博(yanghongbo@ptwy.cn)，创建


typedef enum _REGISTER_TYPE {
    GENERAL_REGISTER,
    MM_REGISTER,
    XMM_REGISTER,
    SEGMENT_REGISTER,
}REGISTER_TYPE;

VM_ERR_CODE SetMemoryValue(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uEffectiveAddress, UINT uValue, DWORD dwFlags, DWORD dwPrefixes);
UINT    GetMemoryValue(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uEffectiveAddress, DWORD dwFlags, DWORD dwPrefixes);
VM_INSTRUCTION_ERR_CODE SetRegisterValue(PVM_Intel_x86_ISA_t pX86, UINT uIndex, UINT uValue, REGISTER_TYPE Type, DWORD dwFlags, DWORD dwPrefixes);
UINT GetRegisterValue(PVM_Intel_x86_ISA_t pX86, UINT uIndex, REGISTER_TYPE Type, DWORD dwFlags, DWORD dwPrefixes);
VM_INSTRUCTION_ERR_CODE GetEffectiveAddress(PVM_Intel_x86_ISA_t pX86, PVM_Intel_x86_InstructionData_t pInstruction, UINT * puEA);
DWORD GetDataType(DWORD dwFlags, Intel_x86_Operand_Size_t OpSize, DWORD dwPrefixes);
void PushStack(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory,UINT uValue , Intel_x86_Operand_Size_t emuOperandSize);
UINT PopStack(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, Intel_x86_Operand_Size_t emuOperandSize);
UINT GetStackElement(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uStackAddress ,Intel_x86_Operand_Size_t emuOperandSize);
void SetStackElement(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uStackAddress, UINT uValue, Intel_x86_Operand_Size_t emuOperandSize);

#endif //_COMMON_H_
