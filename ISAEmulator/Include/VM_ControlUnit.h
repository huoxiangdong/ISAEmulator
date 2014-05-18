#ifndef _VM_CONTROL_UNIT_H_
#define _VM_CONTROL_UNIT_H_
//
//文件名称：        Include/VM_ControlUnit.h
//文件描述：        模拟器CPU结构相关定义
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

#include "VM_Config.h"
#include "VM_Defines.h"

#include "VM_ISARelated.h"
#include "VM_Memory.h"

struct _VM_Emulator_t;
typedef void (*PFN_OUTPUT_CPU_STATE)(struct _VM_CPUStructure_t * pCpuStructure);
typedef VM_INSTRUCTION_ERR_CODE (*PFN_FETCH_ONE_INSTRUCTION)(struct _VM_CPUStructure_t * pCpuStructure, PVM_Memory_t pMemory);
typedef VM_ERR_CODE (*PFN_EXECUTE_ONE_INSTRUCTION)(struct _VM_CPUStructure_t * pCpuStructure, PVM_Memory_t pMemory);
typedef size_t (*PFN_GET_CURRENT_INSTRUCTION_MNEMONIC)(char *, size_t, const struct _VM_CPUStructure_t *);
//名称：VM_ControlUnit_t
//描述：
//更新日志：2009年6月16日，杨鸿博(yanghongbo@ptwy.cn)，创建
typedef struct _VM_ControlUnit_t {
    PFN_OUTPUT_CPU_STATE pfnOutputCpuState;
    PFN_FETCH_ONE_INSTRUCTION pfnFetchOneInstruction;
    PFN_EXECUTE_ONE_INSTRUCTION pfnExecuteOneInstruction;
    PFN_GET_CURRENT_INSTRUCTION_MNEMONIC pfnGetCurrentInstructionMnemonic;
}VM_ControlUnit_t, * PVM_ControlUnit_t;

//VM_ERR_CODE VM_CU_***();

#endif//_VM_CONTROL_UNIT_H_
