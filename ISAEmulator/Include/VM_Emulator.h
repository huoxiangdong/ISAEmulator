#ifndef _VM_EMULATOR_H_
#define _VM_EMULATOR_H_
//
//文件名称：        Include/VM_Emulator.h
//文件描述：        模拟器相关结构体与函数定义
//创建人：          杨鸿博(yanghongbo@ptwy.cn)
//创建日期：        2009年6月5日
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
//2009年6月5日，杨鸿博(yanghongbo@ptwy.cn)，创建

#include "VM_Config.h"
#include "VM_Defines.h"
#include "VM_ISARelated.h"
#include "VM_ControlUnit.h"
#include "VM_Memory.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum _VM_EMULATOR_STATUS {
    RUNNING = 0, 
    STOPPED,  
}VM_EMULATOR_STATUS;

struct _NODE;
typedef struct _NODE NODE, * PNODE;
typedef struct _NODE {
    PNODE pNext;
    PVOID pDatafield;
    size_t siDatafield;
}NODE, * PNODE;

typedef enum _MEMORY_ACCESS_TYPE {
    MEMORY_ACCESS_WRITE,
    MEMORY_ACCESS_READ,
}MEMORY_ACCESS_TYPE;

typedef struct _MemoryAccessLog_t {
    UINT uStartAddr;
    size_t siAccessSize;
    MEMORY_ACCESS_TYPE type;
}MemoryAccessLog_t, * PMemoryAccessLog_t;

typedef struct _VM_Shellcode_Monitor_t {
    UINT uLastAccessMemoryStart;
    size_t siLastAccessMemorySize;

}VM_Shellcode_Monitor_t, * PVM_Shellcode_Monitor_t;

//名称：VM_Emulator_t
//描述：
//更新日志：2009年6月5日，杨鸿博(yanghongbo@ptwy.cn)，创建
//          2009年6月16日，杨鸿博(yanghongbo@ptwy.cn)，补充结构
typedef struct _VM_Emulator_t {
    VM_EMULATOR_STATUS Status;
    VM_CPUStructure_t CPUStructure;
    VM_Memory_t Memory;//可能应该换成链表结构
    VM_ControlUnit_t ControlUnit;
}VM_Emulator_t, * PVM_Emulator_t;

VM_ERR_CODE VM_Emu_LoadProgramCodeFromFile(PVM_Emulator_t pEmulator, const char * filename, OUT size_t * pCodeSize);

VM_ERR_CODE VM_Emu_Initialize(PVM_Emulator_t pEmulator);
VM_ERR_CODE VM_Emu_Step(PVM_Emulator_t pEmulator);
VM_ERR_CODE VM_Emu_Run(PVM_Emulator_t pEmulator);
VM_ERR_CODE VM_Emu_LoadProgramCode(PVM_Emulator_t pEmulator, PBYTE pCodeBuffer, size_t CodeSize);
VM_ERR_CODE VM_Emu_Uninitialize(PVM_Emulator_t pEmulator);

#ifdef  __cplusplus
}
#endif


#endif//_VM_EMULATOR_H_
