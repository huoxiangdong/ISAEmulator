#ifndef _VM_DEFINES_H_
#define _VM_DEFINES_H_
//
//文件名称：        Include/VM_Defines.h
//文件描述：        公共宏定义
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

//名称：数据类型定义
//描述：
//更新日志：2009年6月12日，杨鸿博(yanghongbo@ptwy.cn)，创建
#include "VM_Config.h"
#ifdef  __cplusplus
extern "C" {
#endif

#define _NOT_IMPLEMENTED 0
#define VM_NOT_IMPLEMENTED() assert(_NOT_IMPLEMENTED);

#ifndef NULL
#ifdef __cplusplus
#define NULL    0
#else
#define NULL    ((void *)0)
#endif
#endif

#define JIF(x)  \
            vm_err = (x);    \
            if(VM_ERR_NO_ERROR != vm_err){   \
                assert(VM_ERR_NO_ERROR == vm_err);  \
                return vm_err;                      \
            }

#if defined(VM_ISA_INTEL_X86_64_BIT)
//    typedef UINT64 ADDRESS;
//    typedef UINT64 MEMORY_SIZE;
#elif defined(VM_ISA_INTEL_X86_32_BIT)
//    typedef UINT32 ADDRESS;
//    typedef UINT32 MEMORY_SIZE;
    typedef unsigned long long int UINT64;
    typedef unsigned long int UINT32;
    typedef unsigned short int UINT16;

    typedef long long int INT64;
    typedef long int INT32;
    typedef short int INT16;
#endif

#define  _8_BITS    8
#define  _16_BITS  16
#define  _32_BITS  32
#define  _64_BITS  64

#define IN
#define OUT
#define INOUT

typedef unsigned int UINT;
typedef unsigned char UINT8;
typedef int INT;
typedef char INT8;

typedef int INT;
typedef INT BOOL;
#define FALSE 0
#define TRUE  1

typedef UINT8 BYTE;
typedef UINT16 WORD;
typedef UINT32 DWORD;

//指针
typedef void * PVOID;
typedef BYTE * PBYTE;
typedef WORD * PWORD;
typedef DWORD * PDWORD;

#ifndef NULL
#define NULL ((PVOID)0)
#endif

//名称：VM_ERR_CODE
//描述：工程用的错误代码，大部分函数使用的返回值
//更新日志：2009年6月5日，杨鸿博(yanghongbo@ptwy.cn)，创建，增加ERR_NO_ERROR, ERR_FATAL
//需要将两部分错误代码合并为单一的变量。
typedef enum _VM_ERR_CODE {
    VM_ERR_NO_ERROR = 0,                //正常
    VM_ERR_FATAL_UNKNOWN,               //未知错误
    VM_ERR_FATAL_NULL_POINTER,          //空指针错误
    VM_ERR_FATAL_INVALID_POINTER,       //无效指针
    VM_ERR_FATAL_INSUFFICIENT_MEMORY,   //内存不足
    VM_ERR_FATAL_CANNOT_EXECUTE_INSTRUCTION, //无法执行指令
    VM_ERR_NO_MORE_INSTRUCTION,         //没有指令
    VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION, //非法访问内存
    VM_ERR_FATAL_MEMORY_ACCESS_ADDRESS_NOT_ALIGNMENT, //内存地址未对齐
    VM_ERR_FATAL_DEAD_LOOP,             //loop 0的死循环
    VM_ERR_FATAL_DEAD_MAXIMUM_LOOP,     //loop -X的死循环，在一个代码段往复
    VM_ERR_SHELLCODE_SEEMS_BE_FOUND,    //找到疑似shellcode
}VM_ERR_CODE;

typedef enum _VM_INSTRUCTION_ERR_CODE {
    VM_INSTRUCTION_ERR_SUCCEEDED = 0,                //正常
    VM_INSTRUCTION_ERR_FATAL_UNKNOWN,
    VM_INSTRUCTION_ERR_NOT_IMPLEMENTED,
    VM_INSTRUCTION_ERR_INTEGER_OVERFLOW,                //除法时寄存器没有办法放入较大的数字 Integer overflow
    VM_INSTRUCTION_ERR_INVALID_OPCODE,
    VM_INSTRUCTION_ERR_INVALID_PARAMETER,
    VM_INSTRUCTION_ERR_DIVIDE_BY_ZERO,
    VM_INSTRUCTION_ERR_ERROR_RETURN_BY_VM,          //由返回VM_ERR_CODE的函数报错
}VM_INSTRUCTION_ERR_CODE;

#ifdef  __cplusplus
}
#endif

#endif//_VM_DEFINES_H_
