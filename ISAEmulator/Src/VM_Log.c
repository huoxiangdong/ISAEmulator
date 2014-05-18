//
//文件名称：        src/VM_Log.c
//文件描述：        虚拟机错误输出
//创建人：          杨鸿博(yanghongbo@ptwy.cn)，创建
//创建日期：        2010年3月22日
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
//2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，创建

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include "VM_Defines.h"
#include "VM_Log.h"

#define _CRT_SECURE_NO_DEPRECATE 1

int VM_DebugLog(char * filename, unsigned int linenumber, char * format, ...)
{
    char * buffer = NULL;
    int ret;
    int len;
    va_list args;
    
    if(format){    
        va_start(args, format);
        len = _vscprintf( format, args );
        buffer = (char *)malloc(sizeof(char)*len);
        if(buffer){
            ret = _vsprintf_p(buffer, len, format, args);
            printf("VM Debug log:%s(%d):%s",filename, linenumber, buffer);
            free(buffer);
            buffer = NULL;
        }
        va_end(args);

    }

    return ret;
}
int VM_NormalLog(char * format, ...)
{
    char * buffer = NULL;
    int ret;
    int len;
    va_list args;
    
    if(format){    
        va_start(args, format);
        len = _vscprintf( format, args );
        buffer = (char *)malloc(sizeof(char)*len);
        if(buffer){
            ret = _vsprintf_p(buffer, len, format, args);
            printf("VM log:%s", buffer);
            free(buffer);
            buffer = NULL;
        }
        va_end(args);

    }

    return ret;
}

#define MACRO_TO_STRING(x) #x
void VM_ErrLog(VM_ERR_CODE vm_err)
{
    switch(vm_err){
        case VM_ERR_NO_ERROR:
            printf("VM Err: " MACRO_TO_STRING(VM_ERR_NO_ERROR) "\n");
            break;
        case VM_ERR_FATAL_UNKNOWN:
            printf("VM Err: " MACRO_TO_STRING(VM_ERR_FATAL_UNKNOWN) "\n");
            break;
        case VM_ERR_FATAL_NULL_POINTER:
            printf("VM Err: " MACRO_TO_STRING(VM_ERR_FATAL_NULL_POINTER) "\n");
            break;
        case VM_ERR_FATAL_INVALID_POINTER:
            printf("VM Err: " MACRO_TO_STRING(VM_ERR_FATAL_INVALID_POINTER) "\n");
            break;
        case VM_ERR_FATAL_INSUFFICIENT_MEMORY:
            printf("VM Err: " MACRO_TO_STRING(VM_ERR_FATAL_INSUFFICIENT_MEMORY) "\n");
            break;
        case VM_ERR_FATAL_CANNOT_EXECUTE_INSTRUCTION:
            printf("VM Err: " MACRO_TO_STRING(VM_ERR_FATAL_CANNOT_EXECUTE_INSTRUCTION) "\n");
            break;
        case VM_ERR_NO_MORE_INSTRUCTION:
            printf("VM Err: " MACRO_TO_STRING(VM_ERR_NO_MORE_INSTRUCTION) "\n");
            break;
        case VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION:
            printf("VM Err: " MACRO_TO_STRING(VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION) "\n");
            break;
        case VM_ERR_FATAL_MEMORY_ACCESS_ADDRESS_NOT_ALIGNMENT:
            printf("VM Err: " MACRO_TO_STRING(VM_ERR_FATAL_MEMORY_ACCESS_ADDRESS_NOT_ALIGNMENT) "\n");
            break;
        case VM_ERR_FATAL_DEAD_LOOP:
            printf("VM Err: " MACRO_TO_STRING(VM_ERR_FATAL_DEAD_LOOP) "\n");
            break;
        case VM_ERR_FATAL_DEAD_MAXIMUM_LOOP:
            printf("VM Err: " MACRO_TO_STRING(VM_ERR_FATAL_DEAD_MAXIMUM_LOOP) "\n");
            break;
        case VM_ERR_SHELLCODE_SEEMS_BE_FOUND:
            printf("VM Err: " MACRO_TO_STRING(VM_ERR_SHELLCODE_SEEMS_BE_FOUND) "\n");
            break;
        default:
            printf("VM Err: not defined VM ERROR CODE\n");
            break;
    }
}
