#ifndef _VM_MEMORY_H_
#define _VM_MEMORY_H_
//
//文件名称：        Include/VM_MemoryManagement.h
//文件描述：        虚拟机内存管理接口
//创建人：          杨鸿博(yanghongbo@ptwy.cn)
//创建日期：        2009年6月18日
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
//2009年6月18日，杨鸿博(yanghongbo@ptwy.cn)，创建


#include "VM_Defines.h"

#ifdef  __cplusplus
extern "C" {
#endif



//名称：_VM_MemoryBlock_t
//描述：
//更新日志：2009年6月22日，杨鸿博(yanghongbo@ptwy.cn)，创建
//           2009年9月17日，杨鸿博(yanghongbo@ptwy.cn)，修改变量
//
typedef struct _VM_MemoryBlock_t {
    UINT32 uSegmentDescriptor[2];
    //MEMORY_SIZE uMemoryBlockSize;在SegmentDescriptor中得到
    //BYTE *  pMemoryBlock;
    UINT    uStartAddr;//将目标程序的映射地址
    size_t  uBlockSize;
}VM_MemoryBlock_t, * PVM_MemoryBlock_t;

//名称：_VM_Memory_t
//描述：
//更新日志：2009年6月24日，杨鸿博(yanghongbo@ptwy.cn)，创建
//           2009年9月17日，杨鸿博(yanghongbo@ptwy.cn)，修改变量
//
typedef struct _VM_Memory_t {
    VM_MemoryBlock_t CodeSegment;
    VM_MemoryBlock_t DataSegment;
    VM_MemoryBlock_t StackSegment;
}VM_Memory_t, * PVM_Memory_t;

//暂时如此定义
VM_ERR_CODE VM_MM_InitializeMemoryBlock(PVM_MemoryBlock_t pBlock, UINT uStartAddr, size_t MemorySize);
VM_ERR_CODE VM_MM_UninitializeMemoryBlock(PVM_MemoryBlock_t pBlock);

void VM_MM_InitializeMemory();
void VM_MM_UninitializeMemory();

BYTE VM_MM_ReadOneByte(PVM_MemoryBlock_t pBlock, UINT addr);
//或者这种形式VM_ERR_CODE VM_MM_ReadOneByte(PVM_MemoryBlock_t pBlock, ADDRESS addr, BYTE * pbyData);
WORD VM_MM_ReadOneWord(PVM_MemoryBlock_t pBlock, UINT addr);
DWORD VM_MM_ReadOneDWord(PVM_MemoryBlock_t pBlock, UINT addr);
//参数表应该改:BYTE * pDst, size_t Size, PVM_MemoryBlock_t pBlock, UINT addr, size_t sizeToRead
VM_ERR_CODE VM_MM_ReadOneBlock(PVM_MemoryBlock_t pBlock, UINT addr, BYTE * pDst, size_t Size);
VM_ERR_CODE VM_MM_WriteOneByte(PVM_MemoryBlock_t pBlock, UINT addr, BYTE byData);
VM_ERR_CODE VM_MM_WriteOneWord(PVM_MemoryBlock_t pBlock, UINT addr, WORD wData);
VM_ERR_CODE VM_MM_WriteOneDWord(PVM_MemoryBlock_t pBlock, UINT addr, DWORD dwData);
//参数表应该改:PVM_MemoryBlock_t pBlock, UINT addr, BYTE * pSrc, size_t Size, size_t sizeToRead
VM_ERR_CODE VM_MM_WriteOneBlock(PVM_MemoryBlock_t pBlock, UINT addr, BYTE * pSrc, size_t Size);

#ifdef  __cplusplus
}
#endif


#endif//_VM_MEMORY_H_

