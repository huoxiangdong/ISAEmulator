#ifndef _INTEL_X86_MEMORY_H_
#define _INTEL_X86_MEMORY_H_
//
//文件名称：        Include/ISA/Intel_x86/Memory.h
//文件描述：        Intel x86架构下的内存模块封装
//创建人：          杨鸿博(yanghongbo@ptwy.cn)
//创建日期：        2010年3月16日
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
//2010年3月16日，杨鸿博(yanghongbo@ptwy.cn)，创建

#define MEMORY_MAXIMUM_ADDRESS  PAGE_MAXIMUM_ADDRESS


void MemUninitialize();
void MemInitialize();


//函数名称：MemReadByte
//返回值类型：VM_ERR_CODE
//参数：UINT uAddr, PBYTE pData
//描述：从内存中读取一个字节
//更新日志：2010年3月18日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
//VM_ERR_CODE MemReadByte(UINT uAddr, PBYTE pbyData);
#define MemReadByte(uAddr, pbyData) MemPageReadByte(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), pbyData)

//函数名称：MemWriteByte
//返回值类型：VM_ERR_CODE
//参数：UINT uAddr, BYTE data
//描述：向内存中写入一个字节
//更新日志：2010年3月18日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
#define MemWriteByte(uAddr, data) MemPageWriteByte(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), data)

//函数名称：MemReadWord
//返回值类型：VM_ERR_CODE
//参数：UINT uAddr, PWORD pData
//描述：从内存中读取一个字
//更新日志：2010年3月18日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemReadWord(UINT uAddr, PWORD pwData);
//函数名称：MemWriteWord
//返回值类型：VM_ERR_CODE
//参数：UINT uAddr, BYTE data
//描述：向内存中写入一个字节
//更新日志：2010年3月18日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemWriteWord(UINT uAddr, WORD wData);
//函数名称：MemReadDWord
//返回值类型：VM_ERR_CODE
//参数：UINT uAddr, PDWORD pdwData
//描述：从内存中读取一个双字
//更新日志：2010年3月18日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemReadDWord(UINT uAddr, PDWORD pdwData);

//函数名称：MemWriteWord
//返回值类型：VM_ERR_CODE
//参数：UINT uAddr, DWORD dwData
//描述：向内存中写入一个字节
//更新日志：2010年3月18日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemWriteDWord(UINT uAddr, DWORD dwData);

//函数名称：MemCopyFromVMBuffer
//返回值类型：VM_ERR_CODE
//参数：UINT uDstAddr, size_t sizeBuffer, PVOID pBuffer, size_t sizeToWrite
//描述：将缓冲区复制到虚拟环境内存中
//更新日志：2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemCopyFromVMBuffer(UINT uDstAddr, size_t sizeBuffer, PVOID pBuffer, size_t sizeToWrite);

//函数名称：MemCopyToVMBuffer
//返回值类型：VM_ERR_CODE
//参数：UINT uDstAddr, size_t sizeBuffer, PVOID pBuffer, size_t sizeToWrite
//描述：将虚拟环境内存中复制到缓冲区
//更新日志：2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemCopyToVMBuffer(PVOID pBuffer, size_t sizeBuffer, UINT uSrcAddr, size_t sizeToRead);
#endif //_INTEL_X86_MEMORY_H_