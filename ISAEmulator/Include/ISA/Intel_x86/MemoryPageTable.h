#ifndef _MEMORY_PAGE_TABLE_H_
#define _MEMORY_PAGE_TABLE_H_
//
//文件名称：        Include/ISA/Intel_x86/VM_MemoryPageTable.h
//文件描述：        Intel x86架构下的内存页表实现
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
//2010年3月18日，杨鸿博(yanghongbo@ptwy.cn)，更新
//2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，增加整页/整块内存复制代码

#define PAGE_INDEX_BIT                          19
#define PAGE_SIZE_BIT			                12
#define PAGE_COUNT                              (1 << PAGE_INDEX_BIT)
#define PAGE_SIZE				                (1 << PAGE_SIZE_BIT)        //4096  //4k
#define PAGE_SIZE_MASK_BIT  	                (PAGE_SIZE - 1)   //0x00000fff	//4095
#define PAGE_MAXIMUM_ADDRESS                    ((UINT)(1 << (PAGE_INDEX_BIT + PAGE_SIZE_BIT))  - 1)
#define PAGE_MAXIMUM_SIZE                       (PAGE_MAXIMUM_ADDRESS + 1)
#define PAGE_OFFSET_MASK(addr)	                ((addr)&(PAGE_SIZE_MASK_BIT))
#define PAGE_INDEX_MASK(addr)                   (((addr)&(~PAGE_SIZE_MASK_BIT)) >> PAGE_SIZE_BIT)
#define PAGE_ADDRESS_DWORD_ALIGNMENT_MASK(addr)  ((addr) & 0x3) //地址字对齐
#define PAGE_ADDRESS_WORD_ALIGNMENT_MASK(addr) (((addr) & 0x1)) //地址双字对齐
#define IS_PAGE_ADDRESS_WORD_ALIGNED(addr)      (!PAGE_ADDRESS_WORD_ALIGNMENT_MASK(addr))
#define IS_PAGE_ADDRESS_DWORD_ALIGNED(addr)     (!PAGE_ADDRESS_DWORD_ALIGNMENT_MASK(addr))

#define PAGE_OFFSET_TO_ADDRESS(page, offset)    ((((page) & (PAGE_COUNT - 1)) << PAGE_SIZE_BIT ) | ((offset) & PAGE_SIZE_MASK_BIT))

//当目标地址未初始化时返回的数据。0xcc == int 13, 'NL' -> Not initialized
#define UNINITIALIZED_BYTE             'N'//0xcc
#define UNINITIALIZED_WORD             'NI'//0xcccc
#define UNINITIALIZED_DWORD            'NINI'//0xcccccccc

//名称：MEMORY_PAGE
//描述：内存页的属性
//		PVOID   pPage;页内存指针
//		INT     nAccessCount;访问计数
//更新日志：2010年3月16日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
typedef struct _MEMORY_PAGE {
	PVOID	pPage;
	INT		nAccessCount;
}MEMORY_PAGE, * PMEMORY_PAGE;

//函数名称：MemInitialize
//返回值类型：void
//参数：void
//描述：初始化
//更新日志：2010年3月19日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
void MemPageInitialize();

//函数名称：MemUninitialize
//返回值类型：void
//参数：void
//描述：释放资源
//更新日志：2010年3月19日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
void MemPageUninitialize();


//函数名称：MemPageReadByte
//返回值类型：VM_ERR_CODE
//参数：UINT uPage, UINT uOffset, PBYTE pData
//描述：从内存页中读取一个字节
//更新日志：2010年3月18日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemPageReadByte(UINT uPage, UINT uOffset, PBYTE pbyData);

//函数名称：MemPageWriteByte
//返回值类型：VM_ERR_CODE
//参数：UINT uPage, UINT uOffset, BYTE data
//描述：向内存页中写入一个字节
//更新日志：2010年3月18日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemPageWriteByte(UINT uPage, UINT uOffset, BYTE byData);

//函数名称：MemPageReadWord
//返回值类型：VM_ERR_CODE
//参数：UINT uPage, UINT uOffset, PWORD pData
//描述：从内存页中读取一个字（双字节）
//更新日志：2010年3月18日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemPageReadWord(UINT uPage, UINT uOffset, PWORD pwData);

//函数名称：MemPageWriteWord
//返回值类型：VM_ERR_CODE
//参数：UINT uPage, UINT uOffset, WORD data
//描述：向内存页中写入一个字（双字节）
//更新日志：2010年3月18日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemPageWriteWord(UINT uPage, UINT uOffset, WORD wData);

//函数名称：MemPageReadDWord
//返回值类型：VM_ERR_CODE
//参数：UINT uPage, UINT uOffset, PDWORD pData
//描述：从内存页中读取一个双字（四字节）
//更新日志：2010年3月18日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemPageReadDWord(UINT uPage, UINT uOffset, PDWORD pdwData);

//函数名称：MemPageWriteDWord
//返回值类型：VM_ERR_CODE
//参数：UINT uPage, UINT uOffset, BYTE data
//描述：向内存页中写入一个双字（四字节）
//更新日志：2010年3月18日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemPageWriteDWord(UINT uPage, UINT uOffset, DWORD dwData);
/*
//函数名称：MemPageCopyPages
//返回值类型：VM_ERR_CODE
//参数：UINT uDstToPage, UINT uSrcFromPage, UINT uPageNum
//描述：在虚拟内存中复制连续的内存页（整页复制）
//更新日志：2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemPageCopyPages(UINT uDstToPage, UINT uSrcFromPage, UINT uPageNum);
VM_ERR_CODE MemPageCopy(UINT uDstPage, UINT uDstOffset, UINT uSrcPage, UINT uSrcOffset, size_t sizeToCopy);
*/
//函数名称：MemPageCopyPagesToVMBuffer
//返回值类型：VM_ERR_CODE
//参数：PVOID pBuffer, size_t sizeBuffer, UINT uSrcFromPage, UINT uPageNum
//描述：将虚拟环境的页（首地址为页起始地址——页对齐）数据复制到缓冲区
//更新日志：2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemPageCopyPagesToVMBuffer(PVOID pBuffer, size_t sizeBuffer, UINT uSrcFromPage, UINT uPageNum);

//函数名称：MemPageCopyPagesToVMBuffer
//返回值类型：VM_ERR_CODE
//参数：PVOID pBuffer, size_t sizeBuffer, UINT uSrcFromPage, UINT uPageNum
//描述：将缓冲区复制到虚拟环境的整页内存中（首地址为页起始地址——页对齐）
//更新日志：2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemPageCopyPagesFromVMBuffer(UINT uDstToPage, PVOID pBuffer, size_t sizeBuffer, UINT uPageNum);

//函数名称：MemPageCopyToVMBuffer
//返回值类型：VM_ERR_CODE
//参数：PVOID pBuffer, size_t sizeBuffer, UINT uSrcFromPage, UINT uOffset, size_t sizeBytesToRead
//描述：将虚拟环境内存中（不需要页对齐）复制到缓冲区
//更新日志：2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemPageCopyToVMBuffer(PVOID pBuffer, size_t sizeBuffer, UINT uSrcFromPage, UINT uOffset, size_t sizeBytesToRead);

//函数名称：MemPageCopyFromVMBuffer
//返回值类型：VM_ERR_CODE
//参数：UINT uDstToPage, UINT uOffset, PVOID pBuffer, size_t sizeBuffer, size_t sizeBytesToWrite
//描述：将缓冲区复制到虚拟环境内存中（不需要页对齐）
//更新日志：2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
VM_ERR_CODE MemPageCopyFromVMBuffer(UINT uDstToPage, UINT uOffset, PVOID pBuffer, size_t sizeBuffer, size_t sizeBytesToWrite);

#endif