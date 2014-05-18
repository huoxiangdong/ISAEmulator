//
//文件名称：        src/ISA/Intel_x86/Memory/Memory.c
//文件描述：        Intel x86架构下的内存模块
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "VM_Defines.h"
#include "VM_Log.h"
#include "ISA/Intel_x86/MemoryPageTable.h"

//内存页初始化标志
static BOOL g_bMemoryPageTableInitialized = FALSE;

//名称：MemPageTable
//描述：内存页表指针数组
//更新日志：2010年3月16日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
//
static MEMORY_PAGE MemPageTable[PAGE_COUNT];

//函数名称：MemPageZeroTable
//返回值类型：void
//参数：void
//描述：将所有内存页表指针置为空，静态函数，在初始化时执行，不可外部调用
//更新日志：2010年3月16日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
//
static void MemPageZeroTable();

//函数名称：MemPageFreeTable
//返回值类型：void
//参数：void
//描述：释放所有内存表的内存，在退出时执行，不可外部调用
//更新日志：2010年3月16日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
//
static void MemPageFreeTable();

//函数名称：MemPageAlloc
//返回值类型：VM_ERR_CODE
//参数：UINT uPageAddr
//描述：分配一个页的内存空间。目前实现采用stdlib的malloc分配内存。在实现内存虚拟磁盘文件之后，将需要更复杂的分配和判断操作，不可外部调用
//更新日志：2010年3月17日，杨鸿博(yanghongbo@ptwy.cn)，创建
//
static VM_ERR_CODE MemPageAlloc(UINT uPageAddr);

static void MemPageUsageLog()
{
    UINT pages = 0;
    UINT i = 0;
    for(i = 0; i < PAGE_COUNT; i ++){
        if(MemPageTable[i].pPage){
            pages ++;
        }
    }
    //VM_DEBUGLOG("pages:%u/%u\n", pages, PAGE_COUNT);
    //VM_NormalLog("pages:%u/%u\n", pages, PAGE_COUNT);
    printf("pages:%u/%u\n", pages, PAGE_COUNT);
}

void MemPageInitialize(){
    if(FALSE == g_bMemoryPageTableInitialized){
        MemPageZeroTable();
        g_bMemoryPageTableInitialized = TRUE;
    }
}


void MemPageUninitialize(){
    MemPageFreeTable();
    g_bMemoryPageTableInitialized = FALSE;
}


static void MemPageZeroTable()
{
	memset(MemPageTable, 0, sizeof(MemPageTable));
}


static void MemPageFreeTable()
{
	int i = 0;
	for(i = 0; i < PAGE_COUNT; i++){
		if(MemPageTable[i].pPage){
			free(MemPageTable[i].pPage);
			MemPageTable[i].pPage = NULL;
		}
	}
}

static VM_ERR_CODE MemPageAlloc(UINT uPageAddr)
{
    PVOID page = NULL;
    //内存页已经分配，直接返回
    
    if(MemPageTable[uPageAddr].pPage)
        return VM_ERR_NO_ERROR;

    if(uPageAddr < PAGE_COUNT){
        page = (PVOID)malloc(sizeof(BYTE) * PAGE_SIZE);
        if(NULL == page)
            return VM_ERR_FATAL_INSUFFICIENT_MEMORY;//内存不足
        else {
            memset(page, UNINITIALIZED_BYTE, sizeof(BYTE) * PAGE_SIZE);
            MemPageTable[uPageAddr].pPage = page;
            //printf("page addr:0x%08x\n", uPageAddr << PAGE_SIZE_BIT);
            //MemPageUsageLog();
            return VM_ERR_NO_ERROR;
        }
    }

    return VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;//访问越界
}

VM_ERR_CODE MemPageReadByte(UINT uPage, UINT uOffset, PBYTE pData)
{
    assert(pData);
    if(uPage < PAGE_COUNT && uOffset < PAGE_SIZE ){
        if(MemPageTable[uPage].pPage){
            *pData = *((BYTE*)MemPageTable[uPage].pPage + uOffset);
            return VM_ERR_NO_ERROR;
        }
        else{//页未被分配
            *(pData) = UNINITIALIZED_BYTE;
            return VM_ERR_NO_ERROR;
        }
    }

    return VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
}

VM_ERR_CODE MemPageWriteByte(UINT uPage, UINT uOffset, BYTE data)
{
    VM_ERR_CODE err = VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
    if(uPage < PAGE_COUNT && uOffset < PAGE_SIZE ){
        //分配内存，如果内存页已经分配，则直接返回VM_NO_ERROR。
        err = MemPageAlloc(uPage);
        if(VM_ERR_NO_ERROR == err){
            *((BYTE*)MemPageTable[uPage].pPage + uOffset) = data;
            return VM_ERR_NO_ERROR;
        }
    }

    return err;
}

VM_ERR_CODE MemPageReadWord(UINT uPage, UINT uOffset, PWORD pData)
{
    assert(pData);
    if(!IS_PAGE_ADDRESS_WORD_ALIGNED(uOffset)){
        return VM_ERR_FATAL_MEMORY_ACCESS_ADDRESS_NOT_ALIGNMENT;
    }
    
    if(uPage < PAGE_COUNT && uOffset < PAGE_SIZE ){
        if(MemPageTable[uPage].pPage){
            *pData = *((PWORD)((PBYTE)MemPageTable[uPage].pPage + uOffset));
            return VM_ERR_NO_ERROR;
        }
        else{//页未被分配
            *pData = UNINITIALIZED_WORD;
            return VM_ERR_NO_ERROR;
        }
    }

    return VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
}

VM_ERR_CODE MemPageWriteWord(UINT uPage, UINT uOffset, WORD data)
{
    VM_ERR_CODE err = VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;

    if(!IS_PAGE_ADDRESS_WORD_ALIGNED(uOffset)){
        return VM_ERR_FATAL_MEMORY_ACCESS_ADDRESS_NOT_ALIGNMENT;
    }

    if(uPage < PAGE_COUNT && uOffset < PAGE_SIZE ){
        //分配内存，如果内存页已经分配，则直接返回VM_NO_ERROR。
        err = MemPageAlloc(uPage);
        if(VM_ERR_NO_ERROR == err){
            *((PWORD)((PBYTE)MemPageTable[uPage].pPage + uOffset)) = data;
            return VM_ERR_NO_ERROR;
        }
    }

    return err;
}


VM_ERR_CODE MemPageReadDWord(UINT uPage, UINT uOffset, PDWORD pData)
{
    assert(pData);
    if(!IS_PAGE_ADDRESS_DWORD_ALIGNED(uOffset)){
        return VM_ERR_FATAL_MEMORY_ACCESS_ADDRESS_NOT_ALIGNMENT;
    }
    
    if(uPage < PAGE_COUNT && uOffset < PAGE_SIZE ){
        if(MemPageTable[uPage].pPage){
            *pData = *((PDWORD)((PBYTE)MemPageTable[uPage].pPage + uOffset));
            return VM_ERR_NO_ERROR;
        }
        else{//页未被分配
            *(pData) = UNINITIALIZED_DWORD;
            return VM_ERR_NO_ERROR;
        }
    }

    return VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
}

VM_ERR_CODE MemPageWriteDWord(UINT uPage, UINT uOffset, DWORD data)
{
    VM_ERR_CODE err = VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;

    if(!IS_PAGE_ADDRESS_DWORD_ALIGNED(uOffset)){
        return VM_ERR_FATAL_MEMORY_ACCESS_ADDRESS_NOT_ALIGNMENT;
    }

    if(uPage < PAGE_COUNT && uOffset < PAGE_SIZE ){
        //分配内存，如果内存页已经分配，则直接返回VM_ERR_NO_ERROR。
        err = MemPageAlloc(uPage);
        if(VM_ERR_NO_ERROR == err){
            *((PDWORD)((PBYTE)MemPageTable[uPage].pPage + uOffset)) = data;
            return VM_ERR_NO_ERROR;
        }
    }

    return err;
}
/*
VM_ERR_CODE MemPageCopyPages(UINT uDstToPage, UINT uSrcFromPage, UINT uPageNum)
{
    UINT i = 0;
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN;

    if((0 <= uDstToPage && uDstToPage + uPageNum - 1 < PAGE_COUNT)
        && (0 <= uSrcFromPage && uSrcFromPage + uPageNum - 1 < PAGE_COUNT)){
            for(i = 0; i < uPageNum; i ++){
                 //分配内存页
                if(NULL == MemPageTable[uDstToPage + i].pPage){
                    err = MemPageAlloc(uDstToPage + i);
                    if(VM_ERR_NO_ERROR != err){
                        return err;
                    }
                }
                if(MemPageTable[uSrcFromPage + i].pPage){
                    memcpy(MemPageTable[uDstToPage + i].pPage, MemPageTable[uSrcFromPage + i].pPage, sizeof(BYTE) * PAGE_SIZE);
                }
                else {
                    //源为NULL，则目标页复制UNINITIALIZED_BYTE
                    memset(MemPageTable[uDstToPage + i].pPage, UNINITIALIZED_BYTE, sizeof(BYTE) * PAGE_SIZE);
                }
            }
            return VM_ERR_NO_ERROR;
    }

    return VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
}

VM_ERR_CODE MemPageCopy(UINT uDstPage, UINT uDstOffset, UINT uSrcPage, UINT uSrcOffset, size_t sizeToCopy)
{
    
}
*/
VM_ERR_CODE MemPageCopyPagesToVMBuffer(PVOID pBuffer, size_t sizeBuffer, UINT uSrcFromPage, UINT uPageNum)
{
    UINT i = 0;
    PBYTE pointer = NULL;
    
    assert(pBuffer);

    if(sizeBuffer >= uPageNum * sizeof(BYTE) * PAGE_SIZE){
        pointer = (PBYTE)pBuffer;
        if((0 <= uSrcFromPage && uSrcFromPage + uPageNum - 1 < PAGE_COUNT)){
                for(i = 0; i < uPageNum; i ++){
                    if(MemPageTable[uSrcFromPage + i].pPage){
                        memcpy(pointer, MemPageTable[uSrcFromPage + i].pPage, sizeof(BYTE) * PAGE_SIZE);
                    }
                    else {
                        memset(pointer, UNINITIALIZED_BYTE, sizeof(BYTE) * PAGE_SIZE);
                    }
                    pointer += sizeof(BYTE) * PAGE_SIZE;
                }
                return VM_ERR_NO_ERROR;
        }
    }

    return VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
}

VM_ERR_CODE MemPageCopyPagesFromVMBuffer(UINT uDstToPage, PVOID pBuffer, size_t sizeBuffer, UINT uPageNum)
{
    UINT i = 0;
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN;
    PBYTE pointer = NULL;
    
    assert(pBuffer);

    if(sizeBuffer >= uPageNum * sizeof(BYTE) * PAGE_SIZE){
        pointer = (PBYTE)pBuffer;
        if((0 <= uDstToPage && uDstToPage + uPageNum - 1 < PAGE_COUNT)){
                for(i = 0; i < uPageNum; i ++){
                    //分配内存页
                    if(NULL == MemPageTable[uDstToPage + i].pPage){
                        err = MemPageAlloc(uDstToPage + i);
                        if(VM_ERR_NO_ERROR != err){
                            return err;
                        }
                    }
                    memcpy(MemPageTable[uDstToPage + i].pPage, pointer, sizeof(BYTE) * PAGE_SIZE);
                    pointer += sizeof(BYTE) * PAGE_SIZE;
                }
                return VM_ERR_NO_ERROR;
        }
    }

    return VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
}

VM_ERR_CODE MemPageCopyToVMBuffer(PVOID pBuffer, size_t sizeBuffer, UINT uSrcFromPage, UINT uOffset, size_t sizeBytesToRead)
{
    UINT uSrcAddress = 0;
    PBYTE pointer = NULL;
    size_t sizeLeftToRead = 0;
    size_t sizeBeRead = 0;
    UINT uPagesToRead = 0;
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN ;
    assert(pBuffer);

	if(uSrcFromPage < PAGE_COUNT && uOffset < PAGE_SIZE){
		uSrcAddress = PAGE_OFFSET_TO_ADDRESS(uSrcFromPage, uOffset);
		if(sizeBuffer >= sizeBytesToRead){
			sizeLeftToRead = sizeBytesToRead;
			pointer = (PBYTE)pBuffer;

			if((sizeBytesToRead <= PAGE_MAXIMUM_SIZE) 
				&& (uSrcAddress + sizeBytesToRead <= PAGE_MAXIMUM_ADDRESS )){

					//复制第一部分（可能不是完整的页）
					sizeBeRead = PAGE_SIZE - uOffset;
					if(sizeBeRead > sizeLeftToRead)
						sizeBeRead = sizeLeftToRead;

					if(MemPageTable[uSrcFromPage].pPage){
						memcpy(pointer, (PBYTE)MemPageTable[uSrcFromPage].pPage + uOffset, sizeBeRead);
					}
					else {
						memset(pointer, UNINITIALIZED_BYTE, sizeBeRead);
					}
					sizeLeftToRead -= sizeBeRead;
					if(sizeLeftToRead > 0){
						pointer += sizeBeRead;
						//复制第二部分（可能为0或多个完整页）
						uPagesToRead = (UINT)((sizeLeftToRead - sizeBeRead) / PAGE_SIZE);
						if(uPagesToRead){
							err = MemPageCopyPagesToVMBuffer(pointer, sizeBuffer - sizeBeRead, uSrcFromPage + 1, uPagesToRead);
							if(VM_ERR_NO_ERROR != err)
								return err;
							sizeBeRead = uPagesToRead * sizeof(BYTE) * PAGE_SIZE;
							sizeLeftToRead -= sizeBeRead;
							pointer += sizeBeRead;
						}
	                    
						//复制第三部分（可能没有）
						if(sizeLeftToRead > 0){
							assert(sizeLeftToRead <= sizeof(BYTE) * PAGE_SIZE);
							if(sizeLeftToRead > sizeof(BYTE) * PAGE_SIZE){//剩余字节大于一页，复制第二部分计算出错
								VM_LOG();
								return VM_ERR_FATAL_UNKNOWN;
							}
							if(MemPageTable[uSrcFromPage + 1 + uPagesToRead].pPage){
								memcpy(pointer, (PBYTE)MemPageTable[uSrcFromPage + 1 + uPagesToRead].pPage + uOffset, sizeLeftToRead);
							}
							else {
								memset(pointer, UNINITIALIZED_BYTE, sizeLeftToRead);
							}
						}
					}

					return VM_ERR_NO_ERROR;
			}
		}
    }

    return VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
}

VM_ERR_CODE MemPageCopyFromVMBuffer(UINT uDstToPage, UINT uOffset, PVOID pBuffer, size_t sizeBuffer, size_t sizeBytesToWrite)
{
    UINT uDstAddress = 0;
    PBYTE pointer = NULL;
    size_t sizeLeftToWrite = 0;
    size_t sizeBeWrite = 0;
    UINT uPagesToWrite = 0;
    VM_ERR_CODE err = VM_ERR_FATAL_UNKNOWN ;

    assert(pBuffer);

    uDstAddress = PAGE_OFFSET_TO_ADDRESS(uDstToPage, uOffset);
    if(sizeBuffer <= sizeBytesToWrite){
        sizeLeftToWrite = sizeBytesToWrite;
        pointer = (PBYTE)pBuffer;

        if((uDstAddress <= PAGE_MAXIMUM_ADDRESS) 
            && (sizeBytesToWrite <= PAGE_MAXIMUM_SIZE) 
            && (uDstAddress + sizeBytesToWrite <= PAGE_MAXIMUM_ADDRESS )){

                //复制第一部分（可能不是完整的页）
                sizeBeWrite = PAGE_SIZE - uOffset;
                if(sizeBeWrite > sizeLeftToWrite)
                    sizeBeWrite = sizeLeftToWrite;

                if(NULL == MemPageTable[uDstToPage].pPage){
                    err = MemPageAlloc(uDstToPage);
                    if(VM_ERR_NO_ERROR != err){
                        return err;
                    }
                }
                memcpy((PBYTE)MemPageTable[uDstToPage].pPage + uOffset, pointer, sizeBeWrite);
                
                sizeLeftToWrite -= sizeBeWrite;
                if(sizeLeftToWrite > 0){
                    pointer += sizeBeWrite;

                    //复制第二部分（可能为0或多个完整页）
                    //uPagesToWrite = (UINT)((sizeLeftToWrite - sizeBeWrite) / PAGE_SIZE);
                    uPagesToWrite = (UINT)(sizeLeftToWrite / PAGE_SIZE);
                    if(uPagesToWrite){
                        err = MemPageCopyPagesFromVMBuffer(uDstToPage + 1, pointer, sizeBuffer - sizeBeWrite, uPagesToWrite);
                        if(VM_ERR_NO_ERROR != err)
                            return err;

                        sizeBeWrite = uPagesToWrite * sizeof(BYTE) * PAGE_SIZE;
                        sizeLeftToWrite -= sizeBeWrite;
                        pointer += sizeBeWrite;
                    }

                    //复制第三部分（可能没有）
                    if(sizeLeftToWrite > 0){
                        assert(sizeLeftToWrite <= sizeof(BYTE) * PAGE_SIZE);
                        if(sizeLeftToWrite > sizeof(BYTE) * PAGE_SIZE){//剩余字节大于一页，复制第二部分计算出错
                            VM_LOG();
                            return VM_ERR_FATAL_UNKNOWN;
                        }
                        if(NULL == MemPageTable[uDstToPage + 1 + uPagesToWrite].pPage){
                            err = MemPageAlloc(uDstToPage + 1 + uPagesToWrite);
                            if(VM_ERR_NO_ERROR != err){
                                return err;
                            }
                        }
                        memcpy((PBYTE)MemPageTable[uDstToPage + 1 + uPagesToWrite].pPage + uOffset, pointer, sizeLeftToWrite);
                    }
                }

                return VM_ERR_NO_ERROR;
        }
    }

    return VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
}

#ifdef  __cplusplus
}
#endif
