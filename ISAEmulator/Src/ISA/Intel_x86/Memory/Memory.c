//
//文件名称：        src/ISA/Intel_x86/Memory/Memory.c
//文件描述：        Intel x86架构下的内存模块
//创建人：          杨鸿博(yanghongbo@ptwy.cn)
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

#include "VM_Defines.h"
#include "ISA/Intel_x86/MemoryPageTable.h"
#include "ISA/Intel_x86/Memory.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define _CRT_SECURE_NO_DEPRECATE 1

void MemInitialize()
{
    MemPageInitialize();
}

void MemUninitialize()
{
    MemPageUninitialize();
}

VM_ERR_CODE MemReadWord(UINT uAddr, PWORD pwData)
{
    VM_ERR_CODE err = VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
    WORD wData = 0;
    BYTE byData = 0;
    assert(pwData);
    if(IS_PAGE_ADDRESS_WORD_ALIGNED(uAddr) || (PAGE_OFFSET_MASK(uAddr) < PAGE_SIZE)){
        //双字节未对齐，或者产生跨页访问
        err = MemReadByte(uAddr, &byData);
        if(VM_ERR_NO_ERROR == err){
            wData = byData;
            err = MemReadByte(uAddr+1, &byData);
            if(VM_ERR_NO_ERROR == err){
                wData |= byData << 8;
                *pwData = wData;
            }
        }
    }
    else {
        //地址字节对齐
        err = MemPageReadWord(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), pwData);
    }

    return err;
}



VM_ERR_CODE MemWriteWord(UINT uAddr, WORD wData)
{
    VM_ERR_CODE err = VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
    BYTE byData = 0;
    if(IS_PAGE_ADDRESS_WORD_ALIGNED(uAddr) || (PAGE_OFFSET_MASK(uAddr) < PAGE_SIZE)){
        //双字节未对齐，或者产生跨页访问
        err = MemWriteByte(uAddr, (BYTE)(wData & 0xff));
        if(VM_ERR_NO_ERROR == err){
            err = MemWriteByte(uAddr+1, (BYTE)(wData >> 8));
        }
    }
    else {
        //地址字节对齐
        err = MemPageWriteWord(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), wData);
    }
    return err;
}



VM_ERR_CODE MemReadDWord(UINT uAddr, PDWORD pdwData)
{
    VM_ERR_CODE err = VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;
    DWORD dwData = 0;
    WORD wData = 0;
    BYTE byData = 0;

    assert(pdwData);
    if(IS_PAGE_ADDRESS_DWORD_ALIGNED(uAddr)){
        //地址字节对齐
        err = MemPageReadDWord(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), pdwData);
    }
    else if(IS_PAGE_ADDRESS_WORD_ALIGNED(uAddr)){
        //双字节未对齐
        err = MemPageReadWord(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), &wData);
        if(VM_ERR_NO_ERROR == err){//读第一个字
            dwData = wData;
            err = MemPageReadWord(PAGE_INDEX_MASK(uAddr+2), PAGE_OFFSET_MASK(uAddr+2), &wData);//有可能产生跨页访问
            if(VM_ERR_NO_ERROR == err){//读第二个字
                dwData |= (DWORD)wData << 16;
                *pdwData = dwData;
            }
        }
    }
    else {
        err = MemReadByte(uAddr, &byData);
        if(VM_ERR_NO_ERROR == err){//读第一个字节
            dwData = byData;
            err = MemReadWord(uAddr+1, &wData);//这里处理跨页访问
            if(VM_ERR_NO_ERROR == err){//读第二、三个字节
                dwData |= (DWORD)wData << 8;
                err = MemReadByte(uAddr+3, &byData);
                if(VM_ERR_NO_ERROR == err){//读第四个字节
                    dwData |= (DWORD)byData << 24;
                    *pdwData = dwData;
                }
            }
        }
    }

    return err;
}



VM_ERR_CODE MemWriteDWord(UINT uAddr, DWORD dwData)
{
    VM_ERR_CODE err = VM_ERR_FATAL_MEMORY_ACCESS_VIOLATION;

    if(IS_PAGE_ADDRESS_DWORD_ALIGNED(uAddr)){
        //双字对齐
        err = MemPageWriteDWord(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), dwData);
    }
    else if(IS_PAGE_ADDRESS_WORD_ALIGNED(uAddr)){
        //字对齐
        err = MemPageWriteWord(PAGE_INDEX_MASK(uAddr), PAGE_OFFSET_MASK(uAddr), (WORD)(dwData & 0xffff));
        if(VM_ERR_NO_ERROR == err){
            err = MemPageWriteWord(PAGE_INDEX_MASK(uAddr+2), PAGE_OFFSET_MASK(uAddr+2), (WORD)(dwData >> 16));
        }
    }
    else {
        //未对齐
        err = MemWriteByte(uAddr, (BYTE)(dwData & 0xff));
        if(VM_ERR_NO_ERROR == err){
            err = MemWriteWord(uAddr+1, (WORD)(((dwData >> 8) & 0xffff)));//这里处理跨页访问
            if(VM_ERR_NO_ERROR == err){
                err = MemWriteByte(uAddr, (BYTE)(dwData & 0xff));
            }
        }
    }
    return err;
}

/*
VM_ERR_CODE MemCopy(UINT srcAddr, UINT dstAddr)
{
    
}
*/

//上层仍需要一级系统环境级(Windows/Linux)的包装
VM_ERR_CODE MemCopyToVMBuffer(PVOID pBuffer, size_t sizeBuffer, UINT uSrcAddr, size_t sizeToRead)
{
    return MemPageCopyToVMBuffer(pBuffer, sizeBuffer, PAGE_INDEX_MASK(uSrcAddr), PAGE_OFFSET_MASK(uSrcAddr), sizeToRead);
}

VM_ERR_CODE MemCopyFromVMBuffer(UINT uDstAddr, size_t sizeBuffer, PVOID pBuffer, size_t sizeToWrite)
{
    return MemPageCopyFromVMBuffer(PAGE_INDEX_MASK(uDstAddr), PAGE_OFFSET_MASK(uDstAddr), pBuffer, sizeBuffer, sizeToWrite);
}

#ifdef  __cplusplus
}
#endif
