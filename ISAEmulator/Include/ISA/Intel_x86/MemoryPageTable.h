#ifndef _MEMORY_PAGE_TABLE_H_
#define _MEMORY_PAGE_TABLE_H_
//
//�ļ����ƣ�        Include/ISA/Intel_x86/VM_MemoryPageTable.h
//�ļ�������        Intel x86�ܹ��µ��ڴ�ҳ��ʵ��
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2010��3��16��
//
//��˾���ƣ�        �������������Ƽ����޹�˾
//��Ŀ������
//���ܼ���
//��Ȩ������
//
//����Ŀ���ƣ�      �����������©���ھ�ƽ̨
//����Ŀ������
//����Ŀ����ʱ�䣺  2009��6��X��
//
//����Ŀ���ƣ�      �����������������
//����Ŀ������
//����Ŀ����ʱ�䣺  2009��6��X��
//
//ģ�����ƣ�        ָ�������
//����Ŀ������
//����Ŀ����ʱ�䣺  2009��6��X��

//
//������־��
//2010��3��16�գ���販(yanghongbo@ptwy.cn)������
//2010��3��18�գ���販(yanghongbo@ptwy.cn)������
//2010��3��22�գ���販(yanghongbo@ptwy.cn)��������ҳ/�����ڴ渴�ƴ���

#define PAGE_INDEX_BIT                          19
#define PAGE_SIZE_BIT			                12
#define PAGE_COUNT                              (1 << PAGE_INDEX_BIT)
#define PAGE_SIZE				                (1 << PAGE_SIZE_BIT)        //4096  //4k
#define PAGE_SIZE_MASK_BIT  	                (PAGE_SIZE - 1)   //0x00000fff	//4095
#define PAGE_MAXIMUM_ADDRESS                    ((UINT)(1 << (PAGE_INDEX_BIT + PAGE_SIZE_BIT))  - 1)
#define PAGE_MAXIMUM_SIZE                       (PAGE_MAXIMUM_ADDRESS + 1)
#define PAGE_OFFSET_MASK(addr)	                ((addr)&(PAGE_SIZE_MASK_BIT))
#define PAGE_INDEX_MASK(addr)                   (((addr)&(~PAGE_SIZE_MASK_BIT)) >> PAGE_SIZE_BIT)
#define PAGE_ADDRESS_DWORD_ALIGNMENT_MASK(addr)  ((addr) & 0x3) //��ַ�ֶ���
#define PAGE_ADDRESS_WORD_ALIGNMENT_MASK(addr) (((addr) & 0x1)) //��ַ˫�ֶ���
#define IS_PAGE_ADDRESS_WORD_ALIGNED(addr)      (!PAGE_ADDRESS_WORD_ALIGNMENT_MASK(addr))
#define IS_PAGE_ADDRESS_DWORD_ALIGNED(addr)     (!PAGE_ADDRESS_DWORD_ALIGNMENT_MASK(addr))

#define PAGE_OFFSET_TO_ADDRESS(page, offset)    ((((page) & (PAGE_COUNT - 1)) << PAGE_SIZE_BIT ) | ((offset) & PAGE_SIZE_MASK_BIT))

//��Ŀ���ַδ��ʼ��ʱ���ص����ݡ�0xcc == int 13, 'NL' -> Not initialized
#define UNINITIALIZED_BYTE             'N'//0xcc
#define UNINITIALIZED_WORD             'NI'//0xcccc
#define UNINITIALIZED_DWORD            'NINI'//0xcccccccc

//���ƣ�MEMORY_PAGE
//�������ڴ�ҳ������
//		PVOID   pPage;ҳ�ڴ�ָ��
//		INT     nAccessCount;���ʼ���
//������־��2010��3��16�գ���販(yanghongbo@ptwy.cn)������
//
typedef struct _MEMORY_PAGE {
	PVOID	pPage;
	INT		nAccessCount;
}MEMORY_PAGE, * PMEMORY_PAGE;

//�������ƣ�MemInitialize
//����ֵ���ͣ�void
//������void
//��������ʼ��
//������־��2010��3��19�գ���販(yanghongbo@ptwy.cn)������
//
void MemPageInitialize();

//�������ƣ�MemUninitialize
//����ֵ���ͣ�void
//������void
//�������ͷ���Դ
//������־��2010��3��19�գ���販(yanghongbo@ptwy.cn)������
//
void MemPageUninitialize();


//�������ƣ�MemPageReadByte
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uPage, UINT uOffset, PBYTE pData
//���������ڴ�ҳ�ж�ȡһ���ֽ�
//������־��2010��3��18�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemPageReadByte(UINT uPage, UINT uOffset, PBYTE pbyData);

//�������ƣ�MemPageWriteByte
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uPage, UINT uOffset, BYTE data
//���������ڴ�ҳ��д��һ���ֽ�
//������־��2010��3��18�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemPageWriteByte(UINT uPage, UINT uOffset, BYTE byData);

//�������ƣ�MemPageReadWord
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uPage, UINT uOffset, PWORD pData
//���������ڴ�ҳ�ж�ȡһ���֣�˫�ֽڣ�
//������־��2010��3��18�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemPageReadWord(UINT uPage, UINT uOffset, PWORD pwData);

//�������ƣ�MemPageWriteWord
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uPage, UINT uOffset, WORD data
//���������ڴ�ҳ��д��һ���֣�˫�ֽڣ�
//������־��2010��3��18�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemPageWriteWord(UINT uPage, UINT uOffset, WORD wData);

//�������ƣ�MemPageReadDWord
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uPage, UINT uOffset, PDWORD pData
//���������ڴ�ҳ�ж�ȡһ��˫�֣����ֽڣ�
//������־��2010��3��18�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemPageReadDWord(UINT uPage, UINT uOffset, PDWORD pdwData);

//�������ƣ�MemPageWriteDWord
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uPage, UINT uOffset, BYTE data
//���������ڴ�ҳ��д��һ��˫�֣����ֽڣ�
//������־��2010��3��18�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemPageWriteDWord(UINT uPage, UINT uOffset, DWORD dwData);
/*
//�������ƣ�MemPageCopyPages
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uDstToPage, UINT uSrcFromPage, UINT uPageNum
//�������������ڴ��и����������ڴ�ҳ����ҳ���ƣ�
//������־��2010��3��22�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemPageCopyPages(UINT uDstToPage, UINT uSrcFromPage, UINT uPageNum);
VM_ERR_CODE MemPageCopy(UINT uDstPage, UINT uDstOffset, UINT uSrcPage, UINT uSrcOffset, size_t sizeToCopy);
*/
//�������ƣ�MemPageCopyPagesToVMBuffer
//����ֵ���ͣ�VM_ERR_CODE
//������PVOID pBuffer, size_t sizeBuffer, UINT uSrcFromPage, UINT uPageNum
//�����������⻷����ҳ���׵�ַΪҳ��ʼ��ַ����ҳ���룩���ݸ��Ƶ�������
//������־��2010��3��22�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemPageCopyPagesToVMBuffer(PVOID pBuffer, size_t sizeBuffer, UINT uSrcFromPage, UINT uPageNum);

//�������ƣ�MemPageCopyPagesToVMBuffer
//����ֵ���ͣ�VM_ERR_CODE
//������PVOID pBuffer, size_t sizeBuffer, UINT uSrcFromPage, UINT uPageNum
//�����������������Ƶ����⻷������ҳ�ڴ��У��׵�ַΪҳ��ʼ��ַ����ҳ���룩
//������־��2010��3��22�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemPageCopyPagesFromVMBuffer(UINT uDstToPage, PVOID pBuffer, size_t sizeBuffer, UINT uPageNum);

//�������ƣ�MemPageCopyToVMBuffer
//����ֵ���ͣ�VM_ERR_CODE
//������PVOID pBuffer, size_t sizeBuffer, UINT uSrcFromPage, UINT uOffset, size_t sizeBytesToRead
//�����������⻷���ڴ��У�����Ҫҳ���룩���Ƶ�������
//������־��2010��3��22�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemPageCopyToVMBuffer(PVOID pBuffer, size_t sizeBuffer, UINT uSrcFromPage, UINT uOffset, size_t sizeBytesToRead);

//�������ƣ�MemPageCopyFromVMBuffer
//����ֵ���ͣ�VM_ERR_CODE
//������UINT uDstToPage, UINT uOffset, PVOID pBuffer, size_t sizeBuffer, size_t sizeBytesToWrite
//�����������������Ƶ����⻷���ڴ��У�����Ҫҳ���룩
//������־��2010��3��22�գ���販(yanghongbo@ptwy.cn)������
//
VM_ERR_CODE MemPageCopyFromVMBuffer(UINT uDstToPage, UINT uOffset, PVOID pBuffer, size_t sizeBuffer, size_t sizeBytesToWrite);

#endif