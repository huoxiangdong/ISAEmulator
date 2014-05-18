#ifndef _VM_EMULATOR_H_
#define _VM_EMULATOR_H_
//
//�ļ����ƣ�        Include/VM_Emulator.h
//�ļ�������        ģ������ؽṹ���뺯������
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2009��6��5��
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
//Update Log:
//������־��
//2009��6��5�գ���販(yanghongbo@ptwy.cn)������

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

//���ƣ�VM_Emulator_t
//������
//������־��2009��6��5�գ���販(yanghongbo@ptwy.cn)������
//          2009��6��16�գ���販(yanghongbo@ptwy.cn)������ṹ
typedef struct _VM_Emulator_t {
    VM_EMULATOR_STATUS Status;
    VM_CPUStructure_t CPUStructure;
    VM_Memory_t Memory;//����Ӧ�û�������ṹ
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
