#ifndef _COMMON_H_
#define _COMMON_H_
//
//�ļ����ƣ�        Include/ISA/Intel_x86/common.h
//�ļ�������        ��ָ�������ص�һЩͨ�ú���
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2009��8��4��
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
//2009��8��4�գ���販(yanghongbo@ptwy.cn)������


typedef enum _REGISTER_TYPE {
    GENERAL_REGISTER,
    MM_REGISTER,
    XMM_REGISTER,
    SEGMENT_REGISTER,
}REGISTER_TYPE;

VM_ERR_CODE SetMemoryValue(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uEffectiveAddress, UINT uValue, DWORD dwFlags, DWORD dwPrefixes);
UINT    GetMemoryValue(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uEffectiveAddress, DWORD dwFlags, DWORD dwPrefixes);
VM_INSTRUCTION_ERR_CODE SetRegisterValue(PVM_Intel_x86_ISA_t pX86, UINT uIndex, UINT uValue, REGISTER_TYPE Type, DWORD dwFlags, DWORD dwPrefixes);
UINT GetRegisterValue(PVM_Intel_x86_ISA_t pX86, UINT uIndex, REGISTER_TYPE Type, DWORD dwFlags, DWORD dwPrefixes);
VM_INSTRUCTION_ERR_CODE GetEffectiveAddress(PVM_Intel_x86_ISA_t pX86, PVM_Intel_x86_InstructionData_t pInstruction, UINT * puEA);
DWORD GetDataType(DWORD dwFlags, Intel_x86_Operand_Size_t OpSize, DWORD dwPrefixes);
void PushStack(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory,UINT uValue , Intel_x86_Operand_Size_t emuOperandSize);
UINT PopStack(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, Intel_x86_Operand_Size_t emuOperandSize);
UINT GetStackElement(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uStackAddress ,Intel_x86_Operand_Size_t emuOperandSize);
void SetStackElement(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, UINT uStackAddress, UINT uValue, Intel_x86_Operand_Size_t emuOperandSize);

#endif //_COMMON_H_
