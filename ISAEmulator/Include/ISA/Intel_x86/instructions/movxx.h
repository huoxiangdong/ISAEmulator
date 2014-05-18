#ifndef _MOVXX_H_
#define _MOVXX_H_
//
//�ļ����ƣ�        Include/ISA/Intel_x86/Instructions/movxx.h
//�ļ�������        movzx/movsxָ��ͷ�ļ�
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2010��4��8��
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
//2010��4��8�գ���販(yanghongbo@ptwy.cn)������

VM_INSTRUCTION_ERR_CODE movzx_0F_B6(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);
VM_INSTRUCTION_ERR_CODE movzx_0F_B7(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);

VM_INSTRUCTION_ERR_CODE movsx_0F_BE(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);
VM_INSTRUCTION_ERR_CODE movsx_0F_BF(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);


#endif //_MOVXX_H_