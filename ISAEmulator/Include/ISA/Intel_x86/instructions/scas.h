#ifndef _SCAS_H_
#define _SCAS_H_
//
//�ļ����ƣ�        Include/ISA/Intel_x86/Instructions/scas.h
//�ļ�������        scasָ��ͷ�ļ�
//�����ˣ�          ����(laosheng@ptwy.cn)
//�������ڣ�        2009��8��14��
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
//2009��8��14�գ�����(laosheng@ptwy.cn)������


VM_INSTRUCTION_ERR_CODE scas_ae(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);
VM_INSTRUCTION_ERR_CODE scas_af(PVM_Intel_x86_ISA_t pX86, PVM_Memory_t pMemory, PVM_Intel_x86_InstructionData_t pInstruction);

#endif //_SCAS_H_