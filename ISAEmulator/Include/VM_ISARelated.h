#ifndef _VM_ISA_RELATED_H_
#define _VM_ISA_RELATED_H_
//
//�ļ����ƣ�        Include/VM_ISARelated.h
//�ļ�������        ģ������ܹ��������һЩ����
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2009��6��22��
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
//2009��6��24�գ���販(yanghongbo@ptwy.cn)������


typedef struct _VM_CPUStructure_t {
    PVOID ISAPointer;  //��ʹ�ô�ָ��Ļص���������ǿ������ת��
    size_t PointerStructureSize;//֮ǰunion��ʹ��ָ��ָ��Ľṹ��Ĵ�С
}VM_CPUStructure_t, * PVM_CPUStructure_t;

#endif//_VM_ISA_RELATED_H_
