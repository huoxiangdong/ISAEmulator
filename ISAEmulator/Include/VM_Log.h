#ifndef _VM_LOG_H_
#define _VM_LOG_H_
//
//�ļ����ƣ�        Include/VM_Log.h
//�ļ�������        ģ������־���ģ��
//�����ˣ�          ��販(yanghongbo@ptwy.cn)
//�������ڣ�        2010��3��22��
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
//2010��3��22�գ���販(yanghongbo@ptwy.cn)������

#define VM_LOG()    
//#define VM_DEBUGLOG(args) VM_NormalLog(__FILE__, __LINE__, args)
#ifdef  __cplusplus
extern "C" {
#endif

int VM_NormalLog(char * format, ...);

void VM_ErrLog(VM_ERR_CODE vm_err);

#ifdef  __cplusplus
}
#endif

#endif//_VM_LOG_H_
