#ifndef _VM_ISA_RELATED_H_
#define _VM_ISA_RELATED_H_
//
//文件名称：        Include/VM_ISARelated.h
//文件描述：        模拟器与架构相关联的一些定义
//创建人：          杨鸿博(yanghongbo@ptwy.cn)
//创建日期：        2009年6月22日
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
//Update Log:
//更新日志：
//2009年6月24日，杨鸿博(yanghongbo@ptwy.cn)，创建


typedef struct _VM_CPUStructure_t {
    PVOID ISAPointer;  //由使用此指针的回调函数进行强制类型转换
    size_t PointerStructureSize;//之前union所使用指针指向的结构体的大小
}VM_CPUStructure_t, * PVM_CPUStructure_t;

#endif//_VM_ISA_RELATED_H_
