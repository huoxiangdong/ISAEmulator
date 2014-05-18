#ifndef _VM_LOG_H_
#define _VM_LOG_H_
//
//文件名称：        Include/VM_Log.h
//文件描述：        模拟器日志输出模块
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
//Update Log:
//更新日志：
//2010年3月22日，杨鸿博(yanghongbo@ptwy.cn)，创建

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
