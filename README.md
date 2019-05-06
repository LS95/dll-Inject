# dll-Inject
## 1.1  全局钩子注入

钩子机制  截获和监视系统中的消息 

钩子的分类:
1. 局部钩子 
    针对某个线程 


2. 全局钩子 
    作用于整个系统的基于消息的应用  全局钩子函数必须在一个DLL中 需要使用DLL文件  在DLL中实现相应的钩子函数  

SetWindowsHookEx  

第一个参数 idHook是钩子类型   WM_KEYBOARD 是按键消息   WM_KEYBOARD_LL 低级键盘输入事件  
第二个参数指定钩子回调函数 

第三个参数包含回调函数的DLL模块句柄   在函数中最后调用 return CallNextHookEx()

最后一个参数 dwThreadId == 0 表明钩子过程与系统中所有的线程相关联 

函数成功 则返回值是钩子过程的句柄  失败则返回NULL  

能够让DLL注入到所有的进程中   设置WM_GETMESSAGE消息的全局钩子   
每一个进程都有自己的一个消息队列  都会加载WH_GETMESSAGE类型的全局DLL  


卸载钩子 

UnhookWindowsHookEx(g_hHook);

### 共享内存 

突破进程独立性 多个进程共享同一段内存   

在DLL中创建一个变量，将DLL加载到多个进程空间，一个进程进行了修改，其他DLL值也发生改变  
相当于多个进程共享一个内存。 

共享内存具体设置方法
```
#pragma data_seg("mydata")
    HHOOK g_Hook = NULL;
#pragme data_seg()
#pragme comment(linker,"/SECTION:mydata,RWS/")

```


user32.dll 导出的gShareInfo全局变量可以枚举系统中所有全局钩子的信息   
PE结构中的 Characteristics 包括IMAGE_SCN_MEM_SHARED 标致  则代表在内存中是共享的。

## 1.2  远程线程注入 

一个进程在另一个进程空间中创建线程 

程序加载DLL时  通过调用LoadLibrary函数来实现DLL的动态加载 

1. 获取目标进程LoadLibrary函数地址
2. 向目标空间中写入 dll路径的字符串

kernel32.dll 加载基址在每个进程中相同 导出函数地址也相同   

流程

    OpenProcess  打开待注入的进程执行成功 返回指定进程的打开句柄  失败返回NULL 
    VirtualAllocEx  指定进程虚拟地址空间保留 提交 更改内存状态  分配内存      成功返回分配页面的基址  
    WriteProcessMemory 数据写入内存区域  成功则返回值不为0  
    CreateRemoteThread 创建运行的线程    成功则返回新线程的句柄  
    
    
    HANDLE hRemoteThread = ::CreateRemoteThread(
		hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)pFuncProcAddrs,  // LoadLibray函数地址
		pDllAddr,                                // DLL完整路径 
		0,
		NULL);
    
此方法无法突破Session 0 隔离  不能向系统服务进行注入~

附加的提权函数:  

```
OpenProcessToken  
LookupPrivilegeValue  
AdjustTokenPrivileges

```


## 1.3  突破SESSION 0 隔离的远程线程注入

更底层的函数 ZwCreateThreadEx 在 ntdll.dll中获取函数的导出地址  
直接调用 ZwCreateThreadEx 函数可以进行突破注入   第七个参数 CreateSuspended 置为0    那么线程创建完成后就会恢复运行  实现注入


注意 ZwCreateThreadEx在32位和64位系统下 其函数声明中参数是有区别的

实验测试 注入smss.exe 直接蓝屏掉 

书上介绍 可以注入svchost.exe 

由于会话隔离  系统服务程序中不能显示程序窗体  

为了解决服务层和用户层交互的问题  微软提供了一系列 以WTS Windows Terminal Service 开头的函数来实现这些功能 

## 1.4 APC 注入  

Asynchronous Procedure CALL 异步过程调用   函数在特定线程中被异步执行  

APC是一种并发机制 用于异步IO或者计时器 


每个线程都拥有自己的APC序列  QueueUserAPC函数 将APC函数压入队列  调用的顺序为FIFO  先入先出 

QueueUserAPC函数 将用户模式中的异步过程调用APC对象直接添加到指定线程APC队列中 

当线程处于可警告状态时才会执行APC函数   

一个线程在内部使用 SignalObjectAndWait  SleepEx  WaitForSingleObjectEx  WaitForMultipleObjectsEx等函数把自己挂起时就是可警告状态  此时便会执行APC队列函数  

QueryUserAPC 第一个参数设为LoadLibrary的地址 第三个参数设为DLL路径 则执行APC时就会完成注入  
```
QueueUserAPC((PAPCFUNC)pLoadLibraryAFunc,
					hThread,
					(ULONG_PTR)pBaseAddress)
```
为了确保执行插入的APC  应该向目标进程的所有线程插入相同的APC  则需要遍历线程操作 
具体流程

    1. OpenProcess 打开目标进程 获取句柄
    2. CreateToolhelp32Snapshot 遍历线程 获取目标所有线程ID
    3. VirtualAllocEx  申请空间
    4. WriteProcessMemory 写入路径
    5. 遍历线程ID OpenThread 获取线程句柄
    6. QueueUserAPC 向线程插入APC函数 
    7. 只要唤醒目标进程的任意线程 执行APC 完成DLL注入 
    
## ref
WINDOWS黑客编程技术详解-配套代码 