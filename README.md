# shellcode-factory
> shellcode 生成框架

# shellcode特点
> 位置无关，在执行或注入前无需进行任何额外的处理。

> 简洁小巧，可以轻松的在不同的功能中实现通用的功能。

# 使用方法

> 编译`shellcode-payload.lib`

> 编译`shellcode-generator.exe`

进入它们所在的文件夹，执行shellcode-generator.exe(链接生成器)

你将得到:shellcode-generator.bin与payload.hpp

接下来你 可以直接编译运行shellcode-actuator.exe(执行器)来验证shellcode是否可用

我们主要讲payload.hpp

namespace shellcode 下的 const unsigned char payload [] 是shellcode的字节码

namespace rva 下 记录了你使用SC_EXPORT导出的shellcode入口，其调用规则与你的函数定义一致，由于shellcode注入在多数场景下都是远程线程注入

所以我的payload例子中入口函数使用的是 DWORD(LPVOID)

# 起因与经过
21年中旬朋友在windows的dwm进程中发现一段异常执行的 "恶意代码"
在使用ida进行简单分析后得出结论:“该代码在dwm中 hook 相关渲染函数，恶意截取用户桌面画面”，这段代码的来源指向了一款曾在2017年爆火网络的多人射击游戏，猜测目的为“截取用户游戏画面以判断用户是否在作弊”。
该shellcode引起了我的兴趣，它大概有如下特点：

在该shellcode中，存在一些只会被链接进exe的清单文件
我猜测，该shellcode的开发者先使用编译器编译并链接了一个不带crt的exe
之后对该exe进行加壳，最后使用exe to shellcode类的工具生成该代码。

# 反思
类似该shellcode的生成过程似乎不是很可靠(将无意义的清单文件留存在shellcode中显得不是很专业)，好奇心驱使下，我搜寻了windows 下 生成 shellcode方法,结果不如人意，有的人使用dll to shellcode框架或工具
有的人直接在c++代码中写下两个标记函数，并提取中间的函数 
典型的如论坛曾出现过的帖子:

[Cobalt Strike 生成 shellcode](https://bbs.pediy.com/thread-271048.htm)

[MSVC 配合 Get-PEHeader生成shellcode](https://zeronohacker.com/1544.html)

[Win PE系列之导出表解析与ShellCode的编写及应用](https://bbs.pediy.com/thread-269753.htm)

[基于C++的shellcode框架](https://bbs.pediy.com/thread-268639.htm)

如何能够既方便，并且稳定的生成shellcode呢?
以上工具或多或少存在无法避免的问题:
比如pe文件中的冗余数据
比如va定位提取无法将代码写在多个cpp文件中，并受限于编译器优化策略，有时需要提取的函数并不在“标记函数”之间
再比如无法利用编译器对代码进行优化以减小代码大小

# 原理
该框架的核心是一个shellcode 链接器，我们将需要生成的shellcode编译为lib，shellcode-generator(链接器)可以将lib解析为多个obj文件，并从中提取原始的字节码，最后进行重定位生成.bin文件和.hpp文件

# 部分代码

在payload的项目中，你可以导出多个入口函数，使用SC_EXPORT标记
只有SC_EXPORT标记的函数和该函数的依赖函数才会被链接为shellcode
换句话说:"你没有使用过的函数，不会被链接",但你无需为“&Xxx函数”所担心，shellcode的代码可以完全按照c++语言标准写，在开启c++17后，你还可以使用xorstr 对静态字符串进行混淆。payload支持全局和静态变量。
# 2 你无法使用什么:
#### windows api(系统函数) 
你需要借助[lazy_importer](https://github.com/JustasMasiulis/lazy_importer)
在例子中我展示了用法，所有的系统api都需要使用lazy_importer，来自std的函数也需要 lazy_importer，但是memset与memcpy我已经写在了crt.cpp中，所以这两个函数无需使用 lazy_importer 

#### Tls线程局部储存关键字__declspec(thread)(如果你不知道这是什么请忽略)，但是你可以使用windows api(TlsAlloc TlsSetValue TlsGetValue)来使用Tls线程局部储存。
#### C++异常(请忽略)
#### SDL检查(请忽略)
#### 基本运行时检查(请忽略)

# 3 你可以使用什么:
C++几乎所有语法，函数模板，当你重载std的内存分配后，你可以使用几乎所有测std内容。你可以在多个cpp文件中定义你的函数。


# 缺陷:
该框架只支持 X64 原因是目前没有好办法解决x86下的.data数据重定位问题，在x86下.data数据重定位类型为IMAGE_REL_I386_DIR32，意为"RVA 绝对虚拟地址"
单假如你不在代码中使用静态字符串或者全局变量，你仍旧可以使用x86编译 payload.lib，并用 x86 shellcode-generator.exe生成相应的代码

如果有看雪网友了解 IMAGE_REL_I386_DIR32 和其中的细节，欢迎在帖子后面评论补充。
# Todo:
修改api导入策略，摆脱lazy_importer，实现可以在payload中直接使用api函数和crt函数的方法。

实现链接时混淆和虚拟化，这样我们可以将shellcode-generator(链接生成器)作为服务器功能，将payload.lib储存于服务器，每次执行shellcode获取都会生成完全不同的代码。（这个比较困难）
# 当你熟悉本框架后，你可根据你的技术进行魔改，欢迎分享在评论区。
# 在几周后，我将模仿上面曾提到的“dwm截图shellcode”编写代码，以期实现相同的效果，从事反作弊开发的看雪网友可以将代码作为自己反作弊系统的一部分，以补充反作弊效能。
