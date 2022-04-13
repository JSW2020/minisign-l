# minisign-l
在@[jedisct1](https://github.com/jedisct1/minisign)设计的签名工具minisign基础上新增SM2算法的签名功能
提供windows和linux两个版本
其中windows使用vs2017编译，64位；linux参照命令 cmake&make&sudo make install 可安装
其中需要[libsodium]库(https://doc.libsodium.org/)，集成了Ed25519算法，windows下可参照[文章](https://blog.csdn.net/wangmumutwo/article/details/88927246)配置，linux安装官方提供方式配置即可；
以及[miracl]库(https://github.com/miracl/MIRACL),用于实现sm2算法，windows可参照[文章](https://blog.csdn.net/a344288106/article/details/80094878)配置
