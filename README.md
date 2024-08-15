# detx
去除libtprt.so中的混淆, 去混淆思路看这两个贴子: 
* [使用BinaryNinja去除libtprt.so的混淆 (一)](https://bbs.kanxue.com/thread-282826.htm).  
* [使用BinaryNinja去除libtprt.so的混淆 (二)](https://bbs.kanxue.com/thread-282918.htm).  


## 1. 安装说明
### 1.1 安装依赖
打开BinaryNinja, 按下ctrl+p, 搜索Install python3 module..., 然后安装setuptools和unicorn  

### 1.2 安装插件
将本仓库的所有文件放到%APPDATA%\\Binary Ninja\\plugins\\detx中, 此时plugins文件夹内的结构应该是:  
```
.
├── binexport12_binaryninja.dll
└── detx
    ├── LICENSE
    ├── README.md
    ├── __init__.py
    ├── deflat2.py
    ├── dejmpreg.py
    ├── emulate.py
    └── plugin.json
```

## 2. 使用说明
### 2.1 去\[寄存器间接跳转\]混淆
>代码逻辑在dejmpreg.py中
1. 找到形如"br x9"的指令, 鼠标点击 -> 鼠标右键Plugins -> detx -> dejmpreg
2. auto就是自动去混淆, 会自动搜索一个函数内的所有jmpreg混淆, 然后依次去除
3. once就是只去除鼠标所在的那一处混淆
4. manual就是自己输入跳转表的偏移, 分析失败的时候调试用

### 2.2 去\[控制流平坦化\]混淆
>代码逻辑在deflat2.py中
1. 从mlil ssa层面找到循环分发开始的那个if (或者在汇编层面找到循环分发开始的那个cmp), 鼠标点击该if (汇编层面要点cmp的下一条指令) -> 鼠标右键Plugins -> detx -> deflat2
2. 'deflat use this var' 就是正常的去控制流平坦化混淆
3. 'deflat nested' 是去除嵌套的平坦化 需要手动输入出口地址
4. 'deflat with check' 会将分发块的后继块当作真实块 并且会记录初始的分发寄存器的值 每次循环开始时都会重新设置寄存器值 **推荐**使用这个方法
5. 'deflat manual' 就是手动设置switch变量的一个值 调试用
