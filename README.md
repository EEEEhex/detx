# detx
去除libtprt.so中的混淆, 去混淆思路看这个贴子[使用BinaryNinja去除libtprt.so的混淆](https://bbs.kanxue.com/thread-282826.htm).  

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
有BUG, 一个函数内有多个平坦化(比如平坦化嵌套或者平行)就不行了, 还在改  
