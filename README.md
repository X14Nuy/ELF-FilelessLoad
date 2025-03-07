# ELF-FilelessLoad
实现了arm、x86架构的远程加载（虽然还有很多bug）

在项目https://github.com/MikhailProg/elf/tree/master的基础上进行修改。

# 构建

```bash
make ARCH=i386
```

![image-20250307110542235](./README.assets/image-20250307110542235.png)

如果要构建arm版本，需要有arm-linux-gnueabi-gcc及相关库。

# 使用方法

![image-20250307145845544](./README.assets/image-20250307145845544.png)

![image-20250307145850551](./README.assets/image-20250307145850551.png)
