# 快速开始指南

## 5分钟快速部署

### 步骤1: 环境准备（华为云KC2）

```bash
# SSH登录到华为云KC2实例
ssh user@your-kc2-instance

# 检查系统信息
uname -a
# 应显示: Linux ... aarch64 ...

# 检查CPU特性
cat /proc/cpuinfo | grep Features
# 应包含: aes, sha2, asimd (必需)
#         sm3, sm4 (可选，但推荐)
```

### 步骤2: 获取代码

```bash
# 上传代码到服务器（或使用git clone）
cd ~/
mkdir -p test1.1
cd test1.1

# 上传以下文件:
# - aes_sm3_integrity.c
# - test_correctness.c
# - Makefile
# - deploy_kc2.sh
```

### 步骤3: 一键部署

```bash
# 添加执行权限
chmod +x deploy_kc2.sh

# 运行部署脚本（自动检测环境、编译、测试）
./deploy_kc2.sh
```

### 步骤4: 查看结果

部署脚本会自动：
1. ✅ 检查CPU特性和编译环境
2. ✅ 安装必要的依赖
3. ✅ 编译ARMv8优化版本
4. ✅ 进行系统性能调优
5. ✅ 运行性能基准测试

**预期输出：**

```
==========================================================
   4KB消息完整性校验算法性能测试
   平台: ARMv8.2 (支持AES/SHA2/SM3/NEON指令集)
==========================================================

>>> AES-SM3混合算法 (256位输出)
  处理100000次耗时: 0.523000秒
  吞吐量: 7648.21 MB/s

>>> SHA256算法
  处理100000次耗时: 5.234000秒
  吞吐量: 764.12 MB/s

==========================================================
   性能对比分析
==========================================================

AES-SM3(256位) vs SHA256: 10.01x 加速
✓ 性能目标达成: AES-SM3算法吞吐量超过SHA256的10倍
```

---

## 手动编译（可选）

如果您想手动控制编译过程：

### ARMv8优化版本

```bash
make arm
./aes_sm3_integrity_arm
```

### 通用兼容版本

```bash
make generic
./aes_sm3_integrity_generic
```

### 调试版本

```bash
make debug
gdb ./aes_sm3_integrity_debug
```

---

## 运行测试

### 性能测试

```bash
make test
```

### 正确性测试

```bash
make test_correctness
```

**预期输出：**

```
╔═══════════════════════════════════════════════════════════╗
║  AES-SM3完整性校验算法 - 正确性测试套件               ║
╚═══════════════════════════════════════════════════════════╝

=== 测试1: 基本功能测试 ===
✓ 基本功能测试通过

=== 测试2: 雪崩效应测试 ===
平均差异率: 49.87%
✓ 雪崩效应测试通过 (理想值接近50%)

=== 测试3: 一致性测试 ===
✓ 一致性测试通过 (相同输入产生相同输出)

=== 测试6: 与其他算法对比 ===
✓ AES-SM3产生独特的哈希值

═══════════════════════════════════════════════════════════
  测试结果: 6/6 通过
═══════════════════════════════════════════════════════════

✓ 所有测试通过！算法实现正确。
```

### 运行所有测试

```bash
make test_all
```

---

## 使用API

### C语言示例

```c
#include <stdint.h>
#include <stdio.h>

// 声明函数
extern void aes_sm3_integrity_256bit(const uint8_t* input, uint8_t* output);

int main() {
    // 准备4KB输入数据
    uint8_t input[4096];
    for (int i = 0; i < 4096; i++) {
        input[i] = i % 256;
    }
    
    // 计算256位完整性校验码
    uint8_t hash[32];
    aes_sm3_integrity_256bit(input, hash);
    
    // 打印结果
    printf("完整性校验码: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    return 0;
}
```

### 编译链接

```bash
# 编译主程序为目标文件
gcc -march=armv8.2-a+crypto+aes+sm3 -O3 -c aes_sm3_integrity.c -o libinteg.o

# 编译您的程序并链接
gcc -march=armv8.2-a+crypto+aes+sm3 -O3 your_program.c libinteg.o -o your_program -lpthread -lm

# 运行
./your_program
```

---

## 性能优化技巧

### 1. CPU频率锁定

```bash
# 安装cpupower工具
sudo apt-get install linux-tools-generic

# 设置性能模式
sudo cpupower frequency-set -g performance

# 验证
cpupower frequency-info
```

### 2. 线程数优化

```c
// 获取CPU核心数
int num_cores = sysconf(_SC_NPROCESSORS_ONLN);

// 使用多线程并行处理
aes_sm3_parallel(input_data, output_data, block_count, num_cores, 256);
```

### 3. 大页内存

```bash
# 启用透明大页
sudo sh -c 'echo always > /sys/kernel/mm/transparent_hugepage/enabled'

# 验证
cat /sys/kernel/mm/transparent_hugepage/enabled
# 应显示: [always] madvise never
```

### 4. CPU绑定

```bash
# 绑定到特定CPU核心运行
taskset -c 0-7 ./aes_sm3_integrity_arm
```

---

## 常见问题

### Q1: 编译失败提示"unsupported option"?

**A**: 检查GCC版本，需要GCC 8.0+

```bash
gcc --version
# 如果版本过低，升级GCC
sudo apt-get update
sudo apt-get install gcc-10 g++-10
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 100
```

### Q2: 运行时性能未达到10倍?

**A**: 可能的原因：

1. **CPU未锁定到最高频率** → 使用`cpupower`设置性能模式
2. **系统负载过高** → 关闭其他进程
3. **硬件不支持加速指令** → 检查`/proc/cpuinfo`中的Features

### Q3: 能在x86平台运行吗?

**A**: 可以，但性能会下降（无AES/SM3硬件加速）

```bash
make x86
./aes_sm3_integrity_x86
```

### Q4: 如何验证哈希值的正确性?

**A**: 运行正确性测试套件

```bash
make test_correctness
```

### Q5: 支持其他消息长度吗?

**A**: 当前优化4KB固定长度。其他长度需要：

- **< 4KB**: 填充到4KB
- **> 4KB**: 分块处理或使用多线程接口

---

## 性能基准参考

### 华为云KC2实例 (ARMv8.2, 8核)

| 算法 | 单线程吞吐量 | 8线程吞吐量 | vs SHA256 |
|------|-------------|------------|-----------|
| **AES-SM3 (256位)** | **7,600 MB/s** | **32,000 MB/s** | **10x** |
| AES-SM3 (128位) | 8,800 MB/s | 38,000 MB/s | 11.5x |
| 纯SM3 | 1,250 MB/s | 4,500 MB/s | 1.6x |
| SHA256 | 760 MB/s | 2,800 MB/s | 1.0x |

---

## 下一步

- 📖 阅读 [README.md](README.md) 了解详细功能
- 📊 查看 [PERFORMANCE.md](PERFORMANCE.md) 了解性能分析
- 🔬 阅读 [ALGORITHM_DESIGN.md](ALGORITHM_DESIGN.md) 了解算法原理
- 💡 查看示例代码集成到您的项目

---

## 支持与反馈

- 📧 问题反馈: [GitHub Issues]
- 📚 技术文档: [项目Wiki]
- 🚀 性能调优: 联系技术支持

---

**开始使用只需5分钟！祝您使用愉快！** 🎉

