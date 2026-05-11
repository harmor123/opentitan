# OTBN 直连 Keccak 加速器：架构说明与配置文档

## 一、 背景与架构对比

在直连方案之前，OTBN 计算哈希的路径极其漫长且低效：

> OTBN CPU (执行汇编) -> 写入 WSR 寄存器 -> 经过 OTBN 内部打包逻辑 -> 跨过 OTBN 与 KMAC IP 的边界 -> 进入 KMAC IP 的 MsgFIFO (还要看 FIFO 满没满) -> 等待 KMAC IP 内部极其复杂的状态机 (IDLE->ABSorb->SQUEEZE) -> 算完后再原路返回。
>
> 为了满足 Kyber 等高频密码学算法的需求，我们实现了**直连加速**，彻底绕过 KMAC IP 状态机：
> OTBN CPU -> 直接写自定义 CSR 寄存器 (`DIRECT_MSG0~7`) -> Python 仿真层 (`csr.py`) 自动拼成 256-bit 整数 -> 触发 `DirectKeccakEngine` (PyCryptodome) 懒求值 -> 读 CSR (`DIRECT_DIG0~7`) 直接拿 256-bit 结果拆分返回。

---

## 二、 `keccak_direct.s` 使用方法 (汇编 API 层)

## 后续还可以进行优化！！！

汇编文件作为上层接口，屏蔽了底层 256-bit 拆包/拼包的细节。

### 2.1 发送消息：`keccak_send_msg`

**寄存器约定**：

*   `x5`：配置字 (CFG)
*   `x10`：消息数据起始地址
*   `x11`：消息字节长度
    **CFG 取值表**：

| 算法                                                         | Mode (`[1:0]`) | Strength (`[4:2]`) | 传入 `x5` 的值 |
| :----------------------------------------------------------- | :------------: | :----------------: | :------------: |
| SHAKE128                                                     |       2        |         0          |     `0x02`     |
| SHAKE256                                                     |       2        |         2          |     `0x0A`     |
| SHA3-224                                                     |       0        |         1          |     `0x04`     |
| SHA3-256                                                     |       0        |         2          |     `0x08`     |
| SHA3-384                                                     |       0        |         3          |     `0x0C`     |
| SHA3-512                                                     |       0        |         4          |     `0x10`     |
| **⚠️ 关键底层契约**：                                         |                |                    |                |
| `csr.py` **仅在检测到写入 `DIRECT_MSG7` (0x7f7) 时触发一次 `absorb()`**。因此： |                |                    |                |

1. 循环写入时，**必须**按顺序写满 `0x7f0` 到 `0x7f7`。
2. 空消息分支 **不能直接 `ret`**，必须强行向 `0x7f7` 写入一次（如写 0），否则引擎永远不会启动计算！

### 2.2 读取摘要：`keccak_digest`

**寄存器约定**：

*   `x11`：存储 32 字节摘要的内存起始地址
    读取内部使用 `csrrs x5, 0x7f8, x0` 等指令。底层 `squeeze()` 返回完整的 256-bit 整数，`csr.py` 会自动截取对应的 32-bit 段返回。
    **长摘要处理**：
    对于 SHA3-512 (64字节) 或需要更多输出的 SHAKE，连续调用并偏移指针即可。引擎内部通过模 8 计数器实现“跨批”自动推进。

---

## 三、 完整修改文件清单及路径说明

实现直连 Keccak，共涉及 **10 个核心文件** 的修改，按功能分为四层：

### 3.1 硬件 RTL 层 (防非法指令拦截)

*如果不修改这三个文件，OTBN CPU 在执行 `csrrw x0, 0x7df...` 时会被 Controller 识别为非法 CSR 而抛出异常。*

*   **`hw/ip/otbn/rtl/otbn_pkg.sv`**
    *   *作用*：在 OTBN 包级别声明 `DirectCfg`, `DirectLen`, `DirectMsg`, `DirectDig` 等合法的 CSR 空间枚举。
*   **`hw/ip/otbn/rtl/otbn_controller.sv`**
    *   *作用*：在 Controller 的读/写 CSR 状态机中，增加对这些新地址的识别分支，放行而不是报错。
*   **`hw/ip/otbn/rtl/otbn_predecode.sv`**
    *   *作用*：预解码阶段，识别 `0x7DF - 0x7FF` 范围内的指令为合法的 System 指令，防止预解码阻断。

### 3.2 配置与常量层 (地址映射)

*定义了软硬件之间的“接头暗号”。*

*   **`hw/ip/otbn/dv/otbnsim/sim/csr.yml`**
    *   *作用*：新增了完整的直连 Keccak 寄存器组定义。包括 `direct_cfg` (0x7df), `direct_len` (0x7e1), `direct_msg0~7` (0x7f0~0x7f7), `direct_dig0~7` (0x7f8~0x7ff)。
*   **`hw/ip/otbn/dv/otbnsim/sim/constants.py`**
    *   *作用*：将 `csr.yml` 中的地址编译为 Python 仿真器使用的 `CsrAddrs` 枚举类（如 `CsrAddrs.DIRECT_MSG7`），供 `csr.py` 路由判断。

### 3.3 仿真核心引擎层 (Python 行为模型)

*真正的哈希计算发生在这里，包含了极其严格的 256-bit 数据流契约。*

*   **`hw/ip/otbn/dv/otbnsim/sim/direct_keccak.py`** *(新建)*
    *   *作用*：Keccak 核心引擎。
    *   *关键设计*：
        *   `absorb()` 接收的一定是 **256-bit 整数**，内部直接 `.to_bytes(32, 'little')` 还原。
        *   `squeeze()` 返回的一定是 **256-bit 整数**。内部维护 `_squeeze_count` (模 8)，在第 9 次调用时自动向 PyCryptodome 索取下一个 32 字节块。
*   **`hw/ip/otbn/dv/otbnsim/sim/csr.py`** *(核心修改)*
    *   *作用*：数据缝合剂。
    *   *关键设计*：
        *   **写路径**：对 `DIRECT_MSG0~7` 采用 Read-Modify-Write，将 8 个 32-bit 拼入 `DIRECT_MSG`。**当且仅当写入 `MSG7` 时**，调用 `self._direct_engine.absorb(new_val)`。
        *   **读路径**：对 `DIRECT_DIG0~7`，调用一次 `self.DIRECT_DIG.read_unsigned()` 获取 256-bit 结果，然后通过位运算 `(val >> (32 * n)) & 0xFFFFFFFF` 拆分给 CPU。
        *   实例化了 `DirectCfgISPR`, `DirectLenISPR`, `DirectDigISPR`。
*   **`hw/ip/otbn/dv/otbnsim/sim/state.py`**
    *   *作用*：在 OTBN 状态机初始化时，实例化 `DirectKeccakEngine`，并将其作为参数注入给 `CSRFile` 和 `WSRFile`，完成依赖注入。
*   **`hw/ip/otbn/dv/otbnsim/sim/wsr.py`**
    *   *作用*：配合清理 WSR 0-15 被占用的逻辑，确保仿真初始化时不会因为废弃的 WSR 定义而报错。

### 3.4 测试应用层

*   **`test/kyber_ver2/hash/keccak_direct.s`** *(新建)*
    *   *作用*：提供给业务代码（如 Kyber）调用的最终版安全封装宏。处理了循环填充、空消息 `.L_empty` 兜底写 `0x7f7`、以及摘要按字存内存的逻辑。

## RTL综合后续再看！



# 备注：

- Keccak 硬件本身（每轮 4 周期 × 24 轮 = 固定 96 周期）不会因为 DIRECT/FIFO 而变快或变慢。
- 本次改的是“搬运与控制开销”（把消息搬进/搬出 Keccak，以及本地拼接/指针管理）；
  这部分在 Kyber 里的占比本来就不大，所以：
  - 整体（keypair/encaps）大致只能提升“几个百分点（个位数 %）”；
  - 某个只做很多次小 SHAKE 的局部（例如 poly_gen_matrix 的采样）理论上可以稍微多一点，但也不会翻倍。
    下面分块算给你看，方便你自己判断。

---

## 1) 瓶颈在哪？Keccak 本身的开销是“固定的”

OpenTitan 的 KMAC 硬件里的 Keccak-f[1600]（带一阶掩码）：

- 每轮 4 周期，24 轮固定 96 周期。
- 无论你是：
  - Ibex→KMAC 的 FIFO 路径；
  - 还是你现在用的 OTBN→KMAC 的 DIRECT CSR 路径；
    只要调一次 Keccak，硬件就是 96 周期打底（另外再加一些“进出/搬运”开销）。
    论文里的 profiling 也印证了这一点：在用 KMAC 的配置下，SHAKE 在 ML-DSA-65 的验证中只占 4% 时间；大头是多项式与采样。
    也就是说：Kyber/ML-DSA 在 OTBN+KMAC 上，真正的重头是 NTT、点乘、采样等；Keccak 本身虽然非常关键，但并不是时间的大头。

---

## 2) DIRECT 优化到底改了什么？能快多少？

你做的流水线优化，主要改的是“OTBN 侧搬运与拼接”的代价：

- 原来最坏的情况：每次 init 去清零 2048B（~512 条 sw）—— 这已经被你砍成 0。
- 现在 keccak_send_msg 把 32B 消息从 DMEM 搬到 8 个 CSR（direct_msg0..7），你通过：
  - 预取 8 条 lw；
  - 与 8 条 csrrw 交错；
    把“读写内存 + CSR 写”的气泡压到接近下限（接近每条有用指令 1 周期）。
- sha3_update 里把逐字（4B）循环改成 16B 一次的展开，减少循环开销和分支预测惩罚。
  粗一点估算这段路径的节省（只算“搬运和控制”，不算 Keccak-f）：
- 以前每次 init 做清零（2048B）：约 512 条 sw → ~500 周期；
- 现在不做了：-500 周期；
- 32B 消息的 send：从“每条 lw→csrrw 之间有 1 stall”变成基本不 stall；一条 jal/call + 返回的大致开销不变，但内层循环“每块 32B”的搬运能省出大约 8 个 stall，也就是大约省 ~8 周期（原来 ~24，现在 ~16 的量级）。
- sha3_update 的内存拷贝：对长消息，16B 展开比逐字拷贝大约快 20–30%（指令数与分支数减半）。
  但要注意：这些“搬运”开销只占整个 Kyber 运行时间的很小一部分（Keccak 本身也只有 96 周期/次，而且调用次数远少于 NTT/采样）。

---

### 总结一句话

- Keccak 的 96 周期/次是硬件固定的，而且 Kyber/ML-KEM 的大部分时间花在多项式/NTT/采样上，Keccak 本身只占很小比例；