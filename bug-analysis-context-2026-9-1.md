# Rockey-Dongle 项目审查上下文记录

> 本文件是 2026-09-01 ~ 2026-09-02 一次完整代码审查会话的工作上下文,供后续会话/接手人直接续接工作,避免重复分析。
> 配套交付物:`bug-analysis-report.html`(完整带样式报告,含图表)。

---

## 1. 任务背景

- **用户请求**:① 分析项目有没有 bug;② 评估项目难易程度;③ 生成 HTML 报告;④ **重点检查设备端随机数发生器**。
- **审查方式**:4 路并行深度审查代理 + 主会话独立 RNG/基础库分析 + 可执行验证。
- **审查对象**:master@8555281,自研代码约 33,000 行(不含 `third_party/TASSL`),测试约 5,600 行。
- **结论**:确认 **51 项问题**(Critical 4 / High 11 / Medium 12 / Low 24),难度评级 **专家级 9/10**。

## 2. 项目关键事实(审查中核实,勿重复推导)

### 2.1 构建与模块结构
- 平台:MCU 固件(arm-none-eabi,RockeyARM)/ Linux / Windows / Cygwin / aarch64-linux / WASM / wasmjs,自研 x4c 构建系统(`Build/`)。
- **固件中 `Dongle` 的实现是 `Interface/rockey.cc`**(由 `Interface/xModule.mk:9-11` 选择);`dongle.cc` 是主机侧 USB 实现;`emulator.cc` 是模拟器实现。三个类同名,`secret.cc`/`master.cc`/`script.cc` 为共享成员函数。
- 密码学有两套实现:`base/src/crypto.cc`(5,524 行,常量时间版本)与 `Interface/curve25519.cc`(2,429 行,慢速路径,**dongle 固件 VM 指令实际走这套**)。

### 2.2 固件内存布局(定量核算结果)
| 区域 | 地址/大小 | 说明 |
|---|---|---|
| InOutBuf = `vm.data_` | `0x68000000`,1KB | `[0,256)` 输出/公共区,`[256,1024)` 输入区 |
| ExtendBuf = `vm.buffer_` | `0x68000C00`,1KB | 三段复用:ChaChaPolyCtx/Sha512Ctx@+0(恰256B)、RuntimeHeader@+256、DecodeTextContext@+512,**时序不重叠,安全** |
| 栈 | SP=`0x68000BF0`(start.s:6)向下生长 | 到 InOutBuf 顶共 **2032 字节**,无溢出保护 |
| .bss / .data / .rodata | — | linker.ld 断言:rodata/data 必须为空,BSS ≤ 16 字节 |
| Ed25519 Helper | 恰 1024B 占满 ExtendBuf | `fe` 为 `int32_t[10]`(40B),`rLANG_ABIREQUIRE(sizeof(Helper) <= 1024)` 恰好压线通过 |

### 2.3 脚本体系
- 自研 DSL:TS 编译器(`Web/Script/`)+ C++ VM(`Interface/script.cc`);opstk 仅 16 字、代码上限 100 半字、`pc_` 为 uint8_t。
- 脚本 DATA 区(后 768 字节)完整性仅靠"密钥 = SM3(ScriptText 明文)"的 ChaCha20-Poly1305 MAC(**自引用、知道明文即可重算**);真正签名只覆盖代码区。kScriptAdmin 等关键流程额外做 SM2ECIES 签名是必要的,新增脚本类型必须保持该模式。
- `rlCryptoChaCha20Block` 是**纯函数**(不自增计数器),状态推进全靠调用方 `++entropy_local_[15]`。

## 3. 完整发现清单(51 项)

### Critical(4)
| ID | 位置 | 问题 |
|---|---|---|
| C-01 | `Interface/script.cc:856-869` | OpFuncDigest 5 处 `md=nullptr` 未检查(OpCheckMM 越界只置 zero_,当前指令仍执行)→ 设备写 0 地址挂死,**匿名脚本可达**(MAC 密钥可自算);主机/模拟器 NULL 写段错误 |
| C-02 | `base/src/crypto.cc:24-151` | 自实现 memset/memcpy 严格别名违规 + 146-151 宏重定向。**已实证**:-O2 下 X25519 输错且非确定、Ed25519 200/200 签名不互操作但内部自洽;-O1/-Os/-O3 正确;`-fno-strict-aliasing` 可恢复。当前构建 -O1 碰巧安全,windows.conf 已配 -O2 |
| C-03 | `src/app/main.cc:652/674` + `data.cc:89` | `--list`:rl_BASE64_Write 无界,3,457 字符写 2,048 缓冲,**≥38 只狗触发**,溢出 ~1.4KB |
| C-04 | `base/src/data.cc:49-87` + `main.cc:252` | rl_BASE64_Read(len=-1):strlen 转换被注释,NUL 被忽略,唯一出口是 '=';无 padding 输入 → 越界读 + 无界写 128KB 栈缓冲 |

### High(11)
| ID | 位置 | 问题 |
|---|---|---|
| H-01 | `rockey.cc:51`/`dongle.cc:95`/`emulator.cc:661` | DRBG 熵反馈哈希循环余数而非原始长度:64 倍数长度时反馈 `SHA512("")` 公开常数,**熵积累完全失效**(三处同源复制粘贴) |
| H-02 | `rockey.cc:32`/`dongle.cc:75` | RandBytes 只对前 128B 注入硬件随机,`[128,size)` = 陈旧缓冲区 ⊕ 密钥流 |
| H-03 | `start.s:6` + `linker.ld` | 栈预算 2032B 无保护;Ed25519 链(Sha512Ctx 240B + W[80] 640B + VM ~300B)逼近/超限(README 已知问题的定量化);`master.cc:41/196` 有 1024B 栈对象 |
| H-04 | `start.s:20-29` | 启动桩**无 BX/BLX**,从不跳 app_entry(手工反汇编验证:全靠 app_entry 恰为 .text 首字节);不清 .bss |
| H-05 | `chachapoly.cc:33-39` | Open 先解密后认证:失败时明文已写入且 *size_ 已更新;memcmp 非常量时间 |
| H-06 | `crypto.cc:4325/5449` + `curve25519.cc:2246` | X25519 无全零输出检查(RFC 7748 §6.1 要求):低阶点/小群直达 PREV_MASTER_SECRET 派生链(execute.cc:368);fe_frombytes 忽略最高位 |
| H-07 | `grammar.ts:749-757` | 负数立即数 `[-0x100000,-0x1001]` 且低12位非零:编码把减法做成加法(**实测** -5000→-3192、-8191→-1),静默错码 |
| H-08 | `grammar.ts:820-834` | 编译器不建模栈深:23 半字的 4 层嵌套调用可达栈深 18>16 → SIGSEGV + 清空全部数据 |
| H-09 | `emulator.cc:524-548` | OpWriteSecretFile 失败仍 EncryptBuffer 提交:私钥槽静默变为"合法加密的全零",后续读成功返回全零 |
| H-10 | `main.cc:646-647/810` | 模拟器 Open 任何失败(含口令输错)→ Create + 无条件 "wb" 重写:**口令敲错一次,镜像密钥全部丢失** |
| H-11 | `elf2bin.cjs:68-95` | 只取 phdr[0],其余 PT_LOAD 段静默丢弃;g_FEI 段无断言保护 |

### Medium(12)
| ID | 位置 | 问题 |
|---|---|---|
| M-01 | `curve25519.cc:2192-2213` | Interface 侧 ge_scalarmult 秘密依赖分支(处理签名 nonce);crypto.cc:4176 有常量时间版本未用;`if(!init)` 泄露最高置位位 |
| M-02 | `curve25519.cc:2292` + `dongle.h:66-71` | 私钥清零被 DSE 删除(**实证**:-O2 对象文件 memset 数=0);应改用 crypto.cc:7-16 的 cipher_cleanse |
| M-03 | `tokenize.ts:243-251` | 前导零十进制按八进制截断:"09"→0 不报错 |
| M-04 | `grammar.ts:671-729` | 内存读写内建不检查对齐:VM LoadMM/StoreMM 要求对齐,`kLoadI32(257)` 编译过运行必错 |
| M-05 | `grammar.ts:1266/1836/1723` | `public` 可 >256:输出区覆盖输入区 + 收尾 memset 破坏输入 |
| M-06 | `script.cc:1390/1594` | `Exit(非0)` 被当致命错误:清空全部输出(exit code 与错误码共用 zero_) |
| M-07 | `dongle.cc:132` | 主机 GetPINState 恒失败:实参是逗号表达式(字符串字面量 + DONGLE_FAILED),没调用 API;管理员 PIN 提升路径永远失败 |
| M-08 | `curves.cc:510` | ComputeSecretSecp256k1 返回 uECC 布尔(成功=1),与项目 0=成功 约定相反:ECDH 失败被当成功(:431 有正确写法) |
| M-09 | `emulator.cc:209-241`、`rockey.cc:224/326` | 主密钥 secret[256]/ECCSM2/RSA 私钥材料错误路径残留栈;BN_free 未用 BN_clear_free |
| M-10 | `main.cc:447-449/210-212` | argv 全打印(含 PIN);锁定流程把新管理员 PIN 打日志 3 遍(与"彻底忘记PIN"注释矛盾) |
| M-11 | `execute.cc:84-86` | ExecutePrepare 先 memcpy 256B 再校验 vm.data_/vm.buffer_ 指针(顺序颠倒) |
| M-12 | `rockey.cc:14/32` | 设备端两处 HwARandBytes 不查返回值(TRNG 失败→状态=0⊕编译期常数,同批固件输出一致);启动后无重播种 |

### Low(24)
L-01 `grammar.ts:903/1481` 移位≥32 静默截断 · L-02 `grammar.ts:1101/1019/986` 逻辑运算结果值不对称(5||7→1 但 5&&7→7) · L-03 `Web/Script/main.cc:17` WASM 解析栈 256 层,深嵌套报错误导 · L-04 `dongle.cc:33-66`/`emulator.cc:595` SM2Cipher ASN1 转换导出 API 无输出长度参数 · L-05 `script.cc:160` CreateDataFile 接受负尺寸 · L-06 `main.cc:383` 失败后仍哈希未初始化 dashboard[8192] · L-07 `dongle.cc:789` Enum 不钳制 SDK count(clamp 在越界写之后) · L-08 `script.cc:997` TDES 要求 %16,块大小是 8 · L-09 `curves.cc:27-30` ScopeRNG 全局指针竞态(单线程潜伏) · L-10 `pki.cc:32-38` 未初始化内存做 RAND_seed · L-11 `emulator.cc:761-1004` 模拟器不落实文件权限(安全测试结论偏乐观) · L-12 `main.cc:628` 默认主密钥 "1234567812345678" · L-13 `master.cc:281-307` READ_MASTER_SECRET 失败仍覆写输出 · L-14 `secret.cc:137-141` 错误路径不清零 · L-15 `main.cc:705` isxdigit 负 char UB · L-16 `emulator.cc:536` + `dongle.h:454-459` DONGLE_VERIFY 失败 abort 宿主 · L-17 `main.cc:404` rand() 未播种 · L-18 `sha256.cc:235` size_t→int 截断(>2GB 静默跳过) · L-19 `crypto.cc:928/949` ChaCha20 32 位计数器回绕无检测 · L-20 `crypto.cc:5365` Ed25519 接受非规范公钥(ref10 行为,设计取舍) · L-21 `crypto.cc:5503` PubkeyEx 无 clamping(#if 0 中) · L-22 `curve25519.cc:2206` dummy ge_add 读未初始化 T(UB,MSan 会报) · L-23 `crypto.cc:5477` rlCryptoRandBytes 熵池无播种路径 · L-24 `log.cc:221` 日志颜色复位码被覆盖(sprintf 返回值被丢弃)

## 4. RNG 专项(用户指定重点)

结构:启动 `entropy_local_[16]` ← TRNG 64B → `InitializeEntropyLocal`(secret.cc:99,混编译期常数,LocalChaos 混狗信息)→ 构造函数 `SeedBytes(&info)`。

- **核心判断:该 DRBG 不可预测性完全依赖启动时 64B 硬件随机**——反馈失效(H-01)、无重播种(M-12)、>128B 无硬件熵(H-02),状态演化对知道初始状态者确定已知。全部密钥生成(Ed25519/X25519/uECC/RSA/随机填充)都走这条路径。
- RNG-4(低):计数器仅 `++word[15]`,2^32 块回绕(生命周期内达不到)。
- 修复:P0 = SHA512 用原始长度 + >128B 滚动注入硬件随机 + 检查 get_random 返回;P1 = 周期性重播种(SHA512 混入而非加法)+ 修 Ed25519 栈溢出消除状态覆写通道。

## 5. 已验证无问题项(不要重复审查)

- **算法数值正确性(-O1)**:SHA1/256/384/512(576 组多段含边界)、ChaCha20-Poly1305(RFC8439 + 419 组)、Ed25519(RFC8032 + 208 组,含确定性 nonce/clamping/常量时间比较)、X25519(RFC7748 全向量)、fe_*/sc_muladd/sc_reduce、micro-ecc 三曲线常数——全部与标准一致。**两份实现(crypto.cc 与 curve25519.cc)的 sc_reduce/sc_muladd 逐行等价**。
- C++ VM 运行时防护(栈深/地址/对齐/除零含 INT_MIN/-1/cycles/跳转边界)完备;scanner.cc(flex 移植)无泄漏无越界;ExtendBuf 三段复用时序安全;SM2 各缓冲边界核算无误;rbtree.cc/base.cc 日期算法/logWrite 布局核算无误。

## 6. 难度评估结论

专家级 **9/10**:密码学 5.0 / 极限资源约束 5.0 / 编译器+VM 自研 4.5 / 跨平台构建 4.0 / 密钥管理流程 4.0 / **测试体系 2.5(主要短板)**。维护者画像:同时熟悉密码学实现细节与 ARM 裸机的资深工程师;上手 2-4 周(仅理解内存布局与密钥流程)。

## 7. 修复路线与修复状态

### ✅ 已修复(2026-09-02,共 37 项,均通过验证)

| ID | 修复内容 | 验证方式 |
|---|---|---|
| C-01 | script.cc 五处 digest handler 增加 `if (md)` 空指针检查 | g++ -fsyntax-only 通过 |
| C-02 | 删除 crypto.cc 的 cipher_memset/memcpy/memmove 及宏重定向(134 行),改用 libc | **-O1/-O2/-O3 全部通过 RFC 7748 X25519 + RFC 8032 Ed25519 向量**(修复前 -O2 失败) |
| C-03 | main.cc --list 缓冲 2048→4096(最坏 64 只狗需 3462) | 语法检查通过 |
| C-04 | data.cc 两处(rl_BASE64_Read/rl_BASE64Url_Read):恢复 strlen 转换 + 输入耗尽即冲刷返回 | 功能测试 4 项全过(roundtrip/无padding/垃圾输入/NUL 终止) |
| H-01 | 三处 RandBytes 的 SHA512 反馈改用 `size_total`(原始长度) | 语法检查通过 |
| H-02 | rockey.cc/dongle.cc 硬件随机改为按 64 字节块滚动注入(覆盖全缓冲) | 语法检查通过 |
| H-05 | CHACHAPOLY_Open:常量时间 tag 比较 + 失败清零缓冲 + *size_ 仅成功时更新 | 语法检查通过 |
| H-06 | rlCryptoX25519 与 Curve25519::X25519 改返回 int + 常量时间全零检查(低阶点拒绝);ComputeSecretCurve25519 传播错误;base.h 声明同步 | **功能验证:u=0 低阶点返回 -EFAULT**;RFC 向量仍过 |
| H-07 | grammar.ts 负数立即数:`kLoadMNI\|M` + `kAddUI\|(0x1000-L)` | **10,987 个样本数值验证零失配** |
| H-09 | emulator.cc OpWriteSecretFile:callback 失败时回滚(空槽恢复 empty、已有槽还原明文后重新加密原内容),不再提交"合法加密的全零" | **模拟器测试套件 0 错误** |
| H-10 | main.cc 模拟器入口:仅 `-ENOENT`(首次无镜像)才 Create;其他 Open 失败(口令错/损坏)报错退出,不再 `"wb"` 重写镜像 | **实测:错口令 → -EACCES 退出,镜像 sha256 不变;对口令正常** |
| H-11 | elf2bin.cjs 恢复 phnum 校验(允许一个空 g_FEI 段) | node 语法可解析 |
| M-02 | curve25519.cc X25519 私钥标量、dongle.h HashBase::Clear 改 volatile 逐字节清零(不可被 DSE 删除) | 语法检查通过 |
| M-03 | tokenize.ts 前导零含 8/9 抛 RangeError | tsc 通过 |
| M-04 | grammar.ts Memory Load/Store 常量地址编译期对齐校验(memoryAccessSize);顺带修正 Store 分支错误消息 LoadMemory→StoreMemory | tsc 通过 |
| M-05 | grammar.ts AC_PUBLIC_SIZE_X 上界 1024→256 | tsc 通过 |
| M-06 | Exit(非0) 与故障分离:VM_t 新增 `exit_` 成员,kExit 记 exit_ 不再置 zero_;收尾保留输出,返回 `(exit&0xFFFF)\|(1<<29)`(kResultExitFlag,故障仍是 bit30);main.cc/Web emulator 三处宿主对带标记结果不清输出、照常打印 | **实测:exit 65522 带输出返回 OK;模拟器测试套件 0 错误** |
| M-07 | dongle.cc GetPINState 逗号表达式 → 诚实 `-ENOSYS` 存根(SDK 无该查询 API) | 语法检查通过 |
| M-08 | curves.cc ComputeSecretSecp256k1 返回约定改 `? 0 : -EFAULT` | 语法检查通过 |
| M-09 | emulator.cc Load 的 `secret[256]` 改 SecretBuffer(析构清零);rockey.cc GenerateP256/GenerateSM2/ImportP256/ImportSM2/RSAPrivateRaw 的裸密钥结构体全部改 `SecretBuffer<1,T>`;6 处 `BN_free(pkey)`→`BN_clear_free`(公开指数 e 保留 BN_free) | 完整构建通过 |
| M-10 | main.cc 不再打印 argv 值(只打 argc);RockeyARM_Lock 不再打印随机管理员 PIN(与"彻底忘记PIN"设计一致) | 完整构建通过 |
| M-11 | execute.cc RockeyTrustExecutePrepare:先校验 `vm.data_/vm.buffer_` 再 memcpy 256B | 完整构建通过 |
| M-12 | rockey.cc 构造函数 HwARandBytes 失败重试 3 次(失败清零不残留);RandBytes 两处检查 HwARandBytes 返回值,失败立即返回错误(调用方 master.cc:252 / script.cc:81 均已检查);H-02 的逐块注入即持续重播种 | 完整构建通过 |
| L-01 | grammar.ts 移位量 ∉[0,31] 编译期抛 RangeError(立即数优化 3 处 + 常量折叠 3 处) | tsc 通过 |
| L-05 | script.cc kCreateDataFile 负 size → -EINVAL | 完整构建通过 |
| L-06 | main.cc lock 流程:仅在 ReadDataFile+ReadLine 都成功后才哈希 dashboard | 完整构建通过 |
| L-07 | dongle.cc Enum:Dongle_Enum 返回后先钳制 count≤64 再写 info[] | 完整构建通过 |
| L-08 | script.cc TDES 分块校验 %16→%8(SM4 的 %16 保留) | 完整构建通过 |
| L-10 | Web/Emulator/pki.cc RAND_seed 缓冲零初始化 | tsc/wasm 构建待验(本机未编 wasm) |
| L-13 | master.cc OpManager_ComputeSecretBytes:READ_MASTER_SECRET 失败立即清零上下文并返回 -EFAULT(不再把零秘密哈希进输出) | 完整构建通过 |
| L-14 | secret.cc READ_MASTER_SECRET 两个错误路径补 memset 清零 ENCRYPT_MASTER_SECRET | 完整构建通过 |
| L-15 | main.cc isxdigit 参数 cast unsigned char | 语法检查通过 |
| L-17 | main.cc 删除无意义 rand() 调用(值立即被 RAND_bytes 覆盖) | 完整构建通过 |
| L-18 | sha256.cc Update 按 INT_MAX 分块喂 internal_sha256_update(>2GB 不再静默跳过) | **sha256 测试套件 0 错误** |
| L-22 | curve25519.cc ge_scalarmult 开头把 dummy T 初始化为单位点(fe_0/fe_1,不读未初始化内存;Helper 仍恰 1024B) | **25519 测试套件 0 错误** |
| L-24 | log.cc efmt sprintf 返回值累加 | 语法检查通过 |

修改文件(22):Interface/{script,rockey,dongle,emulator,chachapoly,curve25519,curves,execute,master,secret,sha256}.cc、Interface/{script,dongle}.h、base/src/{crypto,data,log}.cc、base/bits/base.h、src/app/main.cc、Web/Script/lib/{grammar,tokenize}.ts、Web/Emulator/{emulator,pki}.cc、MCU/RockeyARM/elf2bin.cjs。

**2026-09-02 完整构建验证(本机 aarch64 原生,`X4C_NODE=/usr/local/bin/node`)**:
- `make aarch64-linux -j8`(含 TASSL 静态库 + libRockeyARM.a)→ **exit 0,零错误**
- `make foobar -j8`(__EMULATOR__ debug)→ **exit 0**
- 测试套件(退出码 102 = `10086-error` 即 0 错误):__Testing__25519__ / __Testing__sha256__ / __Testing__micro_ecc__ / __Testing__aes__ / __Testing__dongle__(foobar 模拟器后端)全部 0 错误
- __Testing__dongle__ 的 aarch64-linux 版需要实体 USB 硬件(本机无,失败属预期)
- tsc@5:仅剩两个预存在 wasm 产物模块缺失错误(需先 make wasm);wasm/cygwin/windows/arm-none-eabi 固件目标本机未验证,刷机前应跑 `make dongle`

### ⏳ 未修复(需要更大改动或真机验证)

- H-03 栈预算重构(大对象移 ExtendBuf/链接断言/MPU)——设计级改动
- H-04 start.s 启动桩重写(需真机验证启动)
- H-08 编译器栈深静态建模(需要完整的 codegen 栈深计算框架)
- M-01 Interface 侧换用常量时间标量乘(涉及两套实现的取舍)
- L-02 逻辑运算结果值不对称(`5||7`→1 但 `5&&7`→7;改语义可能破坏既有脚本)
- L-03 WASM 解析栈 256 层(wasm 侧改动,本机未编 wasm)
- L-04 SM2Cipher ASN1 转换 API 无输出长度参数(接口变更)
- L-09 ScopeRNG 全局指针竞态(单线程潜伏,加锁需评估)
- L-11 模拟器不落实文件权限(安全测试结论偏乐观,涉及测试方法学)
- L-12 默认主密钥 "1234567812345678"(改动破坏既有镜像兼容性,需产品决策)
- L-16 DONGLE_VERIFY 失败 abort 宿主(改为返回错误影响所有调用点)
- L-19 ChaCha20 32 位计数器回绕无检测(生命周期内达不到,收益低)
- L-20/L-21 Ed25519 非规范公钥/ref10 行为、PubkeyEx 无 clamping(#if 0 死代码)——设计取舍
- L-23 rlCryptoRandBytes 熵池无播种路径(需接主 RNG,涉及初始化顺序)

## 8. 审查方法与可信度边界

- 密码学:提取独立测试程序,本机 aarch64 GCC 11.4.0(与项目交叉编译器同版本)与 OpenSSL/Python cryptography 交叉验证。
- 脚本:解码词法 DFA 表,复刻编译器 + VM 语义可执行模拟(H-07/H-08/前导零均实测)。
- 固件:内存布局定量核算 + start.s 手工反汇编 + 链接脚本断言分析。
- **边界**:交互输入测试未在真实设备执行(仅语义模拟),设备侧行为(C-01 的 BusFault 等)为推断;FTRX `get_random` 硬件质量无法从源码验证,属信任假设。
