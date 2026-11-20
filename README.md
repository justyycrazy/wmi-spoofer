# WMI 伪装器（wmi-spoofer）

> 当前版本 **v1.0.0**——项目版本以 `wmi-spoofer.dll` 的版本资源为准，launcher 与 DLL 成对发布，注入前校验配套（≥ 1.0.0）。

本机隐私防护 / 测试工具：让**指定的目标程序**在读到主板序列号（`Win32_BaseBoard.SerialNumber`）、CPU 标识（`Win32_Processor.ProcessorId`）与磁盘序列号（`Win32_DiskDrive.SerialNumber`）时拿到你设定的假值——启动器默认预填本机真实值，改成其他值即可让目标程序读到不同的指纹。

两个组件：

| 组件 | 形态 | 作用 |
| --- | --- | --- |
| `wmi-spoofer.dll` | C++ / MinHook 进程内注入 DLL | 拦截本进程 WMI COM 调用，按注入环境变量覆写查询结果 |
| `wmi-spoofer.exe` | egui（eframe）图形启动器 | 读取本机真实 WMI 值预填 → 按需改写假值 → 写配置 → 挂起启动目标程序并注入 |

## 免责声明

- 本工具仅用于**本机隐私防护与软件测试**等合法场景；影响范围仅限被注入的进程，不修改系统、注册表、WMI 服务，其他程序查到的仍是真实值，目标进程退出即失效。
- **请勿用于绕过他人软件的授权 / 许可验证**，或任何违反目标软件许可协议、当地法律法规的用途。
- 使用者需对自己有权处理的软件负责，使用本工具产生的一切后果由使用者自行承担。

---

## 目录结构

```
wmi-spoofer/
├─ README.md / LICENSE / .gitignore / .gitattributes
├─ verify.bat                      一键验证（构建 DLL 含版本资源 + C++ 单测 + 探针 + rust fmt/clippy/test）
├─ .github/workflows/ci.yml        CI（rust 检查 + DLL 构建/单测/探针 + 注入冒烟强制门禁）
├─ wmi-spoof-dll/
│  ├─ src/
│  │  ├─ dllmain.cpp               DllMain 入口（模块自钉 + 启动 hook 安装线程）
│  │  ├─ hooks.cpp / hooks.h       MinHook hook 函数（CoCreateInstance(Ex)、CreateProcessW/A）与安装线程
│  │  ├─ proxies.h                 WMI COM 代理层（Locator/Services 包装、IClientSecurity 委托、覆写辅助）
│  │  ├─ replay_enum.h             回放枚举器 CReplayEnum（覆写缓存回放 + FTM 聚合）
│  │  ├─ parse.cpp / parse.h       WQL / 对象路径解析与 VARIANT 辅助（纯逻辑，可单测）
│  │  ├─ config.cpp / config.h     注入参数解析（环境变量 → 覆写规则表）
│  │  ├─ log.cpp / log.h           日志（UTF-8 / 脱敏 / 2MB 轮转）与 DLL 路径
│  │  ├─ inject.cpp / inject.h     子进程注入 + hook 就绪握手
│  │  ├─ common.h / guard.h        共享类型与全局状态 / RAII 与异常边界守卫
│  │  └─ version.rc                版本资源（launcher 注入前校验 ≥ 1.0.0 的依据）
│  ├─ tools/
│  │  ├─ wmitest.cpp               独立 WMI 探针（自证读取结果，用于注入前后对照；
│  │  │                            enum/getobj 子命令覆盖 CreateInstanceEnum/GetObject 路径）
│  │  ├─ probe-wbemdisp.vbs        脚本层（SWbemServices）三段探针：InstancesOf /
│  │  │                            moniker GetObject / ExecQuery（ASCII，任意代码页可跑）
│  │  ├─ probe-dotnet.ps1          .NET System.Management 探针：GetInstances / [wmi] 单实例
│  │  ├─ probe-apartment.cpp       跨 apartment 实证探针：封送/直调/生命周期/跨进程七情形（all / only=N / xproc）
│  │  ├─ probe-blanket.cpp         显式凭据探针：credcheck / withcred（凭据经环境变量）
│  │  ├─ bench-wmi.cpp             热路径测量探针（注入前后对照两类查询平均耗时）
│  │  └─ childtest.cpp             子进程回归探针（CHILDREN=0 时目标自行创建的子进程应正常运行）
│  ├─ tests/
│  │  ├─ test_pure.cpp             C++ 纯函数单元测试（parse / config / log / 回放枚举器）
│  │  └─ build_tests.bat           单测构建脚本（x64 Native Tools 环境运行）
│  ├─ build_msvc.bat               MSVC 构建脚本（GBK 编码，中文 cmd 直接可运行）
│  └─ minhook/                     MinHook 1.3.4 源码（vendor 进工程）
└─ launcher/
   ├─ Cargo.toml / build.rs        Rust 工程定义 + Windows 图标资源嵌入
   ├─ icons/icon.ico               应用图标
   └─ src/
      ├─ main.rs                   eframe 入口（窗口标题/尺寸）+ 中文字体加载在 app.rs
      ├─ app.rs                    egui 界面（PCB 视觉主题/模式切换/假值输入/状态区）
      ├─ core.rs                   真实值查询（real_values）+ launch 写配置并注入
      └─ inject.rs                 挂起启动 + 注入 + 恢复（windows crate 0.61）
```

## 环境要求

- Windows 10/11 x64
- Visual Studio（含 "x64 Native Tools Command Prompt"；MSVC + Windows SDK）
- Rust（MSVC 工具链）
- 目标程序与 DLL **位数必须一致**（本工程默认构建 x64）

## 构建

### 1. wmi-spoofer.dll

在 **"x64 Native Tools Command Prompt for VS"** 中：

```bat
cd wmi-spoof-dll
build_msvc.bat
```

产物：`wmi-spoof-dll\wmi-spoofer.dll`（x64，约 336 KB，随构建略有浮动）。

等价命令（脚本内部即为下列命令）：

```bat
rc /nologo /fo build\version.res src\version.rc
cl /nologo /LD /O2 /MT /EHsc /std:c++17 /utf-8 /D_CRT_SECURE_NO_WARNINGS /DUNICODE /D_UNICODE ^
   src\dllmain.cpp src\hooks.cpp src\log.cpp src\config.cpp src\parse.cpp src\inject.cpp ^
   minhook\src\buffer.c minhook\src\hook.c minhook\src\trampoline.c minhook\src\hde\hde64.c ^
   /I minhook\include /Fe:wmi-spoofer.dll /Fo:build\ ^
   /link wbemuuid.lib ole32.lib oleaut32.lib uuid.lib advapi32.lib build\version.res
```

**32 位目标程序**：改用 "x86 Native Tools Command Prompt"，把命令里的 `hde64.c` 换成 `hde32.c`（脚本末尾附有参考命令），产物同样命名为 `wmi-spoofer.dll`。

> 注：`build_msvc.bat` 为 GBK 编码以保证中文 cmd 正确解析；`/MT` 静态链接 CRT，避免目标机器缺 VC++ 运行库；`/utf-8` 保证源码中的中文字符串常量正确。`minhook\` 源码随工程分发，若缺失脚本会自动从 GitHub 克隆（需 git 与网络）。

可选：编译注入探针（最小 WMI 消费者，注入前后各跑一次即可对照假值是否送达）：

```bat
cl /O2 /EHsc /std:c++17 /utf-8 tools\wmitest.cpp /Fe:tools\wmitest.exe ^
   /link wbemuuid.lib ole32.lib oleaut32.lib
```

### 2. launcher

```bash
cd launcher
cargo build --release
```

产物：`launcher\target\release\wmi-spoofer.exe`（纯 Rust 单程序，无安装包流程；界面基于 egui/eframe，图标由 `build.rs` 通过 winresource 嵌入 exe 资源）。

开发调试：`cargo run`（此时 exe 在 `target\debug\`，DLL 也要放到该目录）。

### 3. 部署

把 `wmi-spoofer.dll` 放到 **`wmi-spoofer.exe` 同目录**。launcher 注入前会校验 DLL 的版本资源（要求 ≥ 1.0.0）——DLL 与 exe 请**成对更新**，旧版 DLL 会被拒绝注入并提示（新旧 DLL 行为差异较大，旧版会"半失效"且无提示）：

```
somewhere/
├─ wmi-spoofer.exe
├─ wmi-spoofer.dll      ← 必需（注入参数经环境变量下发，无外部配置依赖）
├─ wmi-spoofer.ini      ← 启动器设置（记住目标程序路径，自动生成；DLL 不读此文件）
└─ wmi-spoofer.log      ← DLL 运行日志（UTF-8）
```

## 使用

1. 打开 `wmi-spoofer.exe`，选择目标程序（.exe）；启动器自动读取本机真实指纹值预填三个输入框；
2. 把想伪装的值填进对应输入框（例如另一台机器的主板 SN / ProcessorId / 磁盘 SN）。保持本机值不变等于不伪装该项；清空某项则该项不下发参数、走真实值；
3. 在"指纹覆写"区右上角切换启动模式：伪值启动 = 按下发的假值注入启动；无值启动 = 对三类指纹类下发 EMPTY 参数——查询/枚举直接返回 0 实例，单实例 `GetObject` 返回"查无此对象"（WBEM_E_NOT_FOUND），目标程序读不到任何值，走它自己的无值回退逻辑。选好模式后点"注入启动"。
   两种模式启动成功后状态区均显示目标 PID 与实际下发的参数；每个指纹字段旁的"覆写/真实"小片实时标出该项是否会被下发。卡片底部两个开关控制「子进程传播」（onefile 目标必须开启）与「写运行日志」，随设置文件持久化。

## 工作原理

### 拦截链

```
脚本/COM 消费者（pywin32 SWbemLocator、cscript wbemdisp、.NET System.Management …）
  → 进程内 CoCreateInstance(CLSID_WbemLocator)                 ← hook 点 1（combase.dll）
  → IWbemLocator::ConnectServer                                ← 返回 IWbemServices 代理
      修复点：包装前对真实 services 代理 CoSetProxyBlanket(IMPERSONATE)
      （仅当调用方未提供凭据时——凭据条件化，见"已知限制"）。
      不这样做的话，wbemdisp 对"返回指针"的 blanket 设置落在我们这层原生包装上、
      静默失效，真实代理保持进程默认（IDENTIFY），枚举 Next 被 WMI 拒绝
      （WBEM_E_ACCESS_DENIED）——表现为假值从未送达、目标程序读到的仍是真实值。
  → IWbemServices 代理（hook 点 2，代理内）按类名规则覆写三个同步读路径：
      · ExecQuery（WQL 查询）：正则解析类名 → 命中则对真实枚举器设 IMPERSONATE →
        有限超时抽干结果对象 → Get 原值 → Put 假值(VT_BSTR/CIM_STRING) →
        用自制回放枚举器 CReplayEnum 替代原枚举器返回
      · CreateInstanceEnum（SWbemServices.InstancesOf、ManagementClass.GetInstances
        等枚举读取的底层调用，类名即参数）：与 ExecQuery 同一套抽干覆写回放逻辑
        （SpoofRealEnum 公共尾段）
      · GetObject（脚本 moniker 单实例、ManagementObject.Get 等）：解析对象路径类名，
        仅实例对象（路径含 '='）在返回的内存副本上 Get/Put；类定义对象放行
  · EMPTY（denyAll）模式：枚举路径直接返回 0 实例（S_OK，不调真实 API）；
    GetObject 单实例返回 WBEM_E_NOT_FOUND（"查无此对象"语义）
```

代理对象只转发不落库：`Put` 只改内存中的对象副本，系统 WMI 存储不受影响。

### 进程内安全接口修复（.NET / wbemdisp 兼容）

- `CWbemServicesProxy` 自身实现 `IClientSecurity`（SetBlanket/QueryBlanket/CopyProxy
  委托给真实 RPC 代理）。不这样做时，.NET（System.Management）拿到 services 指针后
  第一件事就是 `CoSetProxyBlanket`：combase 查询 `IClientSecurity` 被转发给真实代理后，
  会因"IClientSecurity 属于真实代理、services 是包装"的对象身份不一致而
  E_NOINTERFACE，.NET/WMI 消费者随后在任何 WMI 调用之前就绑定失败（表现如 PowerShell
  `Get-WmiObject` 报"指定的转换无效"）。委托时把调用方传回的本包装解包为真实代理再转交。
- 回放枚举器 `CReplayEnum` 实现 no-op 语义的 `IClientSecurity`：wbemdisp 等消费者在
  services 的 blanket 可用后，会尝试把安全设置复制到枚举器上；本地回放枚举器没有
  RPC 通道，安全设置无实际意义，空操作即可满足该惯例（否则 wbemdisp 的枚举报
  WBEM_E_FAILED）。

> 注意：DLL 对同一 WMI 类的每个实例写入同一个假值；多块物理盘的机器将读到"同一 SN"，
> 当前界面按单盘机器设计，多盘场景请评估后再用。
>
> 已知限制（当前版本未覆盖）：
> - `*Async` 变体（ExecQueryAsync/CreateInstanceEnumAsync/GetObjectAsync 等）不覆写，走真实数据（日志中保留逐 API 调用行便于观察）；`ExecMethod`、事件查询（`ExecNotificationQuery*`）同样不覆写。回放枚举器上的 `NextAsync` 亦不支持（返回 `WBEM_E_NOT_SUPPORTED`，同步查询消费者不受影响）。
> - WMI Locator 捕获仅覆盖 `CoCreateInstance`/`CoCreateInstanceEx` 直接请求 `IID_IWbemLocator` 或先请求 `IID_IUnknown` 再 QI 两条路径（聚合场景不包装）；`CoGetObject`/moniker、`CoGetClassObject` + `IClassFactory` 等其他创建路径不覆盖（未命中即放行真实值，安全兜底）。
> - 回放枚举器的抽干阶段若真实枚举中途失败（网络/权限/超时），错误 HRESULT 会保留并在缓存耗尽后透传给调用方（不再伪装成"完整结果"）。
> - **DLL 注入后不可被 `FreeLibrary` 卸载**：DLL 启动时自钉（`GET_MODULE_HANDLE_EX_FLAG_PIN`），任何宿主 `FreeLibrary` 均为 no-op——hook 跳板指向本模块代码，卸载会使跳板悬空导致宿主崩溃；生命周期 = 进程生命周期，进程退出随进程整体失效。
> - 跨 apartment / 跨单元消费（以下均经探针实测：情形表与各情形说明见 `tools/probe-apartment.cpp` 内注释）：①把 `IWbemServices` 经标准封送到其他单元（如 STA 创建后交给 MTA 工作线程）时，unmarshal 出的是**未包装的真实对象**，伪装静默失效（读到真实值）；同线程、同 MTA 直传不受影响。②`ExecQuery`/`CreateInstanceEnum` 返回的回放枚举器已聚合 FTM（自由线程封送器），封送语义分两种：**同进程跨单元**为直引用（unmarshal 侧 QI/AddRef，生命周期由共享引用计数管理）——探针实测源线程先释放全部引用并退出后，另一单元仍读到假值，早释放安全；**跨进程**（同机器）走 ole32 标准导出（ORYT_STANDARD，子进程代理经本地 RPC 回连源进程内的回放对象），假值同样存活，代价是生命周期随源进程（源进程退出则子进程代理断连）；跨机器封送未支持（未实测）。③跨线程直调 STA 创建的 services（不封送）报 `RPC_E_WRONG_THREAD`，与未注入时的原生行为一致。
> - `ConnectServer` 带显式凭据连远程命名空间的场景未支持且未验证（实测：本地命名空间在连接阶段即拒绝显式凭据，`WBEM_E_LOCAL_CREDENTIALS`，本工具按本地 `ROOT\CIMV2` 设计）。DLL 仅在调用方未提供凭据（`strUser` 为空）时重设代理 blanket，避免覆盖调用方显式凭据。
> - DLL 所在路径超过 `MAX_PATH` 时，DLL 会自动禁用日志与子进程传播（安全降级，不崩溃）。

### 子进程传播（onefile 兼容）

PyInstaller onefile 布局的真实 Python 逻辑运行在子进程。DLL 在 `WMI_SPOOFER_CHILDREN=1`（缺省开启）时才 hook 本进程 `CreateProcessW/A`，追加 `CREATE_SUSPENDED` 启动子进程 → 注入同一 DLL → 等子进程 hook 就绪 → `ResumeThread`（调用方本来就要求挂起则不代为恢复；**开关关闭时不追加挂起标志，子进程行为完全正常**）。就绪等待不受调用方是否要求挂起影响——主线程挂起不妨碍 DLL 安装线程，有界等待（3 秒）闭合"恢复后早期 WMI 调用未命中"的空窗；注入失败则跳过等待直接放行，不产生无效阻塞。`ResumeThread` 失败会记录严重日志（子进程主线程将保持挂起）。子进程继承目标进程的环境变量，注入配置随之自动传播。onedir 单进程布局天然兼容。

### hook 就绪握手

注入与 hook 安装之间用命名事件 `Local\wmi-spoofer-ready-<PID>` 做确定性同步：DLL 仅在**全部必需 hook 创建成功且批量启用成功**后创建并置位该事件（manual-reset，DLL 持有句柄至进程退出以保证内核对象存活）。必需 hook = `CoCreateInstance`/`CoCreateInstanceEx` 恒必需；`CreateProcessW/A` 在子进程传播开启时必需——任一必需项失败即整体回滚（`MH_Uninitialize`，不留半启用状态）且不置位事件。启动器在远程 `LoadLibraryW` 完成后轮询打开并等待该事件（预算 5 秒）；父进程传播子进程时同样等待（预算 3 秒，注入失败则跳过等待直接放行）。等待超时不会阻塞目标运行——启动器状态区会显示"⚠ hook 未确认生效"并提示查看日志；任何安装失败路径都不置位事件，因此"未确认"即"未生效"。

### 注入参数（环境变量）

启动器每次注入时，把本次配置构造成环境变量随 `CreateProcessW` 下发；DLL 在目标进程内用 `GetEnvironmentVariableW` 读取。变量不存在 = 该项不覆写，放行真实数据（安全兜底）：

| 环境变量 | 含义 | 缺省（变量不存在） |
| --- | --- | --- |
| `WMI_SPOOFER_BOARD` | `Win32_BaseBoard.SerialNumber` 假值 | 真实值 |
| `WMI_SPOOFER_CPU` | `Win32_Processor.ProcessorId` 假值 | 真实值 |
| `WMI_SPOOFER_DISK` | `Win32_DiskDrive.SerialNumber` 假值 | 真实值 |
| `WMI_SPOOFER_EMPTY` | 无值模式：逗号分隔的 `board`/`cpu`/`disk`（大小写不敏感），列出的类查询直接返回 0 实例，忽略对应假值 | 无 |
| `WMI_SPOOFER_CHILDREN` | 是否向子进程传播注入（`0` 关闭） | 由界面开关控制，缺省开启 |
| `WMI_SPOOFER_LOG` | 是否写 `wmi-spoofer.log`（`0` 关闭） | 由界面开关控制，缺省开启 |
| `WMI_SPOOFER_LOG_FAKE` | Put 记录里的假值记明文（`1` 开启；缺省同样脱敏） | 关（脱敏） |
| `WMI_SPOOFER_FAULT` | 故障注入开关（仅测试）：逗号分隔的 `createhook`（模拟必需 hook 创建失败）/ `enable`（模拟批量启用失败）/ `resume`（launcher 与子进程传播路径模拟 `ResumeThread` 失败） | 无（全部关闭） |

DLL 加载时会把生效配置逐行写入 `wmi-spoofer.log`（"配置加载完成"之后）。日志做隐私脱敏：真实值与配置假值一律只记"首2字符…末2字符<长度N>"形态（例如 `AB…YZ<长度12>`）；仅在核对送达需要时设 `WMI_SPOOFER_LOG_FAKE=1` 让 Put 记录里的假值保留明文。日志超过 2MB 自动删除重建。子进程继承目标进程的环境变量，配置随传播自动送达。

### 启动器设置文件 wmi-spoofer.ini

只由启动器读写（DLL 不读此文件），保存目标程序路径与两个注入开关，可手工删除（自动重建、恢复默认）：

```ini
[Settings]
exe_path=C:\path\to\target.exe
inject_children=1   ; 子进程传播（onefile 目标必须开启）
log_enabled=1       ; 写运行日志
```

## 验证

1. `build_msvc.bat` 产出 x64 `wmi-spoofer.dll`；`cargo build --release`（launcher 目录）产出 `wmi-spoofer.exe`；**DLL 与目标程序位数必须一致**
2. 把 `wmi-spoofer.dll` 放到 `wmi-spoofer.exe` 同目录（dev 模式是 `launcher/target/debug/`）
3. 启动器打开后三个输入框自动填入本机真实值；填入假值并选择目标程序路径 → 启动成功，`wmi-spoofer.log` 依次出现：`配置加载完成`（其后逐条列出本次生效参数，值为脱敏形态）→ `hook 全部启用成功`（其前有逐条 `hook 已创建：…`）→ `捕获 CLSID_WbemLocator` → `ConnectServer 已包装` → `ExecQuery: SELECT * FROM Win32_BaseBoard`（或 `CreateInstanceEnum: Win32_BaseBoard`、`GetObject: Win32_Processor.DeviceID="CPU0"` 等命中行）→ Put 记录（原值与假值均为 `首2…末2<长度N>` 脱敏形态，核对送达时设 `WMI_SPOOFER_LOG_FAKE=1` 记假值明文）；启动器状态区同时显示"hook 已确认生效"
4. 目标程序实际读到的三类指纹值就是输入框里的值（未填的类为真实值）；用 `tools\wmitest.exe` 探针（含 `enum`/`getobj` 子命令）注入前后对照最直观
5. 另开 PowerShell 查 `Win32_BaseBoard` / `Win32_Processor` 仍是真实值（未影响系统）；不经启动器直接双击目标程序行为完全正常

自动化验证（本仓库自带）：

- 一键验证：仓库根 `verify.bat`（x64 Native Tools 环境）——构建 DLL（含版本资源）+ 纯函数单测 + 探针（产物入干净目录 `build\probes\`，逐项检查编译结果，`childtest` 子进程回归就地运行），再跑 rust fmt/clippy/test；任一步失败整体非零退出。GitHub Actions workflow 见 `.github\workflows\ci.yml`（注入冒烟为强制门禁，失败即红）
- Rust 单元测试（`launcher` 目录下 `cargo test`）：注入环境变量构造（伪值下发 / 未设置省略 / EMPTY 模式）、覆盖值规范化（换行 / NUL / 超长）、DLL 版本校验双分支（正例 1.0+ DLL / 负例无版本资源文件；文件缺失自动跳过）、UI 后台消息顺序（晚到的真实值不覆盖用户输入与启动状态）
- C++ 纯函数单元测试：`wmi-spoof-dll\tests\build_tests.bat`（x64 Native Tools 环境运行）构建并运行 `test_pure.cpp`——覆盖 WQL / 对象路径解析、环境变量四态、EMPTY token 映射、LoadConfig 端到端、脱敏格式，以及回放枚举器：Clone/CopyProxy 位置保留、`Skip` 合约（恰好跳完 S_OK / 越过 S_FALSE）、抽干终止错误透传（含克隆传播与幂等）、QI 失败路径清空输出指针、多线程并发 Next/Clone/Reset 压力（每位置恰消费一次）
- 注入链路冒烟测试：`cargo test inject_smoke -- --ignored`，以 `cmd.exe` 为无害目标，验证真实进程挂起启动 → 注入 → hook 就绪事件确认 → 日志出现 `配置加载完成` 与 `hook 全部启用成功`
- 故障注入验证：`WMI_SPOOFER_FAULT=createhook|enable` 注入探针时应得 `hook_ready=false` 且目标读到真实值（不置位就绪事件、无半启用残留）；`WMI_SPOOFER_FAULT=resume` 下 `inject_smoke` 应报错并以非零退出（不再静默成功）
- 注入探针测试：`WMI_SPOOF_TARGET=<wmitest.exe 路径> cargo test inject_probe -- --ignored --nocapture`，把探针注入后在测试输出中直接对照假值是否送达；加 `WMI_SPOOF_DENY=1` 验证无值启动（探针应读到 0 实例）
- 带参数注入探针：`WMI_SPOOF_TARGET=<exe> WMI_SPOOF_ARGS="<空格分隔参数>" [WMI_SPOOF_CHILDREN=1] [WMI_SPOOF_WAIT=毫秒] cargo test inject_probe_cmd -- --ignored --nocapture`，可直接注入 `wmitest.exe enum/getobj` 子命令、`cscript`（跑 `tools\probe-wbemdisp.vbs` 三段脚本层探针）与 PowerShell（跑 `tools\probe-dotnet.ps1` .NET 探针），覆盖 `ExecQuery` / `CreateInstanceEnum` / `GetObject` 三条路径的注入前后对照
- M8 热路径测量探针：\tools\bench-wmi.cpp（构建后注入前后各跑一次，输出两类查询的平均耗时 µs\次）——用于"是否需要日志降噪"的量化判据。本机实测（N=200）：非规则类 5.1ms→5.5ms（+7.8%，即每条日志 ~0.4ms）、命中类 ~1.04s→~1.04s（WMI 自身查询成本占绝对主导）——按判据无需降噪优化
- C2 子进程回归：先构建 `tools\childtest.exe`（`cl /O2 /EHsc /std:c++17 /utf-8 tools\childtest.cpp /Fe:tools\childtest.exe`），再 `cargo test inject_childtest -- --ignored`——CHILDREN=0 时注入的目标自行创建子进程应正常运行（回归"关闭传播后子进程被永久挂起"的旧缺陷）

`tools\wmitest.exe` 探针子命令：`wmitest.exe`（默认，ExecQuery 三连）｜`wmitest.exe enum <类名>...`（CreateInstanceEnum 路径）｜`wmitest.exe getobj <对象路径>`（GetObject 路径，如 `Win32_Processor.DeviceID="CPU0"`）。

## 排障

**启动器状态区显示"⚠ hook 未确认生效"**
- 表示 DLL 的 hook 就绪事件在 5 秒内未被置位：安装线程失败（MH 初始化/建 hook/启用任一步）或尚未完成。看 `wmi-spoofer.log` 里有无 `hook 全部启用成功`；只有逐条 `hook 已创建` 而无启用成功行，说明 `MH_EnableHook` 失败。目标程序本身不受影响（照常运行，读到真实值）。

**日志里没有"捕获 CLSID_WbemLocator"**
- 先确认上面有 `hook 全部启用成功`；没有则看 DLL 是否加载成功（位数、运行库）。
- 有安装成功但无捕获：目标可能没走 `CoCreateInstance(CLSID_WbemLocator)` 路径。应对方案是改 hook `wbemdisp` 的 `ISWbemLocator`（IDispatch 层）：对 `CoCreateInstance(CLSID_SWbemLocator)` 返回的 IDispatch 做代理，拦截 `ConnectServer` 方法调用，把内部 `IWbemServices` 换成代理。也可以再挂 `CoGetClassObject` + `IClassFactory::CreateInstance` 以覆盖绕过 `CoCreateInstance` 的创建路径。
- 确认写日志已开启（`WMI_SPOOFER_LOG` 缺省开启），且日志与 DLL 同目录。

**假值从未送达（日志有 Put 记录但目标读到的仍是真实值）**
- 用日志核对：命中规则的查询应有 `ConnectServer CoSetProxyBlanket hr=0x00000000`、`[类] 属性: '首2…末2<长度N>' -> '假值' (Put hr=0x00000000)` 与 `真实枚举完成：对象数=N` 三类记录；`真实枚举中断：hr=0x8...` 则记录了真实失败原因。

**CreateRemoteThread 失败 / 注入后目标闪退**
- 目标若加壳或带反调试（PyArmor、Themida 等），远程线程可能被拦截。思路：以管理员运行启动器；向安全软件加白；改用 `SetWindowsHookEx` 或 `NtQueueApcThread` 等注入方式；或对 onefile 目标先解包（`pyi-archive_viewer`）拿到内层 exe 直接注入子进程。

**其他**
- 目标是 32 位 → 用 x86 命令行重编 DLL。
- 日志乱码 → 日志为 UTF-8，用 VSCode/Notepad++ 打开。
- onefile 目标首次启动解包较慢，属正常；日志中会先出现一条 `CreateProcessW：子进程 PID=…，传播注入`。

## 第三方组件

- [MinHook](https://github.com/TsudaKageyu/minhook) 1.3.4 —— BSD-3-Clause，源码 vendor 于 `wmi-spoof-dll/minhook/`（许可见 [minhook/LICENSE.txt](wmi-spoof-dll/minhook/LICENSE.txt)）

## 许可证

本项目以 [MIT License](LICENSE) 开源。
