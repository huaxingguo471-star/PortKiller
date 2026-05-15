# 端口占用查询与查杀工具

这是一个 Windows 小工具，用于输入端口号后查询占用该端口的进程，并支持强制结束对应进程。

## 功能

- 输入端口号查询占用进程。
- 展示协议、本地地址、远端地址、连接状态、PID、进程名、进程路径。
- 支持查杀选中进程。
- 支持查杀当前端口全部进程。
- 自动请求管理员权限。
- 拦截高风险系统进程和当前工具进程，避免误杀关键进程。

## 开发运行

```powershell
python .\port_killer.py
```

## 打包 exe

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

打包完成后，生成文件在：

```text
dist\PortKiller.exe
```

## 注意事项

- 查杀进程使用的是 Windows 原生命令 `taskkill /PID <pid> /F`。
- 强制结束进程可能导致未保存数据丢失，请确认后再执行。
- 如果端口由系统核心进程占用，工具会默认拦截，不直接查杀。
