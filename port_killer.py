import csv
import ctypes
from ctypes import wintypes
import os
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from tkinter import messagebox, ttk
import tkinter as tk


CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

PROTECTED_PROCESS_NAMES = {
    "system",
    "system idle process",
    "idle",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
}


@dataclass(frozen=True)
class PortRecord:
    protocol: str
    local_address: str
    remote_address: str
    state: str
    pid: int
    process_name: str
    process_path: str


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def relaunch_as_admin() -> None:
    if not is_windows() or is_admin():
        return

    if getattr(sys, "frozen", False):
        executable = sys.executable
        params = subprocess.list2cmdline(sys.argv[1:])
    else:
        executable = sys.executable
        script_path = str(Path(__file__).resolve())
        params = subprocess.list2cmdline([script_path, *sys.argv[1:]])

    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, None, 1)
    if int(result) <= 32:
        ctypes.windll.user32.MessageBoxW(
            None,
            "本工具需要管理员权限才能查询和强制结束部分进程。",
            "权限不足",
            0x10,
        )
    sys.exit(0)


def run_command(args: list[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="mbcs",
        errors="replace",
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW,
        check=False,
    )


def parse_port(value: str) -> int:
    port_text = value.strip()
    if not port_text.isdigit():
        raise ValueError("请输入 1 到 65535 之间的数字端口号。")
    port = int(port_text)
    if port < 1 or port > 65535:
        raise ValueError("端口号必须在 1 到 65535 之间。")
    return port


def extract_endpoint_port(endpoint: str) -> int | None:
    endpoint = endpoint.strip()
    if not endpoint or endpoint == "*:*":
        return None
    if endpoint.startswith("["):
        marker_index = endpoint.rfind("]:")
        port_text = endpoint[marker_index + 2 :] if marker_index >= 0 else endpoint.rsplit(":", 1)[-1]
    else:
        port_text = endpoint.rsplit(":", 1)[-1]
    if not port_text.isdigit():
        return None
    return int(port_text)


def parse_netstat_output(output: str, target_port: int) -> list[tuple[str, str, str, str, int]]:
    records: list[tuple[str, str, str, str, int]] = []
    seen: set[tuple[str, str, str, str, int]] = set()

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.startswith(("TCP", "UDP")):
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        protocol = parts[0]
        local_address = parts[1]
        remote_address = parts[2]

        if protocol == "TCP":
            if len(parts) < 5:
                continue
            state = parts[3]
            pid_text = parts[4]
        else:
            state = "-"
            pid_text = parts[-1]

        if extract_endpoint_port(local_address) != target_port:
            continue
        if not pid_text.isdigit():
            continue

        record = (protocol, local_address, remote_address, state, int(pid_text))
        if record not in seen:
            seen.add(record)
            records.append(record)

    return records


def load_process_names() -> dict[int, str]:
    completed = run_command(["tasklist", "/FO", "CSV", "/NH"], timeout=20)
    if completed.returncode != 0:
        return {}

    process_names: dict[int, str] = {}
    rows = csv.reader(completed.stdout.splitlines())
    for row in rows:
        if len(row) < 2:
            continue
        pid_text = row[1].strip()
        if pid_text.isdigit():
            process_names[int(pid_text)] = row[0].strip()
    return process_names


def query_process_path(pid: int) -> str:
    if not is_windows() or pid <= 0:
        return ""

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ""

    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        success = kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size))
        return buffer.value if success else ""
    finally:
        kernel32.CloseHandle(handle)


def build_port_records(raw_records: list[tuple[str, str, str, str, int]]) -> list[PortRecord]:
    process_names = load_process_names()
    results: list[PortRecord] = []

    for protocol, local_address, remote_address, state, pid in raw_records:
        process_path = query_process_path(pid)
        process_name = process_names.get(pid) or (Path(process_path).name if process_path else "未知进程")
        results.append(
            PortRecord(
                protocol=protocol,
                local_address=local_address,
                remote_address=remote_address,
                state=state,
                pid=pid,
                process_name=process_name,
                process_path=process_path,
            )
        )

    return results


def query_port_records(port: int) -> list[PortRecord]:
    completed = run_command(["netstat", "-ano"], timeout=20)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "netstat 执行失败。"
        raise RuntimeError(detail)
    raw_records = parse_netstat_output(completed.stdout, port)
    return build_port_records(raw_records)


def kill_process(pid: int) -> tuple[bool, str]:
    completed = run_command(["taskkill", "/PID", str(pid), "/F"], timeout=20)
    output = (completed.stdout + "\n" + completed.stderr).strip()
    return completed.returncode == 0, output


def is_protected_record(record: PortRecord) -> bool:
    name = record.process_name.strip().lower()
    return record.pid in (0, 4, os.getpid()) or name in PROTECTED_PROCESS_NAMES


class PortKillerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("端口占用查询与查杀工具")
        self.root.geometry("1080x620")
        self.root.minsize(920, 520)

        self.port_var = tk.StringVar()
        self.status_var = tk.StringVar(value="请输入端口号后查询。")
        self.current_port: int | None = None
        self.records: list[PortRecord] = []

        self._build_ui()
        self._bind_shortcuts()

    def _build_ui(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")

        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill=tk.BOTH, expand=True)

        top_bar = ttk.Frame(outer)
        top_bar.pack(fill=tk.X)

        ttk.Label(top_bar, text="端口号").pack(side=tk.LEFT)
        port_entry = ttk.Entry(top_bar, textvariable=self.port_var, width=18)
        port_entry.pack(side=tk.LEFT, padx=(8, 12))
        port_entry.focus_set()

        self.query_button = ttk.Button(top_bar, text="查询占用进程", command=self.on_query_clicked)
        self.query_button.pack(side=tk.LEFT)

        self.kill_button = ttk.Button(top_bar, text="查杀选中进程", command=self.on_kill_selected_clicked, state=tk.DISABLED)
        self.kill_button.pack(side=tk.LEFT, padx=(8, 0))

        self.kill_all_button = ttk.Button(top_bar, text="查杀当前端口全部进程", command=self.on_kill_all_clicked, state=tk.DISABLED)
        self.kill_all_button.pack(side=tk.LEFT, padx=(8, 0))

        admin_text = "管理员权限：是" if is_admin() else "管理员权限：否"
        ttk.Label(top_bar, text=admin_text).pack(side=tk.RIGHT)

        table_frame = ttk.Frame(outer)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(14, 0))
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        columns = ("protocol", "local", "remote", "state", "pid", "process", "path")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="extended", height=18)
        self.tree.heading("protocol", text="协议")
        self.tree.heading("local", text="本地地址")
        self.tree.heading("remote", text="远端地址")
        self.tree.heading("state", text="状态")
        self.tree.heading("pid", text="PID")
        self.tree.heading("process", text="进程名")
        self.tree.heading("path", text="进程路径")

        self.tree.column("protocol", width=70, anchor=tk.CENTER, stretch=False)
        self.tree.column("local", width=190, anchor=tk.W)
        self.tree.column("remote", width=190, anchor=tk.W)
        self.tree.column("state", width=100, anchor=tk.CENTER, stretch=False)
        self.tree.column("pid", width=80, anchor=tk.CENTER, stretch=False)
        self.tree.column("process", width=160, anchor=tk.W)
        self.tree.column("path", width=360, anchor=tk.W)

        self.tree.grid(row=0, column=0, sticky="nsew")

        y_scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        y_scroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=y_scroll.set)

        x_scroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        x_scroll.grid(row=1, column=0, sticky="ew")
        self.tree.configure(xscrollcommand=x_scroll.set)

        status_label = ttk.Label(outer, textvariable=self.status_var, anchor=tk.W)
        status_label.pack(fill=tk.X, pady=(10, 0))

        self.tree.bind("<<TreeviewSelect>>", lambda _event: self._refresh_button_state())

    def _bind_shortcuts(self) -> None:
        self.root.bind("<Return>", lambda _event: self.on_query_clicked())
        self.root.bind("<Delete>", lambda _event: self.on_kill_selected_clicked())

    def on_query_clicked(self) -> None:
        try:
            port = parse_port(self.port_var.get())
        except ValueError as exc:
            messagebox.showwarning("端口号无效", str(exc))
            return

        self.current_port = port
        self._set_busy(True, f"正在查询端口 {port} 的占用进程...")
        thread = threading.Thread(target=self._query_worker, args=(port,), daemon=True)
        thread.start()

    def _query_worker(self, port: int) -> None:
        try:
            records = query_port_records(port)
            self.root.after(0, lambda: self._show_query_result(port, records, None))
        except Exception as exc:
            self.root.after(0, lambda: self._show_query_result(port, [], exc))

    def _show_query_result(self, port: int, records: list[PortRecord], error: Exception | None) -> None:
        self._clear_tree()
        self.records = records

        if error is not None:
            self.status_var.set(f"查询失败：{error}")
            messagebox.showerror("查询失败", str(error))
        elif not records:
            self.status_var.set(f"端口 {port} 暂未发现占用进程。")
        else:
            for index, record in enumerate(records):
                self.tree.insert(
                    "",
                    tk.END,
                    iid=str(index),
                    values=(
                        record.protocol,
                        record.local_address,
                        record.remote_address,
                        record.state,
                        record.pid,
                        record.process_name,
                        record.process_path,
                    ),
                )
            unique_pids = {record.pid for record in records}
            self.status_var.set(f"端口 {port} 查询完成，发现 {len(unique_pids)} 个进程、{len(records)} 条连接记录。")

        self._set_busy(False)
        self._refresh_button_state()

    def on_kill_selected_clicked(self) -> None:
        selected_records = self._selected_records()
        if not selected_records:
            messagebox.showinfo("未选择进程", "请先选择要查杀的进程记录。")
            return
        self._confirm_and_kill(selected_records)

    def on_kill_all_clicked(self) -> None:
        if not self.records:
            messagebox.showinfo("无可查杀进程", "当前端口没有可查杀的进程。")
            return
        self._confirm_and_kill(self.records)

    def _confirm_and_kill(self, records: list[PortRecord]) -> None:
        records_by_pid = self._unique_records_by_pid(records)
        protected_records = [record for record in records_by_pid if is_protected_record(record)]
        killable_records = [record for record in records_by_pid if not is_protected_record(record)]

        if protected_records:
            protected_text = "\n".join(f"PID {record.pid}，{record.process_name}" for record in protected_records)
            messagebox.showwarning("已拦截高风险进程", f"以下系统或当前工具进程不会被查杀：\n{protected_text}")

        if not killable_records:
            return

        summary = "\n".join(f"PID {record.pid}，{record.process_name}" for record in killable_records)
        confirmed = messagebox.askyesno(
            "确认强制结束进程",
            f"将强制结束以下进程，未保存的数据可能丢失：\n{summary}\n\n确认继续？",
        )
        if not confirmed:
            return

        self._set_busy(True, "正在强制结束进程...")
        thread = threading.Thread(target=self._kill_worker, args=(killable_records,), daemon=True)
        thread.start()

    def _kill_worker(self, records: list[PortRecord]) -> None:
        results: list[str] = []
        for record in records:
            success, output = kill_process(record.pid)
            status = "成功" if success else "失败"
            detail = output or "无命令输出"
            results.append(f"PID {record.pid}（{record.process_name}）{status}：{detail}")
        self.root.after(0, lambda: self._show_kill_result(results))

    def _show_kill_result(self, results: list[str]) -> None:
        result_text = "\n\n".join(results)
        messagebox.showinfo("查杀结果", result_text)
        self.status_var.set("查杀命令执行完成，正在重新查询端口状态...")
        if self.current_port is not None:
            thread = threading.Thread(target=self._query_worker, args=(self.current_port,), daemon=True)
            thread.start()
        else:
            self._set_busy(False)

    def _selected_records(self) -> list[PortRecord]:
        selected: list[PortRecord] = []
        for item_id in self.tree.selection():
            if item_id.isdigit():
                index = int(item_id)
                if 0 <= index < len(self.records):
                    selected.append(self.records[index])
        return selected

    def _unique_records_by_pid(self, records: list[PortRecord]) -> list[PortRecord]:
        unique: dict[int, PortRecord] = {}
        for record in records:
            unique.setdefault(record.pid, record)
        return list(unique.values())

    def _clear_tree(self) -> None:
        for item_id in self.tree.get_children():
            self.tree.delete(item_id)

    def _set_busy(self, busy: bool, message: str | None = None) -> None:
        state = tk.DISABLED if busy else tk.NORMAL
        self.query_button.configure(state=state)
        if message:
            self.status_var.set(message)
        if busy:
            self.kill_button.configure(state=tk.DISABLED)
            self.kill_all_button.configure(state=tk.DISABLED)
        else:
            self._refresh_button_state()

    def _refresh_button_state(self) -> None:
        has_records = bool(self.records)
        has_selection = bool(self.tree.selection())
        self.kill_button.configure(state=tk.NORMAL if has_selection else tk.DISABLED)
        self.kill_all_button.configure(state=tk.NORMAL if has_records else tk.DISABLED)


def main() -> None:
    if not is_windows():
        raise SystemExit("本工具仅支持 Windows。")
    relaunch_as_admin()

    root = tk.Tk()
    app = PortKillerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
