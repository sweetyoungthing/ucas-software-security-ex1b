"""Tk interface for the SFT/1 secure file transfer client."""

from datetime import datetime
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import unicodedata

from client import Client, TransferInterrupted, connection_args
from protocol import valid_name

WORKERS = 3


def display_size(size):
    if size < 1024:
        return f"{size:,} B"
    if size < 1024**2:
        return f"{size / 1024:.1f} KiB"
    return f"{size / 1024**2:.2f} MiB"


class App:
    def __init__(self, root, settings):
        self.root, self.settings = root, settings
        self.work = queue.Queue()
        self.events = queue.SimpleQueue()
        self.stopping = threading.Event()
        self.pending = {}
        self.active = set()
        self.next_job = 0
        self.list_revision = 0
        self.channel_versions = {}
        self.closing = False
        self._layout()
        self.workers = [
            threading.Thread(target=self._worker, args=(i,), daemon=True)
            for i in range(1, WORKERS + 1)
        ]
        for worker in self.workers:
            worker.start()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(60, self._poll)
        self.refresh()

    def _layout(self):
        self.root.title("SFT/1 安全文件传输")
        self.root.geometry("940x675")
        self.root.minsize(700, 520)
        shell = ttk.Frame(self.root, padding=(20, 15))
        shell.pack(fill="both", expand=True)
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(2, weight=4)
        shell.rowconfigure(4, weight=3)
        shell.rowconfigure(6, weight=2)

        title = ttk.Frame(shell)
        title.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        ttk.Label(title, text="SFT/1  安全文件传输", font=("TkDefaultFont", 20, "bold")).pack(anchor="w")
        endpoint = f"{self.settings['user']} @ {self.settings['host']}:{self.settings['port']}"
        self.connection_label = ttk.Label(title, text=f"{endpoint}    ·    等待连接")
        self.connection_label.pack(anchor="w", pady=(3, 0))

        toolbar = ttk.Frame(shell)
        toolbar.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(toolbar, text="远程文件", font=("TkDefaultFont", 13, "bold")).pack(side="left")
        self.buttons = [
            ttk.Button(toolbar, text="刷新列表", command=self.refresh),
            ttk.Button(toolbar, text="上传文件…", command=self.pick_upload),
            ttk.Button(toolbar, text="下载所选…", command=self.pick_download),
        ]
        for button in self.buttons:
            button.pack(side="left", padx=(9, 0))
        self.file_count = ttk.Label(toolbar, text="0 个文件")
        self.file_count.pack(side="right")
        self.files = self._table(shell, 2, [
            ("name", "文件名", 590, True),
            ("size", "大小", 125, False),
        ])
        self.files.bind("<Double-1>", lambda event: self.pick_download() if self.files.selection() else None)

        task_header = ttk.Frame(shell)
        task_header.grid(row=3, column=0, sticky="ew", pady=(12, 5))
        ttk.Label(task_header, text="传输队列", font=("TkDefaultFont", 13, "bold")).pack(side="left")
        self.queue_status = ttk.Label(task_header, text="0 进行中 · 0 等待")
        self.queue_status.pack(side="right")
        self.tasks = self._table(shell, 4, [
            ("kind", "操作", 74, False),
            ("name", "文件名", 360, True),
            ("progress", "进度", 193, False),
            ("state", "状态", 104, False),
        ])
        ttk.Label(shell, text="会话日志", font=("TkDefaultFont", 13, "bold")).grid(
            row=5, column=0, sticky="w", pady=(12, 5)
        )
        log_frame = ttk.Frame(shell)
        log_frame.grid(row=6, column=0, sticky="nsew")
        self.log = tk.Text(log_frame, wrap="word", height=5, state="disabled", padx=8, pady=6)
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.log.pack(side="left", fill="both", expand=True)

    @staticmethod
    def _table(parent, row, columns):
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=0, sticky="nsew")
        table = ttk.Treeview(
            frame, columns=[column[0] for column in columns], show="headings", selectmode="extended"
        )
        for key, label, width, stretch in columns:
            table.heading(key, text=label)
            table.column(key, width=width, stretch=stretch, anchor="w")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        table.pack(side="left", fill="both", expand=True)
        return table

    def _log(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", f"{datetime.now():%H:%M:%S}  {text}\n")
        if int(self.log.index("end-1c").split(".")[0]) > 200:
            self.log.delete("1.0", "21.0")
        self.log.see("end")
        self.log.configure(state="disabled")

    def refresh(self):
        if not self.closing:
            self.list_revision += 1
            self.work.put(("list", self.list_revision, None, None))

    def pick_upload(self):
        names = filedialog.askopenfilenames(parent=self.root, title="选择要上传的文件")
        for item in names:
            source = Path(item)
            name = unicodedata.normalize("NFC", source.name)
            if not valid_name(name):
                self._log(f"文件名不符合协议约束，跳过 {source.name}")
                continue
            self._enqueue("upload", name, source)

    def pick_download(self):
        selected = [str(self.files.set(item, "name")) for item in self.files.selection()]
        if not selected:
            self._log("请选择要下载的远程文件")
            return
        directory = filedialog.askdirectory(parent=self.root, title="选择下载目录", mustexist=True)
        if not directory:
            return
        existing = [name for name in selected if (Path(directory) / name).exists()]
        if existing and not messagebox.askyesno(
            "确认覆盖",
            f"下载目录已有 {len(existing)} 个同名文件。校验成功后替换这些文件？",
            parent=self.root,
        ):
            selected = [name for name in selected if name not in existing]
        for name in selected:
            self._enqueue("download", name, Path(directory) / name)

    def _enqueue(self, action, name, path):
        if self.closing:
            return
        target = name if action == "upload" else str(path.parent.resolve() / path.name)
        key = action, unicodedata.normalize("NFC", target.casefold())
        if key in self.pending.values():
            self._log(f"队列已有同一目标 {name}")
            return
        self.next_job += 1
        job = self.next_job
        self.pending[job] = key
        label = "上传" if action == "upload" else "下载"
        self.tasks.insert("", "end", iid=str(job), values=(label, name, "—", "排队"))
        self.tasks.see(str(job))
        self._update_queue()
        self.work.put((action, job, name, path))

    def _update_queue(self):
        self.queue_status.configure(text=f"{len(self.active)} 进行中 · {len(self.pending) - len(self.active)} 等待")

    def _worker(self, index):
        client = None
        try:
            while True:
                work = self.work.get()
                if self.stopping.is_set() or work is None:
                    return
                action, job, name, path = work
                if action != "list":
                    self.events.put(("start", job, index))
                try:
                    if client is None or not client.connected:
                        if client is not None:
                            client.close()
                        client = Client(**self.settings)
                        self.events.put(("connected", index, client.tls_version, client.local_address[1]))
                    if action == "list":
                        self.events.put(("files", job, client.list_files()))
                        continue

                    def progress(done, total):
                        if self.stopping.is_set():
                            raise TransferInterrupted("窗口正在关闭，保留已接收数据")
                        self.events.put(("progress", job, done, total))

                    if action == "upload":
                        receipt = client.upload(path, name, progress)
                    else:
                        receipt = client.download(name, path, progress)
                    self.events.put(("done", job, action, name, receipt))
                except Exception as exc:
                    if client is not None and not client.connected:
                        self.events.put(("disconnected", index))
                    self.events.put(("error", action, job, name, str(exc)))
        finally:
            if client is not None:
                client.close()

    def _connection_status(self):
        endpoint = f"{self.settings['user']} @ {self.settings['host']}:{self.settings['port']}"
        count = len(self.channel_versions)
        if count:
            versions = " / ".join(sorted(set(self.channel_versions.values())))
            status = f"{versions} 双向认证    ·    {count}/{WORKERS} 个长连接"
        else:
            status = "等待连接"
        self.connection_label.configure(text=f"{endpoint}    ·    {status}")

    def _poll(self):
        for _ in range(180):
            try:
                event, *data = self.events.get_nowait()
            except queue.Empty:
                break
            if event == "connected":
                index, version, port = data
                self.channel_versions[index] = version
                self._connection_status()
                self._log(f"通道 {index} 已认证 · {version} · 本地端口 {port}")
            elif event == "disconnected":
                self.channel_versions.pop(data[0], None)
                self._connection_status()
            elif event == "files":
                revision, files = data
                if revision == self.list_revision:
                    self.files.delete(*self.files.get_children())
                    for item in files:
                        self.files.insert("", "end", values=(item["name"], display_size(item["size"])))
                    self.file_count.configure(text=f"{len(files)} 个文件")
            elif event == "start":
                job, index = data
                self.active.add(job)
                self.tasks.set(str(job), "state", f"通道 {index}")
                self._update_queue()
            elif event == "progress":
                job, done, total = data
                percent = done / total * 100 if total else 100
                self.tasks.set(str(job), "progress", f"{display_size(done)} / {display_size(total)}  ·  {percent:.0f}%")
            elif event == "done":
                job, action, name, receipt = data
                self._complete(job, "已校验")
                self._log(
                    f"{'上传' if action == 'upload' else '下载'}完成 {name} · "
                    f"{display_size(receipt['size'])} · 续传偏移 {receipt['offset']:,} B · "
                    f"SHA-256 {receipt['sha256']}"
                )
                if action == "upload":
                    self.refresh()
            elif event == "error":
                action, job, name, error = data
                if action != "list":
                    self._complete(job, "失败")
                self._log(f"{name or '刷新列表'}失败 · {error}")
        if not self.closing or any(worker.is_alive() for worker in self.workers):
            self.root.after(60, self._poll)
        else:
            self.root.destroy()

    def _complete(self, job, label):
        self.tasks.set(str(job), "state", label)
        self.pending.pop(job)
        self.active.discard(job)
        self._update_queue()
        if len(self.tasks.get_children()) > 100:
            for row in self.tasks.get_children():
                if int(row) not in self.pending:
                    self.tasks.delete(row)
                    break

    def close(self):
        if not self.closing:
            self.closing = True
            for button in self.buttons:
                button.state(["disabled"])
            self._log("正在关闭长连接…")
            self.stopping.set()
            for _ in self.workers:
                self.work.put(None)


def main():
    args = connection_args("SFT/1 图形客户端")
    root = tk.Tk()
    App(root, vars(args))
    root.mainloop()


if __name__ == "__main__":
    main()
