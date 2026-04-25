import os
import csv
import tkinter as tk
from tkinter import ttk, filedialog

from IPv4Address import IPv4Address

class SubnetGUI:
    """
    Tkinter-based IPv4 subnetting visualization tool.

    Structure:
    - Input section (IP entry + sliders)
    - Address details panel (auto-bound to IPv4Address properties)
    - Subnet table (Treeview)
    - Theme + export controls

    Core behavior:
    - Parses input into IPv4Address object
    - Updates UI reactively on input change
    - Supports subnetting and supernetting via sliders
    """

    def __init__(self, root):
        self.root = root
        self.root.title("IPv4 Subnet Explorer")
        self.root.state("zoomed")
        self.icon = tk.PhotoImage(file=os.path.join(os.path.dirname(__file__), "icon.png"))
        self.root.iconphoto(True, self.icon)

        self._init_state()
        self._build_layout()
        self.setupTheme()

        # default value
        self.inputVariable.set("10.0.0.1/8")
        self.entry.focus()

    def _init_state(self):
        self.ip = None
        self.supernetIP = None
        self.inputFormat = 0
        self.darkMode = True
        self._message_after_id = None
        self.useOctetBoundary = False
        self.mode = "Classless"

    def _build_layout(self):
        self.root.rowconfigure(0, weight=1) # have root expand vertically to fill out window
        self.root.columnconfigure(0, weight=1) # have root expand horizontally to fill out window

        self.main = ttk.Frame(self.root, padding=10)
        self.main.grid(row=0, column=0, sticky="nsew")

        self.main.rowconfigure(3, weight=1) # have the table row expand vertically to take the remaining space
        self.main.columnconfigure(0, weight=1) # have main expand horizontally to fill out window

        self._create_input_section()
        self._create_info_panel()
        self._create_supernet_label()
        self._create_table()
        self._create_bottom_controls()

    def _create_input_section(self):
        top = ttk.Frame(self.main)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        top.columnconfigure(2, weight=1) # have sliders expand horizontally to take the remaining space

        ttk.Label(top, text="IP Address / Subnet", style="Header.TLabel").grid(row=0, column=0, sticky="w")

        self.inputVariable = tk.StringVar()

        # Trigger update() whenever input text changes
        self.inputVariable.trace_add("write", lambda *_: self.update())

        self.entry = ttk.Entry(top, textvariable=self.inputVariable, font=("Segoe UI", 10))
        self.entry.grid(row=1, column=0, padx=(0, 10), sticky="w")

        ttk.Label(top, text="Prefix").grid(row=1, column=1, sticky="w", padx=(0, 3))
        ttk.Label(top, text="Subnet").grid(row=2, column=1, sticky="w", padx=(0, 3))
        ttk.Label(top, text="Supernet").grid(row=3, column=1, sticky="w", padx=(0, 3))

        self.prefixSlider = tk.Scale(top, from_=1, to=32, orient="horizontal", command=self.updatePrefix)
        self.prefixSlider.grid(row=1, column=2, sticky="ew")

        self.subnetSlider = tk.Scale(top, from_=1, to=32, orient="horizontal", command=self.subnet)
        self.subnetSlider.grid(row=2, column=2, sticky="ew")

        self.supernetSlider = tk.Scale(top, from_=1, to=32, orient="horizontal", command=self.supernet)
        self.supernetSlider.grid(row=3, column=2, sticky="ew")

        self.octetVar = tk.BooleanVar()
        self.octetCheckbox = ttk.Checkbutton(top, text="Octet-boundary mode (faster, visual)", variable=self.octetVar, command=self.onToggleOctet)
        self.octetCheckbox.grid(row=2, column=0, sticky="w", pady=(5, 0))

    def _create_info_panel(self):
        info = ttk.LabelFrame(self.main, text="Address Details")
        info.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        self.labels = {}

        fields = [
            "ipStr", "cidrAdr", "ipBin",
            "netmaskStr", "netIDCIDR", "netmaskBin",
            "hostmaskStr", "ipInt", "hostmaskBin",
            "prefixLen", "netmaskInt", "netIDBin",
            "netIDStr", "hostmaskInt", "broadcastBin",
            "broadcastStr", "netIDInt", "reserved",
            "firstHost", "broadcastInt", "loopback",
            "lastHost", "privateUse", "limitedBroadcast",
            "totalAddresses", "linkLocal", "adrClassStr",
            "usableHosts", "multicast",
        ]

        fieldLabels = [
            "IP Address", "IP Address CIDR", "IP Address Binary",
            "Subnet Mask", "Network ID CIDR", "Subnet Mask Binary",
            "Host Mask", "IP Address Int", "Host Mask Binary",
            "Prefix Length", "Subnet Mask Int", "Network ID Binary",
            "Network ID", "Host Mask Int", "Broadcast Binary",
            "Broadcast", "Network ID Int", "Reserved Address",
            "First Host", "Broadcast Int", "Loopback",
            "Last Host", "Private Use", "Limited Broadcast",
            "Total Addresses", "Link Local", "Legacy Class",
            "Total Usable Hosts", "Multicast",
        ]

        # Dynamically adds labels under Address Details section
        for i, field in enumerate(fields):
            ttk.Label(info, text=fieldLabels[i] + ":").grid(row=i // 3, column=(i % 3) * 2, sticky="e", padx=5, pady=2)
            label = ttk.Label(info, text="")
            label.grid(row=i // 3, column=(i % 3) * 2 + 1, sticky="w")
            self.labels[field] = label

    def _create_supernet_label(self):
        self.supernetLabel = ttk.Label(self.main, text="", style="Header.TLabel")
        self.supernetLabel.grid(row=2, column=0, sticky="w")

    def _create_table(self):
        self.tableFrame = ttk.LabelFrame(self.main, text="Subnets", style="Header.TLabelframe")
        self.tableFrame.grid(row=3, column=0, sticky="nsew")

        self.tableFrame.rowconfigure(0, weight=1) # have subnets table expand vertically to fill out window
        self.tableFrame.columnconfigure(0, weight=1) # have subnets table expand horizontally to fill out window

        columns = ("Network", "HostRange", "Broadcast")

        self.table = ttk.Treeview(self.tableFrame, columns=columns, show="headings", height=12)
        self.table.grid(row=0, column=0, sticky="nsew")

        for col, text in (("Network", "Network ID"), ("HostRange", "Usable Host Range"), ("Broadcast", "Broadcast")):
            self.table.heading(col, text=text, command=lambda c=col: self.sortColumn(c, True))
            self.table.column(col, anchor="center", width=180)

        scrollbar = ttk.Scrollbar(self.tableFrame, command=self.table.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")

        self.table.config(yscrollcommand=scrollbar.set)

        self.table.bind("<Control-c>", self.copySelection)
        self.table.bind("<Control-C>", self.copySelection)

        self.table.bind("<Control-a>", self.selectAll)
        self.table.bind("<Control-A>", self.selectAll)

        self.menu = tk.Menu(self.main, tearoff=0)
        self.menu.add_command(label="Copy (Ctrl+C)", command=self.copySelection)
        self.menu.add_command(label="Select All (Ctrl+A)", command=self.selectAll)
        # Right-click binding (Windows/Linux)
        self.table.bind("<Button-3>", self.showContextMenu)
        # Right-click binding (macOS)
        self.table.bind("<Control-Button-1>", self.showContextMenu)

    def _create_bottom_controls(self):
        bottomFrame = ttk.Frame(self.main)
        bottomFrame.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        bottomFrame.columnconfigure(1, weight=1) # have buttons/status bar expand horizontally to fill out window

        self.themeButton = ttk.Button(bottomFrame, text="Light Mode", command=self.toggleTheme)
        self.themeButton.grid(row=0, column=0, sticky="w")

        self.statusBar = ttk.Label(bottomFrame, text="Ready", anchor="w")
        self.statusBar.grid(row=0, column=1, sticky="ew", padx=10)

        self.exportButton = ttk.Button(bottomFrame, text="Export to CSV", command=self.exportCSV)
        self.exportButton.grid(row=0, column=2, sticky="e")

    def setupTheme(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.applyTheme()

    def applyTheme(self):
        s = self.style

        # Define color palette for dark/light themes
        if self.darkMode:
            BG = "#1E1E1E"
            FG = "#D4D4D4"
            PANEL = "#252526"
            BORDER = "#303031"
            ACCENT = "#007ACC"
            ROW_ALT = "#2A2D2E"
            SELECT = "#0078D4"
        else:
            BG = "#FFFFFF"
            FG = "#000000"
            PANEL = "#F3F3F3"
            BORDER = "#D4D4D4"
            ACCENT = "#007ACC"
            ROW_ALT = "#E8E8E8"
            SELECT = "#90C2F9"

        self.root.configure(bg=BG)

        s.configure("TFrame", background=BG)
        s.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        s.configure("Header.TLabel", background=BG, foreground=FG, font=("Segoe UI", 11, "bold"))

        s.configure("TLabelframe", background=BG, bordercolor=BORDER)
        s.configure("TLabelframe.Label", background=BG, foreground=FG, font=("Segoe UI", 11, "bold"))

        s.configure("TEntry", fieldbackground=PANEL, foreground=FG, insertcolor=FG)

        s.configure("TButton", background=PANEL, foreground=FG)
        s.map("TButton", background=[("active", SELECT), ("!active", PANEL)], foreground=[("active", "white"), ("!active", FG)])

        s.configure("TCheckbutton", background=PANEL, foreground=FG)
        s.map("TCheckbutton", background=[("active", SELECT), ("!active", PANEL)], foreground=[("active", "white"), ("!active", FG)])

        s.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG, rowheight=26, font=("Consolas", 10))

        s.configure("Treeview.Heading", background=ACCENT, foreground="white", font=("Segoe UI", 10, "bold"))
        s.map("Treeview.Heading", background=[("active", SELECT), ("!active", PANEL)], foreground=[("active", "white"), ("!active", FG)])

        s.map("Treeview", background=[("selected", SELECT)], foreground=[("selected", "white")])

        # Table row alternating colors
        if self.darkMode:
            self.table.tag_configure("even", background=PANEL)
            self.table.tag_configure("odd", background=ROW_ALT)
        else:
            self.table.tag_configure("even", background="#ffffff")
            self.table.tag_configure("odd", background=ROW_ALT)

        for slider in [self.prefixSlider, self.subnetSlider, self.supernetSlider]:
            slider.configure(bg=BG, troughcolor=PANEL, fg=FG, activebackground=SELECT, highlightthickness=0)

    def toggleTheme(self):
        self.darkMode = not self.darkMode
        if self.darkMode:
            self.themeButton.configure(text="Light Mode")
        else:
            self.themeButton.configure(text="Dark Mode")
        self.applyTheme()

    def update(self):
        address = self.inputVariable.get().strip()

        if not address:
            return

        try:
            ip = IPv4Address(address)
            self.ip = ip

            # Preserve original input format when updating prefix
            self.inputFormat = self.detectFormat(address)

            # Bind IPv4Address properties to UI labels dynamically
            for key in self.labels:
                if key == "totalAddresses" or key == "usableHosts" or key.endswith("Int"):
                    self.labels[key].config(text=f"{getattr(ip, key):,d}")
                else:
                    self.labels[key].config(text=str(getattr(ip, key)))

            self.prefixSlider.set(ip.prefixLen)

            # Prevent subnet prefix from being <= current prefix
            if self.subnetSlider.get() <= ip.prefixLen:
                self.subnetSlider.set(min(self.ip.prefixLen + 1, 32))

            # If user selects invalid value (supernet size larger than or equal to current prefix), snap slider back to minimum valid prefix
            if self.supernetSlider.get() >= ip.prefixLen:
                self.supernetSlider.set(max(self.ip.prefixLen - 1, 1))

            self.subnet(self.subnetSlider.get())
            self.supernet(self.supernetSlider.get())

            # set theme foreground color and don't clear the message
            self.setStatus("", "Ready", 0)
        except Exception as ex:
            for key in self.labels:
                self.labels[key].config(text="")

            self.clearTable()
            self.supernetLabel.config(text="Supernet:")
            if len(str(ex)) > 120:
                self.setStatus("red", f"Invalid input: {str(ex)[:120]}...", 10)
                print(f"Invalid input: {str(ex)}")
            else:
                self.setStatus("red", f"Invalid input: {str(ex)}", 10)

    def detectFormat(self, address):
        """
        Determines how the user entered the IP address.

        Returns:
        int: format type
            1 = CIDR
            2 = dotted decimal (IP only)
            3 = dotted + netmask
            4 = integer + prefix
            5 = integer only
            0 = unknown
        """
        if address == f"{self.ip.cidrAdr}":
            return 1
        elif address == f"{self.ip.ipStr}":
            return 2
        elif address == f"{self.ip.ipStr} {self.ip.netmaskStr}":
            return 3
        elif address == f"{self.ip.ipInt} /{self.ip.prefixLen}":
            return 4
        elif address == f"{self.ip.ipInt}":
            return 5
        return 0

    def updatePrefix(self, value):
        if not self.ip:
            return

        newPrefix = int(value)
        if newPrefix != self.ip.prefixLen: # ensure there is a change
            if self.inputFormat == 1:
                self.inputVariable.set(f"{self.ip.ipStr}/{newPrefix}")
            elif self.inputFormat == 2:
                self.inputFormat = 1 # changing the prefix changes the format
                self.inputVariable.set(f"{self.ip.ipStr}/{newPrefix}")
            elif self.inputFormat == 3:
                temp = IPv4Address(f"{self.ip.ipStr}/{newPrefix}")
                self.inputVariable.set(f"{self.ip.ipStr} {temp.netmaskStr}")
            elif self.inputFormat == 4:
                self.inputVariable.set(f"{self.ip.ipInt} /{newPrefix}")
            elif self.inputFormat == 5:
                self.inputFormat = 4 # changing the prefix changes the format
                self.inputVariable.set(f"{self.ip.ipInt} /{newPrefix}")

    def subnet(self, value):
        if not self.ip:
            return

        # /32 cannot be subnetted further (single host)
        if self.ip.prefixLen == 32:
            self.subnetSlider.configure(state="disabled")
            self.clearTable()
            self.tableFrame.configure(text=f"Subnets ({self.mode})")
            return
        else:
            self.subnetSlider.configure(state="normal")

        if self.inputFormat == 2 or self.inputFormat == 5: # these are always a /32 and subnetting is not possible
            return

        newPrefix = int(value)

        # Prevent invalid subnet (must be larger prefix)
        if newPrefix <= self.ip.prefixLen:
            self.subnetSlider.set(min(self.ip.prefixLen + 1, 32))
            return

        if newPrefix > self.ip.prefixLen:
            self.clearTable()

            totalSubnets = 2 ** (newPrefix - self.ip.prefixLen)
            if not self.useOctetBoundary:
                if totalSubnets > 4096:
                    self.tableFrame.configure(text=f"Subnets ({self.mode})")
                    self.setStatus("red", f"Too many subnets ({totalSubnets:,d}). Enable octet-boundary mode or reduce prefix.")
                    return
                self.tableFrame.configure(text=f"{totalSubnets:,d} Subnets ({self.mode})")

            for i, ip in enumerate(self.ip.subnets(newPrefix, limit=4096, subnetByOctetBoundary=self.useOctetBoundary)):
                tag = "even" if i % 2 == 0 else "odd"
                self.table.insert("", "end", values=(ip.netIDCIDR, f"{ip.firstHost} - {ip.lastHost}", ip.broadcastStr), tags=(tag,))

            if self.useOctetBoundary:
                self.tableFrame.configure(text=f"{len(self.table.get_children()):,d} Subnets ({self.mode})")

    def supernet(self, value):
        if not self.ip:
            return
        
        # /1 cannot be supernetted further (largest possible network)
        if self.ip.prefixLen == 1:
            self.supernetSlider.configure(state="disabled")
            self.supernetLabel.config(text="Supernet: N/A")
            return
        else:
            self.supernetSlider.configure(state="normal")

        newPrefix = int(value)

        # Ensure supernet prefix is smaller than current prefix
        if newPrefix >= self.ip.prefixLen:
            self.supernetSlider.set(max(self.ip.prefixLen - 1, 1))
            return

        if newPrefix < self.ip.prefixLen:
            self.supernetIP = IPv4Address(f"{self.ip.ipStr}/{newPrefix}")

            self.supernetLabel.config(text=f"Supernet: {self.supernetIP.netIDCIDR} | Usable Host Range: {self.supernetIP.firstHost} - {self.supernetIP.lastHost} | Broadcast: {self.supernetIP.broadcastStr}")

    def sortColumn(self, col, reverse):
        data = []
        for k in self.table.get_children(""):
            ip = self.table.set(k, col)
            if "/" in ip:
                ip = ip.split("/")[0]
            elif " - " in ip:
                ip = ip.split(" - ")[0]
            data.append((ip, k))

        # Try numeric sort if possible.
        try:
            data.sort(key=lambda t: IPv4Address.ip_int_from_string(t[0].split("/")[0]), reverse=reverse)
        except: # Fallback to string sort if parsing fails.
            data.sort(reverse=reverse)

        for index, (_, k) in enumerate(data):
            self.table.move(k, "", index)

        for i, k in enumerate(self.table.get_children("")):
            tag = "even" if i % 2 == 0 else "odd"
            self.table.item(k, tags=(tag,))

        # toggle next sort direction
        self.table.heading(col, command=lambda: self.sortColumn(col, not reverse))

    def onToggleOctet(self):
        self.useOctetBoundary = self.octetVar.get()
        self.mode = "Octet-boundary" if self.useOctetBoundary else "Classless"
        self.clearTable()
        self.subnet(self.subnetSlider.get())

    def clearTable(self):
        for row in self.table.get_children():
            self.table.delete(row)

    def copySelection(self, event=None):
        selected = self.table.selection()
        if not selected:
            return

        rows = []
        for item in selected:
            values = self.table.item(item)["values"]
            rows.append("\t".join(map(str, values)))

        text = "\n".join(rows)

        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def selectAll(self, event=None):
        self.table.selection_set(self.table.get_children())

    def showContextMenu(self, event):
        # Select row under mouse
        rowId = self.table.identify_row(event.y)
        if rowId:
            if rowId not in self.table.selection():
                self.table.selection_set(rowId)
            self.menu.tk_popup(event.x_root, event.y_root)

    def setStatus(self, color, message, clearAfterSeconds=3):
        # Defer the update to the Tkinter event loop instead of running it immediately to avoid UI glitches from forced redraws and to ensure the update is processed in the correct event loop order rather than interleaving with other pending callbacks such as clears
        # This also handles rapid successive updates from sources like sliders or text input by allowing them to collapse into a single visible message representing only the most recent state

        # Defer the update to the Tkinter event loop instead of running it immediately to avoid UI glitches from forced redraws or from being cleared immediately if the _clear_message function is called immiately after setting the text
        # This handles rapid updates to the label from the slider or text input and only displays the last message during the burst of function calls
        self.root.after(0, self._apply_message, color, message, clearAfterSeconds)

    def _apply_message(self, color, message, clearAfterSeconds):
        self.statusBar.config(text=message, foreground=color)

        # cancel any previously scheduled clear so that an older message cannot clear the currently displayed message due to timing overlap in the event loop
        if self._message_after_id:
            self.root.after_cancel(self._message_after_id)
            self._message_after_id = None

        # Having the clearing label scheduled in this scheduled function call prevents the text update and clearing from happening right after each other during bursts of updates to tkinter GUI elements
        # Note: if clearAfterSeconds <= 0, the message won't be cleared
        if isinstance(clearAfterSeconds, int) and clearAfterSeconds > 0:
            self._message_after_id = self.root.after(clearAfterSeconds * 1000, self._clear_message)

    def _clear_message(self):
        self.statusBar.config(text="Ready", foreground="")
        self._message_after_id = None

    def exportCSV(self):
        if not self.table.get_children():
            self.setStatus("red", "No subnets to export")
            return

        filePath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title="Save subnet table")

        if not filePath:
            self.setStatus("red", "Export cancelled")
            return # user canceled

        try:
            with open(filePath, mode="w", newline="") as f:
                writer = csv.writer(f)

                writer.writerow(["Network ID", "Usable Host Range", "Broadcast"])

                for row in self.table.get_children():
                    writer.writerow(self.table.item(row)["values"])

            self.setStatus("green", "Export successful")
            print(f"Saved subnet data to {filePath}")
        except Exception as ex:
            self.setStatus("red", "Export failed", 5)
            print(ex)

if __name__ == "__main__":
    root = tk.Tk()
    app = SubnetGUI(root)
    root.mainloop()
