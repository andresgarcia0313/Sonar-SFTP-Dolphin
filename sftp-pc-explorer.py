#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Explorador SSH/SFTP para Dolphin
Autor: ChatGPT
Descripción:
  - Descubre hosts con SSH (puerto 22) usando Nmap (IPv4) y Avahi/mDNS (IPv4/IPv6).
  - Lista los resultados en una interfaz amigable (Tkinter).
  - Permite abrir Dolphin apuntando a sftp://usuario@host:puerto/ruta
  - Permite abrir una terminal SSH al host seleccionado.
Requisitos recomendados:
  - python3-tk (Tkinter)
  - nmap (para escaneo opcional)
  - avahi-daemon y avahi-utils (para descubrimiento mDNS)
  - Dolphin (KDE) para abrir SFTP
"""
import threading
import xml.etree.ElementTree as ET
from tkinter import Tk, StringVar, BooleanVar, N, S, E, W, END, messagebox, Menu
from tkinter import ttk
import subprocess
import shutil
import ipaddress
import socket
import getpass
from datetime import datetime

APP_TITLE = "Explorador SSH/SFTP para Dolphin"
VERSION = "1.0.0"

def which(cmd):
    return shutil.which(cmd) is not None

def guess_default_subnet():
    # Intenta obtener una subred /24 a partir de la IP local
    # Método más robusto: conectar a un host externo para determinar la IP local
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # No es necesario que el host sea alcanzable
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_loopback:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
                return str(net)
    except Exception: # noqa
        pass
    # fallback común
    return "192.168.1.0/24"

def build_sftp_url(user, host, port, path):
    host_brackets = f"[{host}]" if ":" in host else host  # IPv6 en URL
    port_part = f":{port}" if port and int(port) != 22 else ""
    path = path.strip() or "/"
    if not path.startswith("/"):
        path = "/" + path
    return f"sftp://{user}@{host_brackets}{port_part}{path}"

def detect_terminal_cmd():
    # Detecta un emulador de terminal disponible para ejecutar ssh
    candidates = [
        ("konsole", ["konsole", "-e"]),
        ("gnome-terminal", ["gnome-terminal", "--"]),
        ("xfce4-terminal", ["xfce4-terminal", "-e"]),
        ("xterm", ["xterm", "-e"]),
        ("kitty", ["kitty"]),
        ("alacritty", ["alacritty", "-e"]),
        ("tilix", ["tilix", "-e"]),
    ]
    for name, cmd in candidates:
        if which(name):
            return cmd
    return None

def open_dolphin(url):
    # Abre Dolphin (preferido); si no está, usa xdg-open
    if which("dolphin"):
        try:
            subprocess.Popen(["dolphin", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            pass
    if which("xdg-open"):
        try:
            subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            pass
    return False

def open_ssh_in_terminal(user, host, port):
    term = detect_terminal_cmd()
    ssh_cmd = ["ssh", f"{user}@{host}"]
    if port and int(port) != 22:
        ssh_cmd = ["ssh", "-p", str(port), f"{user}@{host}"]
    if term:
        try:
            subprocess.Popen(term + ssh_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            pass
    # Fallback: intentarlo en background (no ideal)
    try:
        subprocess.Popen(ssh_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

class HostEntry:
    def __init__(self, hostname="", address="", port=22, source="", ts=None):
        self.hostname = hostname or ""
        self.address = address or ""
        self.port = int(port) if port else 22
        self.source = source or ""
        self.ts = ts or datetime.now()

    @property
    def key(self):
        # clave única por IP/hostname+puerto
        base = self.address or self.hostname
        return f"{base}:{self.port}"

    def display_name(self):
        return self.hostname or self.address

class ScannerBackend:
    def __init__(self, ui):
        self.ui = ui
        self.stop_flag = threading.Event()

    def stop(self):
        self.stop_flag.set()

    def run_nmap(self, subnet):
        if not which("nmap"):
            self.ui.append_status("Nmap no está instalado o no se encuentra en PATH.")
            return []
        self.ui.append_status(f"Ejecutando nmap en {subnet}...")
        cmd = ["nmap", "-oX", "-", "-p", "22", "--open", subnet]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=120)
        except subprocess.CalledProcessError as e:
            self.ui.append_status(f"Error de nmap: {e.output.strip()}")
            return []
        except subprocess.TimeoutExpired:
            self.ui.append_status("nmap tardó demasiado y fue cancelado.")
            return []
        # Parse XML
        hosts = []
        try:
            root = ET.fromstring(out)
            for host in root.findall("host"):
                if self.stop_flag.is_set():
                    break
                # Estado del host (up)
                status = host.find("status")
                if status is not None and status.attrib.get("state") != "up":
                    continue
                # IPs
                addrs = host.findall("address")
                ip = ""
                for a in addrs:
                    if a.attrib.get("addrtype") in ("ipv4", "ipv6"):
                        ip = a.attrib.get("addr", "")
                        break
                # Hostname si hay
                hname = ""
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hn = hostnames.find("hostname")
                    if hn is not None:
                        hname = hn.attrib.get("name", "")
                # Puerto 22 abierto
                ports = host.find("ports")
                port_ok = False
                if ports is not None:
                    for p in ports.findall("port"):
                        if p.attrib.get("portid") == "22":
                            state = p.find("state")
                            if state is not None and state.attrib.get("state") == "open":
                                port_ok = True
                                break
                if port_ok and (ip or hname):
                    hosts.append(HostEntry(hostname=hname, address=ip, port=22, source="Nmap"))
        except Exception as e:
            self.ui.append_status(f"Error al parsear salida de nmap: {e}")
        self.ui.append_status(f"nmap encontró {len(hosts)} host(s) con SSH.")
        return hosts

    def run_avahi(self):
        if not which("avahi-browse"):
            self.ui.append_status("avahi-browse no está instalado o no se encuentra en PATH.")
            return []
        hosts = []
        for svc, label in [("_ssh._tcp", "Avahi-SSH"), ("_sftp-ssh._tcp", "Avahi-SFTP")]:
            if self.stop_flag.is_set():
                break
            self.ui.append_status(f"Consultando Avahi: {svc} ...")
            cmd = ["avahi-browse", "-p", "-rt", svc]
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=60)
            except subprocess.CalledProcessError as e:
                self.ui.append_status(f"Error de avahi-browse: {e.output.strip()}")
                continue
            except subprocess.TimeoutExpired:
                self.ui.append_status("avahi-browse tardó demasiado y fue cancelado.")
                continue
            # Formato parseable (-p): "event;iface;proto;name;type;domain;host;address;port;txt"
            for line in out.splitlines():
                if self.stop_flag.is_set():
                    break
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(";")
                if len(parts) < 10:
                    continue
                event = parts[0]
                if event not in ("=",):  # solo entradas resueltas
                    continue
                name = parts[3]
                _type = parts[4]
                domain = parts[5]
                host = parts[6]
                address = parts[7]
                port = parts[8]
                try:
                    p = int(port)
                except:
                    p = 22
                hosts.append(HostEntry(hostname=host or name, address=address, port=p, source=label))
        self.ui.append_status(f"Avahi encontró {len(hosts)} host(s).")
        return hosts

class App:
    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        try:
            root.iconbitmap("")  # no-op si no hay icono; evita errores en algunos escritorios
        except Exception:
            pass

        # Variables
        self.username = StringVar(value=getpass.getuser())
        self.port = StringVar(value="22")
        self.path = StringVar(value="/")
        self.subnet = StringVar(value=guess_default_subnet())
        self.include_avahi = BooleanVar(value=True)
        self.include_nmap = BooleanVar(value=True)

        self.status_text = StringVar(value="Listo.")
        self.host_map = {}  # Para mapear IDs de Treeview a objetos HostEntry
        self.backend = ScannerBackend(self)
        self.scan_thread = None

        self._build_ui()
        self._update_dependency_badges()

    def _build_ui(self):
        container = ttk.Frame(self.root, padding=10)
        container.grid(row=0, column=0, sticky=(N, S, E, W))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Cabecera: configuración
        cfg = ttk.LabelFrame(container, text="Conexión", padding=10)
        cfg.grid(row=0, column=0, sticky=(E, W))
        for i in range(8):
            cfg.columnconfigure(i, weight=1)

        ttk.Label(cfg, text="Usuario:").grid(row=0, column=0, sticky=E, padx=4, pady=4)
        ttk.Entry(cfg, textvariable=self.username, width=18).grid(row=0, column=1, sticky=W, padx=4, pady=4)

        ttk.Label(cfg, text="Puerto:").grid(row=0, column=2, sticky=E, padx=4, pady=4)
        ttk.Entry(cfg, textvariable=self.port, width=8).grid(row=0, column=3, sticky=W, padx=4, pady=4)

        ttk.Label(cfg, text="Ruta inicial:").grid(row=0, column=4, sticky=E, padx=4, pady=4)
        ttk.Entry(cfg, textvariable=self.path, width=18).grid(row=0, column=5, sticky=W, padx=4, pady=4)

        ttk.Label(cfg, text="Subred (IPv4):").grid(row=0, column=6, sticky=E, padx=4, pady=4)
        ttk.Entry(cfg, textvariable=self.subnet, width=18).grid(row=0, column=7, sticky=W, padx=4, pady=4)

        # Descubrimiento
        disc = ttk.LabelFrame(container, text="Descubrir hosts", padding=10)
        disc.grid(row=1, column=0, sticky=(E, W), pady=(6, 0))
        disc.columnconfigure(0, weight=1)
        disc.columnconfigure(1, weight=1)
        disc.columnconfigure(2, weight=1)
        disc.columnconfigure(3, weight=1)

        self.chk_nmap = ttk.Checkbutton(disc, text="Usar Nmap", variable=self.include_nmap)
        self.chk_nmap.grid(row=0, column=0, sticky=W, padx=4, pady=4)

        self.chk_avahi = ttk.Checkbutton(disc, text="Usar Avahi/mDNS", variable=self.include_avahi)
        self.chk_avahi.grid(row=0, column=1, sticky=W, padx=4, pady=4)

        self.btn_scan = ttk.Button(disc, text="🔎 Explorar", command=self.on_scan)
        self.btn_scan.grid(row=0, column=2, sticky=E, padx=4, pady=4)

        self.btn_stop = ttk.Button(disc, text="⏹️ Detener", command=self.on_stop, state="disabled")
        self.btn_stop.grid(row=0, column=3, sticky=E, padx=4, pady=4)

        # Tabla de resultados
        table_frame = ttk.LabelFrame(container, text="Hosts disponibles (SSH/SFTP)", padding=10)
        table_frame.grid(row=2, column=0, sticky=(N, S, E, W), pady=(6, 0))
        container.rowconfigure(2, weight=1)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        columns = ("hostname", "ip", "port", "source")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("hostname", text="Nombre")
        self.tree.heading("ip", text="Dirección")
        self.tree.heading("port", text="Puerto")
        self.tree.heading("source", text="Fuente")

        self.tree.column("hostname", width=220, anchor="w")
        self.tree.column("ip", width=140, anchor="center")
        self.tree.column("port", width=60, anchor="center")
        self.tree.column("source", width=120, anchor="center")
        # La columna URL se elimina para simplificar, se genera al vuelo

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky=(N, S, E, W))
        vsb.grid(row=0, column=1, sticky=(N, S))

        # Menú contextual
        self.menu = Menu(self.root, tearoff=0)
        self.menu.add_command(label="Abrir en Dolphin (SFTP)", command=self.on_open_dolphin)
        self.menu.add_command(label="Conectar por SSH en terminal", command=self.on_open_ssh)
        self.menu.add_separator()
        self.menu.add_command(label="Copiar URL SFTP", command=self.on_copy_url)

        def show_context_menu(event):
            try:
                item = self.tree.identify_row(event.y)
                if item:
                    self.tree.selection_set(item)
                    self.menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.menu.grab_release()
        self.tree.bind("<Button-3>", show_context_menu)

        # Acciones rápidas
        actions = ttk.Frame(container)
        actions.grid(row=3, column=0, sticky=(E, W), pady=(6, 0))
        ttk.Button(actions, text="Abrir en Dolphin", command=self.on_open_dolphin).grid(row=0, column=0, padx=4, pady=4, sticky=W)
        ttk.Button(actions, text="Conectar por SSH", command=self.on_open_ssh).grid(row=0, column=1, padx=4, pady=4, sticky=W)
        ttk.Button(actions, text="Copiar URL", command=self.on_copy_url).grid(row=0, column=2, padx=4, pady=4, sticky=W)

        # Estado
        status = ttk.Frame(container)
        status.grid(row=4, column=0, sticky=(E, W), pady=(8, 0))
        status.columnconfigure(0, weight=1)

        self.dep_badge = ttk.Label(status, text="", foreground="#666")
        self.dep_badge.grid(row=0, column=1, sticky=E, padx=4)

        ttk.Label(status, textvariable=self.status_text, anchor="w").grid(row=0, column=0, sticky=(E, W))

        # Menú superior
        self._build_menubar()

        # Al cerrar
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_menubar(self):
        menubar = Menu(self.root)
        menu_arch = Menu(menubar, tearoff=0)
        menu_arch.add_command(label="Explorar", command=self.on_scan)
        menu_arch.add_separator()
        menu_arch.add_command(label="Salir", command=self.on_close)
        menubar.add_cascade(label="Archivo", menu=menu_arch)

        ayuda = Menu(menubar, tearoff=0)
        ayuda.add_command(label="Requisitos", command=self.show_requirements)
        ayuda.add_command(label="Acerca de", command=self.show_about)
        menubar.add_cascade(label="Ayuda", menu=ayuda)

        self.root.config(menu=menubar)

    def show_requirements(self):
        msg = (
            "Recomendado:\n"
            " • nmap (para escanear IPv4)\n"
            " • avahi-daemon y avahi-utils (para descubrimiento mDNS, IPv4/IPv6)\n"
            " • Dolphin (KDE) o xdg-open para abrir SFTP\n"
            " • Cliente SSH en terminal\n\n"
            "Consejo: puedes usar solo Avahi si tus equipos publican _ssh._tcp o _sftp-ssh._tcp.\n"
        )
        messagebox.showinfo("Requisitos", msg)

    def show_about(self):
        messagebox.showinfo("Acerca de", f"{APP_TITLE}\nVersión {VERSION}\n\n"
                                         "Escanea y descubre hosts con SSH/SFTP y los abre en Dolphin.\n"
                                         "Hecho con cariño y Tkinter.")

    def _update_dependency_badges(self):
        parts = []
        parts.append(f"Nmap: {'✔' if which('nmap') else '✖'}")
        parts.append(f"Avahi: {'✔' if which('avahi-browse') else '✖'}")
        parts.append(f"Dolphin: {'✔' if which('dolphin') else '✖'}")
        parts.append(f"SSH: {'✔' if which('ssh') else '✖'}")
        self.dep_badge.configure(text="  |  ".join(parts))

    def append_status(self, text):
        self.status_text.set(text)

    def on_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        try:
            # Validaciones básicas
            user = self.username.get().strip()
            if not user:
                messagebox.showerror("Error", "El usuario no puede estar vacío.")
                return
            port_str = self.port.get().strip()
            if port_str and not port_str.isdigit():
                messagebox.showerror("Error", "El puerto debe ser numérico.")
                return
            self.btn_scan.config(state="disabled")
            self.btn_stop.config(state="normal")
            self.append_status("Explorando hosts...")
            # Limpia tabla
            for i in self.tree.get_children():
                self.tree.delete(i)
            self.host_map.clear()
            # Inicia hilo de escaneo
            self.backend.stop_flag.clear()
            self.scan_thread = threading.Thread(target=self._scan_thread, daemon=True)
            self.scan_thread.start()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_stop(self):
        self.backend.stop()
        self.append_status("Cancelando exploración...")

    def _scan_thread(self):
        results_dict = {}
        count_added = 0

        try:
            if self.include_nmap.get():
                subnet = self.subnet.get().strip()
                # Validar subred
                try:
                    ipaddress.ip_network(subnet, strict=False)
                except ValueError:
                    self.append_status("Subred inválida. Ejemplo: 192.168.1.0/24")
                else:
                    nmap_hosts = self.backend.run_nmap(subnet)
                    for h in nmap_hosts:
                        if self.backend.stop_flag.is_set():
                            break
                        key = h.key
                        if key not in results_dict:
                            results_dict[key] = h
                            count_added += 1

            if self.include_avahi.get() and not self.backend.stop_flag.is_set():
                avahi_hosts = self.backend.run_avahi()
                for h in avahi_hosts:
                    if self.backend.stop_flag.is_set():
                        break
                    key = h.key
                    if key not in results_dict:
                        results_dict[key] = h
                        count_added += 1

            # volcar en la UI
            if not self.backend.stop_flag.is_set():
                self.root.after(0, self._populate_table, list(results_dict.values()))
                self.append_status(f"Listo. {len(results_dict)} host(s) disponibles.")
            else:
                self.append_status("Exploración detenida.")
        finally:
            self.root.after(0, lambda: (self.btn_scan.config(state="normal"), self.btn_stop.config(state="disabled")))

    def _populate_table(self, hosts):
        # Orden: por hostname/address
        hosts = sorted(hosts, key=lambda h: (h.hostname or h.address, h.address))
        self.host_map.clear()
        for h in hosts:
            item_id = self.tree.insert("", END, values=(h.hostname or "-", h.address or "-", h.port, h.source))
            self.host_map[item_id] = h

    def _get_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Atención", "Selecciona un host de la lista.")
            return None
        item_id = sel[0]
        return self.host_map.get(item_id)

    def on_open_dolphin(self):
        host_entry = self._get_selected()
        if not host_entry:
            return

        user = self.username.get().strip()
        host = host_entry.address or host_entry.hostname
        port = host_entry.port
        path = self.path.get().strip()
        url = build_sftp_url(user, host, port, path)

        ok = open_dolphin(url)
        if not ok:
            self.root.clipboard_clear()
            self.root.clipboard_append(url)
            messagebox.showinfo("No se pudo abrir Dolphin", "No se pudo lanzar Dolphin/xdg-open.\n"
                                                            "La URL SFTP se copió al portapapeles:\n\n" + url)
        else:
            self.append_status(f"Abriendo en Dolphin: {url}")

    def on_copy_url(self):
        host_entry = self._get_selected()
        if not host_entry:
            return

        user = self.username.get().strip()
        host = host_entry.address or host_entry.hostname
        port = host_entry.port
        path = self.path.get().strip()
        url = build_sftp_url(user, host, port, path)

        self.root.clipboard_clear()
        self.root.clipboard_append(url)
        self.append_status("URL SFTP copiada al portapapeles.")

    def on_open_ssh(self):
        host_entry = self._get_selected()
        if not host_entry:
            return

        user = self.username.get().strip()
        host = host_entry.address or host_entry.hostname
        port = host_entry.port
        if not host:
            messagebox.showerror("Error", "No se pudo determinar el host/IP.")
            return
        ok = open_ssh_in_terminal(user, host, port)
        if not ok:
            messagebox.showerror("Error", "No se pudo lanzar la terminal/ssh. Verifica que tengas un emulador de terminal disponible.")
        else:
            self.append_status(f"Abriendo SSH: {user}@{host}:{port}")

    def on_close(self):
        try:
            self.backend.stop()
        except Exception:
            pass
        self.root.destroy()

def main():
    root = Tk()
    app = App(root)
    root.geometry("918x520")
    root.minsize(820, 420)
    root.mainloop()

if __name__ == "__main__":
    main()
