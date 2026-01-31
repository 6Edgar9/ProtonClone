import customtkinter as ctk
import requests
import os
import base64
from tkinter import messagebox, filedialog
from crypto_manager import CryptoManager

# --- CONFIGURACIÓN VISUAL ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")  

# --- CONFIGURACIÓN TÉCNICA ---
SERVER = "http://127.0.0.1:8000"
TOKEN = None
MY_PRIVATE_KEY = None
CURRENT_USER = None
crypto = CryptoManager()

class ChasquiApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Ventana Principal
        self.title("ChasquiCrypt - Mensajería Blindada")
        self.geometry("1000x700")
        
        # Variables de estado
        self.current_file_attachment = None 
        
        # Contenedor Principal
        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True)

        self.show_login()

    # ==========================================
    # 1. SISTEMA DE LOGIN Y REGISTRO
    # ==========================================
    def show_login(self):
        for widget in self.container.winfo_children(): widget.destroy()
        login_frame = ctk.CTkFrame(self.container, width=400, corner_radius=15)
        login_frame.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(login_frame, text="🏃", font=("Arial", 60)).pack(pady=(30, 5))

        ctk.CTkLabel(login_frame, text="CHASQUICRYPT", font=("Roboto Medium", 26, "bold")).pack(pady=(0, 25))

        self.entry_user = ctk.CTkEntry(login_frame, placeholder_text="Usuario", width=280, height=40)
        self.entry_user.pack(pady=10)
        
        self.entry_pass = ctk.CTkEntry(login_frame, placeholder_text="Contraseña", show="*", width=280, height=40)
        self.entry_pass.pack(pady=10)

        ctk.CTkButton(login_frame, text="ACCEDER", command=self.attempt_login, width=280, height=40).pack(pady=20)
        ctk.CTkButton(login_frame, text="Registrarse", command=self.attempt_register, fg_color="transparent", border_width=1, width=280).pack(pady=(0, 40))

    def attempt_login(self):
        global TOKEN, MY_PRIVATE_KEY, CURRENT_USER
        user = self.entry_user.get()
        pwd = self.entry_pass.get()

        if not user or not pwd: return

        try:
            res = requests.post(f"{SERVER}/token", data={"username": user, "password": pwd})
            if res.status_code == 200:
                data = res.json()
                TOKEN = data["access_token"]
                try:
                    MY_PRIVATE_KEY = crypto.load_private_key(data["private_key_enc"].encode(), pwd)
                    CURRENT_USER = user
                    self.show_dashboard()
                except:
                    messagebox.showerror("Error", "Llave corrupta o contraseña incorrecta.")
            else:
                messagebox.showerror("Error", "Credenciales inválidas.")
        except Exception as e:
            messagebox.showerror("Conexión", f"Error: {e}")

    def attempt_register(self):
        user = self.entry_user.get(); pwd = self.entry_pass.get()
        if not user or not pwd: return
        try:
            priv, pub = crypto.generate_key_pair()
            res = requests.post(f"{SERVER}/register", json={
                "username": user, "password": pwd,
                "public_key_pem": crypto.serialize_public_key(pub).decode(),
                "encrypted_private_key_pem": crypto.serialize_private_key(priv, pwd).decode()
            })
            if res.status_code == 200: messagebox.showinfo("Éxito", "Cuenta creada. Inicia sesión.")
            else: messagebox.showerror("Error", "Fallo el registro.")
        except Exception as e: messagebox.showerror("Error", str(e))

    # ==========================================
    # 2. DASHBOARD PRINCIPAL
    # ==========================================
    def show_dashboard(self):
        for widget in self.container.winfo_children(): widget.destroy()

        # Sidebar
        self.sidebar = ctk.CTkFrame(self.container, width=220, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")

        ctk.CTkLabel(self.sidebar, text=f"👤 {CURRENT_USER}", font=("Roboto Medium", 18)).pack(pady=40)
        
        self.create_nav_btn("📝 Redactar", "compose")
        self.create_nav_btn("📥 Bandeja Entrada", "inbox")
        self.create_nav_btn("📤 Enviados", "sent")
        self.create_nav_btn("⚙️ Mi Cuenta", "account") # <--- NUEVO BOTÓN

        ctk.CTkFrame(self.sidebar, fg_color="transparent").pack(expand=True, fill="both")
        ctk.CTkButton(self.sidebar, text="🔒 Salir", command=self.logout, fg_color="#cf4444", hover_color="#8a2be2").pack(pady=20, padx=20, fill="x")

        # Área Principal
        self.main_area = ctk.CTkFrame(self.container, corner_radius=0, fg_color="transparent")
        self.main_area.pack(side="right", fill="both", expand=True, padx=20, pady=20)
        
        self.view_inbox()

    def create_nav_btn(self, text, view):
        ctk.CTkButton(self.sidebar, text=text, command=lambda: self.switch_view(view), 
                      fg_color="transparent", border_width=1, anchor="w").pack(pady=5, padx=20, fill="x")

    def switch_view(self, view_name):
        for widget in self.main_area.winfo_children(): widget.destroy()
        if view_name == "compose": self.view_compose()
        elif view_name == "inbox": self.view_inbox()
        elif view_name == "sent": self.view_sent()
        elif view_name == "account": self.view_account() # <--- NUEVA VISTA

    def logout(self):
        global TOKEN; TOKEN = None
        self.show_login()

    # ==========================================
    # 3. VISTA: REDACTAR
    # ==========================================
    def view_compose(self):
        self.current_file_attachment = None 
        
        ctk.CTkLabel(self.main_area, text="📝 Redactar Nuevo Chasqui", font=("Arial", 24, "bold")).pack(anchor="w", pady=(0, 20))

        ctk.CTkLabel(self.main_area, text="Destinatario (Usuario):").pack(anchor="w")
        self.entry_dest = ctk.CTkEntry(self.main_area, width=400)
        self.entry_dest.pack(anchor="w", pady=(0, 10))

        ctk.CTkLabel(self.main_area, text="Mensaje Secreto:").pack(anchor="w")
        self.txt_body = ctk.CTkTextbox(self.main_area, height=200, width=600)
        self.txt_body.pack(anchor="w", pady=(0, 10))

        self.lbl_file = ctk.CTkLabel(self.main_area, text="⚪ Sin archivo adjunto", text_color="gray")
        self.lbl_file.pack(anchor="w")
        
        btn_frame = ctk.CTkFrame(self.main_area, fg_color="transparent")
        btn_frame.pack(anchor="w", pady=10)
        
        ctk.CTkButton(btn_frame, text="📎 Adjuntar Archivo", command=self.select_file, width=150).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_frame, text="🚀 ENVIAR CHASQUI", command=self.send_chasqui, fg_color="#2CC985", width=200).pack(side="left")

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.current_file_attachment = path
            self.lbl_file.configure(text=f"📎 {os.path.basename(path)}", text_color="#2CC985")

    def send_chasqui(self):
        dest = self.entry_dest.get()
        body = self.txt_body.get("1.0", "end-1c")
        
        if not dest: return messagebox.showwarning("Falta datos", "Escribe un destinatario")
        if not body.strip() and not self.current_file_attachment:
            return messagebox.showwarning("Vacío", "El mensaje está vacío.")

        try:
            kres = requests.get(f"{SERVER}/get-public-key/{dest}", headers={"Authorization": f"Bearer {TOKEN}"})
            if kres.status_code != 200: return messagebox.showerror("Error", "Usuario no encontrado")
            pub_key = kres.json()["public_key"].encode()

            payload_data = {}
            payload_files = {}

            # Cifrar y Firmar Texto
            if body.strip():
                enc_bytes = crypto.encrypt_bytes_for_user(body.encode("utf-8"), pub_key)
                sig_bytes = crypto.sign_data(enc_bytes, MY_PRIVATE_KEY) 
                payload_data["encrypted_text"] = base64.b64encode(enc_bytes).decode('utf-8')
                payload_data["text_signature"] = base64.b64encode(sig_bytes).decode('utf-8')

            # Cifrar y Firmar Archivo
            if self.current_file_attachment:
                enc_file = crypto.encrypt_for_user(self.current_file_attachment, pub_key)
                sig_file = crypto.sign_data(enc_file, MY_PRIVATE_KEY)
                
                temp_name = "temp_gui_upload.enc"
                with open(temp_name, "wb") as f: f.write(enc_file)
                
                real_name = os.path.basename(self.current_file_attachment)
                payload_files["file"] = (real_name, open(temp_name, "rb"))
                payload_data["file_signature"] = base64.b64encode(sig_file).decode('utf-8')

            if "file" not in payload_files: payload_files["file"] = ("", b"")

            res = requests.post(f"{SERVER}/upload/", params={"recipient_username": dest},
                                data=payload_data, files=payload_files, headers={"Authorization": f"Bearer {TOKEN}"})

            if "file" in payload_files and hasattr(payload_files["file"][1], "close"): payload_files["file"][1].close()
            if os.path.exists("temp_gui_upload.enc"): os.remove("temp_gui_upload.enc")

            if res.status_code == 200:
                messagebox.showinfo("Éxito", "✅ Chasqui enviado y firmado.")
                self.switch_view("inbox")
            else:
                messagebox.showerror("Error Servidor", res.text)

        except Exception as e:
            messagebox.showerror("Error Crítico", str(e))

    # ==========================================
    # 4. VISTAS: BANDEJA Y ENVIADOS
    # ==========================================
    def view_inbox(self): self.build_list_view("inbox")
    def view_sent(self): self.build_list_view("sent")

    def build_list_view(self, mode):
        title = "📥 Bandeja de Entrada" if mode == "inbox" else "📤 Historial de Enviados"
        endpoint = "my-files" if mode == "inbox" else "sent-items"
        
        # Cabecera
        head = ctk.CTkFrame(self.main_area, fg_color="transparent")
        head.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(head, text=title, font=("Arial", 24, "bold")).pack(side="left")
        
        # Botonera Derecha
        btn_frame = ctk.CTkFrame(head, fg_color="transparent")
        btn_frame.pack(side="right")
        ctk.CTkButton(btn_frame, text="🔄 Recargar", width=100, command=lambda: self.switch_view(mode)).pack(side="left", padx=5)
        
        if mode == "inbox":
            ctk.CTkButton(btn_frame, text="💣 Vaciar Todo", width=100, fg_color="#cf4444", 
                          command=self.empty_inbox).pack(side="left", padx=5)

        # Scroll
        scroll = ctk.CTkScrollableFrame(self.main_area, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        try:
            res = requests.get(f"{SERVER}/{endpoint}/", headers={"Authorization": f"Bearer {TOKEN}"})
            if res.status_code != 200:
                ctk.CTkLabel(scroll, text=f"⚠️ Error servidor: {res.status_code}", text_color="orange").pack(pady=20)
                return

            files = res.json()
            if not isinstance(files, list) or not files:
                ctk.CTkLabel(scroll, text="📭 No hay mensajes.", font=("Arial", 16)).pack(pady=50)
                return

            for msg in reversed(files): 
                self.create_msg_card(scroll, msg, mode)

        except Exception as e:
            ctk.CTkLabel(scroll, text=f"Error: {e}").pack()

    def create_msg_card(self, parent, msg, mode):
        card_color = "#2b2b2b"
        status_icon = ""
        
        if mode == "inbox":
            if msg.get('is_read'):
                card_color = "#1f1f1f" 
                status_icon = "👁️"
            else:
                card_color = "#2a4d69" 
                status_icon = "🔥 NUEVO"

        card = ctk.CTkFrame(parent, corner_radius=10, fg_color=card_color)
        card.pack(fill="x", pady=5, padx=5)

        icon = "📦"
        if msg.get('encrypted_text') and not msg.get('filename'): icon = "📝"
        if not msg.get('encrypted_text') and msg.get('filename'): icon = "📎"
        
        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(side="left", padx=10, pady=10)
        
        if mode == "inbox":
            lbl_from = f"De: {msg.get('sender_username', 'Desconocido')}  {status_icon}"
        else:
            dest = msg.get('recipient_username', 'Desconocido')
            lbl_from = f"Para: {dest}" 
            
        ctk.CTkLabel(info_frame, text=f"{icon} {lbl_from}", font=("Arial", 14, "bold")).pack(anchor="w")
        
        subtext = "Texto cifrado"
        if msg.get('filename'): subtext += f" + {msg['filename']}"
        ctk.CTkLabel(info_frame, text=subtext, text_color="gray", font=("Arial", 12)).pack(anchor="w")

        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(side="right", padx=10)

        if mode == "inbox":
            ctk.CTkButton(btn_frame, text="🔓 Leer", width=80, fg_color="#2CC985", 
                          command=lambda: self.open_message_modal(msg)).pack(side="left", padx=5)
        
        ctk.CTkButton(btn_frame, text="🗑️", width=40, fg_color="#cf4444", 
                      command=lambda: self.delete_msg(msg['id'], mode)).pack(side="left")

    # ==========================================
    # 5. LECTOR SEGURO
    # ==========================================
    def open_message_modal(self, msg):
        if not msg.get('is_read'):
            try:
                requests.put(f"{SERVER}/mark-read/{msg['id']}", headers={"Authorization": f"Bearer {TOKEN}"})
                msg['is_read'] = True 
            except: pass

        modal = ctk.CTkToplevel(self)
        modal.title("Visor Seguro")
        modal.geometry("600x500")
        modal.attributes('-topmost', True)

        content = ctk.CTkScrollableFrame(modal)
        content.pack(fill="both", expand=True, padx=20, pady=20)

        sender = msg.get('sender_username')
        ctk.CTkLabel(content, text=f"Mensaje de {sender}", font=("Arial", 18, "bold")).pack(anchor="w")

        sender_pub_key = None
        if sender:
            try:
                kres = requests.get(f"{SERVER}/get-public-key/{sender}", headers={"Authorization": f"Bearer {TOKEN}"})
                if kres.status_code == 200: sender_pub_key = kres.json()["public_key"].encode()
            except: pass
        
        if msg.get('encrypted_text'):
            ctk.CTkLabel(content, text="📝 Contenido:", font=("Arial", 14, "bold")).pack(anchor="w", pady=(10, 5))
            try:
                enc_bytes = base64.b64decode(msg['encrypted_text'])
                
                status_sig = "⚠️ Firma no verificada"
                color_sig = "orange"
                if sender_pub_key and msg.get('text_signature'):
                    sig_bytes = base64.b64decode(msg['text_signature'])
                    if crypto.verify_signature(enc_bytes, sig_bytes, sender_pub_key):
                        status_sig = "✅ FIRMA VÁLIDA (Auténtico)"
                        color_sig = "#2CC985"
                    else:
                        status_sig = "❌ FIRMA FALSA (Peligro)"
                        color_sig = "#cf4444"
                
                ctk.CTkLabel(content, text=status_sig, text_color=color_sig).pack(anchor="w")

                dec_bytes = crypto.decrypt_bytes(enc_bytes, MY_PRIVATE_KEY)
                texto_plano = dec_bytes.decode("utf-8")
                
                box = ctk.CTkTextbox(content, height=150)
                box.pack(fill="x")
                box.insert("0.0", texto_plano)
                box.configure(state="disabled")

            except Exception as e:
                ctk.CTkLabel(content, text=f"Error: {e}", text_color="red").pack()

        if msg.get('filename'):
            ctk.CTkLabel(content, text="📎 Adjunto:", font=("Arial", 14, "bold")).pack(anchor="w", pady=(20, 5))
            ctk.CTkLabel(content, text=msg['filename']).pack(anchor="w")
            
            ctk.CTkButton(content, text="⬇️ Descargar y Verificar", 
                          command=lambda: self.download_file(msg, sender_pub_key, modal)).pack(pady=10)

    def download_file(self, msg, pub_key, modal_window):
        try:
            r = requests.get(f"{SERVER}/download/{msg['id']}", headers={"Authorization": f"Bearer {TOKEN}"})
            if r.status_code == 200:
                if pub_key and msg.get('file_signature'):
                    sig = base64.b64decode(msg['file_signature'])
                    if not crypto.verify_signature(r.content, sig, pub_key):
                        modal_window.attributes('-topmost', False)
                        if not messagebox.askyesno("ALERTA", "Firma digital FALLÓ. ¿Guardar igual?"):
                            modal_window.attributes('-topmost', True)
                            return
                        modal_window.attributes('-topmost', True)
                
                dec_file = crypto.decrypt_bytes(r.content, MY_PRIVATE_KEY)
                
                modal_window.attributes('-topmost', False)
                path = filedialog.asksaveasfilename(initialfile="DEC_" + msg['filename'])
                modal_window.attributes('-topmost', True)
                
                if path:
                    with open(path, "wb") as f: f.write(dec_file)
                    messagebox.showinfo("Éxito", "Archivo guardado.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_msg(self, fid, mode):
        if messagebox.askyesno("Confirmar", "¿Borrar este mensaje?"):
            requests.delete(f"{SERVER}/delete/{fid}", headers={"Authorization": f"Bearer {TOKEN}"})
            self.switch_view(mode)

    def empty_inbox(self):
        if messagebox.askyesno("PELIGRO", "¿Borrar TODA la bandeja?"):
            try:
                requests.delete(f"{SERVER}/empty-inbox/", headers={"Authorization": f"Bearer {TOKEN}"})
                self.switch_view("inbox")
                messagebox.showinfo("Limpieza", "Bandeja vaciada.")
            except Exception as e: messagebox.showerror("Error", str(e))

    # ==========================================
    # 6. GESTIÓN DE CUENTA (NUEVO)
    # ==========================================
    def view_account(self):
        ctk.CTkLabel(self.main_area, text="⚙️ Gestión de Cuenta", font=("Arial", 24, "bold")).pack(anchor="w", pady=(0, 20))
        
        # Datos del Usuario
        info_frame = ctk.CTkFrame(self.main_area)
        info_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(info_frame, text=f"Usuario Actual:  {CURRENT_USER}", font=("Arial", 16)).pack(pady=15)
        ctk.CTkLabel(info_frame, text="(El nombre de usuario no se puede cambiar por seguridad)", text_color="gray").pack(pady=(0,15))

        # Cambiar Contraseña
        pwd_frame = ctk.CTkFrame(self.main_area)
        pwd_frame.pack(fill="x", pady=20)
        ctk.CTkLabel(pwd_frame, text="🔐 Cambiar Contraseña", font=("Arial", 16, "bold")).pack(anchor="w", padx=20, pady=10)
        
        self.entry_old_pwd = ctk.CTkEntry(pwd_frame, placeholder_text="Contraseña Actual", show="*", width=300)
        self.entry_old_pwd.pack(pady=5)
        
        self.entry_new_pwd = ctk.CTkEntry(pwd_frame, placeholder_text="Nueva Contraseña", show="*", width=300)
        self.entry_new_pwd.pack(pady=5)
        
        ctk.CTkButton(pwd_frame, text="Actualizar Contraseña", command=self.change_password_action).pack(pady=15)

        # Zona de Peligro
        danger_frame = ctk.CTkFrame(self.main_area, fg_color="#3d1818", border_color="red", border_width=1)
        danger_frame.pack(fill="x", pady=30)
        
        ctk.CTkLabel(danger_frame, text="⚠️ ZONA DE PELIGRO", text_color="red", font=("Arial", 14, "bold")).pack(pady=10)
        ctk.CTkLabel(danger_frame, text="Esta acción borrará tus llaves y archivos para siempre.", text_color="#ffcccc").pack()
        
        ctk.CTkButton(danger_frame, text="☢️ ELIMINAR MI CUENTA", fg_color="red", hover_color="darkred", 
                      command=self.delete_account_action).pack(pady=15)

    def change_password_action(self):
        old = self.entry_old_pwd.get()
        new = self.entry_new_pwd.get()
        if not old or not new: return messagebox.showwarning("Faltan datos", "Escribe ambas contraseñas.")
        
        try:
            print("🔄 Re-encriptando llave maestra...")
            new_key_bytes = crypto.serialize_private_key(MY_PRIVATE_KEY, new)
            new_key_pem = new_key_bytes.decode('utf-8')

            res = requests.put(f"{SERVER}/change-password", 
                               json={
                                   "old_password": old, 
                                   "new_password": new,
                                   "new_encrypted_private_key": new_key_pem
                               },
                               headers={"Authorization": f"Bearer {TOKEN}"})
            
            if res.status_code == 200:
                messagebox.showinfo("Éxito", "Seguridad actualizada. \nTu llave privada ha sido re-encriptada con la nueva clave.")
                self.entry_old_pwd.delete(0, 'end')
                self.entry_new_pwd.delete(0, 'end')
            else:
                messagebox.showerror("Error", res.json().get("detail", "Error al cambiar contraseña"))
        except Exception as e: messagebox.showerror("Error Crítico", str(e))

    def delete_account_action(self):
        if messagebox.askyesno("CONFIRMAR ELIMINACIÓN", "¿ESTÁS SEGURO?\n\n- Se borrarán todos tus mensajes.\n- Se borrará tu usuario.\n- NO se puede deshacer."):
            try:
                res = requests.delete(f"{SERVER}/delete-account", headers={"Authorization": f"Bearer {TOKEN}"})
                if res.status_code == 200:
                    messagebox.showinfo("Adiós", "Tu cuenta ha sido eliminada. El programa se cerrará.")
                    self.destroy()
                else:
                    messagebox.showerror("Error", "No se pudo eliminar la cuenta.")
            except Exception as e: messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = ChasquiApp()
    app.mainloop()