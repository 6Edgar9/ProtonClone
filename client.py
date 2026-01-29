import requests
import os
import getpass
import json
import time
import base64
from tkinter import Tk, filedialog # Librerías para ventanas gráficas
from crypto_manager import CryptoManager

# --- CONFIGURACIÓN ---
SERVER = "http://127.0.0.1:8000"
TOKEN = None
MY_PRIVATE_KEY = None
CURRENT_USER = None
crypto = CryptoManager()
CONTACTS_FILE = "contacts.json" # Agenda local

# --- UTILIDADES DE INTERFAZ ---
def clear():
    """Limpia la pantalla de la terminal (Windows/Linux)"""
    os.system('cls' if os.name == 'nt' else 'clear')

def header(titulo):
    """Encabezado dinámico con usuario"""
    clear()
    print("="*60)
    # Si estamos logueados, mostramos el usuario arriba a la derecha
    user_txt = f"👤 {CURRENT_USER}" if CURRENT_USER else "👤 Invitado"
    
    # Formato:  | TITULO           USUARIO |
    espacios = 60 - len(titulo) - len(user_txt) - 4
    if espacios < 1: espacios = 1
    
    print(f" {titulo}" + " "*espacios + f"{user_txt} ")
    print("="*60 + "\n")

def pause():
    input("\nPresiona ENTER para continuar...")

# --- UTILIDADES DE ARCHIVOS (GUI) ---
def seleccionar_archivo_grafico():
    """Abre una ventana de Windows para elegir archivo"""
    print("⏳ Abriendo ventana de selección...")
    root = Tk()
    root.withdraw() # Oculta la ventanita blanca fea de Tkinter
    root.attributes('-topmost', True) # Fuerza la ventana a aparecer encima
    
    file_path = filedialog.askopenfilename(title="Selecciona el archivo secreto")
    root.destroy()
    
    if file_path:
        print(f"✅ Archivo seleccionado: {os.path.basename(file_path)}")
        return file_path
    else:
        print("❌ Selección cancelada.")
        return None

# --- GESTIÓN DE CONTACTOS (AGENDA PERSONAL) ---
def get_agenda_filename():
    """Genera el nombre del archivo según quién esté logueado"""
    if not CURRENT_USER: return "contacts_invitado.json"
    # Limpiamos el nombre para evitar caracteres raros en windows
    safe_name = "".join([c for c in CURRENT_USER if c.isalnum()])
    return f"contacts_{safe_name}.json"

def cargar_contactos():
    archivo = get_agenda_filename()
    if os.path.exists(archivo):
        with open(archivo, "r") as f: return json.load(f)
    return {}

def guardar_contacto(nombre):
    agenda = cargar_contactos()
    # Solo guardamos si no existe ya
    if nombre not in agenda:
        agenda[nombre] = {"creado": time.ctime()}
        archivo = get_agenda_filename()
        with open(archivo, "w") as f: json.dump(agenda, f)
        print(f"📒 ¡{nombre} añadido a tu agenda personal ({archivo})!")
    else:
        print(f"ℹ️ {nombre} ya estaba en tu agenda.")

def borrar_contacto(nombre):
    agenda = cargar_contactos()
    if nombre in agenda:
        del agenda[nombre]
        archivo = get_agenda_filename()
        with open(archivo, "w") as f: json.dump(agenda, f)
        print(f"🗑️  ¡{nombre} eliminado de tu agenda!")
        time.sleep(1)
    else:
        print("❌ Contacto no encontrado.")

def elegir_contacto_menu():
    """Submenú avanzado para gestionar destinatarios"""
    while True:
        clear() # Limpiamos pantalla para que se vea ordenado
        agenda = cargar_contactos()
        nombres = list(agenda.keys())
        
        print(f"--- AGENDA DE {CURRENT_USER} ---")
        if not nombres:
            print("   (Agenda vacía)")
        else:
            for i, nombre in enumerate(nombres):
                print(f"{i+1}. {nombre}")
        
        print("-" * 30)
        # Opciones dinámicas según el número de contactos
        op_manual = len(nombres) + 1
        op_borrar = len(nombres) + 2
        op_cancelar = len(nombres) + 3
        
        print(f"{op_manual}. ✍️  Escribir usuario manualmente")
        print(f"{op_borrar}. 🗑️  Eliminar un contacto")
        print(f"{op_cancelar}. 🔙 Cancelar selección")
        
        op = input("\nElige opción: ")
        
        if not op.isdigit(): continue
        idx = int(op)
        
        # CASO 1: Eligió un contacto de la lista
        if 1 <= idx <= len(nombres):
            usuario_elegido = nombres[idx-1]
            print(f"✅ Seleccionado: {usuario_elegido}")
            return usuario_elegido
            
        # CASO 2: Manual (Con validación)
        elif idx == op_manual:
            nuevo = input("Escribe el usuario destinatario: ").strip()
            if not nuevo: continue
            
            print(f"🔍 Verificando si '{nuevo}' existe en el servidor...")
            if verificar_usuario_existente(nuevo):
                print("✅ ¡Usuario verificado!")
                time.sleep(0.5)
                return nuevo
            else:
                print("❌ ERROR: Ese usuario NO EXISTE en el servidor.")
                if input("¿Quieres probar de nuevo? (s/n): ").lower() != 's':
                    return None # Cancela si el usuario no existe y no quiere seguir
        
        # CASO 3: Borrar
        elif idx == op_borrar:
            if not nombres:
                print("⚠️ No hay nadie a quien borrar.")
                time.sleep(1)
                continue
            
            p = input("Número del contacto a borrar (0 para cancelar): ")
            if p.isdigit():
                pidx = int(p)
                if 1 <= pidx <= len(nombres):
                    a_borrar = nombres[pidx-1]
                    if input(f"¿Seguro que quieres borrar a {a_borrar}? (s/n): ") == 's':
                        borrar_contacto(a_borrar)
        
        # CASO 4: Cancelar
        elif idx == op_cancelar:
            return None # Retorna "Nada" para volver al menú anterior

# --- FUNCIONES DE AUTENTICACIÓN ---
def login_flow():
    global TOKEN, MY_PRIVATE_KEY, CURRENT_USER
    header("INICIAR SESIÓN")
    user = input("Usuario: ")
    pwd = getpass.getpass("Contraseña: ")
    
    try:
        res = requests.post(f"{SERVER}/token", data={"username": user, "password": pwd})
        if res.status_code == 200:
            data = res.json()
            TOKEN = data["access_token"]
            print("🔓 Desbloqueando Bóveda de Llaves...")
            try:
                MY_PRIVATE_KEY = crypto.load_private_key(data["private_key_enc"].encode(), pwd)
                CURRENT_USER = user
                print(f"👋 ¡Bienvenido, {user}!")
                time.sleep(1.5)
                return True
            except:
                print("❌ Contraseña correcta, pero FALLÓ el descifrado de tu llave PGP.")
        else:
            print("❌ Error:", res.json().get("detail", "Credenciales inválidas"))
    except Exception as e:
        print(f"❌ Error de conexión: {e}")
    
    pause()
    return False

def register_flow():
    header("REGISTRO NUEVO")
    print("Generando llaves criptográficas (mueve el mouse para entropía)...")
    user = input("Nuevo Usuario: ")
    pwd = getpass.getpass("Nueva Contraseña: ")
    
    priv, pub = crypto.generate_key_pair()
    res = requests.post(f"{SERVER}/register", json={
        "username": user, "password": pwd,
        "public_key_pem": crypto.serialize_public_key(pub).decode(),
        "encrypted_private_key_pem": crypto.serialize_private_key(priv, pwd).decode()
    })
    print("Servidor:", res.text)
    pause()

def verificar_usuario_existente(username):
    """Pregunta al servidor si el usuario existe antes de intentar enviar"""
    try:
        # Usamos el endpoint que ya existe para pedir la llave pública
        res = requests.get(f"{SERVER}/get-public-key/{username}", 
                         headers={"Authorization": f"Bearer {TOKEN}"})
        return res.status_code == 200
    except:
        return False
    
def enviar_texto_cifrado(texto, destinatario, pub_key_pem):
    """Empaqueta un texto como si fuera un archivo .txt y lo envía"""
    # 1. Guardar texto en archivo temporal
    nombre_msg = f"mensaje_{int(time.time())}.txt"
    with open(nombre_msg, "w", encoding="utf-8") as f:
        f.write(texto)
    
    try:
        # 2. Cifrar (Reusamos la lógica de archivos)
        print("🔒 Cifrando mensaje...")
        encrypted_data = crypto.encrypt_for_user(nombre_msg, pub_key_pem)
        
        # 3. Subir
        temp = "temp_msg.enc"
        with open(temp, "wb") as f: f.write(encrypted_data)
        
        # Enviamos con el nombre falso .txt para que el server lo guarde así
        files_payload = {"file": (nombre_msg, open(temp, "rb"))}
        
        res = requests.post(f"{SERVER}/upload/", 
            params={"recipient_username": destinatario},
            files=files_payload,
            headers={"Authorization": f"Bearer {TOKEN}"}
        )
        
        # Limpieza
        files_payload["file"][1].close()
        os.remove(temp)
        os.remove(nombre_msg)
        
        return res.status_code == 200, res.text
    except Exception as e:
        return False, str(e)

def menu_cuenta():
    while True:
        header("GESTIÓN DE CUENTA")
        print("1. 🔑 Cambiar Contraseña")
        print("2. 🗑️  ELIMINAR MI CUENTA")
        print("3. 🔙 Volver")
        
        op = input("\nElige: ")
        
        if op == "1":
            old = getpass.getpass("Contraseña actual: ")
            new = getpass.getpass("Nueva contraseña: ")
            if input("¿Confirmar cambio? (s/n): ") == 's':
                res = requests.put(f"{SERVER}/change-password", 
                                 json={"old_password": old, "new_password": new},
                                 headers={"Authorization": f"Bearer {TOKEN}"})
                print("\nServidor:", res.json().get("msg", res.text))
                pause()
        
        elif op == "2":
            print("\n⚠️  PELIGRO: Esto borrará tus archivos y llaves para siempre.")
            print("   No podrás recuperar nada.")
            if input("Escribe 'BORRAR' para confirmar: ") == "BORRAR":
                res = requests.delete(f"{SERVER}/delete-account", 
                                    headers={"Authorization": f"Bearer {TOKEN}"})
                print("\n", res.json().get("msg", res.text))
                # Forzamos cierre de sesión
                return "LOGOUT" 
        
        elif op == "3":
            return

# --- MENÚ DE ENVÍO (CORREGIDO Y COMPLETO) ---
def menu_enviar():
    destinatario = None
    texto_mensaje = None
    archivo_path = None

    while True:
        header("REDACTAR MENSAJE HÍBRIDO")
        
        # Iconos de estado visuales
        s_dest = f"👤 {destinatario}" if destinatario else "❌ (Requerido)"
        s_txt = "📝 (Con Texto)" if texto_mensaje else "⚪ (Sin Texto)"
        s_file = f"📎 {os.path.basename(archivo_path)}" if archivo_path else "⚪ (Sin Archivo)"
        
        print(f"1. Seleccionar Destinatario [{s_dest}]")
        print(f"2. Escribir/Editar Texto    [{s_txt}]")
        print(f"3. Adjuntar Archivo         [{s_file}]")
        print("-" * 40)
        print("4. 🚀 ENVIAR MENSAJE")
        print("5. 🔙 Volver")
        
        op = input("\nElige: ")
        
        if op == "1":
            destinatario = elegir_contacto_menu()
        
        elif op == "2":
            print("\nEscribe tu mensaje (Enter para guardar):")
            texto_mensaje = input("> ")
            if not texto_mensaje.strip(): texto_mensaje = None
        
        elif op == "3":
            path = seleccionar_archivo_grafico()
            if path: archivo_path = path
        
        elif op == "4":
            # Validaciones básicas
            if not destinatario:
                print("❌ Falta destinatario."); time.sleep(1); continue
            if not texto_mensaje and not archivo_path:
                print("❌ El mensaje está vacío (ni texto ni archivo)."); time.sleep(1); continue
            
            print(f"\n🚀 Procesando envío para {destinatario}...")
            
            try:
                # 1. Obtener Llave Pública del destinatario
                kres = requests.get(f"{SERVER}/get-public-key/{destinatario}", headers={"Authorization": f"Bearer {TOKEN}"})
                if kres.status_code != 200:
                    print("❌ Usuario no encontrado."); pause(); continue
                pub_key = kres.json()["public_key"].encode()

                # Preparar diccionarios para el envío
                payload_data = {}
                payload_files = {}

                # 2. Cifrar Texto (si el usuario escribió algo)
                if texto_mensaje:
                    print("🔒 Cifrando texto...")
                    enc_bytes = crypto.encrypt_bytes_for_user(texto_mensaje.encode("utf-8"), pub_key)
                    
                    # --- FIRMAR TEXTO ---
                    print("✍️  Firmando texto digitalmente...")
                    sig_bytes = crypto.sign_data(enc_bytes, MY_PRIVATE_KEY)
                    sig_str = base64.b64encode(sig_bytes).decode('utf-8')
                    # --------------------

                    enc_str = base64.b64encode(enc_bytes).decode('utf-8')
                    payload_data["encrypted_text"] = enc_str
                    payload_data["text_signature"] = sig_str

                # 3. Cifrar Archivo (si el usuario seleccionó uno)
                # AQUÍ ESTABA EL ERROR: RESTAURAMOS LA DEFINICIÓN DE VARIABLES
                if archivo_path:
                    print("🔒 Cifrando adjunto...")
                    enc_file_bytes = crypto.encrypt_for_user(archivo_path, pub_key)
                    
                    # Definimos el nombre del archivo temporal y guardamos los datos cifrados
                    temp_file = "temp_attachment.enc"
                    with open(temp_file, "wb") as f: f.write(enc_file_bytes)
                    
                    # Obtenemos el nombre real del archivo original
                    real_name = os.path.basename(archivo_path)
                    
                    # Lo preparamos para enviar
                    payload_files["file"] = (real_name, open(temp_file, "rb"))
                    
                    # --- FIRMAR ARCHIVO ---
                    print("✍️  Firmando archivo digitalmente...")
                    file_sig_bytes = crypto.sign_data(enc_file_bytes, MY_PRIVATE_KEY)
                    file_sig_str = base64.b64encode(file_sig_bytes).decode('utf-8')
                    payload_data["file_signature"] = file_sig_str

                # === EL ARREGLO MÁGICO (ARCHIVO FANTASMA) ===
                # Si NO hay archivo real, enviamos uno vacío para que FastAPI no se queje.
                if "file" not in payload_files:
                    payload_files["file"] = ("", b"") 
                # ============================================

                # 4. Enviar la petición al servidor
                res = requests.post(
                    f"{SERVER}/upload/",
                    params={"recipient_username": destinatario},
                    data=payload_data,    # Texto cifrado va aquí
                    files=payload_files,  # Archivo (o fantasma) va aquí
                    headers={"Authorization": f"Bearer {TOKEN}"}
                )

                # Limpieza: Cerrar y borrar archivo temporal si se usó
                if archivo_path and "file" in payload_files:
                    # El archivo fantasma es una tupla simple, el real es un archivo abierto
                    # Verificamos si es un archivo real abierto antes de cerrar
                    if hasattr(payload_files["file"][1], "close"):
                        payload_files["file"][1].close()
                    if os.path.exists("temp_attachment.enc"):
                        os.remove("temp_attachment.enc")

                if res.status_code == 200:
                    print("✅ ¡Mensaje enviado exitosamente!")
                    
                    # Preguntar si guardar contacto
                    agenda = cargar_contactos()
                    if destinatario not in agenda:
                        if input("¿Guardar contacto? (s/n): ")=='s': guardar_contacto(destinatario)
                    
                    # Limpiar el formulario para el siguiente mensaje
                    destinatario = None; texto_mensaje = None; archivo_path = None
                else:
                    print("❌ Error del servidor:", res.text)
                
                pause()

            except Exception as e:
                print(f"❌ Error crítico en el envío: {e}"); pause()

        elif op == "5": break

# --- MENÚ DE BANDEJA (CON VERIFICACIÓN DE FIRMA DIGITAL) ---
def menu_bandeja():
    while True:
        header("📬 BANDEJA DE ENTRADA")
        try:
            # 1. Obtener datos del servidor
            res = requests.get(f"{SERVER}/my-files/", headers={"Authorization": f"Bearer {TOKEN}"})
            if res.status_code != 200:
                print("❌ Error de conexión con el servidor.")
                break
            
            files = res.json()
            
            # --- CASO VACÍO ---
            if not files:
                print("\n" + " "*10 + "📭 Tu bandeja está vacía.")
                print("\n1. 🔄 Actualizar")
                print("2. 🔙 Volver")
                if input("\nElige: ") == "2": break
                continue
                
            # --- LISTADO DE MENSAJES ---
            # Nota: Si actualizaste el servidor, podrías mostrar también el REMITENTE aquí
            print(f"{'ID':<5} | {'TIPO':<8} | {'ASUNTO / CONTENIDO'}")
            print("-" * 65)
            
            for f in files:
                has_text = bool(f.get('encrypted_text'))
                has_file = bool(f.get('filename'))
                
                # Iconos
                if has_text and has_file: tipo = "📦PACK"
                elif has_text:            tipo = "📝TEXT"
                elif has_file:            tipo = "📎FILE"
                else:                     tipo = "❓UNK"
                
                # Descripción
                desc = "Sin asunto"
                if has_file: desc = f"Adj: {f['filename']}"
                elif has_text: desc = "Mensaje de texto"
                
                # Cortar para que no rompa la tabla
                if len(desc) > 40: desc = desc[:37] + "..."
                
                print(f"{f['id']:<5} | {tipo:<8} | {desc}")
            print("-" * 65)

            # --- MENU ACCIONES ---
            print("\n👇 OPCIONES:")
            print("1. 👁️  Leer mensaje completo (Texto y Adjuntos)")
            print("2. 🗑️  Eliminar mensaje")
            print("3. ☢️  VACIAR BANDEJA") 
            print("4. 🔙 Volver")

            op = input("\nElige (1-4): ")
            
            if op == "1":
                target_id_str = input("👉 ID del mensaje: ")
                if not target_id_str.isdigit(): continue
                target_id = int(target_id_str)

                msg = next((f for f in files if f['id'] == target_id), None)

                if msg:
                    header(f"VISOR DE MENSAJE #{target_id}")
                    
                    # 1. IDENTIFICAR REMITENTE Y OBTENER LLAVE PÚBLICA
                    sender = msg.get('sender_username')
                    sender_pub_key = None
                    
                    if sender:
                        print(f"📨 REMITENTE: {sender}")
                        try:
                            # Bajamos la llave pública del que dice ser el remitente
                            kres = requests.get(f"{SERVER}/get-public-key/{sender}", headers={"Authorization": f"Bearer {TOKEN}"})
                            if kres.status_code == 200:
                                sender_pub_key = kres.json()["public_key"].encode()
                            else:
                                print("⚠️  No se pudo obtener la llave pública del remitente.")
                        except:
                            print("⚠️  Error de conexión al verificar remitente.")
                    else:
                        print("📨 REMITENTE: Desconocido (Sistema antiguo)")

                    print("-" * 50)

                    tiene_texto = bool(msg.get('encrypted_text'))
                    tiene_archivo = bool(msg.get('filename'))
                    
                    # --- BLOQUE A: VERIFICAR Y MOSTRAR TEXTO ---
                    if tiene_texto:
                        print("📝 CONTENIDO DE TEXTO:")
                        
                        # A.1 VERIFICAR FIRMA DEL TEXTO
                        estado_firma = "⚠️ Sin Firma"
                        if sender_pub_key and msg.get('text_signature'):
                            try:
                                enc_bytes_verify = base64.b64decode(msg['encrypted_text'])
                                sig_bytes_verify = base64.b64decode(msg['text_signature'])
                                if crypto.verify_signature(enc_bytes_verify, sig_bytes_verify, sender_pub_key):
                                    estado_firma = "✅ FIRMA VÁLIDA (Auténtico)"
                                else:
                                    estado_firma = "❌ ⚠️ FIRMA INVÁLIDA (PELIGRO)"
                            except: estado_firma = "❌ Error validando"
                        
                        print(f"   Estado de Seguridad: {estado_firma}")

                        # A.2 DESCIFRAR
                        try:
                            enc_bytes = base64.b64decode(msg['encrypted_text'])
                            dec_bytes = crypto.decrypt_bytes(enc_bytes, MY_PRIVATE_KEY)
                            texto_plano = dec_bytes.decode("utf-8")
                            
                            print("╔" + "═"*58 + "╗")
                            for linea in texto_plano.splitlines():
                                while len(linea) > 56:
                                    print(f"║ {linea[:56]} ║")
                                    linea = linea[56:]
                                print(f"║ {linea:<56} ║")
                            print("╚" + "═"*58 + "╝")
                        except Exception as e:
                            print(f"\n❌ Error al descifrar: {e}")
                    else:
                        print("📝 (Sin texto)")

                    # --- BLOQUE B: VERIFICAR Y DESCARGAR ARCHIVO ---
                    if tiene_archivo:
                        fname = msg['filename']
                        print(f"\n📎 ARCHIVO ADJUNTO: {fname}")
                        
                        # B.1 AVISO DE FIRMA (PREVIO A DESCARGA)
                        if msg.get('file_signature'):
                            print("   🔐 Este archivo está firmado digitalmente.")
                        else:
                            print("   ⚠️ Este archivo NO tiene firma.")

                        if input("   ¿Descargar y Verificar? (s/n): ").lower() == 's':
                            r = requests.get(f"{SERVER}/download/{target_id}", headers={"Authorization": f"Bearer {TOKEN}"})
                            if r.status_code == 200:
                                # B.2 VERIFICAR FIRMA DEL ARCHIVO (Sobre los datos cifrados descargados)
                                firma_ok = True
                                if sender_pub_key and msg.get('file_signature'):
                                    try:
                                        sig_file_bytes = base64.b64decode(msg['file_signature'])
                                        # r.content son los bytes cifrados tal cual llegaron
                                        if crypto.verify_signature(r.content, sig_file_bytes, sender_pub_key):
                                            print("   ✅ FIRMA DEL ARCHIVO: VÁLIDA")
                                        else:
                                            print("   ❌ ⚠️ FIRMA DEL ARCHIVO: INVÁLIDA (El archivo fue alterado)")
                                            firma_ok = False
                                    except:
                                        print("   ❌ Error técnico verificando firma.")
                                        firma_ok = False
                                
                                if firma_ok or input("   ⚠️ La firma falló. ¿Guardar de todos modos? (s/n): ") == 's':
                                    try:
                                        dec_file = crypto.decrypt_bytes(r.content, MY_PRIVATE_KEY)
                                        os.makedirs("Descargas_Proton", exist_ok=True)
                                        path = os.path.join("Descargas_Proton", "DEC_" + fname)
                                        with open(path, "wb") as f: f.write(dec_file)
                                        print(f"   ✅ Guardado en: {path}")
                                    except: print("   ❌ Error al descifrar archivo.")
                            else: print("   ❌ Error descarga.")
                    
                    print("-" * 50)
                    input("Enter para volver...")

                else:
                    print("❌ ID no encontrado.")
                    time.sleep(1)

            # OPCIÓN 2: BORRAR UNO
            elif op == "2":
                pid = input("ID a borrar: ")
                requests.delete(f"{SERVER}/delete/{pid}", headers={"Authorization": f"Bearer {TOKEN}"})
                print("🗑️  Borrado.")
                time.sleep(0.5)

            # OPCIÓN 3: VACIAR TODO
            elif op == "3":
                if input("⚠️  ¿BORRAR TODO? (s/n): ").lower() == 's':
                    requests.delete(f"{SERVER}/empty-inbox/", headers={"Authorization": f"Bearer {TOKEN}"})
                    print("☢️  Bandeja vaciada.")
                    time.sleep(1)

            # OPCIÓN 4: VOLVER
            elif op == "4":
                break

        except Exception as e:
            print(f"Error crítico: {e}")
            pause()
            break

# --- MENÚ PRINCIPAL (ROOT) ---
def main_menu():
    # Declaramos las globales AL PRINCIPIO para evitar el error de sintaxis
    global TOKEN, MY_PRIVATE_KEY, CURRENT_USER 
    
    while True:
        if not TOKEN:
            header("VOLU-VAULT - BIENVENIDO")
            print("1. 🔑 Iniciar Sesión")
            print("2. 📝 Registrarse")
            print("3. ❌ Salir")
            op = input("\nOpción: ")
            if op == "1": login_flow()
            elif op == "2": register_flow()
            elif op == "3": exit()
        else:
            header("MENÚ PRINCIPAL")
            print("1. 📤 Redactar (Texto/Archivo)")
            print("2. 📥 Bandeja de Entrada")
            print("3. ⚙️ Mi Cuenta")
            print("4. 🔒 Cerrar Sesión")
            op = input("\nOpción: ")
            
            if op == "1": menu_enviar()
            elif op == "2": menu_bandeja()
            elif op == "3": 
                # Si borran la cuenta, menu_cuenta devuelve "LOGOUT"
                status = menu_cuenta()
                if status == "LOGOUT":
                    TOKEN = None
                    MY_PRIVATE_KEY = None
                    CURRENT_USER = None
                    
            elif op == "4": 
                TOKEN = None
                MY_PRIVATE_KEY = None
                CURRENT_USER = None
                print("Sesión cerrada.")
                time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nSaliendo...")