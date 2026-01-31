from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Session, select
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime
import os, shutil
from typing import Optional
from database import create_db_and_tables, get_session, User, FileRecord
from pydantic import BaseModel

app = FastAPI()
UPLOAD_DIR = "server_storage"
os.makedirs(UPLOAD_DIR, exist_ok=True)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# --- MODELOS DE DATOS ---
class PasswordChange(BaseModel):
    old_password: str
    new_password: str
    new_encrypted_private_key: str

class UserRegister(BaseModel):
    username: str
    password: str
    public_key_pem: str
    encrypted_private_key_pem: str

# --- ENDPOINTS DE USUARIO ---
@app.post("/register")
def register(user_data: UserRegister, session: Session = Depends(get_session)):
    user = User(
        username=user_data.username,
        hashed_password=pwd_context.hash(user_data.password),
        public_key_pem=user_data.public_key_pem,
        encrypted_private_key_pem=user_data.encrypted_private_key_pem
    )
    session.add(user)
    session.commit()
    return {"msg": "Usuario creado exitosamente"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == form_data.username)).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Credenciales incorrectas")
    
    token = jwt.encode({"sub": user.username}, "SECRET", algorithm="HS256")
    return {
        "access_token": token, 
        "token_type": "bearer",
        "private_key_enc": user.encrypted_private_key_pem
    }

async def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    user_name = jwt.decode(token, "SECRET", algorithms=["HS256"]).get("sub")
    return session.exec(select(User).where(User.username == user_name)).first()

@app.get("/get-public-key/{username}")
def get_key(username: str, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == username)).first()
    if not user: raise HTTPException(status_code=404)
    return {"public_key": user.public_key_pem}

@app.put("/change-password")
def change_password(
    data: PasswordChange, 
    user: User = Depends(get_current_user), 
    session: Session = Depends(get_session)
):
    if not pwd_context.verify(data.old_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="La contraseña actual no es correcta")
    
    user.hashed_password = pwd_context.hash(data.new_password)
    
    if data.new_encrypted_private_key:
        user.encrypted_private_key_pem = data.new_encrypted_private_key

    session.add(user)
    session.commit()
    return {"msg": "Contraseña y Llave Maestra actualizadas correctamente"}

@app.delete("/delete-account")
def delete_account(user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    files = session.exec(select(FileRecord).where(FileRecord.owner_id == user.id)).all()
    for f in files:
        if f.stored_name:
            try: os.remove(os.path.join(UPLOAD_DIR, f.stored_name))
            except: pass
        session.delete(f)
    session.delete(user)
    session.commit()
    return {"msg": "Cuenta eliminada"}

# --- ENDPOINTS DE ARCHIVOS Y MENSAJES ---

@app.post("/upload/")
async def upload_message(
    recipient_username: str,
    file: Optional[UploadFile] = File(None),
    encrypted_text: Optional[str] = Form(None),
    text_signature: Optional[str] = Form(None),
    file_signature: Optional[str] = Form(None),
    current_user: User = Depends(get_current_user), 
    session: Session = Depends(get_session)
):
    recipient = session.exec(select(User).where(User.username == recipient_username)).first()
    if not recipient: raise HTTPException(404, detail="Usuario no encontrado")

    stored_filename = None
    original_filename = None
    
    if file and file.filename: 
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        stored_filename = f"{timestamp}_{file.filename}"
        original_filename = file.filename
        
        with open(os.path.join(UPLOAD_DIR, stored_filename), "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    
    if encrypted_text == "": encrypted_text = None
    if not encrypted_text and not original_filename:
        raise HTTPException(400, detail="Vacio")

    db_msg = FileRecord(
        owner_id=recipient.id,
        sender_username=current_user.username,
        recipient_username=recipient_username,
        is_read=False,
        encrypted_text=encrypted_text,
        text_signature=text_signature,
        filename=original_filename,
        stored_name=stored_filename,
        file_signature=file_signature
    )
    
    session.add(db_msg)
    session.commit()
    return {"info": "Enviado", "id": db_msg.id}

@app.get("/my-files/")
def list_files(user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    return session.exec(select(FileRecord).where(FileRecord.owner_id == user.id)).all()

# --- NUEVO: ENDPOINT DE ENVIADOS ---
@app.get("/sent-items/")
def list_sent_files(user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    # Retorna archivos donde YO soy el remitente
    return session.exec(select(FileRecord).where(FileRecord.sender_username == user.username)).all()

@app.get("/download/{file_id}")
def download(file_id: int, user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    file = session.get(FileRecord, file_id)
    # Seguridad: Solo descarga si eres el dueño O el remitente (para verificar envíos)
    if not file: raise HTTPException(404)
    if file.owner_id != user.id and file.sender_username != user.username:
        raise HTTPException(403)
        
    if not file.stored_name: raise HTTPException(404, detail="Este mensaje no tiene archivo adjunto")
    return FileResponse(f"{UPLOAD_DIR}/{file.stored_name}", headers={"Content-Disposition": f'attachment; filename="{file.filename}"'})

# --- CORRECCIÓN CRÍTICA EN DELETE ---
@app.delete("/delete/{file_id}")
def delete_file(file_id: int, user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    file = session.get(FileRecord, file_id)
    if not file: raise HTTPException(404, detail="Mensaje no encontrado")
    
    # Permiso: Dueño o Remitente
    if file.owner_id != user.id and file.sender_username != user.username:
        raise HTTPException(status_code=403, detail="No tienes permiso")
    
    # 1. Borrar del Disco Duro (SOLO SI EXISTE stored_name)
    if file.stored_name:
        path = os.path.join(UPLOAD_DIR, file.stored_name)
        # Verificamos si existe físicamente antes de intentar borrar
        if os.path.exists(path):
            try: os.remove(path)
            except: pass # Si falla el borrado físico, seguimos con la BD
    
    # 2. Borrar de la BD
    session.delete(file)
    session.commit()
    return {"info": "Eliminado"}

@app.delete("/empty-inbox/")
def empty_inbox(user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    files = session.exec(select(FileRecord).where(FileRecord.owner_id == user.id)).all()
    for file in files:
        if file.stored_name:
            try: os.remove(os.path.join(UPLOAD_DIR, file.stored_name))
            except: pass
        session.delete(file)
    session.commit()
    return {"info": "Bandeja vaciada"}

@app.put("/mark-read/{file_id}")
def mark_as_read(file_id: int, user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    file = session.get(FileRecord, file_id)
    if not file: raise HTTPException(404)

    if file.owner_id != user.id:
        raise HTTPException(403)
    
    file.is_read = True
    session.add(file)
    session.commit()
    return {"info": "Marcado como leído"}