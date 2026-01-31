from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Session, select
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime
import os, shutil
from fastapi import Form
from typing import Optional
from database import create_db_and_tables, get_session, User, FileRecord

app = FastAPI()
UPLOAD_DIR = "server_storage"
os.makedirs(UPLOAD_DIR, exist_ok=True)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# --- MODELOS DE DATOS EXTRA ---
from pydantic import BaseModel

class PasswordChange(BaseModel):
    old_password: str
    new_password: str
class UserRegister(BaseModel):
    username: str
    password: str
    public_key_pem: str
    encrypted_private_key_pem: str

# --- ENDPOINTS ---
@app.post("/register")
def register(user_data: UserRegister, session: Session = Depends(get_session)):
    # Guardamos Usuario + Sus llaves
    user = User(
        username=user_data.username,
        hashed_password=pwd_context.hash(user_data.password),
        public_key_pem=user_data.public_key_pem,
        encrypted_private_key_pem=user_data.encrypted_private_key_pem
    )
    session.add(user)
    session.commit()
    return {"msg": "Usuario y Llaves PGP creadas"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == form_data.username)).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Credenciales incorrectas")
    
    # IMPORTANTE: Al loguear, devolvemos la Llave Privada Cifrada para que el cliente la desbloquee
    token = jwt.encode({"sub": user.username}, "SECRET", algorithm="HS256")
    return {
        "access_token": token, 
        "token_type": "bearer",
        "private_key_enc": user.encrypted_private_key_pem # <--- Esto es clave
    }

async def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    user_name = jwt.decode(token, "SECRET", algorithms=["HS256"]).get("sub")
    return session.exec(select(User).where(User.username == user_name)).first()

@app.get("/get-public-key/{username}")
def get_key(username: str, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == username)).first()
    if not user: raise HTTPException(status_code=404)
    return {"public_key": user.public_key_pem}

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
        raise HTTPException(400, detail="Debes enviar al menos texto o un archivo")

    db_msg = FileRecord(
        owner_id=recipient.id,
        encrypted_text=encrypted_text,
        text_signature=text_signature,
        filename=original_filename,
        stored_name=stored_filename,
        file_signature=file_signature,
        sender_username=current_user.username
    )
    
    session.add(db_msg)
    session.commit()
    return {"info": "Enviado", "id": db_msg.id}

@app.get("/my-files/")
def list_files(user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    return session.exec(select(FileRecord).where(FileRecord.owner_id == user.id)).all()

@app.get("/download/{file_id}")
def download(file_id: int, user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    file = session.get(FileRecord, file_id)
    if not file or file.owner_id != user.id: raise HTTPException(403)
    return FileResponse(f"{UPLOAD_DIR}/{file.stored_name}", headers={"Content-Disposition": f'attachment; filename="{file.filename}"'})
@app.delete("/delete/{file_id}")
def delete_file(file_id: int, user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    file = session.get(FileRecord, file_id)
    if not file or file.owner_id != user.id:
        raise HTTPException(status_code=403, detail="No tienes permiso o el archivo no existe")
    
    # 1. Borrar del Disco Duro
    try:
        os.remove(os.path.join(UPLOAD_DIR, file.stored_name))
    except OSError:
        pass # Si no existe en disco por error, seguimos para borrarlo de la BD
    
    # 2. Borrar de la Base de Datos
    session.delete(file)
    session.commit()
    return {"info": "Archivo eliminado correctamente"}

@app.delete("/empty-inbox/")
def empty_inbox(user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    files = session.exec(select(FileRecord).where(FileRecord.owner_id == user.id)).all()
    count = 0
    for file in files:
        # Borrar disco
        try:
            os.remove(os.path.join(UPLOAD_DIR, file.stored_name))
        except OSError:
            pass
        # Borrar BD
        session.delete(file)
        count += 1
    
    session.commit()
    return {"info": f"Bandeja vaciada. {count} archivos eliminados."}

@app.put("/change-password")
def change_password(
    data: PasswordChange, 
    user: User = Depends(get_current_user), 
    session: Session = Depends(get_session)
):
    # 1. Verificar la contraseña vieja
    if not pwd_context.verify(data.old_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="La contraseña actual no es correcta")

    # 2. Actualizar a la nueva
    user.hashed_password = pwd_context.hash(data.new_password)
    session.add(user)
    session.commit()
    return {"msg": "Contraseña actualizada correctamente"}

@app.delete("/delete-account")
def delete_account(
    user: User = Depends(get_current_user), 
    session: Session = Depends(get_session)
):
    # 1. Borrar todos sus archivos físicos
    files = session.exec(select(FileRecord).where(FileRecord.owner_id == user.id)).all()
    for f in files:
        try:
            os.remove(os.path.join(UPLOAD_DIR, f.stored_name))
        except: pass
        session.delete(f)

    # 2. Borrar al usuario
    session.delete(user)
    session.commit()
    return {"msg": "Cuenta eliminada permanentemente. Hasta la vista."}