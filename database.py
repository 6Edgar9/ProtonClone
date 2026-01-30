from sqlmodel import SQLModel, Field, create_engine, Session
from typing import Optional
from datetime import datetime

DATABASE_URL = "postgresql://admin:sistemas_secret_password@localhost:5432/proton_vault"
engine = create_engine(DATABASE_URL)

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str
    public_key_pem: str
    encrypted_private_key_pem: str

class FileRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    
    # Metadatos
    created_at: datetime = Field(default_factory=datetime.utcnow)
    owner_id: int = Field(foreign_key="user.id")
    
    # Contenido Híbrido (Todo opcional porque un mensaje puede ser solo texto o solo archivo)
    encrypted_text: Optional[str] = None # El mensaje de texto cifrado (en Base64)
    
    filename: Optional[str] = None       # Nombre original del archivo (si hay adjunto)
    stored_name: Optional[str] = None    # Nombre en disco del archivo (si hay adjunto)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session