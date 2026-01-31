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
    sender_username: str
    
    # Contenido Híbrido
    encrypted_text: Optional[str] = None
    text_signature: Optional[str] = None # <--- NUEVO: Firma del texto
    
    filename: Optional[str] = None
    stored_name: Optional[str] = None
    file_signature: Optional[str] = None # <--- NUEVO: Firma del archivo

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session