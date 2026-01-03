from pydantic import BaseModel
from typing import Optional
from datetime import datetime

# Public key entry trong directory
class KeyEntry(BaseModel):
    id: str
    name: str
    department: str
    public_key: str
    created_at: str

# Response model cho signature verification
class VerifyResponse(BaseModel):
    valid: bool
    message: str
    signer: Optional[str] = None

# Response model cho directory listing
class DirectoryResponse(BaseModel):
    entries: list[KeyEntry]

# In-memory storage cho public keys
# Trong production, nên dùng database
key_directory: dict[str, KeyEntry] = {}
