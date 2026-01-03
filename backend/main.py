from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from typing import Optional
from datetime import datetime
import uuid
import base64
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import KeyEntry, VerifyResponse, DirectoryResponse, key_directory
from signature.digital_signature import DigitalSignature
from signature.pdf_signature import PdfSigner

# App setup
app = FastAPI(
    title="Digital Signature API",
    description="RSA Digital Signature System - Custom RSA + SHA-256",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper functions
def key_to_str(key: tuple) -> str:
    return f"{key[0]}:{key[1]}"

def str_to_key(s: str) -> tuple:
    try:
        parts = s.strip().split(':')
        return (int(parts[0]), int(parts[1]))
    except Exception as e:
        raise ValueError(f"Invalid key format: {e}")

# API Endpoints
@app.get("/")
async def root():
    return {
        "status": "ok",
        "message": "Digital Signature API - Custom RSA + SHA-256",
        "version": "3.0.0"
    }

# Sinh cặp khóa RSA mới
@app.post("/generate-keys")
async def generate_keys(
    name: str = Form(...),
    department: str = Form(...),
    key_size: int = Form(1024)
):
    try:
        if key_size not in [512, 1024, 2048]:
            raise HTTPException(status_code=400, detail="Key size must be 512, 1024, or 2048")
        
        ds = DigitalSignature(key_size=key_size)
        public_key, private_key = ds.generate_keys(verbose=False)
        
        key_id = str(uuid.uuid4())[:8]
        
        key_directory[key_id] = KeyEntry(
            id=key_id,
            name=name,
            department=department,
            public_key=key_to_str(public_key),
            created_at=datetime.now().isoformat()
        )
        
        private_key_str = key_to_str(private_key)
        
        return Response(
            content=private_key_str.encode('utf-8'),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename={name.replace(' ', '_')}_private.key",
                "X-Key-ID": key_id
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Key generation failed: {str(e)}")

# Ký file với private key
@app.post("/sign")
async def sign_file(
    file: UploadFile = File(...),
    private_key: UploadFile = File(...)
):
    try:
        file_data = await file.read()
        key_data = await private_key.read()
        priv_key = str_to_key(key_data.decode('utf-8'))
        
        ds = DigitalSignature(key_size=512)
        signature = ds.sign(file_data, private_key=priv_key)
        
        signature_bytes = str(signature).encode('utf-8')
        signature_b64 = base64.b64encode(signature_bytes)
        
        return Response(
            content=signature_b64,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename={file.filename}.sig"
            }
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid key: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signing failed: {str(e)}")

# Xác minh chữ ký của file
@app.post("/verify", response_model=VerifyResponse)
async def verify_file(
    file: UploadFile = File(...),
    signature: UploadFile = File(...),
    key_id: Optional[str] = Form(None),
    public_key_file: Optional[UploadFile] = File(None)
):
    try:
        file_data = await file.read()
        
        sig_data = await signature.read()
        sig_bytes = base64.b64decode(sig_data)
        sig_int = int(sig_bytes.decode('utf-8'))
        
        if key_id and key_id in key_directory:
            entry = key_directory[key_id]
            pub_key = str_to_key(entry.public_key)
            signer = f"{entry.name} ({entry.department})"
        elif public_key_file:
            key_data = await public_key_file.read()
            pub_key = str_to_key(key_data.decode('utf-8'))
            signer = "Uploaded Key"
        else:
            raise HTTPException(
                status_code=400,
                detail="Must provide either key_id or public_key_file"
            )
        
        ds = DigitalSignature(key_size=512)
        valid = ds.verify(file_data, sig_int, public_key=pub_key)
        
        return VerifyResponse(
            valid=valid,
            message=(
                "✓ CHỮ KÝ HỢP LỆ\n"
                "• Tài liệu KHÔNG bị sửa đổi\n"
                "• Người ký XÁC THỰC đúng\n"
                "• Không thể phủ nhận đã ký"
            ) if valid else (
                "✗ CHỮ KÝ KHÔNG HỢP LỆ\n"
                "• Tài liệu có thể đã bị SỬA ĐỔI\n"
                "• HOẶC sai người ký\n"
                "⚠️ CẢNH BÁO: Không sử dụng tài liệu này!"
            ),
            signer=signer if valid else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")

# Lấy danh sách public keys đã đăng ký
@app.get("/directory", response_model=DirectoryResponse)
async def get_directory():
    entries = [entry for entry in key_directory.values()]
    return DirectoryResponse(entries=entries)

# Đăng ký public key vào directory
@app.post("/register")
async def register_key(
    name: str = Form(...),
    department: str = Form(...),
    public_key: UploadFile = File(...)
):
    try:
        key_data = await public_key.read()
        pub_key_str = key_data.decode('utf-8')
        str_to_key(pub_key_str)
        
        key_id = str(uuid.uuid4())[:8]
        
        key_directory[key_id] = KeyEntry(
            id=key_id,
            name=name,
            department=department,
            public_key=pub_key_str,
            created_at=datetime.now().isoformat()
        )
        
        return {"message": "Public key registered successfully", "key_id": key_id}
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid public key: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

# Xóa public key khỏi directory
@app.delete("/directory/{key_id}")
async def delete_key(key_id: str):
    if key_id not in key_directory:
        raise HTTPException(status_code=404, detail="Key not found")
    del key_directory[key_id]
    return {"message": "Key deleted successfully"}


#  PDF STANDARD SIGNING (PAdES)

# Ký PDF theo chuẩn PAdES với certificate PFX/P12
@app.post("/sign-pdf")
async def sign_pdf_standard(
    pdf_file: UploadFile = File(...),
    certificate: UploadFile = File(...),
    password: str = Form("")
):
    try:
        pdf_data = await pdf_file.read()
        cert_data = await certificate.read()
        
        signed_pdf, signer_name = await PdfSigner.sign_async(pdf_data, cert_data, password)
        
        signed_filename = pdf_file.filename.replace('.pdf', '_signed.pdf')
        
        return Response(
            content=signed_pdf,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={signed_filename}",
                "X-Signer-Name": signer_name
            }
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF signing failed: {str(e)}")

# Xác minh chữ ký trong PDF
@app.post("/verify-pdf")
async def verify_pdf_standard(pdf_file: UploadFile = File(...)):
    try:
        pdf_data = await pdf_file.read()
        result = PdfSigner.verify(pdf_data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF verification failed: {str(e)}")

# Sinh certificate test (self-signed) để thử nghiệm ký PDF
@app.post("/generate-certificate")
async def generate_test_certificate(
    name: str = Form(...),
    organization: str = Form("Test Organization"),
    password: str = Form("123456")
):
    try:
        pfx_data, cert_password = PdfSigner.generate_test_certificate(
            name=name,
            organization=organization,
            password=password
        )
        
        filename = f"{name.replace(' ', '_')}_certificate.pfx"
        
        return Response(
            content=pfx_data,
            media_type="application/x-pkcs12",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "X-Certificate-Password": cert_password
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Certificate generation failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("🚀 Digital Signature API Server")
    print("=" * 60)
    print("🌐 Server: http://localhost:8000")
    print("📚 API Docs: http://localhost:8000/docs")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000)
