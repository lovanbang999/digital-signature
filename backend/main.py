from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional
import base64, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Response model cho signature verification
class VerifyResponse(BaseModel):
    valid: bool
    message: str
from signature.digital_signature import DigitalSignature
from signature.pdf_signature import PdfSigner

app = FastAPI(
    title="Digital Signature API",
    description="RSA Digital Signature System - Custom RSA + SHA-256",
    version="3.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# Chuyển tuple key thành string để lưu/gửi
def key_to_str(key: tuple) -> str:
    return f"{key[0]}:{key[1]}"

# Parse string thành tuple key
def str_to_key(s: str) -> tuple:
    parts = s.strip().split(':')
    if len(parts) != 2:
        raise ValueError("Key phải có format e:n hoặc d:n")
    return (int(parts[0]), int(parts[1]))

# Health check
@app.get("/")
async def root():
    return {"status": "ok", "message": "Digital Signature API - Custom RSA + SHA-256", "version": "3.0.0"}

# Tạo cặp khóa RSA mới - trả về cả public và private key
@app.post("/generate-keys")
async def generate_keys(name: str = Form(...), department: str = Form(...), key_size: int = Form(1024)):
    if key_size not in [512, 1024, 2048]:
        raise HTTPException(400, "Key size must be 512, 1024, or 2048")
    ds = DigitalSignature(key_size=key_size)
    public_key, private_key = ds.generate_keys(verbose=False)
    return {
        "public_key": key_to_str(public_key),
        "private_key": key_to_str(private_key),
        "name": name,
        "department": department
    }

# Ký file bằng private key
@app.post("/sign")
async def sign_file(file: UploadFile = File(...), private_key: UploadFile = File(...)):
    file_data = await file.read()
    key_data = await private_key.read()
    try:
        priv_key = str_to_key(key_data.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(400, "Private key không hợp lệ")
    key_size = priv_key[1].bit_length()
    ds = DigitalSignature(key_size=key_size)
    signature = ds.sign(file_data, private_key=priv_key)
    signature_b64 = base64.b64encode(str(signature).encode('utf-8'))
    return Response(
        content=signature_b64, media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={file.filename}.sig"}
    )

# Xác minh chữ ký - chỉ dùng upload public key
@app.post("/verify", response_model=VerifyResponse)
async def verify_file(
    file: UploadFile = File(...), 
    signature: UploadFile = File(...),
    public_key_file: UploadFile = File(...)
):
    file_data = await file.read()
    sig_data = await signature.read()
    try:
        sig_int = int(base64.b64decode(sig_data).decode('utf-8'))
    except:
        raise HTTPException(400, "Signature file bị lỗi")
    
    key_data = await public_key_file.read()
    try:
        pub_key = str_to_key(key_data.decode('utf-8'))
    except:
        raise HTTPException(400, "Public key không đúng format")
    
    key_size = pub_key[1].bit_length()
    ds = DigitalSignature(key_size=key_size)
    valid = ds.verify(file_data, sig_int, public_key=pub_key)
    return VerifyResponse(
        valid=valid,
        message="✓ HỢP LỆ" if valid else "✗ KHÔNG HỢP LỆ"
    )

# Ký PDF với certificate
@app.post("/sign-pdf")
async def sign_pdf_standard(pdf_file: UploadFile = File(...), certificate: UploadFile = File(...), password: str = Form("")):
    pdf_data = await pdf_file.read()
    cert_data = await certificate.read()
    try:
        signed_pdf, signer_name = await PdfSigner.sign_async(pdf_data, cert_data, password)
    except ValueError as e:
        raise HTTPException(400, str(e))
    signed_filename = pdf_file.filename.replace('.pdf', '_signed.pdf')
    return Response(
        content=signed_pdf, media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={signed_filename}", "X-Signer-Name": signer_name}
    )

# Verify PDF đã ký
@app.post("/verify-pdf")
async def verify_pdf_standard(pdf_file: UploadFile = File(...)):
    pdf_data = await pdf_file.read()
    return PdfSigner.verify(pdf_data)

# Tạo certificate test để thử ký PDF
@app.post("/generate-certificate")
async def generate_test_certificate(name: str = Form(...), organization: str = Form("Test Organization"), password: str = Form("123456")):
    pfx_data, cert_password = PdfSigner.generate_test_certificate(name=name, organization=organization, password=password)
    filename = f"{name.replace(' ', '_')}_certificate.pfx"
    return Response(
        content=pfx_data, media_type="application/x-pkcs12",
        headers={"Content-Disposition": f"attachment; filename={filename}", "X-Certificate-Password": cert_password}
    )

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("🚀 Digital Signature API Server")
    print("=" * 60)
    print("🌐 Server: http://localhost:8000")
    print("📚 API Docs: http://localhost:8000/docs")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000)
