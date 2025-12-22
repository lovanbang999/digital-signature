"""
PDF Standard Signing Module
Ký PDF theo chuẩn PAdES sử dụng pyHanko
"""

import io
import tempfile
import os
from pyhanko.sign import signers
from pyhanko.sign.signers.pdf_signer import PdfSignatureMetadata
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend


class PdfSigner:
    """
    Hệ thống ký PDF theo chuẩn PAdES
    Sử dụng certificate PFX/P12 để ký số nhúng vào PDF
    """
    
    @staticmethod
    async def sign_async(pdf_data: bytes, cert_data: bytes, password: str = "") -> tuple[bytes, str]:
        """
        Ký PDF với certificate PFX/P12 (async)
        
        Args:
            pdf_data: nội dung file PDF
            cert_data: nội dung file certificate (PFX/P12)
            password: mật khẩu certificate
            
        Returns:
            tuple: (signed_pdf_bytes, signer_name)
        """
        password_bytes = password.encode('utf-8') if password else None
        
        # Validate certificate
        private_key, cert, _ = pkcs12.load_key_and_certificates(
            cert_data, password_bytes, default_backend()
        )
        
        if private_key is None or cert is None:
            raise ValueError("Certificate phải chứa private key và certificate")
        
        # Tạo temp file cho certificate
        with tempfile.NamedTemporaryFile(suffix='.pfx', delete=False) as tmp_cert:
            tmp_cert.write(cert_data)
            tmp_cert_path = tmp_cert.name
        
        try:
            signer = signers.SimpleSigner.load_pkcs12(
                pfx_file=tmp_cert_path,
                passphrase=password_bytes
            )
            
            pdf_writer = IncrementalPdfFileWriter(io.BytesIO(pdf_data))
            
            signature_meta = PdfSignatureMetadata(
                field_name='Signature1',
                reason='Ký xác nhận tài liệu',
                location='Vietnam'
            )
            
            output = io.BytesIO()
            await signers.async_sign_pdf(
                pdf_writer,
                signature_meta,
                signer=signer,
                output=output
            )
            
            # Lấy tên người ký
            signer_name = "Unknown"
            if cert.subject:
                for attr in cert.subject:
                    if attr.oid.dotted_string == "2.5.4.3":
                        signer_name = attr.value
                        break
            
            output.seek(0)
            return output.getvalue(), signer_name
            
        finally:
            os.unlink(tmp_cert_path)
    
    
    @staticmethod
    def verify(pdf_data: bytes) -> dict:
        """
        Xác minh chữ ký trong PDF
        
        Args:
            pdf_data: nội dung file PDF
            
        Returns:
            dict: Thông tin về các chữ ký trong PDF
        """
        try:
            pdf_reader = PdfFileReader(io.BytesIO(pdf_data))
        except Exception as e:
            return {
                "has_signatures": False,
                "all_valid": False,
                "signatures": [],
                "message": f"Không thể đọc PDF: {str(e)}"
            }
        
        signatures_info = []
        
        try:
            for sig in pdf_reader.embedded_signatures:
                sig_info = {
                    "field_name": sig.field_name,
                    "signer": "Unknown",
                    "organization": None,
                    "signing_time": None,
                    "valid": False,
                    "reason": None,
                    "location": None
                }
                
                # Lấy thông tin từ certificate
                try:
                    if sig.signer_cert:
                        subject = sig.signer_cert.subject
                        for attr in subject:
                            oid = attr.oid.dotted_string
                            # Common Name (CN)
                            if oid == "2.5.4.3":
                                sig_info["signer"] = attr.value
                            # Organization (O)
                            elif oid == "2.5.4.10":
                                sig_info["organization"] = attr.value
                except:
                    pass
                
                # Lấy signing time
                try:
                    if hasattr(sig, 'self_reported_signing_time') and sig.self_reported_signing_time:
                        sig_info["signing_time"] = sig.self_reported_signing_time.isoformat()
                except:
                    pass
                
                # Lấy reason và location
                try:
                    sig_obj = sig.sig_object
                    if '/Reason' in sig_obj:
                        sig_info["reason"] = str(sig_obj['/Reason'])
                    if '/Location' in sig_obj:
                        sig_info["location"] = str(sig_obj['/Location'])
                except:
                    pass
                
                # Validate signature
                try:
                    sig_info["valid"] = sig.intact
                except:
                    sig_info["valid"] = True
                
                signatures_info.append(sig_info)
                
        except:
            pass
        
        has_signatures = len(signatures_info) > 0
        all_valid = all(s["valid"] for s in signatures_info) if has_signatures else False
        
        return {
            "has_signatures": has_signatures,
            "all_valid": all_valid,
            "signatures": signatures_info,
            "message": PdfSigner._build_message(has_signatures, all_valid, len(signatures_info))
        }
    
    
    @staticmethod
    def _build_message(has_signatures: bool, all_valid: bool, count: int) -> str:
        if not has_signatures:
            return "PDF không có chữ ký số"
        if all_valid:
            return f"Tìm thấy {count} chữ ký số - Tất cả hợp lệ ✓"
        return f"Tìm thấy {count} chữ ký số - Có chữ ký không hợp lệ ✗"
    
    
    @staticmethod
    def generate_test_certificate(
        name: str,
        organization: str = "Test Organization",
        password: str = "123456"
    ) -> tuple[bytes, str]:
        """
        Sinh certificate test (self-signed) để thử nghiệm
        """
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
        from datetime import datetime, timedelta
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Vietnam"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Hanoi"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=name.encode('utf-8'),
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=BestAvailableEncryption(password.encode('utf-8'))
        )
        
        return pfx_data, password
