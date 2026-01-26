import io
import zipfile
import anyio
from urllib.parse import quote
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from schemas.dsa_models import KeyGenRequest 
from utils.dss_utils import DSSManager

dss = DSSManager()
router = APIRouter()

@router.post("/dsa/keys/generate")
async def generate_keys_endpoint(req: KeyGenRequest): 
    """Генерує ключі, зберігає тимчасово, архівує і віддає клієнту."""
    try:
        filename_prefix = req.filename_prefix 
        
        priv_path, pub_path = dss.generate_keys(filename_prefix)
  
        async with await anyio.open_file(priv_path, "rb") as f:
            priv_content = await f.read()
            
        async with await anyio.open_file(pub_path, "rb") as f:
            pub_content = await f.read() 

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
            zip_file.writestr(f"{filename_prefix}_private.pem", priv_content)
            zip_file.writestr(f"{filename_prefix}_public.pem", pub_content)
        
        zip_buffer.seek(0)
        
        encoded_filename = quote(f"{filename_prefix}_dsa_keys.zip")

        return StreamingResponse(
            zip_buffer, 
            media_type="application/zip", 
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Помилка: {str(e)}")

@router.post("/dsa/sign/text")
async def sign_text_endpoint(
    text: str = Form(...),
    private_key_file: UploadFile = File(...)
):
    """Підписує текст, приймаючи файл ключа."""
    try:
        data_bytes = text.encode('utf-8')
        key_bytes = await private_key_file.read()
        
        signature = dss.sign_data_with_key_bytes(
            data_bytes, 
            key_bytes
        )
        
        return {
            "input_text": text,
            "signature_hex": signature
        }
    except ValueError:
        raise HTTPException(status_code=400, detail="Невірний формат ключа або пошкоджені дані")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dsa/sign/file")
async def sign_file_endpoint(
    file: UploadFile = File(...),
    private_key_file: UploadFile = File(...)
):
    """Підписує файл, приймаючи файл ключа."""
    try:
        file_content = await file.read()
        key_bytes = await private_key_file.read()
        
        signature = dss.sign_data_with_key_bytes(
            file_content, 
            key_bytes
        )
        
        return {
            "filename": file.filename,
            "signature_hex": signature
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dsa/verify/file")
async def verify_file_endpoint(
    file: UploadFile = File(...),
    public_key_file: UploadFile = File(...),
    signature_hex: str = Form(...)
):
    """Перевіряє підпис файлу, приймаючи файл публічного ключа."""
    try:
        file_content = await file.read()
        key_bytes = await public_key_file.read()
        
        is_valid = dss.verify_signature_with_key_bytes(
            file_content, 
            signature_hex, 
            key_bytes
        )
        
        if is_valid:
            return {"status": "success", "message": "Підпис ДІЙСНИЙ"}
        else:
            return {"status": "failure", "message": "Підпис НЕ ДІЙСНИЙ"}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing verification: {str(e)}")
    

@router.post("/dsa/verify/text")
async def verify_text_endpoint(
    text: str = Form(...),
    signature_hex: str = Form(...),
    public_key_file: UploadFile = File(...)
):
    try:
        data_bytes = text.encode('utf-8')
        key_bytes = await public_key_file.read()
        
        is_valid = dss.verify_signature_with_key_bytes(
            data_bytes, 
            signature_hex.strip(), 
            key_bytes
        )
        
        if is_valid:
            return {"status": "success", "message": "Підпис ДІЙСНИЙ"}
        else:
            return {"status": "failure", "message": "Підпис НЕ ДІЙСНИЙ"}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing verification: {str(e)}")