import os
import base64
from urllib.parse import quote
from fastapi import HTTPException, APIRouter, Request
from fastapi.responses import StreamingResponse
from fastapi.datastructures import UploadFile   
from typing import Optional
from ..utils import crypto_utils
from ..schemas.cryptoModels import TextDecryptRequest, TextDecryptResponse, TextEncryptRequest, TextEncryptResponse
from ..db.session import SessionDep 

router = APIRouter()

@router.post("/text/encrypt", response_model=TextEncryptResponse, tags=["Text"])
async def encrypt_text_endpoint(
    request: TextEncryptRequest,
    session: SessionDep  
):
    try:
        iv = crypto_utils.get_iv_from_lcg(session) 
        encrypted_bytes = crypto_utils.encrypt_text(request.password, request.text, iv)
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
        return TextEncryptResponse(encrypted_data_b64=encrypted_b64)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Помилка шифрування: {e}")

@router.post("/text/decrypt", response_model=TextDecryptResponse, tags=["Text"])
async def decrypt_text_endpoint(request: TextDecryptRequest):
    try:
        encrypted_bytes = base64.b64decode(request.encrypted_data_b64)
        decrypted_text = crypto_utils.decrypt_text(request.password, encrypted_bytes)
        return TextDecryptResponse(text=decrypted_text)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Помилка дешифрування: {e}")

@router.post("/text-to-file/encrypt", tags=["Conversion"])
async def encrypt_text_to_file_endpoint(
    request: TextEncryptRequest,
    session: SessionDep
):
    try:
        iv = crypto_utils.get_iv_from_lcg(session) 
        encrypted_bytes = crypto_utils.encrypt_text(
            request.password, 
            request.text, 
            iv
        )
        
        async def stream_wrapper():
            yield encrypted_bytes

        output_filename = "encrypted_text.txt" 

        encoded_filename = quote(output_filename)

        return StreamingResponse(
            stream_wrapper(),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Помилка шифрування: {e}")

@router.post("/file-to-text/decrypt", response_model=TextDecryptResponse, tags=["Conversion"])
async def decrypt_file_to_text_endpoint(request: Request):
    try:
        form = await request.form()
        password: str = form.get("password")
        file: UploadFile = form.get("file")

        if not file or not file.filename:
            raise HTTPException(status_code=400, detail="Файл не надано")
        if not password:
            raise HTTPException(status_code=400, detail="Пароль не надано")     
    except Exception:
         raise HTTPException(status_code=400, detail="Некоректний form-data запит")

    try:
        encrypted_bytes = await file.read()
        if not encrypted_bytes:
            raise ValueError("Файл порожній")

        decrypted_text = crypto_utils.decrypt_text(password, encrypted_bytes)
        return TextDecryptResponse(text=decrypted_text)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Помилка дешифрування: {e}")
    finally:
        await file.close()

@router.post("/file/encrypt", tags=["File"])
async def encrypt_file_endpoint(
    request: Request,
    session: SessionDep
):
    try:
        form = await request.form()
        password: str = form.get("password")
        file: UploadFile = form.get("file")
        
        if not file or not file.filename:
            raise HTTPException(status_code=400, detail="Файл не надано")
        if not password:
            raise HTTPException(status_code=400, detail="Пароль не надано")
            
    except Exception:
         raise HTTPException(status_code=400, detail="Некоректний form-data запит")

    filename, file_extension = os.path.splitext(file.filename)
    output_filename = f"{filename}_encrypted{file_extension}"

    encoded_filename = quote(output_filename)
    
    try:
        iv = crypto_utils.get_iv_from_lcg(session)
    except Exception as e:
        await file.close() 
        raise HTTPException(status_code=500, detail=f"Помилка генерації IV: {e}")

    async def stream_wrapper():
        try:
            async for chunk in crypto_utils.encrypt_file_stream(password, file, iv):
                yield chunk
        except Exception as e:
            print(f"Error during encryption stream: {e}")
        finally:
            print("Encrypt stream finished. Closing file.")
            await file.close() 

    return StreamingResponse(
        stream_wrapper(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"}
    )


@router.post("/file/decrypt", tags=["File"])
async def decrypt_file_endpoint(
    request: Request 
):
    try:
        form = await request.form()
        password: str = form.get("password")
        file: UploadFile = form.get("file")
        original_filename: Optional[str] = form.get("original_filename")

        if not file or not file.filename:
            raise HTTPException(status_code=400, detail="Файл не надано")
        if not password:
            raise HTTPException(status_code=400, detail="Пароль не надано")
            
    except Exception:
         raise HTTPException(status_code=400, detail="Некоректний form-data запит")
    
    if original_filename:
        output_filename = original_filename
    else:
        filename, file_extension = os.path.splitext(file.filename)
        if filename.endswith("_encrypted"):
            clean_name = filename[:-10]
            output_filename = f"{clean_name}_decrypted{file_extension}"
        else:
            output_filename = f"{filename}_decrypted{file_extension}"

    encoded_filename = quote(output_filename)

    async def stream_wrapper():
        try:
            async for chunk in crypto_utils.decrypt_file_stream(password, file):
                yield chunk
        except ValueError as e:
            print(f"Stream interrupted (wrong password?): {e}")
            pass 
        except Exception as e:
            print(f"Error during decryption stream: {e}")
        finally:
            print("Decrypt stream finished. Closing file.")
            await file.close() 

    return StreamingResponse(
        stream_wrapper(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"}
    )