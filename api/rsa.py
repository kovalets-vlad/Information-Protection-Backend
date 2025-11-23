import io
import zipfile
from urllib.parse import quote
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.datastructures import UploadFile 
from ..utils import rsa_utils

router = APIRouter()

@router.get("/rsa/keys/generate", tags=["RSA"])
async def generate_keys():
    try:
        priv_pem, pub_pem = rsa_utils.generate_rsa_keys()
        
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
            zip_file.writestr("private.pem", priv_pem)
            zip_file.writestr("public.pem", pub_pem)
        
        zip_buffer.seek(0)
        
        return StreamingResponse(
            zip_buffer, 
            media_type="application/zip", 
            headers={"Content-Disposition": "attachment; filename=rsa_keys.zip"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Помилка генерації ключів: {str(e)}")


@router.post("/rsa/encrypt", tags=["RSA"])
async def rsa_encrypt_file(
    request: Request
):
    try:
        form = await request.form()
        file: UploadFile = form.get("file")
        public_key: UploadFile = form.get("public_key")

        if not file or not public_key:
             raise HTTPException(status_code=400, detail="Необхідно надати файл та публічний ключ")

    except Exception:
         raise HTTPException(status_code=400, detail="Некоректний form-data запит")

    try:
        pub_key_bytes = await public_key.read()
        await public_key.close()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Помилка читання ключа: {str(e)}")

    filename = file.filename or "file"
    encoded_filename = quote(f"{filename}.enc")

    async def stream_wrapper():
        try:
            async for chunk in rsa_utils.encrypt_file_hybrid_stream(file, pub_key_bytes):
                yield chunk
        except Exception as e:
            print(f"Error during RSA encryption stream: {e}")
        finally:
            print("RSA Encrypt stream finished. Closing file.")
            await file.close()

    return StreamingResponse(
        stream_wrapper(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"}
    )

@router.post("/rsa/decrypt", tags=["RSA"])
async def rsa_decrypt_file(
    request: Request
):
    try:
        form = await request.form()
        file: UploadFile = form.get("file")
        private_key: UploadFile = form.get("private_key")

        if not file or not private_key:
             raise HTTPException(status_code=400, detail="Необхідно надати файл та приватний ключ")

    except Exception:
         raise HTTPException(status_code=400, detail="Некоректний form-data запит")

    try:
        priv_key_bytes = await private_key.read()
        await private_key.close()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Помилка читання ключа: {str(e)}")

    filename = file.filename or "file.decrypted"
    if filename.endswith(".enc"):
        filename = filename[:-4]
    
    encoded_filename = quote(f"decrypted_{filename}")

    async def stream_wrapper():
        try:
            async for chunk in rsa_utils.decrypt_file_hybrid_stream(file, priv_key_bytes):
                yield chunk
        except ValueError as e:
             print(f"RSA Decryption error (wrong key?): {e}")
        except Exception as e:
             print(f"Error during RSA decryption stream: {e}")
        finally:
            print("RSA Decrypt stream finished. Closing file.")
            await file.close()

    return StreamingResponse(
        stream_wrapper(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"}
    )