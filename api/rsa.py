import io
import zipfile
import traceback
from urllib.parse import quote
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from utils import rsa_utils
from cryptography.hazmat.primitives import serialization

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


@router.post("/rsa/encrypt")
async def encrypt_file_endpoint(request: Request):
    try:
        form = await request.form()
        file = form.get("file")
        public_key = form.get("public_key")

        if not file or not public_key:
            raise HTTPException(status_code=400, detail="Необхідно надати файл та публічний ключ")

    except Exception:
         raise HTTPException(status_code=400, detail="Некоректний form-data запит")

    try:
        pub_key_bytes = await public_key.read()
        await public_key.close() 
        
        try:
            serialization.load_pem_public_key(pub_key_bytes)
        except ValueError:
            raise HTTPException(status_code=400, detail="Некоректний файл публічного ключа (очікується формат PEM).")
        except Exception as e:
             raise HTTPException(status_code=400, detail=f"Помилка валідації ключа: {str(e)}")
             
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Помилка читання ключа: {str(e)}")

    filename = file.filename or "file"
    encoded_filename = quote(f"{filename}.enc")

    # Обгортка для стрімінгу, щоб закрити файл після завершення
    async def stream_wrapper():
        try:
            async for chunk in rsa_utils.encrypt_file_hybrid_stream(file, pub_key_bytes):
                yield chunk
        except Exception as e:
            print(f"Error during RSA encryption stream: {e}")
            # Можна кинути помилку, але стрім вже почався
        finally:
            await file.close()

    return StreamingResponse(
        stream_wrapper(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"}
    )

@router.post("/rsa/decrypt")
async def decrypt_file_endpoint(request: Request):
    try:
        form = await request.form()
        file = form.get("file")
        private_key = form.get("private_key")

        if not file or not private_key:
            raise HTTPException(status_code=400, detail="Необхідно завантажити файл і приватний ключ")

        priv_key_bytes = await private_key.read()

        # --- ЗМІНА ТУТ: Отримуємо decryptor та довжину даних (2 значення) ---
        decryptor, ciphertext_len = await rsa_utils.init_decrypt_session(file, priv_key_bytes)

        filename = file.filename or "decrypted_file"
        if filename.endswith(".enc"):
            filename = filename[:-4]
        encoded_filename = quote(f"decrypted_{filename}")

        async def stream_wrapper():
            try:
                # Передаємо довжину даних у функцію розшифрування
                async for chunk in rsa_utils.stream_decrypt_data(file, decryptor, ciphertext_len):
                    yield chunk
            except Exception as e:
                print(f"Stream error: {e}")
                # Тут вже важко повернути HTTP помилку клієнту, бо стрім пішов, 
                # але сервер не впаде.

        return StreamingResponse(
            stream_wrapper(),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"}
        )

    except HTTPException as e:
        raise e 
    except Exception as e:
        traceback.print_exc() # Виведе деталі в консоль
        raise HTTPException(status_code=500, detail=f"Помилка сервера: {str(e)}")
