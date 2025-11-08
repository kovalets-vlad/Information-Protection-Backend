import base64
from fastapi import HTTPException, UploadFile, File, Form, APIRouter, Depends 
from fastapi.responses import StreamingResponse
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

        encrypted_bytes = crypto_utils.encrypt_text(
            request.password, 
            request.text, 
            iv  #
        )
        
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


@router.post("/file/encrypt", tags=["File"])
async def encrypt_file_endpoint(
    session: SessionDep, 
    password: str = Form(...),
    file: UploadFile = File(...)
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Файл не надано")

    output_filename = f"{file.filename}.rc5"
    
    try:
        iv = crypto_utils.get_iv_from_lcg(session)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Помилка генерації IV: {e}")

    return StreamingResponse(
        crypto_utils.encrypt_file_stream(password, file, iv), 
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={output_filename}"}
    )


@router.post("/file/decrypt", tags=["File"])
async def decrypt_file_endpoint(
    password: str = Form(...),
    file: UploadFile = File(...),
    original_filename: Optional[str] = Form(None)
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Файл не надано")

    if original_filename:
        output_filename = original_filename
    elif file.filename.endswith(".rc5"):
        output_filename = file.filename[:-4] 
    else:
        output_filename = f"{file.filename}.decrypted"

    async def stream_wrapper():
        try:
            async for chunk in crypto_utils.decrypt_file_stream(password, file):
                yield chunk
        except ValueError as e:
            print(f"Stream interrupted: {e}")
            pass

    return StreamingResponse(
        stream_wrapper(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={output_filename}"}
    )