from fastapi import APIRouter, HTTPException, File, UploadFile
<<<<<<<< HEAD:api/md5.py
from schemas.md5_models import MD5Request, MD5Response
from utils.hashfun_utils import MD5
from core.core_varibles import STREAM_CHUNK_SIZE
========
from ..schemas.md5Models import MD5Request, MD5Response
from ..utils.hashfun_utils import MD5
from ..core.core_varibles import STREAM_CHUNK_SIZE
>>>>>>>> c14eb2577f81f05754d65a4cdf1e82f672bfa4a9:api/hashf_MD5.py

router = APIRouter()

@router.post("/md5", response_model=MD5Response)
def md5_from_string(req: MD5Request):
    try:
        md = MD5()
        md.update(req.data)        
        return {"hex": md.hexdigest(), "length": len(req.data.encode("utf-8"))}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/md5/file", response_model=MD5Response)
async def md5_from_file(file: UploadFile = File(...)):
    md = MD5()
    total = 0
    try:
        while True:
            chunk = await file.read(STREAM_CHUNK_SIZE)
            if not chunk:
                break
            md.update(chunk)
            total += len(chunk)
        await file.close()
        return {"hex": md.hexdigest(), "length": total}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))