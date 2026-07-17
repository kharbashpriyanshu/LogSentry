from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from app.schemas.api import ParseLineRequest, ParseResponse, ParseFileResponse
from app.services.parsing_service import ParsingService
from app.api.dependencies import get_parsing_service
from app.parsers.exceptions import UnsupportedParserError, ParserError

router = APIRouter()

@router.post("/parse-line", response_model=ParseResponse)
def parse_line(
    request: ParseLineRequest,
    parsing_service: ParsingService = Depends(get_parsing_service)
):
    try:
        event = parsing_service.parse_line(request.parser_name, request.log_line)
        return ParseResponse(success=True, event=event.model_dump())
    except ValueError as e:
        return ParseResponse(success=False, error=str(e))

@router.post("/parse-file", response_model=ParseFileResponse)
async def parse_file(
    parser_name: str = Form(...),
    file: UploadFile = File(...),
    parsing_service: ParsingService = Depends(get_parsing_service)
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
        
    total, success, failed, events = await parsing_service.parse_file(parser_name, file)
    
    return ParseFileResponse(
        total_lines_processed=total,
        successful_parses=success,
        failed_parses=failed,
        events=[e.model_dump() for e in events]
    )
