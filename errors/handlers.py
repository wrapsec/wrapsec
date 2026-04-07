from fastapi import Request
from fastapi.responses import JSONResponse
from errors.exceptions import WrapSecError


def wrapsec_exception_handler(request: Request, exc: WrapSecError) -> JSONResponse:
    trace_id = str(exc.trace_id) if exc.trace_id else request.headers.get("x-trace-id", "")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code":     exc.code,
                "message":  exc.message,
                "trace_id": trace_id,
            }
        },
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code":     "INTERNAL_ERROR",
                "message":  "An unexpected error occurred.",
                "trace_id": request.headers.get("x-trace-id", ""),
            }
        },
    )