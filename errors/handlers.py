from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from errors.exceptions import WrapSecError


def wrapsec_exception_handler(request: Request, exc: WrapSecError) -> JSONResponse:
    trace_id = str(exc.trace_id) if exc.trace_id else getattr(request.state, "trace_id", "")
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


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Extract first error message
    errors = exc.errors()
    message = errors[0]["msg"].replace("Value error, ", "") if errors else "Validation error"
    trace_id = getattr(request.state, "trace_id", "")
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code":     "VALIDATION_ERROR",
                "message":  message,
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
                "trace_id": getattr(request.state, "trace_id", ""),
            }
        },
    )