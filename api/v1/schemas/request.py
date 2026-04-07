from pydantic import BaseModel, Field, model_validator
from domain.enums import DetectionMode, ExecutionMode
from errors.exceptions import StreamNotSupportedError, ModelRequiredError


class RequestMetadataSchema(BaseModel):
    tenant_id: str | None = None
    source:    str | None = None
    user_id:   str | None = None


class RequestContextSchema(BaseModel):
    user_role:   str | None = None
    sensitivity: str | None = None  # low | medium | high


class RequestOptionsSchema(BaseModel):
    stream: bool = False
    debug:  bool = False


class AIRequestSchema(BaseModel):
    input:          str                       = Field(..., min_length=1, max_length=10000)
    detection_mode: DetectionMode             = DetectionMode.FAST
    execution_mode: ExecutionMode             = ExecutionMode.SCAN_ONLY
    model:          str | None                = None
    metadata:       RequestMetadataSchema     = Field(default_factory=RequestMetadataSchema)
    context:        RequestContextSchema      = Field(default_factory=RequestContextSchema)
    options:        RequestOptionsSchema      = Field(default_factory=RequestOptionsSchema)

    @model_validator(mode="after")
    def validate_mode_combinations(self) -> "AIRequestSchema":
        # stream only valid in proxy mode
        if self.options.stream and self.execution_mode == ExecutionMode.SCAN_ONLY:
            raise StreamNotSupportedError()

        # model required in proxy mode
        if self.execution_mode == ExecutionMode.PROXY and not self.model:
            raise ModelRequiredError()

        return self

    model_config = {"use_enum_values": True, "populate_by_name": True}