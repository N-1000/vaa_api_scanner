from pydantic import BaseModel  # pyre-ignore[21]
from typing import Dict, Any, Optional

class ResponseVector(BaseModel):
    status: int
    length: int
    response_time_ms: float
    keyword_warning: int
    keyword_sql: int
    keyword_stack_trace: bool = False
    is_payload_reflected: bool = False
    context_violation_score: float = 0.0

class GenerationRequest(BaseModel):
    context: Optional[Dict[str, Any]] = None
    vulnerability_type: str
    target_url: Optional[str] = None

class PredictionResponse(BaseModel):
    risk_level: str
    confidence: float

class GenerationResponse(BaseModel):
    payload: str
    context_violation_score: float
