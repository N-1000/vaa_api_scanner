from fastapi import FastAPI, HTTPException
from typing import Dict, Any
from app.models import ResponseVector, GenerationRequest, PredictionResponse, GenerationResponse
from app.core.m1_grammar import M1GrammarModel
from app.core.m2_generation import M2AdaptiveGenerator
from app.core.m3_classification import M3IntelligentClassifier
import os

app = FastAPI(title="VAA - Vulnerability Assessment Agent")


MODELS_DIR = "models"
if not os.path.exists(MODELS_DIR):
    os.makedirs(MODELS_DIR)

MODEL_FILE = os.path.join(MODELS_DIR, "vaa_model.json")

m1_grammar = M1GrammarModel()
m1_grammar.load_context(MODEL_FILE)

m2_generator = M2AdaptiveGenerator()
m3_classifier = M3IntelligentClassifier()

@app.post("/predict", response_model=PredictionResponse)
async def predict_risk(vector: ResponseVector):
    """
    Executes M3: Intelligent Classification.
    """
    try:

        if hasattr(vector, 'model_dump'):
             vector_data = vector.model_dump()
        else:
             vector_data = vector.dict()
             
        risk, confidence = m3_classifier.predict_risk(vector_data)
        return PredictionResponse(risk_level=risk, confidence=confidence)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/learn")
async def learn_from_traffic(traffic: Dict[str, Any]):
    """
    Executes M1: Grammar Inference.
    Feeds traffic data to M1 to refine the application grammar.
    """
    try:
        updated_context = m1_grammar.learn_from_traffic(traffic)
        m1_grammar.save_context(MODEL_FILE)
        return {"message": "Traffic processed", "current_context_size": len(updated_context)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/generate", response_model=GenerationResponse)
async def generate_payload(request: GenerationRequest):
    """
    Executes M2: Adaptive Generation.
    """

    try:

        context_to_use = request.context if request.context else m1_grammar.grammar_context
        

        payload, score = m2_generator.generate_payload(
            context_to_use, 
            request.target_url or "/unknown", 
            request.vulnerability_type
        )
        return GenerationResponse(payload=payload, context_violation_score=score)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
async def root():
    return {"message": "VAA Agent is running"}


