"""
NiksES Scoring Configuration API

Endpoints to view and update scoring configuration dynamically.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
import logging

from app.config.scoring import (
    get_scoring_config, 
    update_scoring_config, 
    reset_scoring_config,
    ScoringConfig,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scoring", tags=["scoring"])


class ThresholdsUpdate(BaseModel):
    """Update risk thresholds."""
    critical: Optional[int] = Field(None, ge=0, le=100)
    high: Optional[int] = Field(None, ge=0, le=100)
    medium: Optional[int] = Field(None, ge=0, le=100)
    low: Optional[int] = Field(None, ge=0, le=100)


class TIWeightsUpdate(BaseModel):
    """Update TI source weights."""
    virustotal: Optional[float] = Field(None, ge=0, le=1)
    google_safebrowsing: Optional[float] = Field(None, ge=0, le=1)
    ipqualityscore: Optional[float] = Field(None, ge=0, le=1)
    abuseipdb: Optional[float] = Field(None, ge=0, le=1)
    urlhaus: Optional[float] = Field(None, ge=0, le=1)
    phishtank: Optional[float] = Field(None, ge=0, le=1)


class SEWeightsUpdate(BaseModel):
    """Update SE technique weights."""
    urgency: Optional[float] = Field(None, ge=0, le=1)
    fear: Optional[float] = Field(None, ge=0, le=1)
    authority: Optional[float] = Field(None, ge=0, le=1)
    reward: Optional[float] = Field(None, ge=0, le=1)
    scarcity: Optional[float] = Field(None, ge=0, le=1)
    trust: Optional[float] = Field(None, ge=0, le=1)
    social_proof: Optional[float] = Field(None, ge=0, le=1)


class AIConfigUpdate(BaseModel):
    """Update AI configuration."""
    block_threshold: Optional[int] = Field(None, ge=0, le=100)
    quarantine_threshold: Optional[int] = Field(None, ge=0, le=100)
    review_threshold: Optional[int] = Field(None, ge=0, le=100)
    llm_blend_weight: Optional[float] = Field(None, ge=0, le=1)


class ScoringConfigUpdate(BaseModel):
    """Full scoring configuration update."""
    thresholds: Optional[ThresholdsUpdate] = None
    ti_weights: Optional[TIWeightsUpdate] = None
    se_weights: Optional[SEWeightsUpdate] = None
    ai_config: Optional[AIConfigUpdate] = None


@router.get("")
async def get_scoring_configuration():
    """
    Get current scoring configuration.
    
    Returns all thresholds, weights, and settings used for scoring.
    """
    config = get_scoring_config()
    return {
        "success": True,
        "config": config.to_dict(),
        "description": {
            "thresholds": "Risk level thresholds (score >= threshold = that level)",
            "ti_weights": "Weights for each TI source in fusion (should sum to ~1.0)",
            "ti_thresholds": "Thresholds for individual TI source verdicts",
            "se_weights": "Weights for SE technique scoring",
            "se_thresholds": "Thresholds for SE risk levels",
            "detection_weights": "Weights for detection rule categories",
            "ai_config": "AI analysis configuration",
        }
    }


@router.patch("")
async def update_scoring_configuration(updates: ScoringConfigUpdate):
    """
    Update scoring configuration dynamically.
    
    Changes take effect immediately for all subsequent analyses.
    """
    update_dict = {}
    
    if updates.thresholds:
        update_dict["thresholds"] = {
            k: v for k, v in updates.thresholds.model_dump().items() 
            if v is not None
        }
    
    if updates.ti_weights:
        update_dict["ti_weights"] = {
            k: v for k, v in updates.ti_weights.model_dump().items() 
            if v is not None
        }
    
    if updates.se_weights:
        update_dict["se_weights"] = {
            k: v for k, v in updates.se_weights.model_dump().items() 
            if v is not None
        }
    
    if updates.ai_config:
        update_dict["ai_config"] = {
            k: v for k, v in updates.ai_config.model_dump().items() 
            if v is not None
        }
    
    if not update_dict:
        raise HTTPException(status_code=400, detail="No updates provided")
    
    config = update_scoring_config(update_dict)
    
    return {
        "success": True,
        "message": "Scoring configuration updated",
        "updated_fields": list(update_dict.keys()),
        "config": config.to_dict(),
    }


@router.post("/reset")
async def reset_scoring_configuration():
    """
    Reset scoring configuration to defaults.
    """
    reset_scoring_config()
    config = get_scoring_config()
    
    return {
        "success": True,
        "message": "Scoring configuration reset to defaults",
        "config": config.to_dict(),
    }


@router.get("/thresholds")
async def get_thresholds():
    """Get just the risk thresholds."""
    config = get_scoring_config()
    return {
        "thresholds": config.thresholds.__dict__,
        "description": {
            "critical": "Score >= this = CRITICAL risk",
            "high": "Score >= this = HIGH risk",
            "medium": "Score >= this = MEDIUM risk",
            "low": "Score >= this = LOW risk",
            "* below low": "Score below low = CLEAN",
        }
    }


@router.get("/weights")
async def get_weights():
    """Get all scoring weights."""
    config = get_scoring_config()
    return {
        "ti_weights": config.ti_weights.__dict__,
        "se_weights": config.se_weights.__dict__,
        "detection_weights": config.detection_weights.__dict__,
        "note": "Weights control how much each component contributes to final score"
    }


@router.get("/presets")
async def get_scoring_presets():
    """
    Get predefined scoring presets.
    
    Use these as starting points for different use cases.
    """
    return {
        "presets": {
            "default": {
                "description": "Balanced detection - good for most environments",
                "thresholds": {"critical": 75, "high": 50, "medium": 25, "low": 10},
            },
            "aggressive": {
                "description": "Catch more threats, higher false positive rate",
                "thresholds": {"critical": 60, "high": 35, "medium": 15, "low": 5},
            },
            "conservative": {
                "description": "Fewer false positives, may miss some threats",
                "thresholds": {"critical": 85, "high": 65, "medium": 40, "low": 20},
            },
            "zero_trust": {
                "description": "Maximum security - flag everything suspicious",
                "thresholds": {"critical": 50, "high": 25, "medium": 10, "low": 1},
            },
        },
        "usage": "PATCH /api/v1/scoring with the preset's thresholds to apply"
    }


@router.post("/presets/{preset_name}")
async def apply_scoring_preset(preset_name: str):
    """Apply a predefined scoring preset."""
    presets = {
        "default": {"critical": 75, "high": 50, "medium": 25, "low": 10},
        "aggressive": {"critical": 60, "high": 35, "medium": 15, "low": 5},
        "conservative": {"critical": 85, "high": 65, "medium": 40, "low": 20},
        "zero_trust": {"critical": 50, "high": 25, "medium": 10, "low": 1},
    }
    
    if preset_name not in presets:
        raise HTTPException(
            status_code=404, 
            detail=f"Preset '{preset_name}' not found. Available: {list(presets.keys())}"
        )
    
    config = update_scoring_config({"thresholds": presets[preset_name]})
    
    return {
        "success": True,
        "message": f"Applied '{preset_name}' preset",
        "thresholds": config.thresholds.__dict__,
    }
