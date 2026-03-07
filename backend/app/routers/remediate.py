from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.alert import Alert
from app.models.remediation import Remediation
from app.schemas.remediation import RemediationResponse

router = APIRouter(tags=["remediation"])


@router.get("/alerts/{alert_id}/remediation", response_model=RemediationResponse)
async def get_remediation(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    remediation = (
        db.query(Remediation).filter(Remediation.alert_id == alert_id).first()
    )
    if not remediation:
        raise HTTPException(status_code=404, detail="Remediation not found")

    return remediation
