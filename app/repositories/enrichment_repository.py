from sqlalchemy.orm import Session
from app.models.enrichment import EnrichmentModel
from typing import List, Optional

class EnrichmentRepository:
    def __init__(self, db: Session):
        self.db = db

    def save_enrichment(self, model: EnrichmentModel) -> EnrichmentModel:
        self.db.add(model)
        self.db.commit()
        self.db.refresh(model)
        return model

    def get_recent_enrichments(self, limit: int = 10) -> List[EnrichmentModel]:
        return self.db.query(EnrichmentModel).order_by(EnrichmentModel.created_at.desc()).limit(limit).all()
        
    def get_latest_enrichment_for_ioc(self, ioc: str) -> Optional[EnrichmentModel]:
        return self.db.query(EnrichmentModel).filter(EnrichmentModel.observable_value == ioc).order_by(EnrichmentModel.created_at.desc()).first()
