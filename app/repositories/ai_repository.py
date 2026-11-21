from sqlalchemy.orm import Session

from app.models.ai_analysis import AIAnalysisModel


class AIRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_analyses_for_alert(self, alert_id: str) -> list[AIAnalysisModel]:
        return (
            self.db.query(AIAnalysisModel)
            .filter(AIAnalysisModel.alert_id == alert_id)
            .order_by(AIAnalysisModel.created_at.desc())
            .all()
        )

    def get_latest_analysis_for_alert(self, alert_id: str) -> AIAnalysisModel | None:
        return (
            self.db.query(AIAnalysisModel)
            .filter(AIAnalysisModel.alert_id == alert_id)
            .order_by(AIAnalysisModel.created_at.desc())
            .first()
        )

    def save_analysis(self, model: AIAnalysisModel) -> AIAnalysisModel:
        self.db.add(model)
        self.db.commit()
        self.db.refresh(model)
        return model
