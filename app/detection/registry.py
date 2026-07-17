from typing import Dict, Type, List
import logging
from app.detection.base import BaseRule

logger = logging.getLogger(__name__)

class RuleRegistry:
    """Registry pattern for managing detection rules."""
    
    _registry: Dict[str, BaseRule] = {}
    
    @classmethod
    def register_rule(cls, rule_class: Type[BaseRule]) -> None:
        """Register a new detection rule."""
        rule_instance = rule_class()
        name = rule_instance.rule_name.lower()
        cls._registry[name] = rule_instance
        logger.info(f"Registered detection rule: {name} v{rule_instance.rule_version}")
        
    @classmethod
    def get_rule(cls, name: str) -> BaseRule:
        """Retrieve a specific rule by name."""
        rule = cls._registry.get(name.lower())
        if not rule:
            raise ValueError(f"Rule {name} not found in registry.")
        return rule
        
    @classmethod
    def get_all_rules(cls) -> List[BaseRule]:
        """Return all registered rules."""
        return list(cls._registry.values())

    @classmethod
    def get_rules_by_names(cls, names: List[str]) -> List[BaseRule]:
        """Return specific rules by their names, ignoring missing ones."""
        return [cls.get_rule(name) for name in names if name.lower() in cls._registry]
