from app.detection.registry import RuleRegistry
from app.detection.rules.sqli import SQLInjectionRule
from app.detection.rules.xss import XSSRule
from app.detection.rules.path_traversal import PathTraversalRule
from app.detection.rules.cmd_injection import CommandInjectionRule
from app.detection.rules.dir_enum import DirectoryEnumerationRule
from app.detection.rules.brute_force import BruteForceRule

# Register all rules
RuleRegistry.register_rule(SQLInjectionRule)
RuleRegistry.register_rule(XSSRule)
RuleRegistry.register_rule(PathTraversalRule)
RuleRegistry.register_rule(CommandInjectionRule)
RuleRegistry.register_rule(DirectoryEnumerationRule)
RuleRegistry.register_rule(BruteForceRule)
