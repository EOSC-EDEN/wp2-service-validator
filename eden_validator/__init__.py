"""eden_validator — EOSC-EDEN service endpoint validation library.

Public API (this is the contract wp2-repo-harvester pins against):
    from eden_validator import ServiceValidator, resolve_type, FusekiLoader
"""
from eden_validator.validator import ServiceValidator
from eden_validator.type_resolver import resolve_type
from eden_validator.fuseki_loader import FusekiLoader

__all__ = ["ServiceValidator", "resolve_type", "FusekiLoader"]
