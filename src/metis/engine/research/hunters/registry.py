# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable

from metis.engine.research.hunters.authz_outlier import AuthzOutlierHunter
from metis.engine.research.hunters.base import Hunter, HunterMetadata
from metis.engine.research.hunters.code_injection import CodeInjectionHunter
from metis.engine.research.hunters.command_injection import CommandInjectionHunter
from metis.engine.research.hunters.crypto_misuse import CryptoMisuseHunter
from metis.engine.research.hunters.deserialization import DeserializationHunter
from metis.engine.research.hunters.evm_external_call import EvmExternalCallHunter
from metis.engine.research.hunters.hardware_security import HardwareSecurityHunter
from metis.engine.research.hunters.iac_exposure import IacExposureHunter
from metis.engine.research.hunters.injection_path import InjectionPathHunter
from metis.engine.research.hunters.memory_lifetime import MemoryLifetimeHunter
from metis.engine.research.hunters.nosql_injection import NoSqlInjectionHunter
from metis.engine.research.hunters.path_traversal import PathTraversalHunter
from metis.engine.research.hunters.secrets_exposure import SecretsExposureHunter
from metis.engine.research.hunters.sql_injection import SqlInjectionHunter
from metis.engine.research.hunters.ssrf import SsrfHunter
from metis.engine.research.hunters.template_injection import TemplateInjectionHunter
from metis.engine.research.hunters.xss import XssHunter
from metis.engine.research.hunters.xxe import XxeHunter


class HunterRegistry:
    def __init__(self, hunters: Iterable[Hunter]) -> None:
        by_name: dict[str, Hunter] = {}
        for hunter in hunters:
            if hunter.name in by_name:
                raise ValueError(f"Duplicate research hunter: {hunter.name}")
            by_name[hunter.name] = hunter
        self._hunters = dict(sorted(by_name.items()))

    @classmethod
    def default(cls) -> "HunterRegistry":
        return cls(
            (
                AuthzOutlierHunter(),
                CodeInjectionHunter(),
                CommandInjectionHunter(),
                CryptoMisuseHunter(),
                DeserializationHunter(),
                EvmExternalCallHunter(),
                HardwareSecurityHunter(),
                IacExposureHunter(),
                InjectionPathHunter(),
                MemoryLifetimeHunter(),
                NoSqlInjectionHunter(),
                PathTraversalHunter(),
                SecretsExposureHunter(),
                SqlInjectionHunter(),
                SsrfHunter(),
                TemplateInjectionHunter(),
                XssHunter(),
                XxeHunter(),
            )
        )

    def available_names(self) -> tuple[str, ...]:
        return tuple(self._hunters)

    def metadata_for(self, name: str) -> HunterMetadata:
        return self._hunter_for(name).metadata

    def select(self, names: Iterable[str]) -> list[Hunter]:
        return [self._hunter_for(name) for name in names]

    def _hunter_for(self, name: str) -> Hunter:
        normalized = str(name).strip()
        hunter = self._hunters.get(normalized)
        if hunter is not None:
            return hunter
        available = ", ".join(self.available_names())
        raise ValueError(
            f"Unknown research hunter: {normalized}. Available hunters: {available}"
        )
