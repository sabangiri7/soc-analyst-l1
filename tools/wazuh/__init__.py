# Wazuh manager tools for the AI SOC engineer.
from tools.wazuh.rules import (
    GetWazuhRules,
    GetWazuhRule,
    CreateWazuhRule,
    UpdateWazuhRule,
    DeleteWazuhRule,
)
from tools.wazuh.decoders import (
    GetWazuhDecoders,
    CreateWazuhDecoder,
    ModifyWazuhDecoder,
    DeleteWazuhDecoder,
)
from tools.wazuh.agents import (
    GetWazuhAgents,
    GetWazuhAgent,
    GetWazuhManagerStatus,
    GetWazuhClusterStatus,
    RestartWazuhManager,
    DisableWazuhAgent,
)
from tools.wazuh.configuration import GetWazuhConfiguration
from tools.wazuh.logtest import RunWazuhLogtest, EndWazuhLogtestSession

TOOLS = [
    GetWazuhRules,
    GetWazuhRule,
    CreateWazuhRule,
    UpdateWazuhRule,
    DeleteWazuhRule,
    GetWazuhDecoders,
    CreateWazuhDecoder,
    ModifyWazuhDecoder,
    DeleteWazuhDecoder,
    GetWazuhAgents,
    GetWazuhAgent,
    GetWazuhManagerStatus,
    GetWazuhClusterStatus,
    RestartWazuhManager,
    DisableWazuhAgent,
    GetWazuhConfiguration,
    RunWazuhLogtest,
    EndWazuhLogtestSession,
]

__all__ = ["TOOLS"]