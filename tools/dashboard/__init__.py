# Wazuh dashboard (OpenSearch Dashboards saved-objects) tools.
from tools.dashboard.visualizations import GetWazuhVisualizations, CreateWazuhVisualization
from tools.dashboard.dashboards import (
    GetWazuhDashboards,
    CreateWazuhDashboard,
    UpdateWazuhDashboard,
    DeleteWazuhDashboard,
)

TOOLS = [
    GetWazuhVisualizations,
    CreateWazuhVisualization,
    GetWazuhDashboards,
    CreateWazuhDashboard,
    UpdateWazuhDashboard,
    DeleteWazuhDashboard,
]

__all__ = ["TOOLS"]