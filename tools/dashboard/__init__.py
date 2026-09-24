# Wazuh dashboard (OpenSearch Dashboards saved-objects) tools.
from tools.dashboard.visualizations import GetWazuhVisualizations, CreateWazuhVisualization
from tools.dashboard.dashboards import (
    GetWazuhDashboards,
    CreateWazuhDashboard,
    UpdateWazuhDashboard,
    DeleteWazuhDashboard,
)
from tools.dashboard.engine import DesignDetectionDashboard

TOOLS = [
    GetWazuhVisualizations,
    CreateWazuhVisualization,
    GetWazuhDashboards,
    CreateWazuhDashboard,
    UpdateWazuhDashboard,
    DeleteWazuhDashboard,
    DesignDetectionDashboard,
]

__all__ = ["TOOLS"]