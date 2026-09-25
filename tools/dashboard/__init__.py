# Wazuh dashboard (OpenSearch Dashboards saved-objects) tools.
from tools.dashboard.visualizations import GetWazuhVisualizations, CreateWazuhVisualization
from tools.dashboard.dashboards import (
    GetWazuhDashboards,
    CreateWazuhDashboard,
    UpdateWazuhDashboard,
    VerifyWazuhDashboard,
    DeleteWazuhDashboard,
)
from tools.dashboard.engine import DesignDetectionDashboard

TOOLS = [
    GetWazuhVisualizations,
    CreateWazuhVisualization,
    GetWazuhDashboards,
    CreateWazuhDashboard,
    UpdateWazuhDashboard,
    VerifyWazuhDashboard,
    DeleteWazuhDashboard,
    DesignDetectionDashboard,
]

__all__ = ["TOOLS"]