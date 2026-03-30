"""HTML report generation."""

import os

from jinja2 import Environment, FileSystemLoader

from app_xray import __version__
from app_xray.models import AuditReport

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


def generate_html(report: AuditReport) -> str:
    """Generate a self-contained HTML privacy report."""
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=True)
    template = env.get_template("report.html")
    return template.render(report=report, version=__version__)
