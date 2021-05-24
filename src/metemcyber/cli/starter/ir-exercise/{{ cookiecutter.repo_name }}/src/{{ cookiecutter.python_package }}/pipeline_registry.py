"""Project pipelines."""
from typing import Dict

from kedro.pipeline import Pipeline
from {{cookiecutter.python_package}}.pipelines import detect_malware_category as dmc
from {{cookiecutter.python_package}}.pipelines import detect_malware_infection as dmi
from {{cookiecutter.python_package}}.pipelines import export_malware_specific_ioc as emsi
from {{cookiecutter.python_package}}.pipelines import get_report_from_sandbox as grfs
from {{cookiecutter.python_package}}.pipelines import make_report as mr


def register_pipelines() -> Dict[str, Pipeline]:
    """Register the project's pipelines.

    Returns:
        A mapping from a pipeline name to a ``Pipeline`` object.
    """
    get_report_from_sandbox_pipeline = grfs.create_pipeline()
    detect_malware_category_pipeline = dmc.create_pipeline()
    export_malware_specific_ioc_pipeline = emsi.create_pipeline()
    detect_malware_infection_pipeline = dmi.create_pipeline()
    make_report_pipeline = mr.create_pipeline()
    return {
        "__default__": get_report_from_sandbox_pipeline +
        detect_malware_category_pipeline +
        detect_malware_infection_pipeline +
        export_malware_specific_ioc_pipeline +
        make_report_pipeline,
        "grfs": get_report_from_sandbox_pipeline,
        "dmc": detect_malware_category_pipeline,
        "emsi": export_malware_specific_ioc_pipeline,
        "dmi": detect_malware_infection_pipeline,
        "mr": make_report_pipeline,
    }
