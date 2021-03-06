"""Project pipelines."""
from typing import Dict

from kedro.pipeline import Pipeline

#from metemcyber_ae8fe20b_62fd_44bf_ac0d_b4f368a35d79.pipelines import explore_anyrun as ea
#from metemcyber_ae8fe20b_62fd_44bf_ac0d_b4f368a35d79.pipelines import search_ioc as si
from metemcyber_ae8fe20b_62fd_44bf_ac0d_b4f368a35d79.pipelines import (
    get_report_from_sandbox as grfs,
    detect_malware_category as dmc,
    export_malware_specific_ioc as emsi,
    detect_malware_infection as dmi,
    make_report as mr
)


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

    #explore_anyrun_pipeline = ea.create_pipeline()
    #search_ioc_pipeline = si.create_pipeline()
    # return {
    #    "__default__": explore_anyrun_pipeline + search_ioc_pipeline,
    #    "ea": explore_anyrun_pipeline,
    #    "si": search_ioc_pipeline,
    # }
