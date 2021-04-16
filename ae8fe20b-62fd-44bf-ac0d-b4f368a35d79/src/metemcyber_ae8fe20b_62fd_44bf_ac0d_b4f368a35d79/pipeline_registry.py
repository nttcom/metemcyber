"""Project pipelines."""
from typing import Dict

from kedro.pipeline import Pipeline

from metemcyber_ae8fe20b_62fd_44bf_ac0d_b4f368a35d79.pipelines import explore_anyrun as ea
from metemcyber_ae8fe20b_62fd_44bf_ac0d_b4f368a35d79.pipelines import search_ioc as si


def register_pipelines() -> Dict[str, Pipeline]:
    """Register the project's pipelines.

    Returns:
        A mapping from a pipeline name to a ``Pipeline`` object.
    """
    explore_anyrun_pipeline = ea.create_pipeline()
    search_ioc_pipeline = si.create_pipeline()
    return {
        "__default__": explore_anyrun_pipeline + search_ioc_pipeline,
        "ea": explore_anyrun_pipeline,
        "si": search_ioc_pipeline,
    }
