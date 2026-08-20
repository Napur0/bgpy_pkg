from multiprocessing import cpu_count
from pathlib import Path

from bgpy.shared.enums import SpecialPercentAdoptions
from bgpy.simulation_framework import ScenarioConfig, Simulation, ForgedOriginPrefixHijack
from bgpy.simulation_engine import (
    ROV,
    BGPSecCrypt,
    BGPiSecCryptTransitive,
    BGPSecCryptBPO,
    BPOBGPiSecCryptTransitive,
)
from bgpy.thesis.graph_data_aggregator_time import GraphDataAggregatorTime, LineStyle
from cryptography.hazmat.backends.openssl import backend


trialNumber =  2
parse_cpus = 2 

def main():

    ### i found it best to clear out previous results from any files reused to avoid wrong results at the end, e.g.:
    with open("~/Desktop/foph_bpo_count/vercount.csv", "r+") as f: 
            f.seek(0)
            f.truncate()
    with open("~/Desktop/foph_bpo_count/vercount_agg.txt", "r+") as f: 
        f.seek(0)
        f.truncate()

    


    sim = Simulation(
        percent_adoptions=( 
            SpecialPercentAdoptions.ONLY_ONE,
            0.1,
            0.2,
            0.4,
            0.8,
            SpecialPercentAdoptions.ALL_BUT_ONE
        ),
        scenario_configs=(
            
            ScenarioConfig(ScenarioCls=ForgedOriginPrefixHijack, AdoptPolicyCls=BGPSecCrypt, BasePolicyCls=ROV, scenario_label="BGPsec"),
            ScenarioConfig(ScenarioCls=ForgedOriginPrefixHijack, AdoptPolicyCls=BGPSecCryptBPO, BasePolicyCls=ROV, scenario_label="BGPsec with BPO"),

            ScenarioConfig(ScenarioCls=ForgedOriginPrefixHijack, AdoptPolicyCls=BGPiSecCryptTransitive, BasePolicyCls=ROV, scenario_label="BGPiSec Transitive Only"),
            ScenarioConfig(ScenarioCls=ForgedOriginPrefixHijack, AdoptPolicyCls=BPOBGPiSecCryptTransitive, BasePolicyCls=ROV, scenario_label="BGPiSec Transitive Only with BPO"),
        ),
        output_dir=Path("~/Desktop/foph_bpo_count").expanduser(),
        num_trials=trialNumber,
        parse_cpus=parse_cpus,
        python_hash_seed=42,
    )
    sim.run()


if __name__ == "__main__":
    print("DONT FORGET TO USE PyPy -O")
    print("DONT FORGET TO SET YOUR PATHS IN GraphDataAggregatorTime WHEN MEASURING SIGNATURE AND VERIFICATION TIMES")
    main()
    
    print(backend.openssl_version_text())

    aggregated_count_results = GraphDataAggregatorTime.compute_average_verifications_by_policy(csv_path="~/Desktop/foph_bpo_count/vercount.csv", output_path="~/Desktop/foph_bpo_count/vercount_agg.txt")

    shared_line_styles: dict[str, LineStyle] = {}

    GraphDataAggregatorTime.plot_metric_by_adoption(
        GraphDataAggregatorTime.extract_verification_count(aggregated_count_results),
        ylabel="Avg. Verifications per Selection Run",
        output_path="~/Desktop/foph_bpo_count/verification_count.png", 
        line_styles=shared_line_styles,   # usable for reusing line style per policy over different Graphs
    )