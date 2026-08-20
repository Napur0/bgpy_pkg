from multiprocessing import cpu_count
from pathlib import Path

from bgpy.shared.enums import SpecialPercentAdoptions
from bgpy.simulation_framework import ScenarioConfig, Simulation, ForgedOriginPrefixHijack
from bgpy.simulation_engine import (
    ROV,
    BGPSecCrypt,
    BGPSecRSA,
    BGPiSecCryptTransitive,
    RSABGPiSecCryptTransitive,
)
from bgpy.thesis.graph_data_aggregator_time import GraphDataAggregatorTime, LineStyle
from cryptography.hazmat.backends.openssl import backend


trialNumber =  2
parse_cpus = 2 

def main():
    ### I found it best to clear out previous results from any files reused to avoid wrong results at the end, e.g.:
    with open("~/Desktop/foph_rsa_time/vercount.csv", "r+") as f: 
        f.seek(0)
        f.truncate()
    with open("~/Desktop/foph_rsa_time/vercount_agg.txt", "r+") as f: 
        f.seek(0)
        f.truncate()
    with open("~/Desktop/foph_rsa_time/times_metrics.csv", "r+") as f: 
        f.seek(0)
        f.truncate()
    with open("~/Desktop/foph_rsa_time/time_metrics_agg.txt", "r+") as f: 
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
            ScenarioConfig(ScenarioCls=ForgedOriginPrefixHijack, AdoptPolicyCls=BGPSecRSA, BasePolicyCls=ROV, scenario_label="BGPsec with RSA"),

            ScenarioConfig(ScenarioCls=ForgedOriginPrefixHijack, AdoptPolicyCls=BGPiSecCryptTransitive, BasePolicyCls=ROV, scenario_label="BGPiSec Transitive Signatures"),
            ScenarioConfig(ScenarioCls=ForgedOriginPrefixHijack, AdoptPolicyCls=RSABGPiSecCryptTransitive, BasePolicyCls=ROV, scenario_label="BGPiSec Transitive Signatures with RSA"),
        ),
        output_dir=Path("~/Desktop/foph_rsa_time").expanduser(),
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

    aggregated_count_results = GraphDataAggregatorTime.compute_average_verifications_by_policy(csv_path="~/Desktop/foph_rsa_time/vercount.csv", output_path="~/Desktop/foph_rsa_time/vercount_agg.txt")
    aggregated_time_results = GraphDataAggregatorTime.aggregate_time_durations(csv_path="~/Desktop/foph_rsa_time/times_metrics.csv", output_path="~/Desktop/foph_rsa_time/time_metrics_agg.txt")

    shared_line_styles: dict[str, LineStyle] = {}

    
    #Current Types for Times:
    #("verification"),
    #("signing"),
    #("verification_process"),

    GraphDataAggregatorTime.plot_metric_by_adoption(
        GraphDataAggregatorTime.fill_missing_adoptionrates(GraphDataAggregatorTime.extract_time_metric(aggregated_time_results, time_type="verification_process")),
        ylabel="Avg. Verification Process Time (ns)",
        output_path="~/Desktop/foph_rsa_time/verification_process_time.png",
        line_styles=shared_line_styles,   # usable for reusing line style per policy over different Graphs
    )
    GraphDataAggregatorTime.plot_metric_by_adoption(
        GraphDataAggregatorTime.fill_missing_adoptionrates(GraphDataAggregatorTime.extract_time_metric(aggregated_time_results, time_type="verification")),
        ylabel="Avg. Verification Time (ns)",
        output_path="~/Desktop/foph_rsa_time/verification_time.png",
        line_styles=shared_line_styles,   # usable for reusing line style per policy over different Graphs
    )
    GraphDataAggregatorTime.plot_metric_by_adoption(
        GraphDataAggregatorTime.fill_missing_adoptionrates(GraphDataAggregatorTime.extract_time_metric(aggregated_time_results, time_type="signing")),
        ylabel="Avg. Signature Creation Time (ns)",
        output_path="~/Desktop/foph_rsa_time/signature_time.png",
        line_styles=shared_line_styles,   # usable for reusing line style per policy over different Graphs
    )

    GraphDataAggregatorTime.plot_metric_by_adoption(
        GraphDataAggregatorTime.extract_verification_count(aggregated_count_results),
        ylabel="Avg. Verifications per Selection Run",
        output_path="~/Desktop/foph_rsa_time/verification_count.png",
        line_styles=shared_line_styles,   # usable for reusing line style per policy over different Graphs
    )