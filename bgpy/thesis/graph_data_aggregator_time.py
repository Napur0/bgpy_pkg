import csv
import os
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from matplotlib import pyplot as plt
from typing import Callable


from bgpy.shared.enums import SpecialPercentAdoptions
from dataclasses import dataclass, field


from itertools import cycle


### Copied over to make a new class since i had problems using import due to circular imports elsewise
class PropertiesGenerator:
    """Generators colors, markers, and line styles"""

    def __init__(self) -> None:
        self._markers_cycle: cycle[str] = cycle(self._expand(self.accepted_markers))
        self._line_styles_cycle: cycle[str] = cycle(
            self._expand(self.accepted_line_styles)
        )
        self._colors_cycle: cycle[str] = cycle(self._expand(self.accepted_colors))

    def get_marker(self) -> str:
        return next(self._markers_cycle)

    def get_line_style(self) -> str:
        return next(self._line_styles_cycle)

    def get_color(self) -> str:
        return next(self._colors_cycle)

    def _expand(self, options: list[str]) -> list[str]:
        """Expands options in a good pattern"""

        new_options = options.copy() + options.copy()[0:-2:2]
        new_options += new_options.copy()[::-1]
        return new_options

    @property
    def accepted_markers(self) -> list[str]:
        """Returns markers allowed for papers"""

        return [".", "1", "*", "x", "d", "2", "3", "4", "v", "+", "s"]

    @property
    def accepted_line_styles(self) -> list[str]:
        """Returns line_styles allowed for papers"""

        return [
            "-",
            "--",
            "-.",
            ":",
            "solid",
            "dotted",
            "dashdot",
            "dashed",
        ]

    @property
    def accepted_colors(self) -> list[str]:
        """Returns colors allowed for papers"""

        return [
            "b",
            "g",
            "r",
            "c",
            "m",
            "y",
            "darkorange",
            "darkgoldenrod",
            "lightcoral",
            "sienna",
            "gold",
            "darkolivegreen",
            "steelblue",
        ]


GENERATOR = PropertiesGenerator()
@dataclass(frozen=True)
class LineStyle:
    marker: str | None = None
    ls: str | None = None
    color: str | None = None

    def __post_init__(self):
        if not self.marker:
            object.__setattr__(self, "marker", GENERATOR.get_marker())
        if not self.ls:
            object.__setattr__(self, "ls", GENERATOR.get_line_style())
        if not self.color:
            object.__setattr__(self, "color", GENERATOR.get_color())



class GraphDataAggregatorTime:
    """Aggregates data for all the graphs from Times"""

    #######################
    # Miscellaneous Funcs #
    #######################

    @staticmethod
    def parse_adoption_rate(raw: str) -> float:
        mapping = {
            "ONLY_ONE": 0.0,
            "ALL_BUT_ONE": 1.0,
        }

        try:
            return float(raw)
        except ValueError:
            if raw in mapping:
                return mapping[raw]
            raise ValueError(f"could not convert string to float: '{raw}'")



    @staticmethod
    def default_adoption_to_x(rate: float | SpecialPercentAdoptions) -> float:
        """
        Converts SpecialPercentAdoption to numbers between 0 and 100 for graphing
        """
        return float(rate) * 100


    #################
    # Writing Funcs #
    #################

    @staticmethod
    def log_verification_counts(
        policy_name: str,
        adoption_rate: float | SpecialPercentAdoptions,
        propagation_round: int,
        verification_counts: list[int],
        output_path: str | Path = "", ###TODO for your own Simulation: Set your own default path here or when calling this function
    ) -> None:
        """
        Logging of number of verifications of a simulation run 
        """
        output_path = Path(output_path).expanduser()
        file_exists = output_path.exists()

        avg = sum(verification_counts) / len(verification_counts) if verification_counts else 0.0
        total = sum(verification_counts)
        maximum = max(verification_counts) if verification_counts else 0

        with open(output_path, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            if (not file_exists) or os.path.getsize(output_path) == 0:
                writer.writerow([
                    "timestamp",
                    "policy_name",
                    "adoption_rate",
                    "propagation_round",
                    "num_selection_runs",
                    "total_verifications",
                    "avg_verifications_per_run",
                    "max_verifications_per_run",
                ])

            writer.writerow([
                datetime.now(timezone.utc).isoformat(),
                policy_name,
                adoption_rate.name if isinstance(adoption_rate, SpecialPercentAdoptions) else adoption_rate,
                propagation_round,
                len(verification_counts),
                total,
                round(avg, 4),
                maximum,
            ])

    @staticmethod
    def log_time_duration(
        policy_name: str,
        adoption_rate: float | SpecialPercentAdoptions,
        propagation_round: int,
        data_type: str,
        time_durations: list[int], # | None = None,
        output_path: str | Path = "", ###TODO for your own Simulation: Set your own default path here or when calling this function
    ) -> None:
        """
        Logging of number of verifications of a simulation run 
        """
        output_path = Path(output_path).expanduser()
        file_exists = output_path.exists()
        avg = sum(time_durations) / len(time_durations) if time_durations else 0.0
        maximum = max(time_durations) if time_durations else 0
        #amount = len(time_durations) if time_durations else 0

        with open(output_path, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            if (not file_exists) or os.path.getsize(output_path) == 0:
                writer.writerow([
                    "timestamp",
                    "policy_name",
                    "adoption_rate",
                    "propagation_round",
                    "num_measurements",
                    "avg_duration_ns",
                    "max_duration_ns",
                    "data_type"
                ])

            writer.writerow([
                datetime.now(timezone.utc).isoformat(),
                policy_name,
                adoption_rate.name if isinstance(adoption_rate, SpecialPercentAdoptions) else adoption_rate,
                propagation_round,
                len(time_durations),
                round(avg, 4),
                maximum,
                data_type,
            ])



    ####################
    # Statistics Funcs #
    ####################
                    
    @staticmethod
    def compute_average_verifications_by_policy(csv_path: str | Path, output_path: str | Path | None,) -> dict[tuple[str, float], float]:
        csv_path = Path(csv_path).expanduser()

        totals: dict[tuple[str, float], int] = defaultdict(int)
        counts: dict[tuple[str, float], int] = defaultdict(int)

        with open(csv_path, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                adoption_rate = GraphDataAggregatorTime.parse_adoption_rate(row["adoption_rate"])
                key = (row["policy_name"], adoption_rate)
                totals[key] += int(row["total_verifications"])
                counts[key] += int(row["num_selection_runs"])

        if(output_path): ### in case one wants to save their measured results apart from in graphs
            output_path = Path(output_path).expanduser()

            with open(output_path, mode="a", newline="", encoding="utf-8") as out:
                for key in totals:
                    if counts[key]:
                        print(f"{key}: {totals[key] / counts[key]}",file=out)
                    else:
                        print(f"{key}: 0.0",file=out)

        return {
            key: totals[key] / counts[key] if counts[key] else 0.0
            for key in totals
        }


    @staticmethod
    def aggregate_time_durations(csv_path: str | Path, output_path: str | Path | None,) ->  dict[tuple[str, float, str], dict[str, float]]:
        csv_path = Path(csv_path).expanduser()

        weighted_sum: dict[tuple[str, float, str], float] = defaultdict(float)
        total_measurements: dict[tuple[str, float, str], int] = defaultdict(int)
        max_value: dict[tuple[str, float, str], float] = defaultdict(float)
        row_count: dict[tuple[str, float, str], int] = defaultdict(int)

        with open(csv_path, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                adoption_rate = GraphDataAggregatorTime.parse_adoption_rate(row["adoption_rate"])
                key = (row["policy_name"], adoption_rate, row["data_type"])

                n = int(row["num_measurements"])
                avg = float(row["avg_duration_ns"])
                row_max = float(row["max_duration_ns"])

                weighted_sum[key] += avg * n
                total_measurements[key] += n
                row_count[key] += 1
                max_value[key] = max(max_value[key], row_max)

        if(output_path): ### in case one wants to save their measured results apart from in graphs
            output_path = Path(output_path).expanduser()
            with open(output_path, mode="a", newline="", encoding="utf-8") as out:
                for key in weighted_sum:
                    weighted_avg =  f"weighted_avg_ns: {weighted_sum[key] / total_measurements[key] if total_measurements[key] else 0.0}"
                    maximum = f"max_ns: {max_value[key]}"
                    total_number = f"total_measurements: {total_measurements[key]}"
                    num_propagation_rounds = f"num_propagation_rounds: {row_count[key],}"

                    entry: str = f"{weighted_avg}, {maximum}, {total_number}, {num_propagation_rounds}"
                    print(f"{key}: {entry}", file=out)

        return {
            key: {
                "weighted_avg": weighted_sum[key] / total_measurements[key] if total_measurements[key] else 0.0,
                "max": max_value[key],
                "total_measurements": total_measurements[key],
            }
            for key in weighted_sum
        }

    ######################
    # Graphing Functions #
    ######################

    @staticmethod
    def plot_metric_by_adoption(
        data: dict[tuple[str, float], tuple[float, float | None]],
        ylabel: str,
        output_path: str | Path,
        xlabel: str = "Percent Adoption",
        title: str | None = None,
        adoption_to_x: Callable[[float | SpecialPercentAdoptions], float] = default_adoption_to_x,
        ylim: tuple[float, float] | None = None,
        line_styles: dict[str, "LineStyle"] | None = None,
    ) -> None:
        """
        Plots a metric over Adoption Rate, one Line per Policy.
        """
        
        grouped: dict[str, list[tuple[float, float, float]]] = defaultdict(list)
        for (policy, rate), (y, yerr) in data.items():
            x = adoption_to_x(rate)
            grouped[policy].append((x, y, yerr if yerr is not None else 0.0))

        line_styles = line_styles or {}

        fig, ax = plt.subplots(figsize=(6.5, 4.8))

        for policy, points in sorted(grouped.items()):
            points.sort(key=lambda p: p[0])
            xs = [p[0] for p in points]
            ys = [p[1] for p in points]
            yerrs = [p[2] for p in points]

            if policy in line_styles:
                style = line_styles[policy]
            else:
                style = line_styles.setdefault(policy, LineStyle())

            ax.errorbar(
                xs, ys,
                yerr=yerrs if any(yerrs) else None,
                label=policy,
                marker=style.marker,
                markersize=10,
                markeredgewidth=2,
                capsize=4,
                linewidth=1.5,
                color=style.color,
                linestyle=style.ls,
            )

        ax.set_xlabel(xlabel, fontsize=13)
        ax.set_ylabel(ylabel, fontsize=13)
        if title:
            ax.set_title(title, fontsize=13)
        if ylim:
            ax.set_ylim(*ylim)
        ax.set_xlim(0, 100)
        ax.legend(loc="upper right", frameon=True)

        fig.tight_layout()

        if output_path:
            output_path = Path(output_path).expanduser()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            fig.savefig(output_path, dpi=150)
        plt.close(fig)


    @staticmethod
    def extract_time_metric(
        aggregated_time_data: dict[tuple[str, float, str], dict[str, float]],
        time_type: str,
        use_max_as_error: bool = False,
    ) -> dict[tuple[str, float], tuple[float, float | None]]:

        result: dict[tuple[str, float], tuple[float, float | None]] = {}
        for (policy, rate, t_type), stats in aggregated_time_data.items():
            if t_type != time_type:
                continue
            avg = stats["weighted_avg"]
            err = (stats["max"] - avg) if use_max_as_error else None
            result[(policy, rate)] = (avg, err)
        return result

    @staticmethod
    def extract_verification_count(
        aggregated_count_data: dict[tuple[str, float], float],
    ) -> dict[tuple[str, float], tuple[float, float | None]]:
        return {key: (value, None) for key, value in aggregated_count_data.items()}

    @staticmethod
    def fill_missing_adoptionrates(
        data: dict[tuple[str, float], tuple[float, float | None]],
    ) -> dict[tuple[str, float], tuple[float, float | None]]:
        policies = {policy for (policy, _) in data.keys()}
        adoption_rates = {adoption_rate for (_, adoption_rate) in data.keys()}

        data_copy = dict(data)


        for policy in policies:
            for adoption_rate in adoption_rates:
                key = (policy, adoption_rate)
                if key not in data_copy:
                    data_copy[key] = (0.0, None) ### (Value = 0,0, Valueerror = None)
        return data_copy
