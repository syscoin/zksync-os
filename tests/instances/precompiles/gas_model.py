import sys
import re
import csv
from pprint import pprint
from collections import defaultdict
from statistics import mean, median

# SYSCOIN: effective-cycle coefficients keyed by delegation CSR ID. CSR 1995
# (0x7cb, SHA-256 round) uses the conservative geometry coefficient 4.
DELEGATION_RATIOS = {
    1991: 16,  # Blake2RoundExtended
    1994: 4,   # U256BigIntOps
    1995: 4,   # SHA-256 round
}
ERGS_PER_GAS = 256

def weighted_delegation_cycles(delegations):
    return sum(
        count * DELEGATION_RATIOS.get(csr, 1)
        for csr, count in delegations.items()
    )

def parse_delegation_block(text):
    match = re.search(r"=== Cycle markers:\n(.*?)\nTotal delegations", text, re.DOTALL)
    if not match:
        return []

    block = match.group(1)
    markers = []

    for line in block.strip().splitlines():
        marker_match = re.match(r"(\w+): net cycles: (\d+), net delegations: ({.*})", line.strip())
        if marker_match:
            name = marker_match.group(1)
            cycles = int(marker_match.group(2))
            delegations = eval(marker_match.group(3))
            markers.append({
                'name': name,
                'cycles': cycles,
                'delegations': delegations
            })

    return markers

def parse_ergs_spent(text):
    return [
        {'name': m.group(1), 'ergs': int(m.group(2))}
        for m in re.finditer(r"Spent ergs for \[(\w+)\]: (\d+)", text)
    ]

def process_file(file_path):
    with open(file_path, 'r') as f:
        content = f.read()

    runs = content.split("==================")
    all_results = []

    for run in runs:
        ergs_spent = parse_ergs_spent(run)
        markers = parse_delegation_block(run)

        ergs_dict = {}
        for erg in ergs_spent:
            ergs_dict.setdefault(erg['name'], []).append(erg['ergs'])

        matched = []
        for marker in markers:
            name = marker['name']
            ergs_list = ergs_dict.get(name, [])
            if not ergs_list:
                continue  # Skip markers without corresponding ergs
            ergs = ergs_list.pop(0)
            matched.append({
                'name': name,
                'cycles': marker['cycles'],
                'delegations': marker['delegations'],
                'ergs': ergs
            })

        if matched:
            all_results.append(matched)

    return all_results



def compute_ratios(all_results):
    ratio_map = defaultdict(list)

    for run in all_results:
        for marker in run:
            name = marker['name']
            cycles = marker['cycles']
            delegations = marker['delegations']
            ergs = marker['ergs']

            # Weighted delegation sum
            weighted_deleg_sum = weighted_delegation_cycles(delegations)

            total_cycles = cycles + weighted_deleg_sum
            gas = ergs / ERGS_PER_GAS

            if gas > 0:
                ratio = total_cycles / gas
                ratio_map[name].append(ratio)

    # Print and collect data
    rows = []
    for name, ratios in ratio_map.items():
        row = {
            'marker': name,
            'count': len(ratios),
            'max': max(ratios),
            'min': min(ratios),
            'mean': mean(ratios),
            'median': median(ratios),
        }
        print(f"{name} (count: {row['count']}):")
        print(f"  max:    {row['max']:.2f}")
        print(f"  min:    {row['min']:.2f}")
        print(f"  mean:   {row['mean']:.2f}")
        print(f"  median: {row['median']:.2f}")
        rows.append(row)

    # Write to CSV
    with open("ratios.csv", "w", newline="") as csvfile:
        fieldnames = ['marker', 'count', 'max', 'min', 'mean', 'median']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for row in rows:
            writer.writerow(row)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py file1.txt file2.txt ...")
        sys.exit(1)

    all_results = []
    for path in sys.argv[1:]:
        results = process_file(path)
        all_results.extend(results)

    compute_ratios(all_results)
