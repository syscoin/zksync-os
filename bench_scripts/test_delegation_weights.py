import ast
import unittest
from pathlib import Path


# SYSCOIN: keep every offline benchmark consumer aligned with the simulator's
# effective-cycle coefficients without importing optional plotting packages.
ROOT = Path(__file__).resolve().parents[1]
CONSUMERS = (
    ROOT / "bench_scripts" / "compare_bench.py",
    ROOT / "tests" / "instances" / "precompiles" / "gas_model.py",
    ROOT / "tests" / "instances" / "precompiles" / "plot_ratios.py",
)
EXPECTED_RATIOS = {1991: 16, 1994: 4, 1995: 4}


def load_weight_calculator(path):
    parsed = ast.parse(path.read_text(), filename=str(path))
    selected = []
    for node in parsed.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "DELEGATION_RATIOS"
            for target in node.targets
        ):
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name == "weighted_delegation_cycles":
            selected.append(node)

    namespace = {}
    module = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))
    exec(compile(module, str(path), "exec"), namespace)
    return namespace["DELEGATION_RATIOS"], namespace["weighted_delegation_cycles"]


class DelegationWeightConsistencyTest(unittest.TestCase):
    def test_all_consumers_use_canonical_weights(self):
        for path in CONSUMERS:
            with self.subTest(path=path):
                ratios, weighted_cycles = load_weight_calculator(path)
                for csr, coefficient in EXPECTED_RATIOS.items():
                    self.assertEqual(ratios[csr], coefficient)
                    self.assertEqual(weighted_cycles({csr: 1}), coefficient)
                self.assertEqual(weighted_cycles({9999: 1}), 1)
                self.assertEqual(
                    weighted_cycles({1991: 2, 1994: 3, 1995: 5, 9999: 7}),
                    2 * 16 + 3 * 4 + 5 * 4 + 7,
                )


if __name__ == "__main__":
    unittest.main()
