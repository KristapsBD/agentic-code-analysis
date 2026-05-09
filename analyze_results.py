import json
import os
import sys
import glob

GT = {
    '0xf6dbe88ba55f1793ff0773c9b1275300f830914f.sol': 'reentrancy',
    'DAO.sol': 'reentrancy',
    '0x33813c2f2aab62ac88c234858a1f08448424828f.sol': 'reentrancy',
    'FibonacciBalance.sol': 'delegatecall',
    'multiowned_vulnerable.sol': 'access_control',
    'parity_wallet_bug_2.sol': 'access_control',
    'BECToken.sol': 'arithmetic',
    'POWH.sol': 'arithmetic',
    'PonziTokenV3.sol': 'arithmetic',
    'king_of_the_ether_throne.sol': 'unchecked_calls',
    'lotto.sol': 'unchecked_calls',
    'unchecked_return_value.sol': 'unchecked_calls',
    'Government.sol': 'denial_of_service',
    'dos_number.sol': 'denial_of_service',
    'list_dos.sol': 'denial_of_service',
}
SAFE = {
    'BaseJumpRateModelV2.sol', 'ExponentialNoError.sol', 'FullMath.sol', 'PercentageMath.sol',
    'ReserveConfiguration.sol', 'TickMath.sol', 'UniswapV2ERC20.sol', 'WadRayMath.sol',
    'BaseDelegation.sol', 'PausableZone.sol', 'Trading.sol', 'Ownable.sol', 'Account.sol',
    'VestingWallet.sol', 'ERC721.sol',
}

AGENT_LABELS = {
    'multi_agent': '3-Agent',
    'two_agent':   '2-Agent',
    'baseline':    '1-Agent',
}


def fname(p):
    return os.path.basename(p.replace('\\', '/'))


def metrics(results):
    tp = sum(r['true_positives'] for r in results)
    fp = sum(r['false_positives'] for r in results)
    fn = sum(r['false_negatives'] for r in results)

    det_tp = sum(1 for r in results if r['binary_predicted_vulnerable'] and fname(r['contract_path']) in GT)
    det_fp = sum(1 for r in results if r['binary_predicted_vulnerable'] and fname(r['contract_path']) in SAFE)
    det_fn = sum(1 for r in results if not r['binary_predicted_vulnerable'] and fname(r['contract_path']) in GT)
    det_tn = sum(1 for r in results if not r['binary_predicted_vulnerable'] and fname(r['contract_path']) in SAFE)

    det_p  = det_tp / (det_tp + det_fp) if (det_tp + det_fp) else 0
    det_r  = det_tp / (det_tp + det_fn) if (det_tp + det_fn) else 0
    det_f1 = 2 * det_p * det_r / (det_p + det_r) if (det_p + det_r) else 0

    cls_tp = sum(r['true_positives'] for r in results if fname(r['contract_path']) in GT)
    cls_fp = sum(r['false_positives'] for r in results if fname(r['contract_path']) in GT)
    cls_fn = sum(r['false_negatives'] for r in results if fname(r['contract_path']) in GT)

    cls_p  = cls_tp / (cls_tp + cls_fp) if (cls_tp + cls_fp) else 0
    cls_r  = cls_tp / (cls_tp + cls_fn) if (cls_tp + cls_fn) else 0
    cls_f1 = 2 * cls_p * cls_r / (cls_p + cls_r) if (cls_p + cls_r) else 0

    mic_p  = tp / (tp + fp) if (tp + fp) else 0
    mic_r  = tp / (tp + fn) if (tp + fn) else 0
    mic_f1 = 2 * mic_p * mic_r / (mic_p + mic_r) if (mic_p + mic_r) else 0

    fps = [fname(r['contract_path']) for r in results if r['false_positives'] > 0]
    fns = [fname(r['contract_path']) for r in results if r['false_negatives'] > 0]

    return dict(
        tp=tp, fp=fp, fn=fn,
        det_tp=det_tp, det_fp=det_fp, det_fn=det_fn, det_tn=det_tn,
        det_p=det_p, det_r=det_r, det_f1=det_f1,
        cls_tp=cls_tp, cls_fp=cls_fp, cls_fn=cls_fn,
        cls_p=cls_p, cls_r=cls_r, cls_f1=cls_f1,
        mic_p=mic_p, mic_r=mic_r, mic_f1=mic_f1,
        fps=fps, fns=fns,
    )


def analyze(filepath):
    with open(filepath) as f:
        d = json.load(f)

    run_data = {}
    for agent_type in ['multi_agent', 'two_agent', 'baseline']:
        section = d[agent_type]
        m = metrics(section['contract_results'])
        m['model']    = section.get('model', '?')
        m['provider'] = section.get('provider', '?')
        run_data[agent_type] = m
    return run_data


def print_run(label, run_data):
    W = 64
    print()
    print("=" * W)
    print(f"  {label}")
    print("=" * W)
    hdr = f"  {'Config':<16} {'Det Prec':>9} {'Det Rec':>9} {'Det F1':>9}  |  {'Cls Prec':>9} {'Cls Rec':>9} {'Cls F1':>9}  |  {'Micro F1':>9}"
    print(hdr)
    print("  " + "-" * (W - 2))
    for agent_type in ['multi_agent', 'two_agent', 'baseline']:
        m = run_data[agent_type]
        lbl = AGENT_LABELS[agent_type]
        print(
            f"  {lbl:<16}"
            f" {m['det_p']:>8.1%} {m['det_r']:>9.1%} {m['det_f1']:>9.1%}  |"
            f" {m['cls_p']:>9.1%} {m['cls_r']:>9.1%} {m['cls_f1']:>9.1%}  |"
            f" {m['mic_f1']:>9.1%}"
        )
    print()
    for agent_type in ['multi_agent', 'two_agent', 'baseline']:
        m = run_data[agent_type]
        lbl = AGENT_LABELS[agent_type]
        det_counts = f"Det TP={m['det_tp']} FP={m['det_fp']} FN={m['det_fn']} TN={m['det_tn']}"
        cls_counts = f"Cls TP={m['cls_tp']} FP={m['cls_fp']} FN={m['cls_fn']}"
        print(f"  {lbl}  {det_counts}  |  {cls_counts}")
        if m['fps']:
            print(f"    FP: {m['fps']}")
        if m['fns']:
            print(f"    FN: {m['fns']}")


def print_comparison(runs):
    configs = ['multi_agent', 'two_agent', 'baseline']
    for cfg in configs:
        lbl = AGENT_LABELS[cfg]
        print()
        print(f"  ── {lbl} ──────────────────────────────────────────────────────────")
        hdr = f"  {'Provider/Model':<30} {'Det P':>7} {'Det R':>7} {'Det F1':>7}  |  {'Cls P':>7} {'Cls R':>7} {'Cls F1':>7}  |  {'Micro F1':>9}"
        print(hdr)
        print("  " + "-" * 90)
        for label, run_data in runs:
            m = run_data[cfg]
            tag = f"{m['provider']} / {m['model']}"
            print(
                f"  {tag:<30}"
                f" {m['det_p']:>6.1%} {m['det_r']:>7.1%} {m['det_f1']:>7.1%}  |"
                f" {m['cls_p']:>7.1%} {m['cls_r']:>7.1%} {m['cls_f1']:>7.1%}  |"
                f" {m['mic_f1']:>9.1%}"
            )


if __name__ == "__main__":
    results_dir = "data/results"

    if len(sys.argv) > 1:
        files = sys.argv[1:]
    else:
        all_files = sorted(
            glob.glob(os.path.join(results_dir, "benchmark_*.json")),
            key=os.path.getmtime,
            reverse=True,
        )
        files = all_files[:3]

    runs = []
    for fp in files:
        try:
            rd = analyze(fp)
            model = rd['multi_agent']['model']
            provider = rd['multi_agent']['provider']
            label = f"{provider} / {model}  ({os.path.basename(fp)})"
            runs.append((label, rd))
            print_run(label, rd)
        except Exception as e:
            print(f"ERROR reading {fp}: {e}")

    if len(runs) > 1:
        print()
        print("=" * 94)
        print("  CROSS-PROVIDER COMPARISON")
        print("=" * 94)
        print_comparison(runs)
