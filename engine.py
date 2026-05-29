from rules import evaluate_rules

def evaluate(file_info):
    score, findings = evaluate_rules(file_info)

    # future: context scoring
    # future: entropy bonus
    # future: reputation adjustments

    return score, findings