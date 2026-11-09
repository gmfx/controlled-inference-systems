"""Offline constructed-event scorer. Reads six runtime files; never an oracle."""
from __future__ import annotations

import argparse
import csv
import itertools
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
from fractions import Fraction
from pathlib import Path

FILES = {
    "work_units": "work_units.csv", "trials": "policy_trials.csv",
    "policies": "policy_versions.csv", "checks": "checks.jsonl",
    "events": "events.jsonl", "parameters": "parameters.json",
}
COST_BASES = {"INFERENCE": "INFERENCE", "AUTOMATION": "AUTOMATION",
              "HUMAN": "REVIEW_LABOR", "CYCLE": "CYCLE_TIME_NONLABOR"}
ACTION_AUTH = {"PRIMARY_ROUTE": ("PRIMARY_ROUTE", "ROUTE_PLANNER"),
               "REVIEW": ("HUMAN_REVIEW", "HUMAN_REVIEWER"),
               "RECOVERY": ("HUMAN_REVIEW", "HUMAN_REVIEWER"),
               "COMMIT": ("COMMIT", "CASE_DISPOSER")}
FORBIDDEN = {"baseline_expected_accepted_arms", "accepted_by_complexity",
             "accepted_totals", "expectedwinner", "expected_cutoff_values"}


class InvalidFixture(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise InvalidFixture(reason)


def rational(value):
    require(isinstance(value, str) and re.fullmatch(r"-?\d+(?:/[1-9]\d*)?", value),
            "EXACT_RATIONAL_REQUIRED")
    return Fraction(value)


def integer(value):
    require(not isinstance(value, bool) and
            (isinstance(value, int) or isinstance(value, str) and value.isdigit()),
            "INTEGER_REQUIRED")
    return int(value)


def timestamp(value):
    require(isinstance(value, str) and
            re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value), "UTC_REQUIRED")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidFixture("INVALID_TIMESTAMP") from exc


def no_oracle(value):
    if isinstance(value, dict):
        for key, item in value.items():
            require(isinstance(key, str), "INVALID_FIELD_NAME")
            require(not key.lower().startswith("expected") and key not in FORBIDDEN,
                    "ORACLE_FIELD_IN_RUNTIME:" + key)
            no_oracle(item)
    elif isinstance(value, list):
        for item in value:
            no_oracle(item)


def index_rows(rows, replay=False):
    result = {}
    for row in rows:
        require(isinstance(row, dict), "RECORD_MAPPING_REQUIRED")
        key = row["id"]
        require(isinstance(key, str) and bool(key), "INVALID_RECORD_ID")
        if key in result:
            require(replay and result[key] == row, "DUPLICATE_OR_CONFLICTING_ID:" + key)
        result[key] = row
    return result


def load_data(directory):
    """Explicit allowlist: no directory scans, contract reads, or expected outputs."""
    root = Path(directory)
    result = {}
    for kind, filename in FILES.items():
        path = root / filename
        if filename.endswith(".csv"):
            with path.open(encoding="utf-8", newline="") as handle:
                result[kind] = list(csv.DictReader(handle))
            if kind == "policies":
                for row in result[kind]:
                    row["rules"] = json.loads(row.pop("rules_json"))
        elif filename.endswith(".jsonl"):
            result[kind] = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                            if line.strip()]
        else:
            result[kind] = json.loads(path.read_text(encoding="utf-8"))
    return result


class Ledger:
    def __init__(self, data):
        require(isinstance(data, dict), "DATA_MAPPING_REQUIRED")
        require(all(isinstance(data.get(k), list) for k in
                    ("work_units", "trials", "policies", "checks", "events"))
                and isinstance(data.get("parameters"), dict), "RUNTIME_COLLECTION_TYPE")
        no_oracle(data)
        self.data = data
        self.params = data["parameters"]
        self.units = index_rows(data["work_units"])
        self.trials = index_rows(data["trials"])
        self.checks = index_rows(data["checks"], replay=True)
        self.events = index_rows(data["events"], replay=True)
        require(not set(self.checks).intersection(self.events), "CROSS_KIND_ID_COLLISION")
        self.refs = {**self.checks, **self.events}
        self.costs = defaultdict(list)
        self.validate()

    def policy(self, policy, at, reference):
        eligible = [p for p in self.data["policies"] if p["policy"] == policy
                    and timestamp(p["effective_from"]) <= at < timestamp(p["effective_to"])
                    and timestamp(p["observed_at"]) <= at]
        require(len(eligible) == 1 and eligible[0]["version"] == reference,
                "MISSING_OR_AMBIGUOUS_POLICY")
        return eligible[0]["rules"]

    def ref(self, key, unit, trial=None):
        require(key in self.refs, "BROKEN_REFERENCE:" + str(key))
        item = self.refs[key]
        require(item["group_id"] == unit, "CROSS_UNIT_REFERENCE")
        if item.get("trial_id"):
            require(item["trial_id"] == trial, "CROSS_TRIAL_REFERENCE")
        return item

    def inputs(self, action, trial):
        at = timestamp(action["action_time"])
        for key in action.get("input_refs", []):
            item = self.ref(key, trial["group_id"], trial["id"])
            require(timestamp(item["available_at"]) <= at, "FUTURE_ACTION_INPUT")
        return at

    def authorized(self, action, trial):
        grant = self.ref(action["grant_ref"], trial["group_id"], trial["id"])
        require(grant["kind"] == "GRANT", "WRONG_GRANT_TYPE")
        at = timestamp(action["action_time"])
        require(action["kind"] in ACTION_AUTH, "UNKNOWN_GOVERNED_ACTION")
        permission, role = ACTION_AUTH[action["kind"]]
        return (grant["allowed"] is True and grant["principal"] == action["principal"]
                and grant["scope"] == trial["group_id"]
                and action["permission"] == permission and permission in grant["permissions"]
                and grant["role"] == role
                and timestamp(grant["available_at"]) <= at
                and timestamp(grant["observed_at"]) <= at
                and timestamp(grant["effective_from"]) <= at < timestamp(grant["effective_to"]))

    def validate(self):
        p = self.params
        require(p["currency"] == "USD" and integer(p["maturity_days"]) == 30,
                "UNSUPPORTED_PARAMETER_SCOPE")
        policies = set(p["policies"])
        require(policies == {"G", "S", "H", "T"}, "POLICY_SET")
        require(isinstance(p["families"], dict) and isinstance(p["policies"], dict),
                "PARAMETER_MAPPING_REQUIRED")
        work_rules = {}
        for policy in self.data["policies"]:
            require(isinstance(policy, dict) and isinstance(policy.get("rules"), dict),
                    "POLICY_MAPPING_REQUIRED")
            require(timestamp(policy["effective_from"]) < timestamp(policy["effective_to"]), "POLICY_WINDOW")
            rules = policy["rules"]
            require(isinstance(rules["routes"], dict), "ROUTE_RULE_TYPE")
            require(set(rules["routes"]) == {"LOW", "HIGH"}, "ROUTE_RULE_TYPE")
            key = (policy["version"], policy["effective_from"], policy["effective_to"])
            common = (rules["eligible_action"], rules["ineligible_action"], tuple(sorted(rules["required_sources"])))
            require(key not in work_rules or work_rules[key] == common, "INCOMPARABLE_WORK_RULE")
            work_rules[key] = common
        for f in p["families"].values():
            require(rational(f["value"]) >= 0 and rational(f["defect_burden"]) >= 0,
                    "NEGATIVE_VALUE_OR_BURDEN")
        for v in p["policies"].values():
            require(rational(v["investment"]) >= 0 and integer(v["capacity"]) > 0,
                    "INVALID_POLICY_ASSUMPTION")
        strata = defaultdict(list)
        for u in self.units.values():
            require(u["confidentiality_class"] == "SYNTHETIC", "NON_SYNTHETIC_DATA")
            require(u["family"] in p["families"] and u["complexity"] in ("routine", "complex"),
                    "UNKNOWN_STRATUM")
            lo, hi, weight = integer(u["first"]), integer(u["last"]), integer(u["multiplicity"])
            require(lo > 0 and hi >= lo and weight == hi - lo + 1, "INVALID_RANGE_WEIGHT")
            at = timestamp(u["decision_time"])
            require(at.date().isoformat() == p["origin_day"], "DIFFERENT_ORIGIN_COHORT")
            require(timestamp(u["maturity_due"]) == at + timedelta(days=30), "MATURITY_RULE")
            ref = self.ref(u["reference_ref"], u["id"])
            require(ref["kind"] == "SOURCE_FACT" and ref["role"] == "REFERENCE", "REFERENCE_TYPE")
            fact = ref["payload"]
            require(isinstance(fact, dict), "PAYLOAD_MAPPING_REQUIRED")
            require(type(fact["eligible"]) is bool and type(fact["artifact_fact"]) is int
                    and isinstance(fact["recipient"], str) and fact["recipient"]
                    and fact["risk"] in ("LOW", "HIGH") and isinstance(fact["sources"], dict),
                    "REFERENCE_FACT_TYPE")
            for source_fact in fact["sources"].values():
                require(type(source_fact["amount"]) is int and integer(source_fact["version"]) > 0
                        and timestamp(source_fact["available_at"]) <= timestamp(ref["available_at"]),
                        "REFERENCE_FACT_TYPE")
            strata[(u["family"], u["complexity"])].append((lo, hi))
        for family, f in p["families"].items():
            for complexity in ("routine", "complex"):
                end = 0
                for lo, hi in sorted(strata[(family, complexity)]):
                    require(lo == end + 1, "COHORT_GAP_OR_OVERLAP")
                    end = hi
                require(end == integer(f[complexity]), "STRATUM_DENOMINATOR")
        self.by_group = defaultdict(set)
        for t in self.trials.values():
            require(t["group_id"] in self.units and t["policy"] in policies, "TRIAL_COHORT")
            require(t["policy"] not in self.by_group[t["group_id"]], "DUPLICATE_POLICY_ARM")
            self.by_group[t["group_id"]].add(t["policy"])
        require(all(self.by_group[k] == policies for k in self.units), "MISSING_POLICY_ARM")
        coverage_versions = {}
        for row in list(self.checks.values()) + list(self.events.values()):
            if row["id"] in self.events:
                require(row["kind"] in {"SOURCE_FACT", "COVERAGE", "COST_SOURCE", "COST", "BUSINESS_STATE"},
                        "EVENT_TYPE")
                require("event_time" in row, "MISSING_EVENT_TIME")
                timestamp(row["event_time"])
            else:
                require(row["kind"] in {"GRANT", "PRIMARY_ROUTE", "STAGE", "REVIEW", "RECOVERY", "COMMIT"},
                        "CHECK_TYPE")
            if row["kind"] in {"SOURCE_FACT", "COST_SOURCE", "BUSINESS_STATE", "STAGE", "REVIEW", "RECOVERY"}:
                require(isinstance(row.get("payload"), dict), "PAYLOAD_MAPPING_REQUIRED")
            if row["kind"] in {"SOURCE_FACT", "COST_SOURCE"}:
                require(integer(row["source_version"]) > 0, "SOURCE_VERSION")
            require(row["confidentiality_class"] == "SYNTHETIC", "NON_SYNTHETIC_DATA")
            require(row["group_id"] in self.units, "UNKNOWN_UNIT")
            if row.get("trial_id"):
                require(row["trial_id"] in self.trials and
                        self.trials[row["trial_id"]]["group_id"] == row["group_id"], "TRIAL_SCOPE")
            timestamp(row["available_at"])
            if row.get("event_time"):
                require(timestamp(row["event_time"]) <= timestamp(row["available_at"]), "FUTURE_OCCURRENCE")
            if row["kind"] == "COVERAGE":
                # This contract supports shared work-unit coverage, not trial coverage.
                require(not row.get("trial_id"), "COVERAGE_SCOPE")
                require(row["source"] in p["required_sources"] and
                        timestamp(row["coverage_end"]) <= timestamp(row["available_at"])
                        and type(row["reconciled"]) is bool, "COVERAGE_TIME_OR_TYPE")
                key = (row["group_id"], row["source"], integer(row["source_version"]))
                require(key[2] > 0, "COVERAGE_VERSION")
                meaning = {k: v for k, v in row.items() if k != "id"}
                require(key not in coverage_versions or coverage_versions[key] == meaning,
                        "CONFLICTING_COVERAGE_VERSION")
                coverage_versions[key] = meaning
            if row["kind"] == "GRANT":
                require(isinstance(row["permissions"], list)
                        and all(isinstance(permission, str) and permission
                                for permission in row["permissions"]), "GRANT_PERMISSION_LIST")
                require(timestamp(row["effective_from"]) < timestamp(row["effective_to"]), "GRANT_WINDOW")
                timestamp(row["observed_at"])
            if row["kind"] == "COST":
                self.validate_cost(row)
            if row["kind"] == "COST_SOURCE":
                require(set(row["change_scope"]) == set(row["payload"])
                        and set(row["change_scope"]).issubset(COST_BASES)
                        and len(row["change_scope"]) == len(set(row["change_scope"])), "COST_SOURCE_SCOPE")
        for t in self.trials.values():
            u = self.units[t["group_id"]]
            required = ["route_ref", "aggregate_ref", "primary_ref", "create_ref", "commit_ref", "business_ref"]
            if u["complexity"] == "complex" or t["policy"] == "T":
                required.append("review_ref")
            for field in required:
                require(t.get(field), "MISSING_REQUIRED_CHECK:" + field)
                self.ref(t[field], u["id"], t["id"])
            check_types = {
                "route_ref": ({"PRIMARY_ROUTE"}, None),
                "aggregate_ref": ({"STAGE"}, "aggregation"),
                "primary_ref": ({"STAGE"}, u["family"]),
                "create_ref": ({"STAGE"}, "content"),
                "commit_ref": ({"COMMIT"}, None),
                "review_ref": ({"REVIEW", "RECOVERY"}, u["family"]),
            }
            for field, (kinds, family) in check_types.items():
                if t.get(field):
                    require(t[field] in self.checks, "REQUIRED_CHECK_TYPE:" + field)
                    check = self.checks[t[field]]
                    require(check["kind"] in kinds and (family is None or check.get("family") == family),
                            "REQUIRED_CHECK_TYPE:" + field)
            require(self.checks[t["route_ref"]]["kind"] == "PRIMARY_ROUTE", "ROUTE_CHECK_TYPE")
            require(self.checks[t["commit_ref"]]["kind"] == "COMMIT", "COMMIT_CHECK_TYPE")
            business = self.events[t["business_ref"]]
            require(business["kind"] == "BUSINESS_STATE" and business["action_ref"] == t["commit_ref"],
                    "BUSINESS_COMMIT_LINK")
            require(timestamp(business["event_time"]) == timestamp(u["decision_time"]), "COMMIT_TIME")
            stages = [t["aggregate_ref"], t["primary_ref"], t["create_ref"]]
            if t.get("review_ref"):
                stages.append(t["review_ref"])
            for ref in [t["route_ref"], t["commit_ref"]] + stages:
                action = self.checks[ref]
                at = self.inputs(action, t)
                self.policy(t["policy"], at, t["policy_version"])
                require(u["reference_ref"] in action["input_refs"], "MISSING_REFERENCE_SNAPSHOT")
                require(timestamp(action["available_at"]) >= at, "ACTION_OBSERVED_BEFORE_OCCURRENCE")
                if action["kind"] in ("PRIMARY_ROUTE", "REVIEW", "RECOVERY", "COMMIT"):
                    require(action.get("grant_ref"), "MISSING_GRANT_REFERENCE")
                    self.authorized(action, t)  # False is a valid negative work case.
            commit = self.checks[t["commit_ref"]]
            require(timestamp(commit["action_time"]) == timestamp(u["decision_time"]), "COMMIT_TIME")
            require(timestamp(self.checks[t["route_ref"]]["action_time"]) <
                    timestamp(self.checks[t["primary_ref"]]["available_at"]) <
                    timestamp(commit["action_time"]), "PRIMARY_SEQUENCE")
            if t.get("review_ref"):
                review = self.checks[t["review_ref"]]
                require(t["primary_ref"] in review["input_refs"], "MISSING_RECOVERY_EVIDENCE")
                require(timestamp(review["action_time"]) < timestamp(commit["action_time"]), "RECOVERY_SEQUENCE")
            components = self.costs[t["id"]]
            require({x["category"] for x in components} == set(COST_BASES), "MISSING_COST_CHANNEL")
        self.validate_chains()

    def validate_cost(self, row):
        require(row["trial_id"] in self.trials, "UNKNOWN_COST_TRIAL")
        require(row["category"] in COST_BASES and row["amount_basis"] == "PER_ORIGINAL_UNIT",
                "COST_AMOUNT_BASIS")
        require(row["currency"] == "USD" and rational(row["amount"]) >= 0, "COST_AMOUNT_CURRENCY")
        require(row["economic_basis"] == COST_BASES[row["category"]], "DECLARED_BASIS_OVERLAP")
        require(row.get("attribution_rule"), "MISSING_ATTRIBUTION_RULE")
        source = self.ref(row["source_ref"], row["group_id"], row["trial_id"])
        require(source["kind"] == "COST_SOURCE", "COST_SOURCE_TYPE")
        require(source["available_at"] == row["available_at"] and
                row["category"] in source["change_scope"], "COST_SOURCE_SCOPE")
        fact = source["payload"][row["category"]]
        require(rational(fact["amount"]) == rational(row["amount"]) and
                fact["economic_basis"] == row["economic_basis"], "COST_SOURCE_MISMATCH")
        require(integer(row["version"]) > 0, "INVALID_COST_VERSION")
        self.costs[row["trial_id"]].append(row)

    def validate_chains(self):
        chains = defaultdict(dict)
        for rows in self.costs.values():
            for r in rows:
                key = (r["trial_id"], r["logical_effect_id"], r["category"])
                v = integer(r["version"])
                if v in chains[key]:
                    prior = chains[key][v]
                    require({k: x for k, x in prior.items() if k != "id"} ==
                            {k: x for k, x in r.items() if k != "id"}, "CONFLICTING_COST_VERSION")
                else:
                    chains[key][v] = r
        seen_category = set()
        for key, versions in chains.items():
            pair = (key[0], key[2])
            require(pair not in seen_category, "DUPLICATE_ECONOMIC_BASIS")
            seen_category.add(pair)
            require(sorted(versions) == list(range(1, max(versions) + 1)), "MISSING_COST_PREDECESSOR")
            previous = None
            for v in sorted(versions):
                r = versions[v]
                if previous is None:
                    require(not r.get("supersedes"), "ROOT_SUPERSESSION")
                else:
                    require(r.get("supersedes") in self.events, "MISSING_COST_PREDECESSOR")
                    parent = self.events[r["supersedes"]]
                    require(parent["kind"] == "COST" and
                            (parent["trial_id"], parent["logical_effect_id"], parent["category"]) == key
                            and integer(parent["version"]) == v - 1, "CROSS_COMPONENT_SUPERSESSION")
                    require(timestamp(previous["available_at"]) <= timestamp(r["available_at"]),
                            "COST_VERSION_TIME_ORDER")
                previous = r
        self.chains = chains
        for e in self.events.values():
            if e["kind"] == "COST_SOURCE":
                for category in e["change_scope"]:
                    require(any(r["source_ref"] == e["id"] and r["category"] == category
                                for r in self.costs[e["trial_id"]]), "UNRECONCILED_COST_SOURCE")

    def quality(self, family, payload, reference, rules, at):
        if family == "decision":
            wanted = rules["eligible_action"] if reference["eligible"] else rules["ineligible_action"]
            return payload.get("disposition") == wanted
        if family == "content":
            return (payload.get("fact") == reference["artifact_fact"] and
                    payload.get("recipient") == reference["recipient"] and
                    payload.get("approved") is True and payload.get("delivered") is True)
        if family == "aggregation":
            wanted = reference["sources"]
            source_ids = payload.get("source_ids")
            versions = payload.get("source_versions")
            # The event envelope is well formed, but a malformed artifact is
            # failed work. Do not coerce booleans/floats/strings into version 1.
            if (not isinstance(source_ids, list)
                    or not all(isinstance(k, str) for k in source_ids)
                    or len(source_ids) != len(set(source_ids))
                    or not isinstance(versions, dict)
                    or any(type(versions.get(k)) is not int or versions[k] <= 0 for k in wanted)):
                return False
            return (set(wanted) == set(rules["required_sources"])
                    and set(source_ids) == set(wanted) and
                    all(versions[k] == integer(f["version"]) and
                        timestamp(f["available_at"]) <= at for k, f in wanted.items()) and
                    payload.get("sum") == sum(f["amount"] for f in wanted.values()))
        raise InvalidFixture("UNKNOWN_FAMILY")

    def costs_at(self, trial, cutoff):
        channels, trace, amended, unknown = {}, [], False, []
        for key, versions in sorted(self.chains.items()):
            if key[0] != trial["id"]:
                continue
            visible = [r for r in versions.values() if timestamp(r["available_at"]) <= cutoff]
            if not visible:
                unknown.append(key[2])
                continue
            r = max(visible, key=lambda x: integer(x["version"]))
            amount = rational(r["amount"])
            channels[r["category"]] = amount
            amended = amended or integer(r["version"]) > 1
            trace.append({"logical_effect_id": r["logical_effect_id"], "category": r["category"],
                          "source_ref": r["source_ref"], "version": integer(r["version"]),
                          "per_original_unit": str(amount), "economic_basis": r["economic_basis"]})
        return channels, trace, amended, unknown

    def maturity(self, unit, cutoff):
        if cutoff < timestamp(unit["maturity_due"]):
            return False, "WINDOW_OPEN"
        for source in self.params["required_sources"]:
            facts = [e for e in self.events.values() if e["kind"] == "COVERAGE"
                     and e["group_id"] == unit["id"] and e["source"] == source
                     and timestamp(e["available_at"]) <= cutoff]
            if not facts:
                return False, "SOURCE_COVERAGE_NOT_OBSERVED"
            latest = max(facts, key=lambda x: (timestamp(x["available_at"]), integer(x["source_version"])))
            if timestamp(latest["coverage_end"]) < timestamp(unit["maturity_due"]) or not latest["reconciled"]:
                return False, "SOURCE_INCOMPLETE"
        return True, "COMPLETE_AS_OF_CUTOFF"

    def work(self, trial, cutoff):
        u = self.units[trial["group_id"]]
        commit = self.checks[trial["commit_ref"]]
        business = self.events[trial["business_ref"]]
        reference = self.events[u["reference_ref"]]["payload"]
        # A retrospective adjudication cannot consume a mandatory record before
        # that record is visible to the evaluator. Follow the required evidence
        # graph as well as the authoritative business-state observation.
        required = [u["reference_ref"], trial["business_ref"]]
        required += [trial[k] for k in ("route_ref", "aggregate_ref", "primary_ref",
                                       "review_ref", "create_ref", "commit_ref") if trial.get(k)]
        seen, unavailable = set(), []
        while required:
            ref_id = required.pop()
            if ref_id in seen:
                continue
            seen.add(ref_id)
            item = self.ref(ref_id, u["id"], trial["id"])
            if timestamp(item["available_at"]) > cutoff:
                unavailable.append(ref_id)
            required.extend(item.get("input_refs", []))
            if item.get("grant_ref"):
                required.append(item["grant_ref"])
        if unavailable:
            return "UNRESOLVED", {"historical_commit_acceptance": None,
                                   "unavailable_required_evidence": sorted(unavailable)}, []
        at = timestamp(commit["action_time"])
        rules = self.policy(trial["policy"], at, trial["policy_version"])
        route = self.checks[trial["route_ref"]]
        route_rules = self.policy(trial["policy"], timestamp(route["action_time"]), trial["policy_version"])
        desired = route_rules["routes"][reference["risk"]]
        route_ok = route["actual_route"] == desired
        governed = [route, commit]
        if trial.get("review_ref"):
            governed.append(self.checks[trial["review_ref"]])
        auth = {x["id"]: self.authorized(x, trial) for x in governed}
        quality = self.quality(u["family"], business["payload"], reference, rules, at)
        valid = business["committed"] is True and quality and route_ok and all(auth.values())
        stage_trace = []
        for field in ("aggregate_ref", "primary_ref", "review_ref", "create_ref"):
            if trial.get(field):
                stage = self.checks[trial[field]]
                ok = self.quality(stage["family"], stage["payload"], reference, rules,
                                  timestamp(stage["action_time"]))
                stage_trace.append({"id": stage["id"], "kind": stage["kind"],
                                    "stage_valid": ok, "available_at": stage["available_at"]})
        return ("ACCEPTED" if valid else "DEFECT"), {
            "work_predicate": quality, "route_valid": route_ok, "desired_route": desired,
            "actual_route": route["actual_route"], "action_authorization": auth,
            "historical_commit_acceptance": bool(valid), "business_ref": business["id"],
        }, stage_trace

    def evaluate(self, cutoff_text, q_text):
        cutoff, q = timestamp(cutoff_text), rational(q_text)
        require(q >= 0, "NEGATIVE_CONSEQUENCE_SCALE")
        policies = {k: {"N": 0, "A": 0, "F": 0, "P": 0, "families": {},
                        "cost_channels": {c: Fraction(0) for c in COST_BASES},
                        "value": Fraction(0), "burden_coefficient": Fraction(0),
                        "amended": False, "unknown_cost_channels": 0} for k in self.params["policies"]}
        traces = []
        for trial in sorted(self.trials.values(), key=lambda x: x["id"]):
            unit = self.units[trial["group_id"]]
            weight = integer(unit["multiplicity"])
            state, work_trace, stages = self.work(trial, cutoff)
            mature, reason = self.maturity(unit, cutoff)
            costs, component_trace, amended, unknown = self.costs_at(trial, cutoff)
            complete = mature and state != "UNRESOLVED" and not unknown
            classification = "A" if complete and state == "ACCEPTED" else "F" if complete else "P"
            out = policies[trial["policy"]]
            out["N"] += weight
            out[classification] += weight
            cell = out["families"].setdefault(unit["family"], {}).setdefault(
                unit["complexity"], {"N": 0, "A": 0, "F": 0, "P": 0})
            cell["N"] += weight
            cell[classification] += weight
            terms = self.params["families"][unit["family"]]
            if classification == "A":
                out["value"] += weight * rational(terms["value"])
            elif classification == "F":
                out["burden_coefficient"] += weight * rational(terms["defect_burden"])
            for category, per_unit in costs.items():
                out["cost_channels"][category] += weight * per_unit
            out["amended"] |= amended
            out["unknown_cost_channels"] += len(unknown)
            traces.append({"trial_id": trial["id"], "group_id": unit["id"], "label": unit["label"],
                           "weight": weight, "policy": trial["policy"], "work_adjudication": state,
                           "economic_maturity": "COMPLETE" if complete else "PENDING",
                           "economic_classification": classification, "maturity_reason": reason,
                           "unknown_cost_channels": unknown, "work_trace": work_trace,
                           "stages": stages, "economic_components": component_trace})
        totals, all_complete, horizon_ok = {}, True, True
        for policy, out in policies.items():
            require(out["A"] + out["F"] + out["P"] == out["N"], "COUNT_PARTITION")
            cost = sum(out["cost_channels"].values(), Fraction(0))
            complete = out["P"] == 0 and out["unknown_cost_channels"] == 0
            all_complete &= complete
            horizon_ok &= complete and not out["amended"]
            net = out["value"] - q * out["burden_coefficient"] - cost
            investment = rational(self.params["policies"][policy]["investment"])
            totals[policy] = {"N": out["N"], "A": out["A"], "F": out["F"], "P": out["P"],
                              "families": out["families"], "known_value": str(out["value"]),
                              "known_burden_coefficient": str(out["burden_coefficient"]),
                              "cost_channels": {k: str(v) for k, v in out["cost_channels"].items()},
                              "known_cost": str(cost), "known_net": str(net),
                              "financial_status": "COMPLETE_AT_CUTOFF" if complete else "PARTIAL_AT_CUTOFF",
                              "partial_sum_is_financial_bound": False,
                              "capacity": integer(self.params["policies"][policy]["capacity"]),
                              "admissible_at_assumed_peak": integer(self.params["policies"][policy]["capacity"])
                              >= integer(self.params["required_peak"]),
                              "baseline_horizon_net": str(integer(self.params["horizon_days"]) * net - investment)
                              if complete and not out["amended"] else None}
        nets = {p: Fraction(v["known_net"]) for p, v in totals.items()}
        result = {"evidence_status": "CONSTRUCTED_SYNTHETIC_EVENT_FIXTURE",
                  "independent_acceptance": "NOT_ESTABLISHED", "operational_authority": "NOT_GRANTED",
                  "cutoff": cutoff_text, "q": str(q), "validation": "VALID_FIXTURE", "policies": totals,
                  "daily_preference": preference(nets) if all_complete else "ABSTAIN_INCOMPLETE",
                  "daily_winner_set": winners(nets) if all_complete else [],
                  "investment_preference": "NOT_EVALUATED", "investment_winner_set": [],
                  "baseline_crossovers": None, "traces": traces}
        if horizon_ok:
            horizons = {p: Fraction(v["baseline_horizon_net"]) for p, v in totals.items()}
            result["investment_preference"] = preference(horizons)
            result["investment_winner_set"] = winners(horizons)
            lines = {p: (out["value"] - sum(out["cost_channels"].values(), Fraction(0)),
                         out["burden_coefficient"]) for p, out in policies.items()}
            hlines = {p: (integer(self.params["horizon_days"]) * a -
                          rational(self.params["policies"][p]["investment"]),
                          integer(self.params["horizon_days"]) * b) for p, (a, b) in lines.items()}
            result["baseline_crossovers"] = {"daily": crossovers(lines), "investment": crossovers(hlines)}
        else:
            # A single amended origin cohort is not 90 identical amended cohorts.
            for out in totals.values():
                out["baseline_horizon_net"] = None
        return result


def winners(values):
    high = max(values.values())
    return sorted(k for k, v in values.items() if v == high)


def preference(values):
    selected = winners(values)
    return selected[0] if len(selected) == 1 else "TIE"


def crossovers(lines):
    result = {}
    for a, b in itertools.combinations(sorted(lines), 2):
        intercept = lines[a][0] - lines[b][0]
        slope = lines[a][1] - lines[b][1]
        result[a + ":" + b] = str(intercept / slope) if slope else "ALL_Q_TIE" if not intercept else "PARALLEL"
    return result


def evaluate(data, cutoff, q="7/10"):
    try:
        return Ledger(data).evaluate(cutoff, q)
    except (InvalidFixture, KeyError, TypeError, ValueError, ZeroDivisionError) as exc:
        return {"validation": "INVALID_FIXTURE", "error": str(exc),
                "daily_preference": "ABSTAIN_INVALID", "investment_preference": "NOT_EVALUATED",
                "eligible_input_groups": len(data.get("work_units", [])),
                "independent_acceptance": "NOT_ESTABLISHED"}


def run_suite(data):
    reports = {}
    for key, cutoff in data["parameters"]["observation_cutoffs"].items():
        reports[key] = {q: evaluate(data, cutoff, q) for q in data["parameters"]["q_values"]}
    return {"evidence_status": "CONSTRUCTED_SELF_TEST_CANDIDATE_PENDING_INDEPENDENT_VERIFICATION",
            "independent_acceptance": "NOT_ESTABLISHED", "reports": reports}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="data")
    parser.add_argument("--cutoff")
    parser.add_argument("--q", default="7/10")
    parser.add_argument("--output")
    args = parser.parse_args()
    data = load_data(args.data)
    result = evaluate(data, args.cutoff, args.q) if args.cutoff else run_suite(data)
    value = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(value, encoding="utf-8")
    else:
        print(value, end="")
    return 2 if result.get("validation") == "INVALID_FIXTURE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
