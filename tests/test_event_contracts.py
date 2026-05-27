from core.events.bus import EventBus
from core.scan_model import Finding


def test_eventbus_warns_and_continues_on_invalid_payload():
    bus = EventBus(strict=False)
    # invalid: payload must be dict for known events
    out = bus.publish("finding.added", payload="nope")
    assert out == "nope"  # nosec: B101
    assert bus.invalid_events >= 1  # nosec: B101


def test_eventbus_strict_raises_on_invalid_payload():
    bus = EventBus(strict=True)
    raised = False
    try:
        bus.publish("finding.added", payload="nope")
    except ValueError:
        raised = True
    assert raised is True  # nosec: B101


def test_eventbus_enrichment_updates_payload_dict():
    bus = EventBus(strict=False)

    def enricher(_t, payload):
        if isinstance(payload, dict):
            return {"x": 2}
        return {}

    bus.subscribe("module.completed", enricher)
    p = bus.publish("module.completed", {"module": "m1"})
    assert isinstance(p, dict)  # nosec: B101
    assert p.get("x") == 2  # nosec: B101


def test_canonical_finding_id_is_stable_for_same_fields():
    f1 = Finding(module="M", severity="HIGH", description="D", endpoint="http://a", parameter="p", evidence={"summary": "e"})
    f2 = Finding(module="M", severity="HIGH", description="D", endpoint="http://a", parameter="p", evidence={"summary": "e"})
    assert f1.finding_id == f2.finding_id  # nosec: B101

