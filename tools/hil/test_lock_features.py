# SPDX-License-Identifier: GPL-3.0-or-later
"""Passcodes, fingerprints, cards and the keypad admin passcode over the USB serial console, which counts as
presence at the board, against the owner's TTLock lock held by the ESP32-S3. The checks that need no lock run
on any board.

The lock belongs to its owner. The suite never clears a list and never factory-resets the lock, deletes only
the passcodes it created, and checks at the end that the lock kept its name. Codes stay in Private values and
only comparisons are asserted, so no code reaches the output. Changing the keypad admin passcode runs only with
--allow-admin-passcode-change and puts the original code back afterwards. Enrolment runs without a finger or a
card at the lock, so it must end with a timeout.
"""

from __future__ import annotations

import re
import secrets as random
import sys
import time
from collections import Counter
from collections.abc import Iterator
from typing import Any

import pytest
from board import events_for, prepare, stored, wait_idle
from latchkey_cli import Console
from owner import Private, PrivateBytes, hide

DOCUMENTATION_MAC = "00:00:5E:00:53:99"
LOCK_TIMEOUT_S = 90.0
ENROL_TIMEOUT_S = 120.0
SETTLE_S = 60.0
NAME_PREFIX = "HIL "
PASSCODE_ID = re.compile(r"[0-9a-f]{12}")
CREDENTIAL_ID = re.compile(r"0|[1-9][0-9]*")
DIGITS = re.compile(r"[0-9]{4,9}")
PASSCODE_KEYS = {"id", "type", "name", "validity", "managed"}
CREDENTIAL_KEYS = {"id", "name", "validity"}
PASSCODE_TYPES = {"permanent", "timed", "one_time", "cyclic"}
ADMIN_KEYS = {"code", "source"}
UNKNOWN_PASSCODE = "000000000000"
LOCK_METHODS: dict[str, dict[str, Any]] = {
    "lock.passcodes.list": {},
    "lock.passcodes.add": {"type": "permanent"},
    "lock.passcodes.update": {"id": UNKNOWN_PASSCODE, "name": "x"},
    "lock.passcodes.delete": {"id": UNKNOWN_PASSCODE},
    "lock.passcodes.clear": {},
    "lock.fingerprints.list": {},
    "lock.fingerprints.enroll": {},
    "lock.fingerprints.setValidity": {"id": "1", "validity": None},
    "lock.fingerprints.delete": {"id": "1"},
    "lock.fingerprints.clear": {},
    "lock.cards.list": {},
    "lock.cards.enroll": {},
    "lock.cards.setValidity": {"id": "1", "validity": None},
    "lock.cards.delete": {"id": "1"},
    "lock.cards.clear": {},
    "lock.adminPasscode.get": {},
    "lock.adminPasscode.set": {},
    "lock.adminPasscode.raw": {},
}
BAD_PARAMS: list[tuple[str, dict[str, Any]]] = [
    ("lock.passcodes.add", {}),
    ("lock.passcodes.add", {"type": "weekly"}),
    ("lock.passcodes.add", {"type": "permanent", "code": "123"}),
    ("lock.passcodes.add", {"type": "permanent", "code": "12a4"}),
    ("lock.passcodes.add", {"type": "permanent", "code": 1234}),
    ("lock.passcodes.add", {"type": "permanent", "name": "x" * 25}),
    ("lock.passcodes.add", {"type": "timed"}),
    ("lock.passcodes.add", {"type": "timed", "validity": {"start": 1900000000, "end": 1899999999}}),
    ("lock.passcodes.add", {"type": "timed", "validity": {"start": 1900000000, "end": 5000000000}}),
    ("lock.passcodes.update", {}),
    ("lock.passcodes.update", {"id": "XYZ", "name": "x"}),
    ("lock.passcodes.update", {"id": UNKNOWN_PASSCODE, "code": "1"}),
    ("lock.passcodes.delete", {"id": 7}),
    ("lock.fingerprints.enroll", {"name": "x" * 25}),
    ("lock.fingerprints.setValidity", {"id": "-1", "validity": None}),
    ("lock.fingerprints.setValidity", {"id": "1", "validity": {"start": 2, "end": 1}}),
    ("lock.fingerprints.setValidity", {"id": "1", "validity": None, "cycle": {"days": [0], "start": "08:00"}}),
    ("lock.fingerprints.delete", {"id": "281474976710656"}),
    ("lock.cards.delete", {"id": "01"}),
    ("lock.cards.setValidity", {"id": "1", "validity": None, "cycle": {"days": [1], "start": "18:00", "end": "08:00"}}),
    ("lock.adminPasscode.set", {"code": "123"}),
    ("lock.adminPasscode.set", {"code": "1234567890"}),
]


def code_of(console: Console, method: str, params: dict[str, Any], timeout: float = LOCK_TIMEOUT_S) -> str | None:
    return console.request(method, params, timeout=timeout).get("error", {}).get("code")


def frames(console: Console) -> int:
    return console.call("system.info")["ble"]["frames"]


def random_code(digits: int) -> Private:
    return Private("".join(str(random.randbelow(10)) for _ in range(digits)))


def minute() -> int:
    return int(time.time()) // 60 * 60


def passcodes(console: Console, mac: str) -> list[dict[str, Any]]:
    return console.call("lock.passcodes.list", {"lock": mac}, timeout=LOCK_TIMEOUT_S)["passcodes"]


def listed(console: Console, mac: str, passcode_id: str) -> dict[str, Any] | None:
    return next((entry for entry in passcodes(console, mac) if entry["id"] == passcode_id), None)


def settle(console: Console, mac: str) -> tuple[float, list[str]]:
    started = time.monotonic()
    refused: list[str] = []
    while time.monotonic() - started < SETTLE_S:
        reply = console.request("lock.status", {"lock": mac}, timeout=LOCK_TIMEOUT_S)
        if "result" in reply:
            return time.monotonic() - started, refused
        refused.append(reply["error"]["message"])
        time.sleep(3.0)
    pytest.fail(f"the lock did not answer lock.status within {SETTLE_S:.0f} s after the enrolment: {refused}")


@pytest.fixture(scope="module")
def board(console: Console) -> dict[str, Any]:
    return prepare(console)


@pytest.fixture(scope="module")
def baseline(console: Console, board: dict[str, Any], lock_mac: str) -> dict[str, Any] | None:
    return hide(stored(console, lock_mac))


@pytest.fixture
def held(console: Console, baseline: dict[str, Any] | None, lock_mac: str) -> dict[str, Any]:
    lock = stored(console, lock_mac)
    if lock is None:
        pytest.skip("this board holds no keys for the lock")
    return hide(lock)


@pytest.fixture(scope="module")
def created(console: Console, board: dict[str, Any], lock_mac: str) -> Iterator[list[str]]:
    ids: list[str] = []
    yield ids
    if not ids or stored(console, lock_mac) is None:
        return
    left = {entry["id"] for entry in passcodes(console, lock_mac)} & set(ids)
    for passcode_id in left:
        console.call("lock.passcodes.delete", {"lock": lock_mac, "id": passcode_id}, timeout=LOCK_TIMEOUT_S)


@pytest.fixture(scope="module")
def admin() -> dict[str, Any]:
    return {}


def test_access_methods_check_their_params_without_touching_the_lock(console: Console, board: dict[str, Any]) -> None:
    wait_idle(console)
    before = frames(console)
    for method, params in LOCK_METHODS.items():
        assert code_of(console, method, {}) == "invalid_argument", method
        assert code_of(console, method, {"lock": "not-a-mac", **params}) == "invalid_argument", method
        assert code_of(console, method, {"lock": DOCUMENTATION_MAC, **params}) == "not_paired", method
    for method, params in BAD_PARAMS:
        assert code_of(console, method, {"lock": DOCUMENTATION_MAC, **params}) == "invalid_argument", (method, params)
    assert frames(console) == before


def test_pairing_checks_the_admin_passcode_before_it_waits(console: Console, board: dict[str, Any]) -> None:
    for code in ("123", "1234567890", "12a4567", " 1234567", 1234567):
        started = time.monotonic()
        params = {"mac": DOCUMENTATION_MAC, "wait": 1, "adminPasscode": code}
        assert code_of(console, "locks.pair", params) == "invalid_argument", code
        assert time.monotonic() - started < 5.0
    accepted = {"mac": DOCUMENTATION_MAC, "wait": 1, "adminPasscode": "31415926"}
    assert code_of(console, "locks.pair", accepted) == "timeout"


def test_cyclic_passcodes_are_refused_without_a_frame(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    wait_idle(console)
    before = frames(console)
    start = minute() + 3600
    params = {
        "lock": lock_mac,
        "type": "cyclic",
        "name": NAME_PREFIX + "cyclic",
        "validity": {"start": start, "end": start + 86400},
        "cycle": {"days": [1, 2, 3, 4, 5], "start": "08:00", "end": "18:00"},
    }
    reply = console.request("lock.passcodes.add", params, timeout=LOCK_TIMEOUT_S)
    assert reply["error"]["code"] == "unsupported"
    assert frames(console) == before


def test_the_passcode_list_has_ids_and_never_codes(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    entries = passcodes(console, lock_mac)
    for entry in entries:
        assert set(entry) == PASSCODE_KEYS
        assert PASSCODE_ID.fullmatch(entry["id"])
        assert entry["type"] in PASSCODE_TYPES
        assert isinstance(entry["managed"], bool)
    assert len({entry["id"] for entry in entries}) == len(entries)
    types = Counter(entry["type"] for entry in entries)
    managed = sum(entry["managed"] for entry in entries)
    named = sum(bool(entry["name"]) for entry in entries)
    print(f"passcode list: {len(entries)} entries {dict(types)}, {managed} managed, {named} named", file=sys.stderr)


def test_a_passcode_is_added_listed_changed_and_deleted(
    console: Console, held: dict[str, Any], lock_mac: str, created: list[str]
) -> None:
    first = random_code(7)
    params = {"lock": lock_mac, "type": "permanent", "name": NAME_PREFIX + "permanent", "code": first}
    added = console.call("lock.passcodes.add", params, timeout=LOCK_TIMEOUT_S)["passcode"]
    created.append(added["id"])
    assert set(added) == PASSCODE_KEYS | {"code"}
    same = added["code"] == first
    assert same, "the added passcode is not the code that was sent"
    assert (added["type"], added["name"], added["validity"], added["managed"]) == (
        "permanent",
        NAME_PREFIX + "permanent",
        None,
        True,
    )
    entry = listed(console, lock_mac, added["id"])
    assert entry == {key: added[key] for key in PASSCODE_KEYS}

    second = random_code(8)
    update = {"lock": lock_mac, "id": added["id"], "name": NAME_PREFIX + "renamed", "code": second}
    changed = console.call("lock.passcodes.update", update, timeout=LOCK_TIMEOUT_S)["passcode"]
    created.append(changed["id"])
    assert set(changed) == PASSCODE_KEYS
    assert changed["id"] != added["id"]
    assert (changed["type"], changed["name"], changed["managed"]) == ("permanent", NAME_PREFIX + "renamed", True)
    ids = {item["id"] for item in passcodes(console, lock_mac)}
    assert changed["id"] in ids
    assert added["id"] not in ids

    rename = {"lock": lock_mac, "id": changed["id"], "name": NAME_PREFIX + "named again"}
    renamed = console.call("lock.passcodes.update", rename, timeout=LOCK_TIMEOUT_S)["passcode"]
    assert (renamed["id"], renamed["name"]) == (changed["id"], NAME_PREFIX + "named again")

    assert console.call("lock.passcodes.delete", {"lock": lock_mac, "id": changed["id"]}, timeout=LOCK_TIMEOUT_S) == {}
    assert listed(console, lock_mac, changed["id"]) is None
    assert code_of(console, "lock.passcodes.delete", {"lock": lock_mac, "id": changed["id"]}) == "invalid_argument"


def test_timed_and_one_time_passcodes_keep_their_windows(
    console: Console, held: dict[str, Any], lock_mac: str, created: list[str]
) -> None:
    start = minute() + 3600
    window = {"start": start, "end": start + 7200}
    moved = {"start": start + 86400, "end": start + 2 * 86400}
    for kind in ("timed", "one_time"):
        params = {
            "lock": lock_mac,
            "type": kind,
            "name": NAME_PREFIX + kind,
            "code": random_code(6),
            "validity": window,
        }
        added = console.call("lock.passcodes.add", params, timeout=LOCK_TIMEOUT_S)["passcode"]
        created.append(added["id"])
        assert (added["type"], added["validity"], added["managed"]) == (kind, window, True)
        entry = listed(console, lock_mac, added["id"])
        assert entry is not None
        print(
            f"{kind} passcode listed with {'the same' if entry['validity'] == window else 'another'} window: "
            f"{entry['validity']}",
            file=sys.stderr,
        )
        assert entry["type"] == kind
        if kind == "timed":
            assert entry["validity"] == window
        update = {"lock": lock_mac, "id": added["id"], "validity": moved}
        changed = console.call("lock.passcodes.update", update, timeout=LOCK_TIMEOUT_S)["passcode"]
        assert (changed["id"], changed["validity"]) == (added["id"], moved)
        if kind == "timed":
            assert listed(console, lock_mac, added["id"])["validity"] == moved
        assert (
            console.call("lock.passcodes.delete", {"lock": lock_mac, "id": added["id"]}, timeout=LOCK_TIMEOUT_S) == {}
        )
        assert listed(console, lock_mac, added["id"]) is None


def test_a_random_passcode_has_six_digits_and_a_duplicate_is_refused(
    console: Console, held: dict[str, Any], lock_mac: str, created: list[str]
) -> None:
    params = {"lock": lock_mac, "type": "permanent", "name": NAME_PREFIX + "random"}
    added = console.call("lock.passcodes.add", params, timeout=LOCK_TIMEOUT_S)["passcode"]
    created.append(added["id"])
    code = Private(added["code"])
    six = re.fullmatch(r"[0-9]{6}", code) is not None
    assert six, "a random passcode is not six digits"
    again = {"lock": lock_mac, "type": "permanent", "name": NAME_PREFIX + "again", "code": code}
    assert code_of(console, "lock.passcodes.add", again) == "lock_error"
    assert console.call("lock.passcodes.delete", {"lock": lock_mac, "id": added["id"]}, timeout=LOCK_TIMEOUT_S) == {}


def test_the_admin_passcode_is_read_from_the_lock(
    console: Console, held: dict[str, Any], lock_mac: str, admin: dict[str, Any]
) -> None:
    result = console.call("lock.adminPasscode.get", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)
    code = Private(result["code"])
    shaped = DIGITS.fullmatch(code) is not None
    assert shaped, "the admin passcode is not 4 to 9 digits"
    assert result["source"] in ("lock", "board")
    if result["source"] == "lock":
        assert set(result) == ADMIN_KEYS | {"matchesBoard"}
        assert isinstance(result["matchesBoard"], bool)
    else:
        assert set(result) == ADMIN_KEYS
    print(
        f"admin passcode read from the {result['source']}, matches the board's copy: {result.get('matchesBoard')}",
        file=sys.stderr,
    )
    admin.update(code=code, source=result["source"], matches=result.get("matchesBoard"))


def test_the_raw_admin_code_reply_holds_the_code_at_its_declared_length(
    console: Console, held: dict[str, Any], lock_mac: str, admin: dict[str, Any]
) -> None:
    if "get_admin_code" not in console.call("lock.features", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)["features"]:
        pytest.skip("the lock does not report get_admin_code")
    battery = console.call("lock.status", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)["battery"]
    reply = PrivateBytes(
        bytes.fromhex(console.call("lock.adminPasscode.raw", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)["reply"])
    )
    assert len(reply) >= 2
    declared = reply[1]
    body = reply[2 : 2 + declared]
    holds_code = admin.get("source") == "lock" and body == admin["code"].encode()
    print(
        f"0x65 reply: {len(reply)} bytes, byte 0 equals the battery level ({battery}): {reply[0] == battery}, "
        f"declared length covers the code read: {holds_code}, bytes after it: {len(reply) - 2 - declared}",
        file=sys.stderr,
    )
    if admin.get("source") == "lock":
        assert holds_code, "the raw reply does not hold the parsed code at its declared length"


def test_the_admin_passcode_must_be_four_to_nine_digits(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    wait_idle(console)
    before = frames(console)
    for code in ("123", "1234567890", "12a4567"):
        assert code_of(console, "lock.adminPasscode.set", {"lock": lock_mac, "code": code}) == "invalid_argument"
    assert frames(console) == before


def test_the_admin_passcode_changes_and_comes_back(
    console: Console, held: dict[str, Any], lock_mac: str, admin: dict[str, Any], allow_admin_passcode_change: bool
) -> None:
    if not allow_admin_passcode_change:
        pytest.skip("pass --allow-admin-passcode-change to change the keypad admin passcode")
    if admin.get("source") != "lock" or admin.get("matches") is not True:
        pytest.skip("the lock's admin passcode could not be read back, so it could not be put back for sure")
    original = admin["code"]
    chosen = random_code(8)
    while chosen == original:
        chosen = random_code(8)
    try:
        assert console.call("lock.adminPasscode.set", {"lock": lock_mac, "code": chosen}, timeout=LOCK_TIMEOUT_S) == {}
        read = console.call("lock.adminPasscode.get", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)
        changed = (read["code"] == chosen, read["source"], read["matchesBoard"])
        assert changed == (True, "lock", True)
        generated = console.call("lock.adminPasscode.set", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)
        assert set(generated) == {"code"}
        fresh = Private(generated["code"])
        seven = re.fullmatch(r"[0-9]{7}", fresh) is not None
        assert seven, "a random admin passcode is not seven digits"
        read = console.call("lock.adminPasscode.get", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)
        assert (read["code"] == fresh, read["source"]) == (True, "lock")
    finally:
        assert (
            console.call("lock.adminPasscode.set", {"lock": lock_mac, "code": original}, timeout=LOCK_TIMEOUT_S) == {}
        )
    read = console.call("lock.adminPasscode.get", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)
    restored = (read["code"] == original, read["source"], read["matchesBoard"])
    assert restored == (True, "lock", True)


@pytest.mark.parametrize(
    ("method", "kind", "total"), [("lock.fingerprints.enroll", "fingerprint", 4), ("lock.cards.enroll", "card", 1)]
)
def test_an_enrolment_without_a_finger_or_card_ends_with_a_timeout(
    console: Console, held: dict[str, Any], lock_mac: str, method: str, kind: str, total: int
) -> None:
    console.events.clear()
    started = time.monotonic()
    reply = console.request(method, {"lock": lock_mac, "name": NAME_PREFIX + kind}, timeout=ENROL_TIMEOUT_S)
    elapsed = time.monotonic() - started
    assert reply.get("error", {}).get("code") == "timeout", reply
    progress = events_for(console, "enroll.progress", lock_mac)
    assert progress, "no enroll.progress event arrived"
    assert progress[0] == {"lock": lock_mac, "kind": kind, "stage": "waiting", "scans": 0, "total": total}
    assert all(event["stage"] == "waiting" for event in progress)
    waited, refused = settle(console, lock_mac)
    print(
        f"{kind} enrolment ended with a timeout after {elapsed:.1f} s; lock.status answered {waited:.1f} s later "
        f"after {len(refused)} refusals {refused}",
        file=sys.stderr,
    )


def test_card_and_fingerprint_lists_use_decimal_ids(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    for method, key in (("lock.fingerprints.list", "fingerprints"), ("lock.cards.list", "cards")):
        entries = console.call(method, {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)[key]
        for entry in entries:
            assert set(entry) in (CREDENTIAL_KEYS, CREDENTIAL_KEYS | {"cycle"})
            assert CREDENTIAL_ID.fullmatch(entry["id"])
        print(f"{key}: {len(entries)} enrolled", file=sys.stderr)


def test_the_lock_keeps_its_name(console: Console, held: dict[str, Any], baseline: dict[str, Any] | None) -> None:
    assert baseline is not None
    kept = held["name"] == baseline["name"]
    assert kept, "the lock's name changed during the suite"
