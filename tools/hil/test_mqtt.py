# SPDX-License-Identifier: GPL-3.0-or-later
"""MQTT and Home Assistant discovery against a real board and the broker named in secrets.local.json.

Skipped without the mqtt key ({host, port, username, password}) in secrets.local.json, and on a board whose
MQTT is on or set up for another broker, so the suite never replaces an owner's settings or their password.
The suite sets the board's MQTT settings over the USB console with discovery prefixes of its own, so Home
Assistant does not pick its entities up, and watches the broker with its own paho-mqtt client. At the end it
turns MQTT off, removes the retained messages the board left under its topics and the suite's prefixes, and
puts the board's settings back as it found them.

On a board that holds the lock (lock_mac; the lock tests skip without it), LOCK and UNLOCK move the real lock
and the lock is always left locked; no credential on the lock is touched. On a board that holds no lock and
no owner login (no totp_uri), the last test factory-resets the board and claims it again. The heap check
also loads the web server through the hil_relay host when there is one.
"""

from __future__ import annotations

import json
import re
import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import paho.mqtt.client as mqtt
import pytest
from board import error_code, set_clock
from latchkey_cli import Console
from owner import Private, claim_secret
from relay import Relay

TEST_PREFIX = "latchkey_hil"
SECOND_PREFIX = "latchkey_hil2"
SETTINGS_KEYS = ("enabled", "host", "port", "username", "prefix", "passwordSet")
VIEW_KEYS = {*SETTINGS_KEYS, "connected", "problem"}
CONNECTED_LINE = re.compile(r"mqtt: connected to the broker, topics under latchkey/([A-Za-z0-9_-]+)/")
RETRY_LINE = re.compile(r"mqtt: cannot connect \((?P<why>[^)]*)\); trying again in (?P<wait>\d+) s")
IGNORED_LINE = re.compile(r"mqtt: ignored ")
COMMAND_LINE = re.compile(r"mqtt: (LOCK|UNLOCK) for ")
REFUSED_RESULT = re.compile(r"queued x(\d+)")
DOCUMENTATION_LOCK = "00005e005399"
UNRESOLVABLE_HOST = "broker.invalid"
UNROUTABLE_HOST = "192.0.2.1"
WRONG_PASSWORD = Private("not the broker password")
REFUSED_LOGIN = "the broker refused the username or password"
UNREACHABLE = "cannot reach the broker"
CONNECT_TIMEOUT_S = 60.0
LOCK_TIMEOUT_S = 150.0
FIRST_POLL_TIMEOUT_S = 180.0
LINK_TIMEOUT_S = 180.0
RESTART_TIMEOUT_S = 120.0
REFUSAL_WINDOW_S = 60.0
QUIET_S = 4.0
EXTRA_COMMANDS = 4
AUDIT_PAGE = 20
MIN_FREE_HEAP = 30_000
MIN_STACK_FREE = 1024
WEB_PAGE_LOADS = 3
COMPONENTS = (
    ("lock", ""),
    ("sensor", "_battery"),
    ("sensor", "_last_event"),
    ("binary_sensor", "_link"),
    ("event", "_unlock_alert"),
)
BAD_SETTINGS = (
    {},
    {"enabled": "yes"},
    {"enabled": True},
    {"enabled": True, "host": "   "},
    {"enabled": False, "host": "bad host"},
    {"enabled": False, "host": "broker.example/x"},
    {"enabled": False, "host": "mqtt://broker.example"},
    {"enabled": False, "host": "h" * 65},
    {"enabled": False, "host": 1883},
    {"enabled": False, "port": 0},
    {"enabled": False, "port": 65536},
    {"enabled": False, "port": "1883"},
    {"enabled": False, "port": 1883.5},
    {"enabled": False, "username": "u" * 65},
    {"enabled": False, "username": "tab\there"},
    {"enabled": False, "prefix": "home/assistant"},
    {"enabled": False, "prefix": "a+b"},
    {"enabled": False, "prefix": "p" * 33},
    {"enabled": False, "password": 1234},
    {"enabled": False, "password": "p" * 65},
    {"enabled": False, "password": "é" * 33},
)


@dataclass
class Message:
    topic: str
    payload: str
    retained: bool


@dataclass
class Session:
    board: str
    availability: str


@dataclass
class LockTopics:
    lock: str
    state: str
    command: str
    battery: str
    last_event: str
    link: str


class Broker:
    """A client of the broker that records every message under the topics it watches."""

    def __init__(self, settings: dict[str, Any]) -> None:
        self.settings = settings
        self.guard = threading.Lock()
        self.messages: list[Message] = []
        self.client = self.open(self.record)

    def open(self, on_message: Callable[[Message], None]) -> mqtt.Client:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"latchkey-hil-{uuid.uuid4().hex[:8]}")
        client.username_pw_set(self.settings["username"], self.settings["password"])
        answers: list[Any] = []
        connected = threading.Event()

        def on_connect(_client: mqtt.Client, _userdata: Any, _flags: Any, reason: Any, _properties: Any) -> None:
            answers.append(reason)
            connected.set()

        def deliver(_client: mqtt.Client, _userdata: Any, message: mqtt.MQTTMessage) -> None:
            on_message(Message(message.topic, message.payload.decode("utf-8", "replace"), bool(message.retain)))

        client.on_connect = on_connect
        client.on_message = deliver
        client.connect(self.settings["host"], int(self.settings["port"]), keepalive=30)
        client.loop_start()
        reached = connected.wait(10.0)
        assert reached, "the MQTT broker did not answer"
        accepted = not answers[0].is_failure
        assert accepted, "the MQTT broker refused the suite's login"
        return client

    def record(self, message: Message) -> None:
        with self.guard:
            self.messages.append(message)

    def subscribe(self, client: mqtt.Client, filters: list[str]) -> None:
        granted = threading.Event()
        client.on_subscribe = lambda *_args: granted.set()
        client.subscribe([(topic, 1) for topic in filters])
        subscribed = granted.wait(10.0)
        assert subscribed, "the MQTT broker did not confirm a subscription"

    def watch(self, filters: list[str]) -> None:
        self.subscribe(self.client, filters)

    def mark(self) -> int:
        with self.guard:
            return len(self.messages)

    def since(self, mark: int, topic: str) -> list[Message]:
        with self.guard:
            return [message for message in self.messages[mark:] if message.topic == topic]

    def wait(self, topic: str, matches: Callable[[str], bool], timeout: float, mark: int = 0) -> Message | None:
        deadline = time.monotonic() + timeout
        while True:
            found = next((message for message in self.since(mark, topic) if matches(message.payload)), None)
            if found is not None or time.monotonic() >= deadline:
                return found
            time.sleep(0.2)

    def publish(self, topic: str, payload: str, retain: bool = False) -> None:
        info = self.client.publish(topic, payload, qos=1, retain=retain)
        info.wait_for_publish(10.0)
        published = info.is_published()
        assert published, "the MQTT broker did not take a message from the suite"

    def retained(self, topic_filter: str) -> dict[str, str]:
        found: dict[str, str] = {}
        lock = threading.Lock()

        def keep(message: Message) -> None:
            if message.retained:
                with lock:
                    found[message.topic] = message.payload

        client = self.open(keep)
        try:
            self.subscribe(client, [topic_filter])
            time.sleep(QUIET_S)
        finally:
            client.loop_stop()
            client.disconnect()
        with lock:
            return dict(found)

    def clear(self, topic_filter: str) -> None:
        for topic in self.retained(topic_filter):
            self.publish(topic, "", retain=True)

    def close(self) -> None:
        self.client.loop_stop()
        self.client.disconnect()


def settings_for(broker_settings: dict[str, Any], enabled: bool = True, **extra: Any) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "host": broker_settings["host"],
        "port": int(broker_settings["port"]),
        "username": broker_settings["username"],
        "prefix": TEST_PREFIX,
        **extra,
    }


def same_broker(view: dict[str, Any], broker_settings: dict[str, Any]) -> bool:
    return (
        view["host"] == broker_settings["host"]
        and view["port"] == int(broker_settings["port"])
        and view["username"] == broker_settings["username"]
    )


def wait_line(
    console: Console, pattern: re.Pattern[str], seen: int, timeout: float, what: str
) -> tuple[int, re.Match[str]]:
    deadline = time.monotonic() + timeout
    while True:
        for index in range(seen, len(console.lines)):
            match = pattern.search(console.lines[index])
            if match:
                return index, match
        if time.monotonic() >= deadline:
            pytest.fail(f"the board did not log {what} within {timeout:.0f} s")
        console.call("system.info")
        time.sleep(0.5)


def wait_connected(console: Console, seen: int, timeout: float = CONNECT_TIMEOUT_S) -> str:
    _, match = wait_line(console, CONNECTED_LINE, seen, timeout, "a connection to the broker")
    return Private(match.group(1))


def reapply(console: Console, params: dict[str, Any]) -> dict[str, Any]:
    seen = len(console.lines)
    view = console.call("mqtt.set", params)
    wait_connected(console, seen)
    return view


def audit_since(console: Console, seq: int) -> list[dict[str, Any]]:
    entries = console.call("audit.list", {"limit": AUDIT_PAGE})["entries"]
    return [entry for entry in entries if entry["seq"] > seq]


def last_audit_seq(console: Console) -> int:
    entries = console.call("audit.list", {"limit": 1})["entries"]
    return entries[0]["seq"] if entries else 0


def wait_audit(console: Console, seq: int, method: str, timeout: float) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout
    while True:
        found = next((entry for entry in audit_since(console, seq) if entry["method"] == method), None)
        if found is not None or time.monotonic() >= deadline:
            return found
        time.sleep(1.0)


def refused_count(entries: list[dict[str, Any]]) -> int:
    counts = [REFUSED_RESULT.fullmatch(entry["result"]) for entry in entries if entry["method"] == "mqtt.command"]
    return sum(int(match.group(1)) for match in counts if match)


def lock_topics(session: Session, lock: str) -> LockTopics:
    base = f"latchkey/{session.board}/{lock}/"
    return LockTopics(
        Private(lock),
        Private(base + "state"),
        Private(base + "set"),
        Private(base + "battery"),
        Private(base + "last_event"),
        Private(base + "link"),
    )


def config_topic(session: Session, component: str, lock: str, suffix: str, prefix: str = TEST_PREFIX) -> str:
    return Private(f"{prefix}/{component}/{session.board}/{lock}{suffix}/config")


def config_topics(session: Session, lock: str, prefix: str = TEST_PREFIX) -> list[str]:
    return [config_topic(session, component, lock, suffix, prefix) for component, suffix in COMPONENTS]


def run_guarded(steps: list[Callable[[], Any]]) -> None:
    problems: list[BaseException] = []
    for step in steps:
        try:
            step()
        except Exception as err:
            problems.append(err)
    if problems:
        raise problems[0]


@pytest.fixture(scope="module")
def broker_settings(secrets: dict[str, Any]) -> dict[str, Any]:
    settings = secrets.get("mqtt")
    if not settings:
        pytest.skip("secrets.local.json has no mqtt")
    return settings


@pytest.fixture(scope="module")
def broker(broker_settings: dict[str, Any]) -> Iterator[Broker]:
    watcher = Broker(broker_settings)
    yield watcher
    watcher.close()


@pytest.fixture(scope="module")
def board(console: Console, broker_settings: dict[str, Any]) -> dict[str, Any]:
    info = console.wait_ready()
    if not info["wifi"]["configured"]:
        pytest.fail("the board has no Wi-Fi settings: claim it first")
    set_clock(console)
    return console.wait_info(lambda state: state["wifi"]["connected"], CONNECT_TIMEOUT_S, "Wi-Fi to connect")


@pytest.fixture(scope="module")
def before(console: Console, board: dict[str, Any], broker_settings: dict[str, Any]) -> dict[str, Any]:
    view = console.call("mqtt.get")
    if view["enabled"]:
        pytest.skip("MQTT is on on this board: the suite would replace its owner's settings")
    if view["host"] and not same_broker(view, broker_settings):
        pytest.skip("the board has MQTT settings for another broker: the suite would lose their password")
    return view


@pytest.fixture(scope="module")
def connected(
    console: Console, before: dict[str, Any], broker: Broker, broker_settings: dict[str, Any]
) -> Iterator[Session]:
    seen = len(console.lines)
    console.call("mqtt.set", settings_for(broker_settings, password=broker_settings["password"]))
    root = wait_connected(console, seen)
    session = Session(root, Private(f"latchkey/{root}/availability"))
    broker.watch([f"latchkey/{root}/#", f"{TEST_PREFIX}/+/{root}/#", f"{SECOND_PREFIX}/+/{root}/#"])
    restore = {key: before[key] for key in ("enabled", "host", "port", "username", "prefix")}
    if not before["passwordSet"]:
        restore["password"] = ""
    try:
        yield session
    finally:
        run_guarded(
            [
                lambda: console.call("mqtt.set", settings_for(broker_settings, enabled=False)),
                lambda: broker.clear(f"latchkey/{root}/#"),
                lambda: broker.clear(f"{TEST_PREFIX}/+/{root}/#"),
                lambda: broker.clear(f"{SECOND_PREFIX}/+/{root}/#"),
                lambda: console.call("mqtt.set", restore),
            ]
        )


@pytest.fixture
def held(console: Console, connected: Session, secrets: dict[str, Any]) -> dict[str, Any]:
    mac = secrets.get("lock_mac")
    if not mac:
        pytest.skip("secrets.local.json has no lock_mac")
    lock = next((lock for lock in console.call("locks.list")["locks"] if lock["id"] == mac.upper()), None)
    if lock is None:
        pytest.skip("this board holds no keys for the lock")
    return lock


@pytest.fixture
def held_topics(connected: Session, held: dict[str, Any]) -> LockTopics:
    return lock_topics(connected, Private(held["id"].replace(":", "").lower()))


def test_settings_are_checked(console: Console, board: dict[str, Any]) -> None:
    view = console.call("mqtt.get")
    assert set(view) == VIEW_KEYS
    for params in BAD_SETTINGS:
        assert error_code(console, "mqtt.set", params) == "invalid_argument", sorted(params)
    same = console.call("mqtt.get") == view
    assert same, "a refused mqtt.set changed the settings"


def test_the_password_is_never_read_back(console: Console, connected: Session, broker_settings: dict[str, Any]) -> None:
    view = console.call("mqtt.get")
    assert set(view) == VIEW_KEYS
    assert view["enabled"] is True
    assert view["passwordSet"] is True
    assert same_broker(view, broker_settings), "mqtt.get reports another broker than the suite set"
    assert view["prefix"] == TEST_PREFIX
    again = reapply(console, settings_for(broker_settings))
    same = {key: again[key] for key in SETTINGS_KEYS} == {key: view[key] for key in SETTINGS_KEYS}
    assert same, "mqtt.set without a password answered other settings"
    leaked = broker_settings["password"] in json.dumps(again)
    assert not leaked, "mqtt.set returned the password"


def test_the_board_is_online(console: Console, broker: Broker, connected: Session) -> None:
    held = broker.retained(connected.availability)
    online = held.get(connected.availability) == "online"
    assert online, "the board's availability is not a retained online"
    view = console.call("mqtt.get")
    assert view["connected"] is True
    assert view["problem"] is None


def test_the_held_lock_is_announced(
    broker: Broker, connected: Session, held: dict[str, Any], held_topics: LockTopics
) -> None:
    configs = broker.retained(f"{TEST_PREFIX}/+/{connected.board}/#")
    for (component, suffix), topic in zip(COMPONENTS, config_topics(connected, held_topics.lock)):
        present = topic in configs
        assert present, f"no retained {component}{suffix} config"
        config = json.loads(configs[topic])
        device = config["device"]
        same = device["name"] == held["name"] and device["identifiers"] == [f"latchkey_{held_topics.lock}"]
        assert same, "a config names another device"
        same = device["model"] == held["model"]
        assert same, "a config names another model"
        assert device["manufacturer"] == "TTLock"
        assert isinstance(device["sw_version"], str) and device["sw_version"]
        assert config["origin"]["name"] == "Latchkey"
        same = config["availability_topic"] == connected.availability
        assert same, "a config names another availability topic"
        unique = f"latchkey_{connected.board}_{held_topics.lock}_{suffix.lstrip('_') or 'lock'}"
        same = config["unique_id"] == unique
        assert same, f"the {component}{suffix} config has another unique_id"
    lock = json.loads(configs[config_topic(connected, "lock", held_topics.lock, "")])
    assert lock["name"] is None
    named = lock["state_topic"] == held_topics.state and lock["command_topic"] == held_topics.command
    assert named, "the lock entity names other state or command topics"


def test_the_held_lock_reports_its_state_battery_and_link(
    broker: Broker, connected: Session, held: dict[str, Any], held_topics: LockTopics
) -> None:
    state = broker.wait(held_topics.state, lambda payload: payload in ("LOCKED", "UNLOCKED"), FIRST_POLL_TIMEOUT_S)
    assert state is not None, "no lock state reached the broker"
    battery = broker.wait(
        held_topics.battery, lambda payload: payload.isdigit() and 0 <= int(payload) <= 100, FIRST_POLL_TIMEOUT_S
    )
    assert battery is not None, "no battery level reached the broker"
    link = broker.wait(held_topics.link, lambda payload: payload == "ON", LINK_TIMEOUT_S)
    assert link is not None, "the link never reported ON"
    retained = broker.retained(f"latchkey/{connected.board}/{held_topics.lock}/+")
    for topic in (held_topics.state, held_topics.battery, held_topics.link):
        kept = topic in retained
        assert kept, "a state topic is not retained"
    print(f"state {retained[held_topics.state]} battery {retained[held_topics.battery]}", file=sys.stderr)


def test_unlock_and_lock_from_mqtt_move_the_lock(
    console: Console, broker: Broker, connected: Session, held: dict[str, Any], held_topics: LockTopics
) -> None:
    seq = last_audit_seq(console)
    mark = broker.mark()
    broker.publish(held_topics.command, "UNLOCK")
    try:
        unlocked = broker.wait(held_topics.state, lambda payload: payload == "UNLOCKED", LOCK_TIMEOUT_S, mark)
        assert unlocked is not None, "the lock state did not follow UNLOCK"
        entry = wait_audit(console, seq, "lock.unlock", 10.0)
        assert entry is not None, "UNLOCK was not audited"
        assert entry["source"] == "mqtt"
        assert entry["result"] == "ok"
        same = entry["target"] == held["id"]
        assert same, "the audit entry names another lock"
        event = broker.wait(held_topics.last_event, lambda payload: payload == "Unlocked from the app", 10.0, mark)
        assert event is not None, "the last event did not follow UNLOCK"
    finally:
        mark = broker.mark()
        seq = last_audit_seq(console)
        broker.publish(held_topics.command, "LOCK")
        entry = wait_audit(console, seq, "lock.lock", LOCK_TIMEOUT_S)
        if entry is None or entry["result"] != "ok":
            console.call("lock.lock", {"lock": held["id"]}, timeout=LOCK_TIMEOUT_S)
    assert entry is not None, "LOCK was not audited"
    assert entry["source"] == "mqtt"
    assert entry["result"] == "ok"
    locked = broker.wait(held_topics.state, lambda payload: payload == "LOCKED", 10.0, mark)
    assert locked is not None, "the lock state did not follow LOCK"
    event = broker.wait(held_topics.last_event, lambda payload: payload == "Locked from the app", 10.0, mark)
    assert event is not None, "the last event did not follow LOCK"


def test_extra_commands_for_a_lock_are_refused_and_counted(
    console: Console, broker: Broker, connected: Session, held: dict[str, Any], held_topics: LockTopics
) -> None:
    seq = last_audit_seq(console)
    for _ in range(1 + EXTRA_COMMANDS):
        broker.publish(held_topics.command, "LOCK")
    ran = wait_audit(console, seq, "lock.lock", LOCK_TIMEOUT_S)
    assert ran is not None and ran["source"] == "mqtt" and ran["result"] == "ok"
    deadline = time.monotonic() + REFUSAL_WINDOW_S + 15.0
    while refused_count(audit_since(console, seq)) < EXTRA_COMMANDS and time.monotonic() < deadline:
        time.sleep(2.0)
    entries = audit_since(console, seq)
    assert refused_count(entries) == EXTRA_COMMANDS
    refusals = [entry for entry in entries if entry["method"] == "mqtt.command"]
    assert 1 <= len(refusals) <= 2
    assert all(entry["source"] == "mqtt" and entry["target"] == "" for entry in refusals)
    assert [entry["method"] for entry in entries].count("lock.lock") == 1
    stacks = console.call("system.info")["stackFree"]
    print(f"after the refused commands: stackFree mqtt={stacks['mqtt']}", file=sys.stderr)
    assert stacks["mqtt"] >= MIN_STACK_FREE


def test_a_command_for_a_lock_the_board_does_not_hold_is_not_received(
    console: Console, broker: Broker, connected: Session
) -> None:
    seq = last_audit_seq(console)
    seen = len(console.lines)
    broker.publish(lock_topics(connected, DOCUMENTATION_LOCK).command, "LOCK")
    time.sleep(QUIET_S)
    console.call("system.info")
    assert audit_since(console, seq) == []
    heard = any(COMMAND_LINE.search(line) or IGNORED_LINE.search(line) for line in console.lines[seen:])
    assert not heard, "the board took a command for a lock it does not hold"


def test_an_unknown_payload_is_ignored_and_logged(
    console: Console, broker: Broker, connected: Session, held_topics: LockTopics
) -> None:
    seq = last_audit_seq(console)
    seen = len(console.lines)
    broker.publish(held_topics.command, "OPEN")
    time.sleep(QUIET_S)
    console.call("system.info")
    assert audit_since(console, seq) == []
    assert any(IGNORED_LINE.search(line) for line in console.lines[seen:]), "the ignored payload was not logged"


def test_a_retained_command_does_not_run_again_on_reconnect(
    console: Console, broker: Broker, connected: Session, held_topics: LockTopics, broker_settings: dict[str, Any]
) -> None:
    seq = last_audit_seq(console)
    broker.publish(held_topics.command, "LOCK", retain=True)
    try:
        live = wait_audit(console, seq, "lock.lock", LOCK_TIMEOUT_S)
        assert live is not None, "a command published with the retain flag was not run when it arrived"
        seq = last_audit_seq(console)
        seen = len(console.lines)
        reapply(console, settings_for(broker_settings))
        time.sleep(QUIET_S)
        console.call("system.info")
        assert [entry["method"] for entry in audit_since(console, seq)] == ["mqtt.set"]
        assert any(IGNORED_LINE.search(line) for line in console.lines[seen:]), "the replayed command was not logged"
    finally:
        broker.publish(held_topics.command, "", retain=True)


def test_a_lock_the_board_does_not_hold_loses_its_configs_and_state(broker: Broker, connected: Session) -> None:
    stale = lock_topics(connected, DOCUMENTATION_LOCK)
    config = config_topic(connected, "lock", DOCUMENTATION_LOCK, "")
    broker.publish(stale.state, "LOCKED", retain=True)
    mark = broker.mark()
    broker.publish(config, json.dumps({"name": None, "unique_id": "latchkey_hil_stale"}), retain=True)
    emptied = broker.wait(config, lambda payload: payload == "", 15.0, mark)
    assert emptied is not None, "the board did not remove the stale config"
    cleared = broker.wait(stale.state, lambda payload: payload == "", 15.0, mark)
    assert cleared is not None, "the board did not clear the stale lock's state"
    left = set(broker.retained(f"{TEST_PREFIX}/+/{connected.board}/#")) | set(
        broker.retained(f"latchkey/{connected.board}/{DOCUMENTATION_LOCK}/+")
    )
    assert config not in left
    assert stale.state not in left


def test_a_new_prefix_removes_the_old_configs(
    console: Console, broker: Broker, connected: Session, held_topics: LockTopics, broker_settings: dict[str, Any]
) -> None:
    old = config_topics(connected, held_topics.lock)
    new = config_topics(connected, held_topics.lock, SECOND_PREFIX)
    try:
        reapply(console, settings_for(broker_settings, prefix=SECOND_PREFIX))
        time.sleep(QUIET_S)
        moved = set(broker.retained(f"{SECOND_PREFIX}/+/{connected.board}/#"))
        left = set(broker.retained(f"{TEST_PREFIX}/+/{connected.board}/#"))
        assert all(topic in moved for topic in new), "the configs are missing under the new prefix"
        assert not any(topic in left for topic in old), "configs are left under the old prefix"
    finally:
        reapply(console, settings_for(broker_settings))
    time.sleep(QUIET_S)
    assert not set(broker.retained(f"{SECOND_PREFIX}/+/{connected.board}/#")) & set(new)


def test_the_password_stays_only_with_its_broker(
    console: Console, connected: Session, broker_settings: dict[str, Any]
) -> None:
    try:
        moved = console.call("mqtt.set", settings_for(broker_settings, enabled=False, host=UNRESOLVABLE_HOST))
        assert moved["passwordSet"] is False
        back = console.call("mqtt.set", settings_for(broker_settings, enabled=False))
        assert back["passwordSet"] is False
    finally:
        view = reapply(console, settings_for(broker_settings, password=broker_settings["password"]))
    assert view["passwordSet"] is True


def test_a_lost_broker_is_retried_with_a_growing_wait(
    console: Console, connected: Session, broker_settings: dict[str, Any]
) -> None:
    try:
        seen = len(console.lines)
        console.call("mqtt.set", settings_for(broker_settings, password=WRONG_PASSWORD))
        waits = []
        while len(waits) < 3:
            index, match = wait_line(console, RETRY_LINE, seen, 30.0, "a retry after the refused login")
            assert match.group("why") == REFUSED_LOGIN
            waits.append(int(match.group("wait")))
            seen = index + 1
        assert waits == [1, 2, 4]
        view = console.call("mqtt.get")
        assert view["connected"] is False
        assert view["problem"] == REFUSED_LOGIN
        for host in (UNRESOLVABLE_HOST, UNROUTABLE_HOST):
            seen = len(console.lines)
            console.call("mqtt.set", settings_for(broker_settings, host=host, password=WRONG_PASSWORD))
            _, match = wait_line(console, RETRY_LINE, seen, 30.0, f"a retry after {host}")
            assert match.group("why") == UNREACHABLE
            assert match.group("wait") == "1"
            assert console.call("mqtt.get")["problem"] == UNREACHABLE
    finally:
        reapply(console, settings_for(broker_settings, password=broker_settings["password"]))
    stacks = console.call("system.info")["stackFree"]
    print(f"after the lost broker: stackFree mqtt={stacks['mqtt']} mqttClient={stacks['mqttClient']}", file=sys.stderr)
    assert stacks["mqtt"] >= MIN_STACK_FREE
    assert stacks["mqttClient"] >= MIN_STACK_FREE


def test_heap_holds_with_mqtt_connected(
    console: Console, connected: Session, secrets: dict[str, Any], board_settings: dict[str, Any]
) -> None:
    console.call("locks.scan", {"seconds": 10}, timeout=30.0)
    relay_settings = secrets.get("hil_relay")
    if relay_settings:
        timeout_s = int(relay_settings.get("timeout_s", 150))
        relay = Relay(list(relay_settings["command"]), timeout_s, board_settings["static_ip"])
        pages = relay.run([{"type": "http", "path": "/"}] * WEB_PAGE_LOADS, timeout_s=120)
        loaded = [page.get("status") for page in pages] == [200] * WEB_PAGE_LOADS
        assert loaded, [page.get("error") for page in pages]
    info = console.call("system.info")
    heap = info["heap"]
    stacks = info["stackFree"]
    print(
        f"heap free={heap['free']} minFree={heap['minFree']} largestBlock={heap['largestBlock']} "
        f"stackFree mqtt={stacks['mqtt']} mqttClient={stacks['mqttClient']} web pages={bool(relay_settings)}",
        file=sys.stderr,
    )
    assert heap["minFree"] >= MIN_FREE_HEAP
    assert heap["largestBlock"] > 16_384
    assert stacks["mqtt"] >= MIN_STACK_FREE
    assert stacks["mqttClient"] >= MIN_STACK_FREE


def test_a_restart_sends_the_last_will_then_online(console: Console, broker: Broker, connected: Session) -> None:
    mark = broker.mark()
    seen = len(console.lines)
    console.call_and_wait_restart("system.reboot")
    wait_connected(console, seen, RESTART_TIMEOUT_S)
    online = broker.wait(connected.availability, lambda payload: payload == "online", RESTART_TIMEOUT_S, mark)
    assert online is not None, "the board did not come back online"
    payloads = [message.payload for message in broker.since(mark, connected.availability)]
    assert "offline" in payloads, "the broker did not publish the last will"
    assert "online" in payloads[payloads.index("offline") :]
    assert payloads[-1] == "online"
    set_clock(console)


def test_no_secret_reaches_the_console_or_the_audit(
    console: Console, connected: Session, broker_settings: dict[str, Any]
) -> None:
    password = broker_settings["password"]
    leaked = any(password in line for line in console.lines) or password in json.dumps(console.events)
    assert not leaked, "the console printed the MQTT password"
    leaked = password in json.dumps(console.call("audit.list", {"limit": AUDIT_PAGE})["entries"])
    assert not leaked, "an audit entry holds the MQTT password"
    leaked = password in json.dumps(console.call("mqtt.get"))
    assert not leaked, "mqtt.get returned the MQTT password"


def test_turning_mqtt_off_leaves_the_board_offline(
    console: Console, broker: Broker, connected: Session, broker_settings: dict[str, Any]
) -> None:
    mark = broker.mark()
    view = console.call("mqtt.set", settings_for(broker_settings, enabled=False))
    assert view["enabled"] is False
    assert view["passwordSet"] is True
    assert view["connected"] is False
    offline = broker.wait(connected.availability, lambda payload: payload == "offline", 15.0, mark)
    assert offline is not None, "the board did not publish offline"
    time.sleep(QUIET_S)
    assert [message.payload for message in broker.since(mark, connected.availability)] == ["offline"]
    held = broker.retained(connected.availability)
    stays_offline = held.get(connected.availability) == "offline"
    assert stays_offline, "the retained availability is not offline"


def test_a_board_factory_reset_removes_its_entities(
    console: Console,
    broker: Broker,
    connected: Session,
    secrets: dict[str, Any],
    board_settings: dict[str, Any],
    broker_settings: dict[str, Any],
) -> None:
    if board_settings.get("totp_uri"):
        pytest.skip("the owner holds this board's login (totp_uri in secrets.local.json): no factory reset")
    if console.call("locks.list")["locks"]:
        pytest.skip("the board holds lock keys, which a factory reset would erase")
    reapply(console, settings_for(broker_settings, password=broker_settings["password"]))
    present = connected.availability in broker.retained(connected.availability)
    assert present, "the board's availability is not retained before the reset"
    board_name = console.call("system.info")["board"]
    console.call_and_wait_restart("system.factoryReset")
    try:
        left = broker.retained(connected.availability)
        assert connected.availability not in left, "the reset left the board's availability on the broker"
        assert console.call("mqtt.get")["enabled"] is False
    finally:
        claim_secret(console, secrets, board_settings, board_name)
        console.wait_info(lambda state: state["wifi"]["connected"], CONNECT_TIMEOUT_S, "Wi-Fi to connect")
        set_clock(console)
