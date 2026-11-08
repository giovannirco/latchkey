// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Generate test/vectors/kind3r_vectors.h by running the command classes of kind3r/ttlock-sdk-js (GPL-3.0).
 *
 * Run from the repository root with Deno 2.9.8 and a ttlock-sdk-js checkout at commit 8c84cda:
 *
 *     TZ=UTC deno run --allow-env --allow-read --allow-write=test/vectors \
 *         --config tools/vectors/kind3r_deno.json tools/vectors/kind3r_vectors.ts <ttlock-sdk-js>
 *
 * The config maps kind3r's bare `moment` and `crypto` imports (moment 2.29.1, locked in deno.lock) and turns on
 * sloppy imports for its extensionless paths.
 *
 * Every expected value is what kind3r's own `build()` or `processData()` produces. The inputs are synthetic.
 * `Date.now` and `Math.random` are replaced by deterministic stand-ins before any kind3r module loads, and the
 * run refuses any time zone but UTC, so a second run writes an identical file. Parsers are fed by setting
 * `commandResponse` and `commandData` on a constructed command and calling `processData()`: Deno emits class
 * fields with define semantics, which would reset what kind3r's base constructor parsed.
 *
 * Two inputs are kind3r's own published data: the passcode-list plaintext that `docs/Bad CRC quest.md` prints
 * (the factory passcode 123456), and the IC-card frame plus the key it was encrypted with from `tools/debug.js`,
 * checked and decrypted here by kind3r's `CodecUtils` and `AESUtil`.
 */

const FIXED_NOW_MS = 1762524000000;
const KIND3R_COMMIT = "8c84cda";

Date.now = () => FIXED_NOW_MS;

let randomState = 1;
function seedRandom(seed: number): void {
  randomState = seed;
}
Math.random = () => {
  randomState = (randomState * 1103515245 + 12345) % 2147483648;
  return randomState / 2147483648;
};

if (new Date(0).getTimezoneOffset() !== 0) {
  throw new Error("run with TZ=UTC");
}

const kind3rRoot = Deno.args[0];
if (!kind3rRoot) {
  throw new Error("usage: kind3r_vectors.ts <ttlock-sdk-js checkout>");
}

async function load(relative: string) {
  const path = `${kind3rRoot}/src/${relative}.ts`;
  return await import(new URL(`file://${Deno.realPathSync(path)}`).href);
}

const commands = {
  AddAdmin: (await load("api/Commands/AddAdminCommand")).AddAdminCommand,
  AesKey: (await load("api/Commands/AESKeyCommand")).AESKeyCommand,
  AudioManage: (await load("api/Commands/AudioManageCommand")).AudioManageCommand,
  AutoLockManage: (await load("api/Commands/AutoLockManageCommand")).AutoLockManageCommand,
  CalibrationTime: (await load("api/Commands/CalibrationTimeCommand")).CalibrationTimeCommand,
  CheckAdmin: (await load("api/Commands/CheckAdminCommand")).CheckAdminCommand,
  CheckRandom: (await load("api/Commands/CheckRandomCommand")).CheckRandomCommand,
  CheckUserTime: (await load("api/Commands/CheckUserTimeCommand")).CheckUserTimeCommand,
  ControlRemoteUnlock: (await load("api/Commands/ControlRemoteUnlockCommand")).ControlRemoteUnlockCommand,
  DeviceFeatures: (await load("api/Commands/DeviceFeaturesCommand")).DeviceFeaturesCommand,
  GetAdminCode: (await load("api/Commands/GetAdminCodeCommand")).GetAdminCodeCommand,
  GetKeyboardPasswords: (await load("api/Commands/GetKeyboardPasswordsCommand")).GetKeyboardPasswordsCommand,
  Init: (await load("api/Commands/InitCommand")).InitCommand,
  InitPasswords: (await load("api/Commands/InitPasswordsCommand")).InitPasswordsCommand,
  Lock: (await load("api/Commands/LockCommand")).LockCommand,
  ManageFR: (await load("api/Commands/ManageFRCommand")).ManageFRCommand,
  ManageIC: (await load("api/Commands/ManageICCommand")).ManageICCommand,
  ManageKeyboardPassword: (await load("api/Commands/ManageKeyboardPasswordCommand")).ManageKeyboardPasswordCommand,
  OperateFinished: (await load("api/Commands/OperateFinishedCommand")).OperateFinishedCommand,
  OperationLog: (await load("api/Commands/OperationLogCommand")).OperationLogCommand,
  PassageMode: (await load("api/Commands/PassageModeCommand")).PassageModeCommand,
  ReadDeviceInfo: (await load("api/Commands/ReadDeviceInfoCommand")).ReadDeviceInfoCommand,
  ResetLock: (await load("api/Commands/ResetLockCommand")).ResetLockCommand,
  ScreenPasscodeManage: (await load("api/Commands/ScreenPasscodeManageCommand")).ScreenPasscodeManageCommand,
  SearchBicycleStatus: (await load("api/Commands/SearchBicycleStatusCommand")).SearchBicycleStatusCommand,
  SetAdminKeyboardPwd: (await load("api/Commands/SetAdminKeyboardPwdCommand")).SetAdminKeyboardPwdCommand,
  Unlock: (await load("api/Commands/UnlockCommand")).UnlockCommand,
};
const { AESUtil } = await load("util/AESUtil");
const { CodecUtils } = await load("util/CodecUtils");
const { PassageModeOperate } = await load("constant/PassageModeOperate");

const lines: string[] = [];

function camel(name: string): string {
  return name
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
}

function emitBytes(name: string, data: Uint8Array): void {
  if (data.length === 0) {
    throw new Error(`${name} is empty`);
  }
  const values = Array.from(data, (byte) => `0x${byte.toString(16).padStart(2, "0")}`);
  const rows: string[] = [];
  for (let i = 0; i < values.length; i += 12) {
    rows.push(values.slice(i, i + 12).join(", "));
  }
  lines.push(`inline constexpr uint8_t k${camel(name)}[] = {\n    ${rows.join(",\n    ")},\n};`);
}

function emitNumber(name: string, type: string, value: number | bigint): void {
  const suffix = type === "uint64_t" ? "ULL" : "";
  lines.push(`inline constexpr ${type} k${camel(name)} = ${value.toString()}${suffix};`);
}

function emitString(name: string, value: string): void {
  if (!/^[0-9A-Za-z_:.-]*$/.test(value)) {
    throw new Error(`${name} needs escaping: ${value}`);
  }
  lines.push(`inline constexpr const char* k${camel(name)} = "${value}";`);
}

function built(command: { build(): Buffer }): Buffer {
  return Buffer.from(command.build());
}

function reply(commandType: number, data: number[]): Buffer {
  return Buffer.from([commandType, 0x01, ...data]);
}

function parsed(Command: new () => any, plain: Buffer): any {
  const command = new Command();
  command.commandResponse = plain.readInt8(1);
  command.commandData = plain.subarray(2);
  command.processData();
  return command;
}

function fromHex(hex: string): number[] {
  return Array.from(Buffer.from(hex, "hex"));
}

function section(_title: string): void {
  lines.push("");
}

section("core: handshake and pairing");
emitBytes("aes_key_request", built(new commands.AesKey()));
const addAdmin = new commands.AddAdmin();
emitNumber("add_admin_admin_ps", "uint32_t", addAdmin.setAdminPs(12345678));
emitNumber("add_admin_unlock_key", "uint32_t", addAdmin.setUnlockKey(87654321));
emitBytes("add_admin", built(addAdmin));
const checkAdmin = new commands.CheckAdmin();
checkAdmin.setParams(12345678);
emitBytes("check_admin", built(checkAdmin));
const checkRandom = new commands.CheckRandom();
checkRandom.setSum(0x01020304, 87654321);
emitBytes("check_random", built(checkRandom));
const checkUserTime = new commands.CheckUserTime();
checkUserTime.setPayload(0, "0001311400", "9911301400", 0);
emitBytes("check_user_time", built(checkUserTime));
const checkUserTimeFlag = new commands.CheckUserTime();
checkUserTimeFlag.setPayload(0, "0001311400", "9911301400", 0x123456);
emitBytes("check_user_time_flag", built(checkUserTimeFlag));
emitNumber("fixed_now_utc", "int64_t", FIXED_NOW_MS / 1000);
const unlock = new commands.Unlock();
unlock.setSum(0x0a0b0c0d, 87654321);
emitBytes("unlock", built(unlock));
const lock = new commands.Lock();
lock.setSum(0x0a0b0c0d, 87654321);
emitBytes("lock", built(lock));
emitBytes("calibrate_time", built(new commands.CalibrationTime()));
emitBytes("search_status", built(new commands.SearchBicycleStatus()));
for (const [name, item] of [["model", 1], ["hardware", 2], ["firmware", 3], ["manufacture_date", 4]] as const) {
  const read = new commands.ReadDeviceInfo();
  read.setInfoType(item);
  emitBytes(`read_device_info_${name}`, built(read));
}
const setAdmin = new commands.SetAdminKeyboardPwd();
setAdmin.setAdminPasscode("3141592");
emitBytes("set_admin_passcode", built(setAdmin));
emitString("set_admin_passcode_code", "3141592");
seedRandom(20251107);
const initPasswords = new commands.InitPasswords();
const initPayload = built(initPasswords);
const pwdInfo = initPasswords.getPwdInfo();
emitBytes("init_passwords", initPayload);
emitNumber("init_passwords_year", "uint8_t", initPayload[0]);
lines.push(
  `inline constexpr uint16_t kInitPasswordsCodes[] = {${
    pwdInfo.map((entry: { code: number }) => entry.code).join(", ")
  }};`,
);
lines.push(
  `inline constexpr uint64_t kInitPasswordsSecrets[] = {${
    pwdInfo.map((entry: { secret: string }) => `${BigInt(entry.secret)}ULL`).join(", ")
  }};`,
);
emitNumber("initialization_payload_size", "size_t", built(new commands.Init()).length);
emitNumber("operate_finished_payload_size", "size_t", built(new commands.OperateFinished()).length);
emitNumber("reset_lock_payload_size", "size_t", built(new commands.ResetLock()).length);
emitNumber("search_device_feature_payload_size", "size_t", built(new commands.DeviceFeatures()).length);
emitNumber("get_admin_code_payload_size", "size_t", built(new commands.GetAdminCode()).length);

section("core: replies");
const unlockReplyData = fromHex("5a000000000000002a190b070e0005");
const unlockReply = parsed(commands.Unlock, reply(0x47, unlockReplyData));
const unlockData = unlockReply.getUnlockData();
emitBytes("unlock_reply_data", Buffer.from(unlockReplyData));
emitNumber("unlock_reply_battery", "int", unlockData.batteryCapacity);
emitNumber("unlock_reply_uid", "uint32_t", unlockData.uid);
emitNumber("unlock_reply_unique_id", "uint32_t", unlockData.uniqueid);
emitString("unlock_reply_date_time", unlockData.dateTime);
const statusReplyData = [0x50, 0x01];
emitBytes("status_reply_data", Buffer.from(statusReplyData));
emitNumber(
  "status_reply_state",
  "int",
  parsed(commands.SearchBicycleStatus, reply(0x14, statusReplyData)).getLockStatus(),
);

section("passcodes");
const update = new commands.ManageKeyboardPassword();
if (!update.updatePasscode(3, "13579", "246810", "202511070900", "202512312359")) {
  throw new Error("updatePasscode rejected its input");
}
emitBytes("passcode_update", built(update));
const deletePasscode = new commands.ManageKeyboardPassword();
deletePasscode.deletePasscode(1, "13579");
emitBytes("passcode_delete", built(deletePasscode));
const clearPasscodes = new commands.ManageKeyboardPassword();
clearPasscodes.clearAllPasscodes();
emitBytes("passcode_clear", built(clearPasscodes));
for (const [name, sequence] of [["0", 0], ["b4", 0xb4]] as const) {
  const list = new commands.GetKeyboardPasswords();
  list.setSequence(sequence);
  emitBytes(`passcode_list_request_${name}`, built(list));
}
const passcodeCaptureData = fromHex("001700b4140106313233343536063132333435360001010000");
const passcodeCapture = parsed(commands.GetKeyboardPasswords, reply(0x07, passcodeCaptureData));
const capturedPasscodes = passcodeCapture.getPasscodes();
if (capturedPasscodes.length !== 1) {
  throw new Error("kind3r passcode capture should hold one passcode");
}
emitBytes("passcode_capture_data", Buffer.from(passcodeCaptureData));
emitNumber("passcode_capture_sequence", "int", passcodeCapture.getSequence());
emitNumber("passcode_capture_type", "int", capturedPasscodes[0].type);
emitString("passcode_capture_code", capturedPasscodes[0].newPassCode);
emitString("passcode_capture_start", capturedPasscodes[0].startDate);
const passcodeEndData = fromHex("0000");
const passcodeEnd = parsed(commands.GetKeyboardPasswords, reply(0x07, passcodeEndData));
emitNumber("passcode_end_sequence", "int", passcodeEnd.getSequence());
emitNumber("passcode_end_count", "size_t", passcodeEnd.getPasscodes().length);

section("ic cards");
for (const [name, sequence] of [["0", 0], ["258", 258]] as const) {
  const list = new commands.ManageIC();
  list.setSequence(sequence);
  emitBytes(`card_list_request_${name}`, built(list));
}
const cardAdd = new commands.ManageIC();
cardAdd.setAdd();
emitBytes("card_enroll_start", built(cardAdd));
const cardModify4 = new commands.ManageIC();
cardModify4.setModify("305419896", "202511070900", "202612312359");
emitBytes("card_set_validity_4", built(cardModify4));
const cardModify8 = new commands.ManageIC();
cardModify8.setModify("1234605616436508552", "202511070900", "202612312359");
emitBytes("card_set_validity_8", built(cardModify8));
const cardDelete = new commands.ManageIC();
cardDelete.setDelete("305419896");
emitBytes("card_delete_4", built(cardDelete));
const cardDelete8 = new commands.ManageIC();
cardDelete8.setDelete("1234605616436508552");
emitNumber("card_delete_8_kind3r_size", "size_t", built(cardDelete8).length);
const cardClear = new commands.ManageIC();
cardClear.setClear();
emitBytes("card_clear", built(cardClear));
const cardPageData = fromHex("5501000212345678190b0709001a0c1f173b");
const cardPage = parsed(commands.ManageIC, reply(0x05, cardPageData));
emitBytes("card_page_data", Buffer.from(cardPageData));
emitNumber("card_page_sequence", "int", cardPage.getSequence());
emitNumber("card_page_count", "size_t", cardPage.getCards().length);
emitString("card_page_number", cardPage.getCards()[0].cardNumber);
emitString("card_page_start", cardPage.getCards()[0].startDate);
emitString("card_page_end", cardPage.getCards()[0].endDate);
const cardAdded4Data = fromHex("55020112345678");
const cardAdded4 = parsed(commands.ManageIC, reply(0x05, cardAdded4Data));
emitBytes("card_added_4_data", Buffer.from(cardAdded4Data));
emitNumber("card_added_4_status", "int", cardAdded4.getType());
emitString("card_added_4_number", cardAdded4.getCardNumber());
const cardAdded8Data = fromHex("5502011122334455667788");
const cardAdded8 = parsed(commands.ManageIC, reply(0x05, cardAdded8Data));
emitBytes("card_added_8_data", Buffer.from(cardAdded8Data));
emitNumber("card_added_8_status", "int", cardAdded8.getType());
emitString("card_added_8_number", cardAdded8.getCardNumber());
const captureKey = Buffer.from("e817e962c7176c296403f646129f362c", "hex");
const captureFrame = Buffer.from("7f5a0503020001000154aa1095a3bd4703fde2b76397587b6ee44b7b28", "hex");
if (
  CodecUtils.crccompute(captureFrame.subarray(0, captureFrame.length - 1)) !== captureFrame[captureFrame.length - 1]
) {
  throw new Error("kind3r IC capture should pass its CRC");
}
const captureLength = captureFrame[11];
const capturePlain = AESUtil.aesDecrypt(captureFrame.subarray(12, 12 + captureLength), captureKey);
const captureCommand = parsed(commands.ManageIC, capturePlain);
emitBytes("card_capture_frame", captureFrame);
emitBytes("card_capture_key", captureKey);
emitBytes("card_capture_plain", capturePlain);
emitNumber("card_capture_response", "int", captureCommand.getResponse());
emitNumber("card_capture_status", "int", captureCommand.getType());
emitNumber("card_capture_battery", "int", captureCommand.getBatteryCapacity());

section("fingerprints");
const fingerprintList = new commands.ManageFR();
fingerprintList.setSequence(0);
emitBytes("fingerprint_list_request_0", built(fingerprintList));
const fingerprintAdd = new commands.ManageFR();
fingerprintAdd.setAdd();
emitBytes("fingerprint_enroll_start", built(fingerprintAdd));
const fingerprintModify = new commands.ManageFR();
fingerprintModify.setModify("1234567890123", "202511070900", "202612312359");
emitBytes("fingerprint_set_validity", built(fingerprintModify));
const fingerprintDelete = new commands.ManageFR();
fingerprintDelete.setDelete("1234567890123");
emitBytes("fingerprint_delete", built(fingerprintDelete));
const fingerprintClear = new commands.ManageFR();
fingerprintClear.setClear();
emitBytes("fingerprint_clear", built(fingerprintClear));
const fingerprintPageData = fromHex("64060001011f71fb04cb190b0709001a0c1f173b");
const fingerprintPage = parsed(commands.ManageFR, reply(0x06, fingerprintPageData));
emitBytes("fingerprint_page_data", Buffer.from(fingerprintPageData));
emitNumber("fingerprint_page_sequence", "int", fingerprintPage.getSequence());
emitNumber("fingerprint_page_count", "size_t", fingerprintPage.getFingerprints().length);
emitString("fingerprint_page_number", fingerprintPage.getFingerprints()[0].fpNumber);
emitString("fingerprint_page_start", fingerprintPage.getFingerprints()[0].startDate);
emitString("fingerprint_page_end", fingerprintPage.getFingerprints()[0].endDate);
for (const [name, hex] of [["waiting", "640202"], ["progress", "640203"], ["added", "640201011f71fb04cb"]] as const) {
  const data = fromHex(hex);
  const enrollReply = parsed(commands.ManageFR, reply(0x06, data));
  emitBytes(`fingerprint_${name}_data`, Buffer.from(data));
  emitNumber(`fingerprint_${name}_status`, "int", enrollReply.getType());
  if (name === "added") {
    emitString("fingerprint_added_number", enrollReply.getFpNumber());
  }
}

section("passage mode");
const passageQuery = new commands.PassageMode();
passageQuery.setSequence(0);
emitBytes("passage_query_0", built(passageQuery));
const passageData = { type: 1, weekOrDay: 5, month: 0, startHour: "0800", endHour: "1730" };
const passageAdd = new commands.PassageMode();
passageAdd.setData(passageData, PassageModeOperate.ADD);
emitBytes("passage_add", built(passageAdd));
const passageDelete = new commands.PassageMode();
passageDelete.setData(passageData, PassageModeOperate.DELETE);
emitBytes("passage_delete", built(passageDelete));
const passageClear = new commands.PassageMode();
passageClear.setClear();
emitBytes("passage_clear", built(passageClear));
const passagePageData = fromHex("5a01ff0105000800111e");
const passagePage = parsed(commands.PassageMode, reply(0x66, passagePageData));
const passageEntries = passagePage.getData();
emitBytes("passage_page_data", Buffer.from(passagePageData));
emitNumber("passage_page_sequence", "int", passagePage.getSequence());
emitNumber("passage_page_count", "size_t", passageEntries.length);
emitNumber("passage_page_type", "int", passageEntries[0].type);
emitNumber("passage_page_week_or_day", "int", passageEntries[0].weekOrDay);
emitNumber("passage_page_month", "int", passageEntries[0].month);
emitString("passage_page_start", passageEntries[0].startHour);
emitString("passage_page_end", passageEntries[0].endHour);

section("settings");
emitBytes("sound_query", built(new commands.AudioManage()));
const soundOn = new commands.AudioManage();
soundOn.setNewValue(1);
emitBytes("sound_on", built(soundOn));
const soundOff = new commands.AudioManage();
soundOff.setNewValue(0);
emitBytes("sound_off", built(soundOff));
const soundReplyData = [0x5a, 0x01, 0x01];
const soundReply = parsed(commands.AudioManage, reply(0x62, soundReplyData));
emitBytes("sound_reply_data", Buffer.from(soundReplyData));
emitNumber("sound_reply_value", "int", soundReply.getValue());
emitNumber("sound_reply_battery", "int", soundReply.getBatteryCapacity());
emitBytes("auto_lock_query", built(new commands.AutoLockManage()));
const autoLockSet = new commands.AutoLockManage();
autoLockSet.setTime(300);
emitBytes("auto_lock_set_300", built(autoLockSet));
const autoLockReplyData = fromHex("5a01001e000500b4");
const autoLockReply = parsed(commands.AutoLockManage, reply(0x36, autoLockReplyData));
emitBytes("auto_lock_reply_data", Buffer.from(autoLockReplyData));
emitNumber("auto_lock_reply_seconds", "int", autoLockReply.getTime());
emitBytes("remote_unlock_query", built(new commands.ControlRemoteUnlock()));
const remoteOn = new commands.ControlRemoteUnlock();
remoteOn.setNewValue(1);
emitBytes("remote_unlock_on", built(remoteOn));
const remoteOff = new commands.ControlRemoteUnlock();
remoteOff.setNewValue(0);
emitBytes("remote_unlock_off", built(remoteOff));
const remoteReplyData = [0x5a, 0x01, 0x01];
const remoteReply = parsed(commands.ControlRemoteUnlock, reply(0x37, remoteReplyData));
emitBytes("remote_unlock_reply_data", Buffer.from(remoteReplyData));
emitNumber("remote_unlock_reply_value", "int", remoteReply.getValue());
emitBytes("screen_passcode_query", built(new commands.ScreenPasscodeManage()));

section("operation log");
const logNew = new commands.OperationLog();
logNew.setSequence(0xffff);
emitBytes("log_request_new", built(logNew));
const logFive = new commands.OperationLog();
logFive.setSequence(5);
emitBytes("log_request_5", built(logFive));
const logPageData = fromHex("001300051001190b070e00055a000000000000002a");
const logPage = parsed(commands.OperationLog, reply(0x25, logPageData));
const logs = logPage.getLogs();
emitBytes("log_page_data", Buffer.from(logPageData));
emitNumber("log_page_sequence", "int", logPage.getSequence());
emitNumber("log_page_count", "size_t", logs.length);
emitNumber("log_page_record_number", "int", logs[0].recordNumber);
emitNumber("log_page_record_type", "int", logs[0].recordType);
emitString("log_page_operate_date", logs[0].operateDate);
emitNumber("log_page_battery", "int", logs[0].electricQuantity);
emitNumber("log_page_uid", "uint32_t", logs[0].uid);
emitNumber("log_page_record_id", "uint32_t", logs[0].recordId);

const header = [
  "// SPDX-License-Identifier: GPL-3.0-or-later",
  `// Generated by tools/vectors/kind3r_vectors.ts from kind3r/ttlock-sdk-js ${KIND3R_COMMIT}. Do not edit.`,
  "#pragma once",
  "",
  "#include <cstddef>",
  "#include <cstdint>",
  "",
  "namespace vectors::kind3r {",
];
const footer = ["", "}  // namespace vectors::kind3r", ""];
const text = [...header, ...lines, ...footer].join("\n");
const outPath = "test/vectors/kind3r_vectors.h";
Deno.writeTextFileSync(outPath, text);
console.log(`wrote ${outPath}`);
