/// <reference path="../pb_data/types.d.ts" />

// Note: every handler runs in its own isolated context, so the small settings lookup is repeated inline.

// Registration from the apps is open only when the "signup" setting is "true" (or, before that setting
// exists, when SVALKA_ALLOW_SIGNUP=true). The server owner (superuser) can always create accounts.
onRecordCreateRequest((e) => {
  let value = "";
  try { value = $app.findFirstRecordByData("svalka_settings", "key", "signup").getString("value"); } catch (_) {}
  const open = value ? value === "true" : $os.getenv("SVALKA_ALLOW_SIGNUP") === "true";
  if (!open && !e.hasSuperuserAuth()) {
    throw new ForbiddenError("Регистрация на этом сервере закрыта. Попроси владельца создать аккаунт.");
  }
  e.next();
}, "users");

// Lets the apps check that the address really is a СВАЛКА server, whether sign-up is open,
// and whether the server was restored from a backup since their last visit ("instance" changed).
routerAdd("GET", "/api/svalka/info", (e) => {
  const read = (key) => {
    try { return $app.findFirstRecordByData("svalka_settings", "key", key).getString("value"); } catch (_) { return ""; }
  };
  const signup = read("signup");
  return e.json(200, {
    app: "svalka-sync",
    version: 2,
    signup: signup ? signup === "true" : $os.getenv("SVALKA_ALLOW_SIGNUP") === "true",
    instance: read("instance"),
  });
});

// Never let an older edit overwrite a newer one (two devices editing the same record at once).
// A delete for good always goes through: it must reach every device even if its clock runs behind.
onRecordUpdateRequest((e) => {
  const before = e.record.original().getInt("updatedAt");
  const after = e.record.getInt("updatedAt");
  if (after < before && !e.record.getBool("purged")) {
    throw new ApiError(409, "На сервере более новая версия записи.");
  }
  e.next();
}, "items");

// PocketBase's own backup restore brings back the old "instance" value with the rest of the database, so the
// apps would not notice the restore and would never re-upload edits made after that backup. Mark the restore in
// the backups folder (the one folder a restore keeps) and give the restored database a new instance at the next
// start; PocketBase restarts itself right after a restore.
onBackupRestore((e) => {
  try { $os.writeFile(e.app.dataDir() + "/backups/.svalka-restored", e.name, 0o600); } catch (_) {}
  e.next();
});

onBootstrap((e) => {
  e.next();
  const marker = e.app.dataDir() + "/backups/.svalka-restored";
  try { $os.stat(marker); } catch (_) { return; }
  try {
    const record = e.app.findFirstRecordByData("svalka_settings", "key", "instance");
    record.set("value", $security.randomString(16));
    e.app.save(record);
    $os.remove(marker);
  } catch (err) {
    console.log("svalka: could not renew the instance after a restore:", err);
  }
});
