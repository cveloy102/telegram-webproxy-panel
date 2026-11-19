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
onRecordUpdateRequest((e) => {
  const before = e.record.original().getInt("updatedAt");
  const after = e.record.getInt("updatedAt");
  if (after < before) {
    throw new ApiError(409, "На сервере более новая версия записи.");
  }
  e.next();
}, "items");
