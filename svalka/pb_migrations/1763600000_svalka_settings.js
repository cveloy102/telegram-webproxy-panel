/// <reference path="../pb_data/types.d.ts" />

// Collection "svalka_settings": server-wide switches kept in the database, so they travel with backups
// and can be changed by the owner (superuser) through the API, for example from a server panel.
//   signup   — "true" / "false": may the apps create accounts themselves
//   instance — random id; a restore from a backup gives it a new value (PocketBase restore: pb_hooks;
//              panel restore: restore.py; by hand: svalka-sync.sh new-instance), and the apps then compare
//              all their records with the server once, so edits newer than the backup are not lost.
migrate((app) => {
  const settings = new Collection({
    type: "base",
    name: "svalka_settings",
    listRule: null,
    viewRule: null,
    createRule: null,
    updateRule: null,
    deleteRule: null,
    fields: [
      { name: "key", type: "text", required: true, min: 1, max: 64 },
      { name: "value", type: "text", max: 256 },
    ],
    indexes: ["CREATE UNIQUE INDEX idx_svalka_settings_key ON svalka_settings (key)"],
  });
  app.save(settings);

  const put = (key, value) => {
    const record = new Record(settings);
    record.set("key", key);
    record.set("value", value);
    app.save(record);
  };
  put("signup", $os.getenv("SVALKA_ALLOW_SIGNUP") === "true" ? "true" : "false");
  put("instance", $security.randomString(16));
}, (app) => {
  app.delete(app.findCollectionByNameOrId("svalka_settings"));
});
