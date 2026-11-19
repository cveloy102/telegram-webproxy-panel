/// <reference path="../pb_data/types.d.ts" />

// Collection "items": one row per record of the app (task, purchase, link or thought).
// Fields mirror the app's JSON format; "updatedAt" is the client's edit time (ms) used to pick the newest edit,
// "purged" marks a record deleted for good so other devices remove it too.
migrate((app) => {
  const users = app.findCollectionByNameOrId("users");
  const own = "owner = @request.auth.id";
  const items = new Collection({
    type: "base",
    name: "items",
    listRule: own,
    viewRule: own,
    createRule: "@request.auth.id != '' && @request.body.owner = @request.auth.id",
    updateRule: own + " && (@request.body.owner:isset = false || @request.body.owner = @request.auth.id)",
    deleteRule: own,
    fields: [
      { name: "owner", type: "relation", required: true, collectionId: users.id, maxSelect: 1, cascadeDelete: true },
      { name: "itemId", type: "text", required: true, min: 1, max: 64 },
      { name: "title", type: "text", max: 10000 },
      { name: "list", type: "select", maxSelect: 1, values: ["tasks", "shopping", "links", "thoughts"] },
      { name: "createdAt", type: "number", onlyInt: true },
      { name: "updatedAt", type: "number", onlyInt: true },
      { name: "completed", type: "bool" },
      { name: "pinned", type: "bool" },
      { name: "reminderAt", type: "number", onlyInt: true },
      { name: "deletedAt", type: "number", onlyInt: true },
      { name: "snoozeUntil", type: "number", onlyInt: true },
      { name: "url", type: "text", max: 4000 },
      { name: "repeat", type: "select", maxSelect: 1, values: ["none", "daily", "weekly", "monthly"] },
      { name: "purged", type: "bool" },
      { name: "created", type: "autodate", onCreate: true, onUpdate: false },
      { name: "updated", type: "autodate", onCreate: true, onUpdate: true },
    ],
    indexes: [
      "CREATE UNIQUE INDEX idx_items_owner_item ON items (owner, itemId)",
      "CREATE INDEX idx_items_owner_updated ON items (owner, updated)",
    ],
  });
  app.save(items);

  const settings = app.settings();
  settings.meta.appName = "СВАЛКА sync";
  settings.backups.cron = "0 3 * * *";
  settings.backups.cronMaxKeep = 7;
  app.save(settings);
}, (app) => {
  app.delete(app.findCollectionByNameOrId("items"));
});
