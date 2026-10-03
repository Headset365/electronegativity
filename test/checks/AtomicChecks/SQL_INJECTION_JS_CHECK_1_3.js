// statements built from values: an IPC-supplied id, a concatenated name, a second-order value
const { ipcMain } = require('electron');
function getRecordModel(event, recordID) {
  return dbQuery(`SELECT * FROM tblRecords WHERE RecordID = ${recordID};`);
}
ipcMain.handle('record-import-model', getRecordModel);
function byName(name) { return db.prepare("SELECT id FROM users WHERE name = '" + name + "'").get(); }
async function detailInfo(contact) { return dbQuery(`SELECT * FROM tblDetails WHERE ContactID = ${contact.ContactID};`); }
// not reported: parameters, a tagged statement, a constant table name, plain text
function safe(id) { return db.prepare('SELECT * FROM notes WHERE id = ?').get(id); }
const tagged = (id) => sql`SELECT * FROM notes WHERE id = ${id}`;
const TABLE = 'notes';
const all = () => db.prepare(`SELECT * FROM ${TABLE}`).all();
const message = (n) => `Select ${n} files from the list`;
