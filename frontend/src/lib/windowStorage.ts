// Lightweight IndexedDB-backed window.storage polyfill.
// Exposes async getItem/setItem/removeItem and message-specific helpers.
// This file is imported once by components that need persistent storage.

type KV = { key: string; value: string };

const DB_NAME = 'emotion-shield-storage';
const DB_VERSION = 1;

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('kv')) {
        db.createObjectStore('kv', { keyPath: 'key' });
      }
      if (!db.objectStoreNames.contains('messages')) {
        const store = db.createObjectStore('messages', { keyPath: 'id' });
        store.createIndex('conversation_id', 'conversation_id', { unique: false });
        store.createIndex('created_at', 'created_at', { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet<T = any>(storeName: string, key?: IDBValidKey): Promise<T | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const req = key !== undefined ? store.get(key) : store.getAll();
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

async function idbPut(storeName: string, value: any): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    const req = store.put(value);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

async function idbDelete(storeName: string, key: IDBValidKey): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    const req = store.delete(key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

async function idbGetByIndex(storeName: string, index: string, value: any): Promise<any[]> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const ix = store.index(index);
    const request = ix.getAll(value);
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(request.error);
  });
}

// Attach a simple API to window.storage
declare global {
  interface Window {
    storage: {
      getItem: (key: string) => Promise<string | null>;
      setItem: (key: string, value: string) => Promise<void>;
      removeItem: (key: string) => Promise<void>;
      clear: () => Promise<void>;
      // message helpers
      saveMessage: (msg: any) => Promise<void>;
      removeMessage: (id: string) => Promise<void>;
      getMessagesByConversation: (conversation_id: string) => Promise<any[]>;
      getAllMessages: () => Promise<any[]>;
      clearConversation: (conversation_id: string) => Promise<void>;
    };
  }
}

window.storage = {
  async getItem(key: string) {
    const row = (await idbGet<KV>('kv', key)) as KV | null;
    return row ? row.value : null;
  },
  async setItem(key: string, value: string) {
    await idbPut('kv', { key, value });
  },
  async removeItem(key: string) {
    await idbDelete('kv', key);
  },
  async clear() {
    const db = await openDB();
    return new Promise<void>((resolve, reject) => {
      const tx = db.transaction(['kv', 'messages'], 'readwrite');
      tx.objectStore('kv').clear();
      tx.objectStore('messages').clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },
  async saveMessage(msg: any) {
    if (!msg || !msg.id) return;
    await idbPut('messages', msg);
  },
  async removeMessage(id: string) {
    if (!id) return;
    await idbDelete('messages', id);
  },
  async getMessagesByConversation(conversation_id: string) {
    if (!conversation_id) return [];
    const rows = await idbGetByIndex('messages', 'conversation_id', conversation_id);
    // sort chronologically
    rows.sort((a: any, b: any) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
    return rows;
  },
  async getAllMessages() {
    const rows = (await idbGet<any[]>('messages')) || [];
    rows.sort((a: any, b: any) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
    return rows;
  },
  async clearConversation(conversation_id: string) {
    if (!conversation_id) return;
    const db = await openDB();
    return new Promise<void>((resolve, reject) => {
      const tx = db.transaction('messages', 'readwrite');
      const store = tx.objectStore('messages');
      const index = store.index('conversation_id');
      const req = index.openCursor(IDBKeyRange.only(conversation_id));
      req.onsuccess = () => {
        const cursor = req.result;
        if (cursor) {
          cursor.delete();
          cursor.continue();
        }
      };
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },
};

export {};
