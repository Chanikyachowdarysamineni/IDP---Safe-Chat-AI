/* eslint-disable @typescript-eslint/no-explicit-any */
// Lightweight compatibility shim for legacy Supabase imports.
// The app has been migrated to use the local backend API (/api/*).
// This shim maps a small subset of the Supabase client API to backend endpoints
// so older imports won't crash while the migration completes.

type AnyObj = Record<string, any>;

const buildFrom = (table: string) => ({
  select: async (_q?: string) => {
    const res = await fetch(`/api/${table}${_q && _q.includes('user_id') ? `?${_q}` : ''}`);
    const json = await res.json();
    return { data: json.data, error: null } as AnyObj;
  },
    insert: async (payload: AnyObj) => {
    const token = await window.storage.getItem('token');
    const res = await fetch(`/api/${table}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    return { data: json.data, error: res.ok ? null : json.error } as AnyObj;
  },
    update: async (payload: AnyObj) => {
    // naive: maps to PUT on profiles
    if (table === 'profiles') {
      const token = await window.storage.getItem('token');
      const res = await fetch(`/api/profiles/${payload.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify(payload),
      });
      const json = await res.json();
      return { data: json, error: res.ok ? null : json.error } as AnyObj;
    }
    return { data: null, error: 'not implemented' } as AnyObj;
  },
  delete: async () => ({ data: null, error: 'not implemented' }),
  eq: () => ({ select: async () => ({ data: [], error: null }) }),
});

export const supabase = {
  from: (table: string) => buildFrom(table),
  // Realtime channel shim: no-op subscribe
  channel: (_name: string) => ({
    on: () => ({ subscribe: async () => ({}) }),
  }),
  removeChannel: (_c: any) => {},
  auth: {
    signInWithPassword: async ({ email, password }: AnyObj) => {
      const res = await fetch('/api/auth/signin', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
      const json = await res.json();
      if (json.token) await window.storage.setItem('token', json.token);
      return { data: json, error: json.error || null };
    },
    signUp: async ({ email, password, options }: AnyObj) => {
      const username = options?.data?.username || email.split('@')[0];
      const res = await fetch('/api/auth/signup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password, username }) });
      const json = await res.json();
      if (json.token) await window.storage.setItem('token', json.token);
      return { data: json, error: json.error || null };
    },
    signOut: async () => {
      await window.storage.removeItem('token');
      return { error: null };
    },
    getSession: async () => {
      const token = await window.storage.getItem('token');
      if (!token) return { data: { session: null } };
      const res = await fetch('/api/auth/session', { headers: { Authorization: `Bearer ${token}` } });
      const json = await res.json();
      return { data: { session: json.user || null } };
    },
    onAuthStateChange: (_cb: any) => ({ data: { subscription: { unsubscribe: () => {} } } }),
  },
};
