// Minimal type shim kept for compatibility. The backend now defines the
// data shapes. Keep lightweight types to satisfy imports.

export type Json = string | number | boolean | null | { [key: string]: Json } | Json[];

export type Profile = {
  user_id: string;
  username: string;
  avatar_url?: string;
  created_at?: string;
  roles?: string[];
};

export type Message = {
  id: string;
  content: string;
  user_id: string;
  created_at: string;
  is_abusive?: boolean;
  abuse_score?: number;
  abuse_type?: string | null;
  severity?: string;
  emotions?: Json;
  profiles?: Profile;
};

export type Database = { public: { Tables: { messages: Message; profiles: Profile } } };

