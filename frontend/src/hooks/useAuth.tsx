import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';

// This Auth provider now talks to the new backend API (./backend) over /api/auth/*

interface AuthContextType {
  user: { id: string; email?: string } | null;
  session: { token?: string } | null;
  signIn: (email: string, password: string) => Promise<{ error?: string | null }>;
  signUp: (email: string, password: string, username: string) => Promise<{ error?: string | null }>;
  signOut: () => Promise<void>;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<{ id: string; email?: string } | null>(null);
  const [session, setSession] = useState<{ token?: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    // Load session from window.storage token (backend JWT)
    (async () => {
      try {
        const token = await window.storage.getItem('token');
        if (!token) {
          setLoading(false);
          return;
        }

        const res = await fetch('/api/auth/session', { headers: { Authorization: `Bearer ${token}` } });
        const data = await res.json();
        if (data?.user) {
          setUser(data.user);
          setSession({ token });
        } else {
          // token invalid — clear
          await window.storage.removeItem('token');
        }
      } catch (e) {
        console.debug('Auto-login failed', e);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const signIn = async (email: string, password: string) => {
    try {
      const res = await fetch('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (data?.token) {
        await window.storage.setItem('token', data.token);
        setUser(data.user);
        navigate('/');
        return { error: null };
      }
      return { error: data?.error || 'Sign in failed' };
    } catch (err) {
      return { error: err instanceof Error ? err.message : String(err) };
    }
  };

  const signUp = async (email: string, password: string, username: string) => {
    try {
      const res = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, username }),
      });
      const data = await res.json();
      // Do NOT auto-sign-in the user after signup. Require explicit sign-in for better UX/security.
      // Return success if the backend accepted the signup (even if it returned a token).
      if (data?.token || data?.user) {
        return { error: null };
      }
      return { error: data?.error || 'Sign up failed' };
    } catch (err) {
      return { error: err instanceof Error ? err.message : String(err) };
    }
  };

  const signOut = async () => {
    try {
      await window.storage.removeItem('token');
    } catch (e) {
      console.debug('Failed to remove token from storage', e);
    }
    setUser(null);
    setSession(null);
    navigate('/auth');
  };

  return (
    <AuthContext.Provider value={{ user, session, signIn, signUp, signOut, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
