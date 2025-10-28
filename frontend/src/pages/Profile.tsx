import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
// Backend API used instead of Supabase
import { useAuth } from '../hooks/useAuth';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { useToast } from '../hooks/use-toast';
import { User, Home, Shield, MessageSquare } from 'lucide-react';

import { type ChangeEvent } from 'react';
import nacl from 'tweetnacl';
import { encodeBase64, decodeBase64 } from 'tweetnacl-util';

const Profile = () => {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [username, setUsername] = useState('');
  const [roles, setRoles] = useState<string[]>([]);
  const [messageStats, setMessageStats] = useState({ total: 0, flagged: 0 });
  const [loading, setLoading] = useState(true);
  const [publicKey, setPublicKey] = useState<string | null>(null);
  const [hasSecret, setHasSecret] = useState<boolean>(false);
  const [showImportForm, setShowImportForm] = useState(false);
  const [secretInput, setSecretInput] = useState('');
  const [importError, setImportError] = useState<string | null>(null);

  useEffect(() => {
    if (!user) {
      navigate('/auth');
      return;
    }
    fetchProfile();
    (async () => {
      try {
        const sec = await window.storage.getItem('e2ee_secret');
        setHasSecret(!!sec);
      } catch (e) {
        console.debug('could not read e2ee_secret', e);
      }
    })();
  }, [user]);

  const fetchProfile = async () => {
    if (!user) return;
    try {
  const token = await window.storage.getItem('token');
  const headers = token ? { Authorization: `Bearer ${token}` } : undefined;
      const base = ((import.meta as any).env?.VITE_BACKEND_URL as string) || 'http://localhost:4000';
      const profileRes = await fetch(`${base}/api/profiles/${user.id}`, { headers });
      const profileJson = await profileRes.json();
      if (profileJson.profile) setUsername(profileJson.profile.username || '');
      setPublicKey(profileJson.profile?.public_key || null);
  const rolesRes = await fetch(`${base}/api/user_roles/${user.id}`, { headers });
  const rolesJson = (await rolesRes.json()) as { roles?: string[] };
  setRoles(rolesJson.roles || ['user']);

      // messages
  const msgsRes = await fetch(`${base}/api/messages?user_id=${user.id}`, { headers });
  const msgsJson = (await msgsRes.json()) as { data?: Array<{ is_abusive?: boolean }> };
  const all = msgsJson.data || [];
  const flagged = all.filter((m) => m.is_abusive).length;
      setMessageStats({ total: all.length, flagged });
    } catch (err) {
      console.error('Profile fetch error', err);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateProfile = async () => {
    if (!user || !username.trim()) return;

    try {
      const token = await window.storage.getItem('token');
      const base = ((import.meta as any).env?.VITE_BACKEND_URL as string) || 'http://localhost:4000';
      const res = await fetch(`${base}/api/profiles/${user.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ username: username.trim() }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || 'Failed');
      toast({
        title: 'Profile Updated',
        description: 'Your username has been updated successfully.',
      });
      return;
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update profile.',
        variant: 'destructive',
      });
      return;
    }
  };

  const handleSignOut = async () => {
    await signOut();
    navigate('/');
  };

  const handleGenerateAndUploadKey = async () => {
    if (!user) return;
    try {
      const kp = nacl.box.keyPair();
      const pub = encodeBase64(kp.publicKey);
      const sec = encodeBase64(kp.secretKey);
      await window.storage.setItem('e2ee_pub', pub);
      await window.storage.setItem('e2ee_secret', sec);
      const token = await window.storage.getItem('token');
      const base = ((import.meta as any).env?.VITE_BACKEND_URL as string) || 'http://localhost:4000';
      const res = await fetch(`${base}/api/keys`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify({ public_key: pub }) });
      if (!res.ok) throw new Error('upload failed');
      setPublicKey(pub);
      toast({ title: 'E2EE Enabled', description: 'Your public key was uploaded.' });
    } catch (err) {
      console.error('upload key failed', err);
      toast({ title: 'Error', description: 'Failed to upload public key', variant: 'destructive' });
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <User className="w-8 h-8 text-primary" />
            <h1 className="text-2xl font-bold">Profile</h1>
          </div>
          <Button variant="outline" onClick={() => navigate('/')}>
            <Home className="w-4 h-4 mr-2" />
            Home
          </Button>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <div className="grid gap-6">
          {/* Profile Info */}
          <Card>
            <CardHeader>
              <CardTitle>Profile Information</CardTitle>
              <CardDescription>Update your personal details</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">Email</label>
                <Input value={user?.email || ''} disabled />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Username</label>
                <div className="flex gap-2">
                  <Input
                    value={username}
                    onChange={(e: ChangeEvent<HTMLInputElement>) => setUsername(e.target.value)}
                    placeholder="Enter username"
                  />
                  <Button onClick={handleUpdateProfile}>Update</Button>
                </div>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">End-to-end encryption</label>
                <div className="flex gap-2 items-center">
                  <div className="text-sm text-muted-foreground">{publicKey ? 'Public key uploaded' : 'No public key uploaded'}</div>
                  {!publicKey && (
                    <Button onClick={handleGenerateAndUploadKey}>Generate & Upload Key</Button>
                  )}
                  {publicKey && (
                    <Button variant="ghost" onClick={() => { navigator.clipboard?.writeText(publicKey); toast({ title: 'Copied', description: 'Public key copied to clipboard' }); }}>Copy Public Key</Button>
                  )}
                  {/* Secret key import/export controls */}
                  <div className="ml-4 flex items-center gap-2">
                    {hasSecret ? (
                      <>
                        <div className="text-sm text-muted-foreground">Private key present</div>
                        <Button variant="outline" onClick={async () => {
                          const sec = await window.storage.getItem('e2ee_secret');
                          if (!sec) { toast({ title: 'No secret', description: 'No secret key found', variant: 'destructive' }); return; }
                          await navigator.clipboard?.writeText(sec);
                          toast({ title: 'Copied', description: 'Private key copied to clipboard' });
                        }}>Export Secret</Button>
                        <Button variant="ghost" onClick={async () => {
                          await window.storage.removeItem('e2ee_secret');
                          setHasSecret(false);
                          toast({ title: 'Cleared', description: 'Private key removed from this browser' });
                        }}>Clear Secret</Button>
                      </>
                    ) : (
                      <>
                        {!showImportForm ? (
                          <Button variant="secondary" onClick={() => setShowImportForm(true)}>Import Secret</Button>
                        ) : (
                          <div className="flex items-start gap-2">
                            <textarea
                              className="border border-border rounded p-2 w-64 text-sm"
                              placeholder="Paste Base64 private key here"
                              value={secretInput}
                              onChange={(e) => { setSecretInput(e.target.value); setImportError(null); }}
                            />
                            <div className="flex flex-col gap-2">
                              <Button onClick={async () => {
                                try {
                                  const val = secretInput.trim();
                                  if (!val) { setImportError('Please paste a Base64 private key'); return; }
                                  let decoded: Uint8Array;
                                  try {
                                    decoded = decodeBase64(val);
                                  } catch (e) {
                                    setImportError('Invalid Base64');
                                    return;
                                  }
                                  if (!(decoded && decoded.length === 32)) {
                                    setImportError('Invalid key length — expected 32 bytes');
                                    return;
                                  }
                                  await window.storage.setItem('e2ee_secret', val);
                                  setHasSecret(true);
                                  setShowImportForm(false);
                                  setSecretInput('');
                                  toast({ title: 'Imported', description: 'Private key saved locally' });
                                } catch (err) {
                                  console.error('Import failed', err);
                                  setImportError('Failed to import key');
                                }
                              }}>Save</Button>
                              <Button variant="ghost" onClick={() => { setShowImportForm(false); setSecretInput(''); setImportError(null); }}>Cancel</Button>
                            </div>
                          </div>
                        )}
                        {importError && <div className="text-xs text-destructive mt-1">{importError}</div>}
                      </>
                    )}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Roles */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-primary" />
                Your Roles
              </CardTitle>
              <CardDescription>Your current access level and permissions</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-2">
                {roles.map((role) => (
                  <span
                    key={role}
                    className={`px-3 py-1 rounded-full text-sm font-medium ${
                      role === 'admin'
                        ? 'bg-warning/20 text-warning border border-warning/50'
                        : role === 'moderator'
                        ? 'bg-accent/20 text-accent border border-accent/50'
                        : 'bg-primary/20 text-primary border border-primary/50'
                    }`}
                  >
                    {role.charAt(0).toUpperCase() + role.slice(1)}
                  </span>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Message Stats */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <MessageSquare className="w-5 h-5 text-accent" />
                Message Statistics
              </CardTitle>
              <CardDescription>Your messaging activity overview</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid md:grid-cols-2 gap-4">
                <div className="p-4 border border-border rounded-lg">
                  <div className="text-3xl font-bold text-primary mb-1">
                    {messageStats.total}
                  </div>
                  <div className="text-sm text-muted-foreground">Total Messages</div>
                </div>
                <div className="p-4 border border-border rounded-lg">
                  <div className="text-3xl font-bold text-destructive mb-1">
                    {messageStats.flagged}
                  </div>
                  <div className="text-sm text-muted-foreground">Flagged Messages</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Account Actions */}
          <Card>
            <CardHeader>
              <CardTitle>Account Actions</CardTitle>
              <CardDescription>Manage your account settings</CardDescription>
            </CardHeader>
            <CardContent>
              <Button variant="destructive" onClick={handleSignOut}>
                Sign Out
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Profile;
