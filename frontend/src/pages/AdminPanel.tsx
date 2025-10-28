import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
// using backend APIs
import { useAuth } from '../hooks/useAuth';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { useToast } from '../hooks/use-toast';
import { Shield, UserCog, Home, Crown } from 'lucide-react';

interface UserWithRole {
  id: string;
  username: string;
  created_at?: string;
  roles: string[];
}

const AdminPanel = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [users, setUsers] = useState<UserWithRole[]>([]);
  const [isAdmin, setIsAdmin] = useState(false);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    totalUsers: 0,
    totalModerators: 0,
    totalAdmins: 0,
    totalMessages: 0,
  });

  useEffect(() => {
    checkAdminStatus();
  }, [user]);

  const checkAdminStatus = async () => {
    if (!user) {
      navigate('/auth');
      return;
    }
    try {
  const token = await window.storage.getItem('token');
  const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
      const res = await fetch(`/api/admin/has_role?_user_id=${user.id}&_role=admin`, { headers });
      const json = await res.json();
      if (json.has) {
        setIsAdmin(true);
        await Promise.all([fetchUsers(), fetchStats()]);
      } else {
      toast({
        title: 'Access Denied',
        description: 'You need admin privileges to access this page.',
        variant: 'destructive',
      });
      navigate('/');
    }
    } catch (err) {
      console.error('Error checking admin status:', err);
      setLoading(false);
      return;
    }
    setLoading(false);
  };

  const fetchStats = async () => {
    try {
  const token = await window.storage.getItem('token');
  const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
      const profilesRes = await fetch('/api/messages', { headers });
      const profilesJson = (await profilesRes.json()) as { data?: Array<{ severity?: string }> };
      const data = profilesJson.data || [];
      // For simple stats use messages endpoint and profiles endpoint
      // user_roles endpoint may not exist globally; fallback to scanning profiles
      const rolesRes = await fetch('/api/user_roles', { headers }).catch(() => null);
      const profilesAll = await (await fetch('/api/profiles', { headers })).json().catch(() => ({ data: [] }));
      const totalUsers = (profilesAll.data || []).length;
      const messagesCount = data.length;
      setStats({ totalUsers, totalModerators: 0, totalAdmins: 0, totalMessages: messagesCount });
    } catch (err) {
      console.error('Error fetching stats', err);
    }
  };

  const fetchUsers = async () => {
    try {
  const token = await window.storage.getItem('token');
  const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
      const res = await fetch('/api/profiles', { headers });
      const json = await res.json();
      const profiles = (json.data || []) as Array<{ user_id: string; username: string; created_at?: string; roles?: string[] }>;
      const usersWithRoles = profiles.map((profile) => ({
        id: profile.user_id,
        username: profile.username,
        created_at: profile.created_at,
        roles: profile.roles || ['user'],
      }));
      setUsers(usersWithRoles);
    } catch (err) {
      console.error('Error fetching users', err);
    }
  };

  const handleRoleChange = async (userId: string, newRole: string) => {
    // Remove existing moderator and admin roles
    try {
      // naive approach: update profile roles
      const token = await window.storage.getItem('token');
      await fetch(`/api/profiles/${userId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ roles: newRole === 'user' ? ['user'] : [newRole] }),
      });
    } catch (err) {
      toast({
        title: 'Error',
        description: 'Failed to update user role.',
        variant: 'destructive',
      });
      return;
    }
    toast({
      title: 'Role Updated',
      description: `User role has been changed to ${newRole}.`,
    });
    fetchUsers();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    );
  }

  if (!isAdmin) {
    return null;
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Crown className="w-8 h-8 text-warning" />
            <h1 className="text-2xl font-bold">Admin Panel</h1>
          </div>
          <Button variant="outline" onClick={() => navigate('/')}>
            <Home className="w-4 h-4 mr-2" />
            Home
          </Button>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8 space-y-8">
        {/* Stats */}
        <div className="grid md:grid-cols-4 gap-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-primary">{stats.totalUsers}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Moderators</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-accent">{stats.totalModerators}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Admins</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-warning">{stats.totalAdmins}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Total Messages</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-success">{stats.totalMessages}</div>
            </CardContent>
          </Card>
        </div>

        {/* User Management */}
        <Card>
          <CardHeader>
            <CardTitle>User Management</CardTitle>
            <CardDescription>Manage user roles and permissions</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {users.map((userItem) => (
                <div
                  key={userItem.id}
                  className="flex items-center justify-between p-4 border border-border rounded-lg hover:border-primary/50 transition-all"
                >
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded-full bg-primary/20 flex items-center justify-center">
                      <UserCog className="w-5 h-5 text-primary" />
                    </div>
                    <div>
                      <div className="font-semibold">{userItem.username}</div>
                      <div className="text-sm text-muted-foreground">
                        Joined: {userItem.created_at ? new Date(userItem.created_at).toLocaleDateString() : 'Unknown'}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="flex gap-2">
                      {userItem.roles.map((role) => (
                        <span
                          key={role}
                          className={`px-2 py-1 rounded text-xs ${
                            role === 'admin'
                              ? 'bg-warning/20 text-warning'
                              : role === 'moderator'
                              ? 'bg-accent/20 text-accent'
                              : 'bg-muted text-muted-foreground'
                          }`}
                        >
                          {role}
                        </span>
                      ))}
                    </div>
                    <Select
                      value={userItem.roles.includes('admin') ? 'admin' : userItem.roles.includes('moderator') ? 'moderator' : 'user'}
                      onValueChange={(value) => handleRoleChange(userItem.id, value)}
                      disabled={userItem.id === user?.id}
                    >
                      <SelectTrigger className="w-32">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="user">User</SelectItem>
                        <SelectItem value="moderator">Moderator</SelectItem>
                        <SelectItem value="admin">Admin</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default AdminPanel;
