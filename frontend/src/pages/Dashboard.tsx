import { useEffect, useState } from 'react';
import { Card } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { ScrollArea } from '../components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
// Use backend API instead of Supabase
import { AlertTriangle, Shield, MessageSquare, TrendingUp, Home, User } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../hooks/use-toast';
import { useNavigate, Link } from 'react-router-dom';

interface Message {
  id: string;
  content: string;
  is_abusive: boolean;
  abuse_score: number;
  abuse_type: string | null;
  severity: string;
  created_at: string;
  profiles: {
    username: string;
  };
}

const Dashboard = () => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [stats, setStats] = useState({ total: 0, flagged: 0, high: 0, medium: 0 });
  const [filter, setFilter] = useState<string>('all');
  const { user, signOut } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();

  useEffect(() => {
    if (!user) {
      navigate('/auth');
      return;
    }
    fetchMessages();
    fetchStats();
  }, [user, navigate]);

  const fetchMessages = async () => {
    try {
      const token = await window.storage.getItem('token');
      const res = await fetch('/api/messages', { headers: token ? { Authorization: `Bearer ${token}` } : undefined });
      const json = (await res.json()) as { data?: Message[] };
      setMessages(json.data || []);
    } catch (err) {
      console.error('Error fetching messages:', err);
    }
  };

  const fetchStats = async () => {
    try {
      const token = await window.storage.getItem('token');
      const res = await fetch('/api/messages', { headers: token ? { Authorization: `Bearer ${token}` } : undefined });
      const json = (await res.json()) as { data?: Message[] };
      const data = json.data || [];
      const total = data.length;
      const flagged = data.filter((m) => m.severity !== 'safe').length;
      const high = data.filter((m) => m.severity === 'high').length;
      const medium = data.filter((m) => m.severity === 'medium').length;
      setStats({ total, flagged, high, medium });
    } catch (err) {
      console.error('Error fetching stats:', err);
    }
  };

  const filteredMessages = messages.filter(msg => {
    if (filter === 'all') return true;
    if (filter === 'flagged') return msg.is_abusive;
    return msg.severity === filter;
  });

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high': return 'bg-destructive';
      case 'medium': return 'bg-warning';
      case 'low': return 'bg-accent';
      default: return 'bg-success';
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <div className="border-b border-border bg-card p-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-gradient-primary shadow-glow">
              <Shield className="w-6 h-6 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Moderation Dashboard</h1>
              <p className="text-sm text-muted-foreground">Monitor and manage content</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <Link to="/">
              <Button variant="outline">
                <Home className="w-4 h-4 mr-2" />
                Home
              </Button>
            </Link>
            <Link to="/chat">
              <Button variant="outline">
                <MessageSquare className="w-4 h-4 mr-2" />
                Chat
              </Button>
            </Link>
            <Link to="/profile">
              <Button variant="outline">
                <User className="w-4 h-4 mr-2" />
                Profile
              </Button>
            </Link>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto p-6 space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="p-6">
            <div className="flex items-center gap-3">
              <MessageSquare className="w-8 h-8 text-primary" />
              <div>
                <p className="text-sm text-muted-foreground">Total Messages</p>
                <p className="text-2xl font-bold">{stats.total}</p>
              </div>
            </div>
          </Card>
          <Card className="p-6">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-8 h-8 text-warning" />
              <div>
                <p className="text-sm text-muted-foreground">Flagged</p>
                <p className="text-2xl font-bold">{stats.flagged}</p>
              </div>
            </div>
          </Card>
          <Card className="p-6">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-destructive" />
              <div>
                <p className="text-sm text-muted-foreground">High Risk</p>
                <p className="text-2xl font-bold">{stats.high}</p>
              </div>
            </div>
          </Card>
          <Card className="p-6">
            <div className="flex items-center gap-3">
              <TrendingUp className="w-8 h-8 text-accent" />
              <div>
                <p className="text-sm text-muted-foreground">Medium Risk</p>
                <p className="text-2xl font-bold">{stats.medium}</p>
              </div>
            </div>
          </Card>
        </div>

        {/* Messages List */}
        <Card className="p-6">
          <Tabs defaultValue="all" onValueChange={setFilter}>
            <TabsList>
              <TabsTrigger value="all">All</TabsTrigger>
              <TabsTrigger value="flagged">Flagged</TabsTrigger>
              <TabsTrigger value="high">High Risk</TabsTrigger>
              <TabsTrigger value="medium">Medium Risk</TabsTrigger>
              <TabsTrigger value="low">Low Risk</TabsTrigger>
            </TabsList>

            <TabsContent value={filter} className="mt-4">
              <ScrollArea className="h-[600px]">
                <div className="space-y-4">
                  {filteredMessages.map((message) => (
                    <Card key={message.id} className="p-4">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <span className="font-semibold">{message.profiles.username}</span>
                            <Badge className={getSeverityColor(message.severity)}>
                              {message.severity}
                            </Badge>
                            {message.abuse_type && (
                              <Badge variant="destructive">{message.abuse_type}</Badge>
                            )}
                          </div>
                          <p className="text-sm mb-2">{message.content}</p>
                          <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            <span>Toxicity: {Math.round(message.abuse_score * 100)}%</span>
                            <span>{new Date(message.created_at).toLocaleString()}</span>
                          </div>
                        </div>
                      </div>
                    </Card>
                  ))}
                  {filteredMessages.length === 0 && (
                    <div className="text-center py-12 text-muted-foreground">
                      No messages found
                    </div>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>
          </Tabs>
        </Card>
      </div>
    </div>
  );
};

export default Dashboard;
