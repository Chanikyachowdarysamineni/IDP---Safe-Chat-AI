import { useEffect, useState, type ChangeEvent } from 'react';
import { useNavigate } from 'react-router-dom';
// using backend APIs
import { useAuth } from '../hooks/useAuth';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { Textarea } from '../components/ui/textarea';
import { useToast } from '../hooks/use-toast';
import { Shield, AlertTriangle, Ban, Clock, Home } from 'lucide-react';

interface Message {
  id: string;
  content: string;
  user_id: string;
  abuse_type: string;
  severity: string;
  abuse_score: number;
  created_at: string;
  profiles: {
    username: string;
  };
}

const ModeratorPanel = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [messages, setMessages] = useState<Message[]>([]);
  const [isModerator, setIsModerator] = useState(false);
  const [loading, setLoading] = useState(true);
  const [selectedMessage, setSelectedMessage] = useState<Message | null>(null);
  const [actionType, setActionType] = useState<string>('');
  const [reason, setReason] = useState('');

  useEffect(() => {
    checkModeratorStatus();
  }, [user]);

  const checkModeratorStatus = async () => {
    if (!user) {
      navigate('/auth');
      return;
    }
    try {
  const token = await window.storage.getItem('token');
  const res = await fetch(`/api/admin/has_role?_user_id=${user.id}&_role=moderator`, { headers: token ? { Authorization: `Bearer ${token}` } : undefined });
  const json = await res.json();
  const res2 = await fetch(`/api/admin/has_role?_user_id=${user.id}&_role=admin`, { headers: token ? { Authorization: `Bearer ${token}` } : undefined });
      const json2 = await res2.json();
      if (json.has || json2.has) {
        setIsModerator(true);
        fetchFlaggedMessages();
      } else {
      toast({
        title: 'Access Denied',
        description: 'You need moderator privileges to access this page.',
        variant: 'destructive',
      });
      navigate('/');
    }
    } catch (err) {
      console.error('Error checking moderator status:', err);
      setLoading(false);
      return;
    }
    setLoading(false);
  };

  const fetchFlaggedMessages = async () => {
    try {
  const token = await window.storage.getItem('token');
  const res = await fetch('/api/messages/flagged', { headers: token ? { Authorization: `Bearer ${token}` } : undefined });
      const json = await res.json();
      setMessages(json.data || []);
    } catch (err) {
      console.error('Error fetching messages:', err);
    }
  };

  const handleModeratorAction = async () => {
    if (!selectedMessage || !actionType || !reason.trim()) {
      toast({
        title: 'Missing Information',
        description: 'Please select an action and provide a reason.',
        variant: 'destructive',
      });
      return;
    }

    const expiresAt = actionType === 'temp_ban' 
      ? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
      : null;

    try {
      const token = await window.storage.getItem('token');
      const res = await fetch('/api/moderation_actions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          message_id: selectedMessage.id,
          user_id: selectedMessage.user_id,
          moderator_id: user?.id,
          action_type: actionType,
          reason,
          expires_at: expiresAt,
        }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || 'Failed');
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to record moderation action.',
        variant: 'destructive',
      });
      return;
    }

    toast({
      title: 'Action Recorded',
      description: `Moderation action "${actionType}" has been applied.`,
    });

    setSelectedMessage(null);
    setActionType('');
    setReason('');
    fetchFlaggedMessages();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    );
  }

  if (!isModerator) {
    return null;
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-primary" />
            <h1 className="text-2xl font-bold">Moderator Panel</h1>
          </div>
          <Button variant="outline" onClick={() => navigate('/')}>
            <Home className="w-4 h-4 mr-2" />
            Home
          </Button>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8">
        <div className="grid lg:grid-cols-2 gap-6">
          {/* Flagged Messages List */}
          <Card>
            <CardHeader>
              <CardTitle>Flagged Messages</CardTitle>
              <CardDescription>Messages detected as potentially abusive</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4 max-h-[600px] overflow-y-auto">
                {messages.length === 0 ? (
                  <div className="text-center text-muted-foreground py-8">
                    No flagged messages at this time
                  </div>
                ) : (
                  messages.map((message) => (
                    <div
                      key={message.id}
                      className={`p-4 border rounded-lg cursor-pointer transition-all ${
                        selectedMessage?.id === message.id
                          ? 'border-primary bg-primary/5'
                          : 'border-border hover:border-primary/50'
                      }`}
                      onClick={() => setSelectedMessage(message)}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <span className="font-semibold">{message.profiles?.username}</span>
                        <span
                          className={`px-2 py-1 rounded text-xs ${
                            message.severity === 'high'
                              ? 'bg-destructive/20 text-destructive'
                              : message.severity === 'medium'
                              ? 'bg-warning/20 text-warning'
                              : 'bg-muted text-muted-foreground'
                          }`}
                        >
                          {message.severity}
                        </span>
                      </div>
                      <p className="text-sm mb-2">{message.content}</p>
                      <div className="flex gap-2 text-xs text-muted-foreground">
                        <span>{message.abuse_type}</span>
                        <span>•</span>
                        <span>Score: {(message.abuse_score * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>

          {/* Moderation Actions */}
          <Card>
            <CardHeader>
              <CardTitle>Take Action</CardTitle>
              <CardDescription>
                {selectedMessage
                  ? 'Select an action and provide a reason'
                  : 'Select a message to take action'}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {selectedMessage ? (
                <div className="space-y-4">
                  <div className="p-4 border border-border rounded-lg bg-card">
                    <div className="font-semibold mb-2">Selected Message:</div>
                    <p className="text-sm mb-2">{selectedMessage.content}</p>
                    <div className="text-xs text-muted-foreground">
                      By: {selectedMessage.profiles?.username}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium">Action Type</label>
                    <Select value={actionType} onValueChange={setActionType}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select action type" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="warning">
                          <div className="flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 text-warning" />
                            Warning
                          </div>
                        </SelectItem>
                        <SelectItem value="temp_ban">
                          <div className="flex items-center gap-2">
                            <Clock className="w-4 h-4 text-warning" />
                            Temporary Ban (7 days)
                          </div>
                        </SelectItem>
                        <SelectItem value="permanent_ban">
                          <div className="flex items-center gap-2">
                            <Ban className="w-4 h-4 text-destructive" />
                            Permanent Ban
                          </div>
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium">Reason</label>
                    <Textarea
                      placeholder="Explain the reason for this action..."
                      value={reason}
                      onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setReason(e.target.value)}
                      rows={4}
                    />
                  </div>

                  <div className="flex gap-2">
                    <Button
                      onClick={handleModeratorAction}
                      disabled={!actionType || !reason.trim()}
                      className="flex-1"
                    >
                      Apply Action
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => {
                        setSelectedMessage(null);
                        setActionType('');
                        setReason('');
                      }}
                    >
                      Cancel
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="text-center text-muted-foreground py-12">
                  Select a message from the list to take moderation action
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default ModeratorPanel;
