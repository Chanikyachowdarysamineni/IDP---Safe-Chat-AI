import React, { useState, useRef, useEffect, useCallback, type ChangeEvent, type KeyboardEvent } from 'react';
import '../lib/windowStorage';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { ScrollArea } from './ui/scroll-area';
import { Card } from './ui/card';
import { Send, Shield, LogOut, LayoutDashboard, Home, User, Flag, DownloadCloud } from 'lucide-react';
import MessageAnalysis from './MessageAnalysis';
import { analyzeMessage } from '../lib/ml-analyzer';
import nacl from 'tweetnacl';
import { decodeBase64 } from 'tweetnacl-util';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../hooks/use-toast';
import { useNavigate, Link, useParams } from 'react-router-dom';
// E2EE removed: messages are plain text now

interface Message {
  id: string;
  content: string;
  user_id: string;
  conversation_id?: string;
  recipient_id?: string;
  created_at: string;
  is_abusive: boolean;
  abuse_score: number;
  abuse_type?: string;
  severity: 'safe' | 'low' | 'medium' | 'high';
  emotions: Array<{ label: string; score: number }>;
  read_by?: Array<{ user_id: string; read_at: string }>;
  ciphertext?: string;
  nonce?: string;
  sender_pubkey?: string;
  profiles: {
    username: string;
    avatar_url?: string;
  };
  // optional client-side helpers
  client_temp_id?: string;
  delivery?: 'sending' | 'delivered' | 'failed';
  flagged?: boolean;
}

interface Profile {
  user_id: string;
  username: string;
  avatar_url?: string;
}

interface Conversation {
  conversation: {
    id: string;
    participant_ids: string[];
  };
  participants?: Array<{ username: string; user_id: string }>;
  last_message?: Message | null;
  unread: number;
}

export default function ChatInterface(): JSX.Element {
  const { user, signOut } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const { conversationId } = useParams<{ conversationId?: string }>();

  const [messages, setMessages] = useState<Message[]>([]);
  const [loadingMessages, setLoadingMessages] = useState<boolean>(true);
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedConversationId, setSelectedConversationId] = useState<string | null>(conversationId || null);
  const [input, setInput] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isModelLoaded, setIsModelLoaded] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<Profile[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [onlineUsers, setOnlineUsers] = useState<Record<string, boolean>>({});

  const scrollRef = useRef<HTMLDivElement | null>(null);
  const socketRef = useRef<any>(null);
  const e2eeReadyRef = useRef<boolean>(false);
  const e2eeSecretRef = useRef<string | null>(null);
  const tokenRef = useRef<string | null>(null);
  const messageReadEmittedRef = useRef<Set<string>>(new Set());
  const MAX_CHARS = 2000;
  const [remainingChars, setRemainingChars] = useState<number>(MAX_CHARS);

  const BACKEND_URL = (import.meta as any).env?.VITE_BACKEND_URL || 'http://localhost:4000';

  // Scroll to bottom helper
  const scrollToBottom = useCallback(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, []);

  // E2EE helpers
  const getOrCreateKeyPair = useCallback(async () => {
    // E2EE disabled — no keypair management required.
    return null;
  }, []);

  const uploadPublicKey = useCallback(async (pub: string) => {
    try {
      const token = await window.storage.getItem('token');
      if (!token) return;
      await fetch(`${BACKEND_URL}/api/keys`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ public_key: pub }),
      });
    } catch (err) {
      console.error('Upload public key failed:', err);
    }
  }, [BACKEND_URL]);

  const fetchPublicKey = useCallback(async (userId: string): Promise<string | null> => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/keys/${userId}`);
      if (!res.ok) return null;
      const json = await res.json();
      return json.public_key || null;
    } catch (err) {
      console.error('Fetch public key error:', err);
      return null;
    }
  }, [BACKEND_URL]);

  const decryptIncoming = useCallback((m: any): any => {
    // If server provided plaintext, use it. Otherwise, if ciphertext is present
    // attempt client-side decryption using the user's secret key stored in `window.storage`.
    try {
      if (!m) return m;
      if (m.content) return { ...m, content: m.content };

      // Attempt decryption only if ciphertext, nonce and sender_pubkey are present
      if (m.ciphertext && m.nonce && m.sender_pubkey) {
        try {
          const mySecretBase64 = e2eeSecretRef.current;
          if (mySecretBase64) {
            const secretKey = decodeBase64(mySecretBase64);
            const senderPub = decodeBase64(m.sender_pubkey);
            const nonce = decodeBase64(m.nonce);
            const cipher = decodeBase64(m.ciphertext);
            const opened = nacl.box.open(new Uint8Array(cipher), new Uint8Array(nonce), new Uint8Array(senderPub), new Uint8Array(secretKey));
            if (opened) {
              const text = new TextDecoder().decode(opened);
              return { ...m, content: text };
            }
          }
        } catch (e) {
          // decryption failed; fall through to encrypted placeholder
          console.debug('E2EE decrypt failed for message', m.id, e);
        }
      }

  // no plaintext available — show an explicit encrypted placeholder so users
  // understand the message is encrypted and they don't have the key locally.
  return { ...m, content: '(encrypted message)' };
    } catch (err) {
      return { ...m, content: m.content ?? '' };
    }
  }, []);

  // Fetch messages for a specific conversation
  const fetchMessages = useCallback(async (convId?: string) => {
    try {
      const token = await window.storage.getItem('token');
      tokenRef.current = token;
      const cid = convId || selectedConversationId || conversationId;

      if (!cid) {
        setMessages([]);
        return;
      }

      setLoadingMessages(true);

      // Load cached messages for this conversation first
      try {
        const cached = await window.storage.getMessagesByConversation(cid);
        if (Array.isArray(cached) && cached.length > 0) {
          setMessages(cached.map((m) => decryptIncoming(m)));
        }
      } catch (e) {
        console.debug('no cached messages', e);
      }

      const url = `${BACKEND_URL}/api/conversations/${cid}/messages`;
      const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};

      const res = await fetch(url, { headers });
      if (!res.ok) {
        console.error('Failed to fetch messages:', res.statusText);
        setLoadingMessages(false);
        return;
      }

      const json = await res.json();
      const msgs = (json.data || []).map((m: any) => decryptIncoming(m));

      // persist
      for (const m of msgs) {
        try {
          await window.storage.saveMessage(m);
        } catch (e) {
          console.debug('save message error', e);
        }
      }

      setMessages((cur) => {
        const merged = [...cur];
        for (const m of msgs) {
          if (!merged.some((x) => x.id === m.id)) merged.push(m);
        }
        merged.sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
        return merged;
      });

      // Mark conversation as read
      if (cid) {
        setConversations((cur) =>
          cur.map((c) => ({
            ...c,
            unread: c.conversation.id === cid ? 0 : c.unread,
          }))
        );
      }

      setLoadingMessages(false);
    } catch (err) {
      console.error('Error fetching messages:', err);
      setLoadingMessages(false);
    }
  }, [selectedConversationId, conversationId, decryptIncoming, BACKEND_URL]);

  // Fetch all conversations
  const fetchConversations = useCallback(async () => {
    try {
      const token = await window.storage.getItem('token');
      tokenRef.current = token;
      const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};

      const res = await fetch(`${BACKEND_URL}/api/conversations`, { headers });
      if (!res.ok) return;
      
      const json = await res.json();
      const rows = (json.data || []).map((r: any) => {
        const last = r.last_message ? decryptIncoming(r.last_message) : null;
        return { ...r, last_message: last, unread: r.unread || 0 };
      });

      // Sort by last_message.created_at desc
      rows.sort((a: any, b: any) => {
        const ta = a.last_message?.created_at ? new Date(a.last_message.created_at).getTime() : 0;
        const tb = b.last_message?.created_at ? new Date(b.last_message.created_at).getTime() : 0;
        return tb - ta;
      });

      setConversations(rows);
    } catch (err) {
      console.error('Error fetching conversations:', err);
    }
  }, [decryptIncoming, BACKEND_URL]);

  // Start conversation with a user
  const startConversationWith = useCallback(async (profile: Profile) => {
    if (!user) {
      navigate('/auth');
      return;
    }
    
    if (profile.user_id === user.id) {
      toast({ title: 'Notice', description: 'This is your profile.' });
      navigate('/profile');
      return;
    }

    try {
      const token = await window.storage.getItem('token');
      const res = await fetch(`${BACKEND_URL}/api/conversations`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ participant_ids: [user.id, profile.user_id] }),
      });

      const json = await res.json();
      const convo = json.data;
      
      if (convo && convo.id) {
        setSearchQuery('');
        setSearchResults([]);
        navigate(`/chat/${convo.id}`);
      }
    } catch (err) {
      console.error('Conversation create error:', err);
      toast({ title: 'Error', description: 'Could not start conversation' });
    }
  }, [user, navigate, toast, BACKEND_URL]);

  // Debounced search
  useEffect(() => {
    const q = (searchQuery || '').trim();
    if (!q) {
      setSearchResults([]);
      return;
    }

    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        setIsSearching(true);
        const token = await window.storage.getItem('token');
        const res = await fetch(
          `${BACKEND_URL}/api/profiles?search=${encodeURIComponent(q)}`,
          { headers: token ? { Authorization: `Bearer ${token}` } : undefined }
        );
        
        if (!cancelled && res.ok) {
          const json = await res.json();
          setSearchResults(json.data || []);
        }
      } catch (err) {
        console.error('Search error:', err);
      } finally {
        if (!cancelled) setIsSearching(false);
      }
    }, 300);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [searchQuery, BACKEND_URL]);

  // Initialize component
  useEffect(() => {
    if (!user) {
      navigate('/auth');
      return;
    }

    let mounted = true;

    // Load cached token and e2ee secret from storage
    (async () => {
      try {
        const t = await window.storage.getItem('token');
        tokenRef.current = t;
        const secret = await window.storage.getItem('e2ee_secret');
        e2eeSecretRef.current = secret;
      } catch (e) {
        console.debug('Could not read window.storage keys', e);
      }
    })();

    // Preload ML analyzer
    (async () => {
      try {
        await analyzeMessage('test');
        if (mounted) setIsModelLoaded(true);
      } catch (e) {
        console.error('ML analyzer load error:', e);
        if (mounted) setIsModelLoaded(true);
      }
    })();

    // Initial data fetch
    fetchConversations();
    if (conversationId) {
      fetchMessages(conversationId);
    }

    // Polling fallback
    const pollInterval = setInterval(() => {
      fetchConversations();
      if (selectedConversationId || conversationId) {
        fetchMessages();
      }
    }, 5000);

    // Setup Socket.IO
    (async () => {
      if (socketRef.current) return;

      try {
        const token = await window.storage.getItem('token');
        tokenRef.current = token;
        let mod: any;
        
        try {
          mod = await import('socket.io-client');
        } catch (err) {
          // Fallback to CDN (dev only)
          // @ts-ignore -- dynamic CDN import
          mod = await import('https://cdn.jsdelivr.net/npm/socket.io-client@4.7.2/dist/socket.io.esm.min.js');
        }

        const create = mod?.io || mod?.default || mod;
        socketRef.current = create(BACKEND_URL, { auth: { token } });

        // Handle incoming messages
        socketRef.current.on('message', (raw: any) => {
          const msg = decryptIncoming(raw);
          
          setMessages((cur) => {
            if (!msg) return cur;

            // If a message with the server id already exists, update it
            if (msg.id && cur.some((m) => m.id === msg.id)) {
              const idxExist = cur.findIndex((m) => m.id === msg.id);
              const next = [...cur];
              next[idxExist] = { ...msg, delivery: 'delivered' };
              window.storage.saveMessage(next[idxExist]).catch(() => {});
              return next;
            }

            // Try to find optimistic entry by client_temp_id
            if (msg.client_temp_id) {
              const idx = cur.findIndex((m) => m.client_temp_id === msg.client_temp_id || m.id === msg.client_temp_id);
              if (idx !== -1) {
                const oldId = cur[idx].id;
                const next = [...cur];
                next[idx] = { ...msg, delivery: 'delivered' };
                window.storage.saveMessage(next[idx]).catch(() => {});
                // remove optimistic record if it had a different id
                if (oldId && oldId !== msg.id) {
                  window.storage.removeMessage(oldId).catch(() => {});
                }
                return next;
              }
            }

            // Fuzzy fallback: match by same user_id + content + sending status within a small time window
            const fuzzyIdx = cur.findIndex((m) => m.delivery === 'sending' && m.user_id === msg.user_id && m.content === msg.content && Math.abs(new Date(m.created_at).getTime() - new Date(msg.created_at).getTime()) < 5000);
            if (fuzzyIdx !== -1) {
              const oldId = cur[fuzzyIdx].id;
              const next = [...cur];
              next[fuzzyIdx] = { ...msg, delivery: 'delivered' };
              window.storage.saveMessage(next[fuzzyIdx]).catch(() => {});
              if (oldId && oldId !== msg.id) window.storage.removeMessage(oldId).catch(() => {});
              return next;
            }

            // Append new message (dedupe by id just in case)
            if (msg.id && cur.some((m) => m.id === msg.id)) return cur;
            window.storage.saveMessage({ ...msg, delivery: 'delivered' }).catch(() => {});
            return [...cur, { ...msg, delivery: 'delivered' }];
          });

          // Update conversations list
          if (msg.conversation_id) {
            setConversations((cs) => {
              const copy = [...cs];
              const idx = copy.findIndex(
                (x) => x.conversation && x.conversation.id === msg.conversation_id
              );

              if (idx !== -1) {
                copy[idx] = { ...copy[idx], last_message: msg };
                
                // Increment unread if not active conversation
                if ((selectedConversationId || conversationId) !== msg.conversation_id) {
                  copy[idx].unread = (copy[idx].unread || 0) + 1;
                }

                // Move to top
                const [item] = copy.splice(idx, 1);
                copy.unshift(item);
              } else {
                // New conversation
                copy.unshift({
                  conversation: { id: msg.conversation_id, participant_ids: [] },
                  last_message: msg,
                  unread: 1,
                });
              }

              return copy;
            });
          }

          // Auto-mark as read if it's from someone else
          if (msg.id && msg.user_id !== user?.id) {
            const s = socketRef.current;
            if (s?.connected && !messageReadEmittedRef.current.has(msg.id)) {
              s.emit('message_read', { message_id: msg.id });
              messageReadEmittedRef.current.add(msg.id);
            }
          }
        });

        // Acknowledgement for optimistic messages -> includes client_temp_id
        socketRef.current.on('message_sent', (ack: any) => {
          if (!ack) return;

          // Server may send the ack under different shapes. Support { data } and { message }.
          const clientTempId = ack.client_temp_id || ack.clientTempId || (ack.data && ack.data.client_temp_id) || (ack.message && ack.message.client_temp_id) || null;
          const rawMessage = ack.message || ack.data || ack;

          if (!rawMessage) return;

          const msg = decryptIncoming(rawMessage);

          setMessages((cur) => {
            // If message already exists by real id, update it
            if (msg.id && cur.some((m) => m.id === msg.id)) {
              const idxExist = cur.findIndex((m) => m.id === msg.id);
              const next = [...cur];
              next[idxExist] = { ...msg, delivery: 'delivered' };
              window.storage.saveMessage(next[idxExist]).catch(() => {});
              return next;
            }

            // Try to find optimistic entry by clientTempId
            if (clientTempId) {
              const idx = cur.findIndex((m) => m.client_temp_id === clientTempId || m.id === clientTempId);
              if (idx !== -1) {
                const oldId = cur[idx].id;
                const next = [...cur];
                next[idx] = { ...msg, delivery: 'delivered' };
                window.storage.saveMessage(next[idx]).catch(() => {});
                if (oldId && oldId !== msg.id) window.storage.removeMessage(oldId).catch(() => {});
                return next;
              }
            }

            // If no optimistic found, and no duplicate by id, append
            if (msg.id && cur.some((m) => m.id === msg.id)) return cur;
            window.storage.saveMessage({ ...msg, delivery: 'delivered' }).catch(() => {});
            return [...cur, { ...msg, delivery: 'delivered' }];
          });
        });

        // Handle presence updates
        socketRef.current.on('presence', (p: any) => {
          setOnlineUsers((cur) => ({ ...cur, [p.user_id]: !!p.online }));
        });

        socketRef.current.on('connect', () => {
          console.log('Socket connected');
        });

        socketRef.current.on('disconnect', () => {
          console.log('Socket disconnected');
        });

        // When a conversation is cleared server-side, remove local cache and update UI
        socketRef.current.on('conversation_cleared', async (payload: any) => {
          try {
            const conversation_id = payload && payload.conversation_id;
            if (!conversation_id) return;
            // Remove from local storage
            await window.storage.clearConversation(conversation_id);
            // If currently viewing this conversation, clear messages from UI
            const cid = selectedConversationId || conversationId;
            if (cid === conversation_id) {
              setMessages([]);
            }
            // Update conversations list
            setConversations((prev) => prev.map((c) => (c.conversation && c.conversation.id === conversation_id ? { ...c, last_message: null, unread: 0 } : c)));
          } catch (err) {
            console.debug('conversation_cleared handler error', err);
          }
        });

      } catch (err) {
        console.error('Socket.io setup error:', err);
      }
    })();

    return () => {
      mounted = false;
      clearInterval(pollInterval);
      
      if (socketRef.current) {
        try {
          socketRef.current.disconnect();
        } catch (e) {
          console.error('Socket disconnect error:', e);
        }
        socketRef.current = null;
      }
    };
  }, [user, navigate, fetchConversations, fetchMessages, conversationId, selectedConversationId, decryptIncoming, BACKEND_URL]);

  // Scroll to bottom when messages change
  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  // Join/leave conversation room
  useEffect(() => {
    const socket = socketRef.current;
    if (!socket || !conversationId) return;

    socket.emit('join_conversation', conversationId);

    return () => {
      if (socket && conversationId) {
        socket.emit('leave_conversation', conversationId);
      }
    };
  }, [conversationId]);

  // Update selected conversation when route changes
  useEffect(() => {
    if (conversationId && conversationId !== selectedConversationId) {
      setSelectedConversationId(conversationId);
      fetchMessages(conversationId);
    }
  }, [conversationId, selectedConversationId, fetchMessages]);

  // Handle send message (plain text)
  const handleSend = async () => {
    if (!input.trim() || !user || !isModelLoaded) return;

    const text = input.trim();
    setInput('');
    setIsAnalyzing(true);

    try {
      const analysis = await analyzeMessage(text);

      const currentConvId = selectedConversationId || conversationId;

      // Try to resolve recipient from local conversations state (1:1 expected)
      let recipientId: string | null = null;
      if (currentConvId) {
        const found = conversations.find((c: any) => c.conversation && c.conversation.id === currentConvId);
        if (found && Array.isArray(found.conversation.participant_ids)) {
          const others = found.conversation.participant_ids.filter((id: string) => id !== user.id);
          if (others.length === 1) recipientId = others[0];
        }
      }

      // Prepare payload with plaintext content and moderation metadata
      const payload: any = {
        conversation_id: currentConvId || null,
        recipient_id: recipientId || null,
        content: text,
        is_abusive: analysis.isAbusive,
        abuse_score: analysis.abuseScore,
        abuse_type: analysis.abuseType,
        severity: analysis.severity,
        emotions: analysis.emotions,
      };

      // Create client_temp_id for optimistic reconciliation
      const clientTempId = `ct-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

      // Optimistic UI update (plain text)
      const localMsg: Message = {
        id: clientTempId,
        client_temp_id: clientTempId,
        delivery: 'sending',
        content: text,
        user_id: user.id,
        recipient_id: recipientId || undefined,
        conversation_id: currentConvId || undefined,
        created_at: new Date().toISOString(),
        is_abusive: analysis.isAbusive,
        abuse_score: analysis.abuseScore,
        abuse_type: analysis.abuseType,
        severity: analysis.severity,
        emotions: analysis.emotions,
        profiles: { username: (user as any)?.username || 'You' },
        read_by: [],
      };
      setMessages((cur) => [...cur, localMsg]);
      // persist optimistic message
      try {
        await window.storage.saveMessage(localMsg);
      } catch (e) {
        console.debug('save optimistic message failed', e);
      }

      // Send via socket or HTTP
      const socket = socketRef.current;
      // add client_temp_id to payload so server can acknowledge and map
      payload.client_temp_id = clientTempId;

      if (socket?.connected) {
        socket.emit('send_message', payload);
      } else {
        const token = await window.storage.getItem('token');
        const url = currentConvId
          ? `${BACKEND_URL}/api/conversations/${currentConvId}/messages`
          : `${BACKEND_URL}/api/messages`;

        const res = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          body: JSON.stringify(payload),
        });

        if (!res.ok) {
          toast({ title: 'Error', description: 'Failed to send message' });
        } else {
          await fetchMessages();
        }
      }
    } catch (err) {
      console.error('Send error:', err);
      toast({ title: 'Error', description: 'Failed to send message' });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void handleSend();
    }
  };

  const handleConversationClick = async (convId: string) => {
    setSelectedConversationId(convId);
    navigate(`/chat/${convId}`);
    await fetchMessages(convId);
  };

  return (
    <div className="flex h-screen bg-background">
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <div className="border-b border-border bg-card p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-gradient-primary shadow-glow">
                <Shield className="w-6 h-6 text-primary-foreground" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-foreground">Safe Chat AI</h1>
                <p className="text-sm text-muted-foreground">
                  {isModelLoaded ? 'Real-time content moderation active' : 'Loading models...'}
                </p>

                {/* Search */}
                <div className="mt-3 relative">
                  <Input
                    placeholder="Search users by username..."
                    value={searchQuery}
                    onChange={(e: ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
                    className="w-64"
                  />
                  {(searchResults.length > 0 || (searchQuery && !isSearching)) && (
                    <div className="absolute z-50 mt-1 w-64 bg-card border border-border rounded shadow-lg max-h-64 overflow-auto">
                      {searchResults.length > 0 ? (
                        searchResults.map((p) => (
                          <div
                            key={p.user_id}
                            className="p-2 hover:bg-accent/20 cursor-pointer"
                            onClick={() => startConversationWith(p)}
                          >
                            <div className="flex items-center justify-between">
                              <div className="text-sm font-medium">{p.username}</div>
                              <div className="text-xs text-muted-foreground">{p.user_id.substring(0, 8)}</div>
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="p-2 text-sm text-muted-foreground">No users found</div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Navigation */}
            <div className="flex items-center gap-2">
              <Link to="/">
                <Button variant="outline" size="sm">
                  <Home className="w-4 h-4 mr-2" />
                  Home
                </Button>
              </Link>
              <Link to="/dashboard">
                <Button variant="outline" size="sm">
                  <LayoutDashboard className="w-4 h-4 mr-2" />
                  Dashboard
                </Button>
              </Link>
              <Link to="/profile">
                <Button variant="outline" size="sm">
                  <User className="w-4 h-4 mr-2" />
                  Profile
                </Button>
              </Link>
              <Button variant="outline" size="sm" onClick={signOut}>
                <LogOut className="w-4 h-4 mr-2" />
                Sign Out
              </Button>
            </div>
          </div>
        </div>

        <div className="flex flex-1 overflow-hidden">
          {/* Sidebar - Conversations List */}
          <div className="w-1/3 border-r border-border overflow-y-auto">
            <div className="p-2">
              {conversations.length === 0 ? (
                <div className="p-8 text-center text-muted-foreground">
                  <p className="text-sm">No conversations yet</p>
                  <p className="text-xs mt-2">Search for a user to start chatting</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {conversations.map((c) => {
                    const conv = (c.conversation || {}) as any;
                    const last = c.last_message || null;
                    const others = (conv.participant_ids || []).filter((id: string) => id !== user?.id);
                    const name =
                      (c.participants?.[0]?.username) ||
                      (last?.profiles?.username) ||
                      (others[0] ? `User ${others[0].substring(0, 8)}` : 'Unknown');
                    const preview = last?.content ?? 'No messages yet';
                    const time = last?.created_at ? new Date(last.created_at).toLocaleTimeString() : '';
                    const isActive = selectedConversationId === conv.id;

                    return (
                      <div
                        key={conv.id}
                        className={`p-3 rounded-lg cursor-pointer transition-colors ${
                          isActive
                            ? 'bg-accent/20 border border-primary'
                            : 'border border-border hover:bg-accent/10'
                        }`}
                        onClick={() => handleConversationClick(conv.id)}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3 flex-1 min-w-0">
                            <div className="w-10 h-10 rounded-full bg-primary/20 flex items-center justify-center text-sm font-semibold text-primary-foreground flex-shrink-0">
                              {name.charAt(0).toUpperCase()}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="font-medium truncate">{name}</div>
                              <div className="text-sm text-muted-foreground truncate">{preview}</div>
                            </div>
                          </div>
                          <div className="text-right flex-shrink-0 ml-2">
                            <div className="text-xs text-muted-foreground">{time}</div>
                            {c.unread > 0 && (
                              <div className="mt-1 inline-block bg-red-500 text-white text-xs px-2 py-0.5 rounded-full">
                                {c.unread}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* Chat Area */}
          <div className="flex-1 flex flex-col">
            <div className="flex items-center justify-between px-4 pt-3">
              <div className="text-sm text-muted-foreground">
                {selectedConversationId || conversationId ? (
                  <>
                    Messages: <span className="font-medium">{messages.length}</span>
                  </>
                ) : (
                  'No conversation selected'
                )}
              </div>
              {(selectedConversationId || conversationId) && (
                <div>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={async () => {
                      const cid = selectedConversationId || conversationId;
                      if (!cid) return;
                      if (!confirm('Clear chat messages for this conversation? This cannot be undone.')) return;
                      try {
                        // Clear local DB entries for this conversation
                        await window.storage.clearConversation(cid);

                        // Clear UI messages for this conversation
                        setMessages([]);

                        // Update conversations list: clear last_message and unread count
                        setConversations((prev) =>
                          prev.map((c) =>
                            c.conversation && c.conversation.id === cid
                              ? { ...c, last_message: null, unread: 0 }
                              : c
                          )
                        );

                        // Notify backend to remove messages server-side (best-effort)
                        try {
                          const token = await window.storage.getItem('token');
                          const res = await fetch(`${BACKEND_URL}/api/conversations/${cid}/messages`, {
                            method: 'DELETE',
                            headers: {
                              'Content-Type': 'application/json',
                              ...(token ? { Authorization: `Bearer ${token}` } : {}),
                            },
                          });
                          if (!res.ok) {
                            console.debug('Backend did not delete conversation messages:', res.statusText);
                          }
                        } catch (err) {
                          console.debug('Backend delete messages failed (non-blocking):', err);
                        }

                        // Emit socket event so other connected clients can react (best-effort)
                        try {
                          const s = socketRef.current;
                          if (s && s.connected) s.emit('clear_conversation', { conversation_id: cid });
                        } catch (err) {
                          console.debug('Socket emit clear_conversation failed:', err);
                        }
                      } catch (e) {
                        console.error('Failed to clear conversation', e);
                        toast({ title: 'Error', description: 'Could not clear conversation' });
                      }
                    }}
                  >
                    Clear chat
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="ml-2"
                    onClick={async () => {
                      const cid = selectedConversationId || conversationId;
                      if (!cid) return;
                      try {
                        // load messages from window.storage
                        const rows = await window.storage.getMessagesByConversation(cid);
                        if (!Array.isArray(rows) || rows.length === 0) {
                          toast({ title: 'Export', description: 'No messages to export for this conversation.' });
                          return;
                        }

                        // CSV header
                        const header = ['id', 'created_at', 'user_id', 'content', 'is_abusive', 'abuse_score', 'severity', 'emotions'];
                        const lines = [header.join(',')];
                        for (const m of rows) {
                          const em = (m.emotions && Array.isArray(m.emotions)) ? JSON.stringify(m.emotions).replace(/"/g, '""') : '';
                          const content = (m.content || '').replace(/"/g, '""');
                          const line = [`"${m.id}"`, `"${m.created_at || ''}"`, `"${m.user_id || ''}"`, `"${content}"`, `${m.is_abusive ? 1 : 0}`, `${m.abuse_score ?? ''}`, `"${m.severity ?? ''}"`, `"${em}"`].join(',');
                          lines.push(line);
                        }

                        const csv = lines.join('\n');
                        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        const filename = `conversation-${cid}.csv`;
                        a.download = filename;
                        document.body.appendChild(a);
                        a.click();
                        a.remove();
                        URL.revokeObjectURL(url);
                        toast({ title: 'Export', description: `Downloaded ${rows.length} messages to ${filename}` });
                      } catch (err) {
                        console.error('Export failed', err);
                        toast({ title: 'Export failed', description: String(err) });
                      }
                    }}
                  >
                    <DownloadCloud className="w-4 h-4 mr-2" />
                    Export
                  </Button>
                </div>
              )}
            </div>
            <ScrollArea className="flex-1 p-4" ref={scrollRef}>
              <div className="space-y-4 max-w-4xl mx-auto">
                {messages.length === 0 ? (
                  <Card className="p-8 text-center border-dashed">
                    <Shield className="w-16 h-16 mx-auto mb-4 text-primary opacity-50" />
                    <h2 className="text-xl font-semibold mb-2">Start a Safe Conversation</h2>
                    <p className="text-muted-foreground">
                      Messages will be analyzed in real-time for abuse detection and emotion recognition.
                    </p>
                  </Card>
                ) : (
                  messages.map((message) => (
                    <div key={message.id} className="animate-slide-up">
                      <Card className="p-4 bg-card border-border">
                        <div className="flex items-start gap-3">
                          <div className="w-10 h-10 rounded-full bg-gradient-primary flex items-center justify-center text-sm font-semibold text-primary-foreground flex-shrink-0">
                            {(((message.profiles && message.profiles.username) || (message.user_id === user?.id ? 'You' : (message.user_id ? `User ${message.user_id.substring(0, 8)}` : 'Unknown'))).charAt && ((message.profiles && message.profiles.username) || (message.user_id === user?.id ? 'You' : (message.user_id ? `User ${message.user_id.substring(0, 8)}` : 'Unknown'))).charAt(0).toUpperCase()) || '?'}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-semibold text-foreground">
                                {(message.profiles && message.profiles.username) || (message.user_id === user?.id ? 'You' : (message.user_id ? `User ${message.user_id.substring(0, 8)}` : 'Unknown'))}
                              </span>
                              <span className="text-xs text-muted-foreground">
                                {new Date(message.created_at).toLocaleTimeString()}
                              </span>
                            </div>
                            <p className="text-foreground mb-3 break-words">{message.content}</p>
                            <div className="mt-2 flex gap-2">
                              {!message.flagged && (
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  onClick={async () => {
                                    try {
                                      const token = await window.storage.getItem('token');
                                      const res = await fetch(`${BACKEND_URL}/api/messages/${message.id}/flag`, {
                                        method: 'POST',
                                        headers: {
                                          'Content-Type': 'application/json',
                                          ...(token ? { Authorization: `Bearer ${token}` } : {}),
                                        },
                                        body: JSON.stringify({ reason: 'user_report' }),
                                      });
                                      if (res.ok) {
                                        toast({ title: 'Flagged', description: 'Message sent to moderation' });
                                        setMessages((cur) => cur.map((m) => (m.id === message.id ? { ...m, flagged: true } : m)));
                                      } else {
                                        toast({ title: 'Error', description: 'Could not flag message' });
                                      }
                                    } catch (err) {
                                      console.error('Flag error', err);
                                      toast({ title: 'Error', description: 'Could not flag message' });
                                    }
                                  }}
                                >
                                  <Flag className="w-3 h-3 mr-2" />
                                  Flag
                                </Button>
                              )}
                              {message.flagged && (
                                <div className="text-xs text-muted-foreground">Flagged</div>
                              )}
                            </div>
                            {message.delivery === 'sending' && (
                              <div className="text-xs text-muted-foreground mb-2">Sending…</div>
                            )}
                            {message.content === '(encrypted message)' && (
                              <div className="text-xs text-muted-foreground mt-1">
                                This message is encrypted. If you have your private key, import it in your <a href="/profile" className="underline">Profile</a> to decrypt it locally.
                              </div>
                            )}
                            <MessageAnalysis
                              analysis={{
                                isAbusive: message.is_abusive,
                                abuseScore: message.abuse_score,
                                abuseType: message.abuse_type,
                                emotions: message.emotions,
                                severity: message.severity,
                              }}
                              messageId={message.id}
                              content={message.content}
                            />
                            {Array.isArray(message.read_by) && message.read_by.length > 0 && (
                              <div className="text-xs text-muted-foreground mt-2">
                                Read by:{' '}
                                {message.read_by
                                  .map((r) => (r.user_id === user?.id ? 'You' : r.user_id.substring(0, 8)))
                                  .join(', ')}
                              </div>
                            )}
                          </div>
                        </div>
                      </Card>
                    </div>
                  ))
                )}
                {isAnalyzing && (
                  <Card className="p-4 bg-card/50 border-dashed animate-pulse">
                    <div className="flex items-center gap-2 text-muted-foreground">
                      <div className="w-2 h-2 rounded-full bg-accent animate-pulse" />
                      <span className="text-sm">Analyzing message...</span>
                    </div>
                  </Card>
                )}
              </div>
            </ScrollArea>

            {/* Message Input */}
            <div className="border-t border-border bg-card p-4">
              <div className="max-w-4xl mx-auto flex gap-2">
                  <Input
                  value={input}
                  onChange={(e: ChangeEvent<HTMLInputElement>) => {
                    const v = e.target.value.slice(0, MAX_CHARS);
                    setInput(v);
                    setRemainingChars(MAX_CHARS - v.length);
                  }}
                  onKeyDown={handleKeyDown}
                  placeholder={
                    selectedConversationId || conversationId
                      ? 'Type a message to analyze...'
                      : 'Select a conversation to start messaging'
                  }
                  className="flex-1 bg-background border-border text-foreground"
                  disabled={!isModelLoaded || !(selectedConversationId || conversationId)}
                />
                <Button
                  onClick={handleSend}
                  disabled={
                    !input.trim() ||
                    isAnalyzing ||
                    !isModelLoaded ||
                    !(selectedConversationId || conversationId)
                  }
                  className="bg-gradient-primary text-primary-foreground shadow-glow hover:shadow-none transition-all"
                >
                  <Send className="w-4 h-4" />
                </Button>
              </div>
              <div className="max-w-4xl mx-auto text-xs text-muted-foreground mt-2">{remainingChars} characters remaining</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}