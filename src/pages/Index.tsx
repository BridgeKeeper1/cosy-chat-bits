import { useState, useEffect, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import { ChatSidebar } from "@/components/chat/ChatSidebar";
import { ChatHeader } from "@/components/chat/ChatHeader";
import { ChatContainer } from "@/components/chat/ChatContainer";
import { UsersSidebar } from "@/components/chat/UsersSidebar";
import { IncomingCallModal } from "@/components/ui/IncomingCallModal";
import { CallInterface } from "@/components/ui/CallInterface";
import { ProfileModal } from "@/components/ui/ProfileModal";
import { GroupProfileModal } from "@/components/ui/GroupProfileModal";
import { messagesApi, usersApi, uploadFile, API_BASE, Message as ApiMessage, DmMessage, GdmThread, GdmMessage, OnlineUser } from "@/lib/api";
import { Message, Chat, Reaction } from "@/types/chat";
import { 
  connectSocket, 
  onPublicMessage, 
  onDmMessage, 
  onGdmMessage, 
  onTyping, 
  onStopTyping,
  onUserListRefresh,
  onSystemMessage,
  onIncomingCall,
  onCallAnswered,
  onCallEnded,
  onCallError,
  onMessageEdited,
  onMessageDeleted,
  onGdmThreadsRefresh,
  sendPublicMessage,
  sendDmMessage,
  sendGdmMessage,
  sendTypingPublic,
  sendStopTypingPublic,
  SocketMessage
} from "@/lib/socket";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";

const Index = () => {
  const { user, isLoading: authLoading, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  
  const [selectedChatId, setSelectedChatId] = useState<string | null>("public");
  const [publicMessages, setPublicMessages] = useState<Message[]>([]);
  const [dmMessages, setDmMessages] = useState<Record<string, Message[]>>({});
  const [gdmThreads, setGdmThreads] = useState<GdmThread[]>([]);
  const [gdmMessages, setGdmMessages] = useState<Record<number, Message[]>>({});
  const [onlineUsers, setOnlineUsers] = useState<OnlineUser[]>([]);
  const [usersSidebarOpen, setUsersSidebarOpen] = useState(false);
  const [typingUsers, setTypingUsers] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [chats, setChats] = useState<any[]>([]);
  const [profileModalOpen, setProfileModalOpen] = useState(false);
  const [groupProfileModalOpen, setGroupProfileModalOpen] = useState(false);
  const [profileUsername, setProfileUsername] = useState("");
  const [groupProfileInfo, setGroupProfileInfo] = useState({ id: "", name: "" });

  // Call state
  const [incomingCall, setIncomingCall] = useState<{
    call_id: string;
    from_user: string;
    call_type: 'voice' | 'video';
  } | null>(null);
  const [showIncomingCallModal, setShowIncomingCallModal] = useState(false);
  const [activeCall, setActiveCall] = useState<{
    callId: string;
    remoteUser: string;
    callType: 'voice' | 'video';
  } | null>(null);

  // Redirect to auth if not authenticated
  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      navigate('/auth');
    }
  }, [authLoading, isAuthenticated, navigate]);

  // Helper function to determine attachment type
  const getAttachmentType = (filename: string): "image" | "file" | "link" => {
    if (!filename || typeof filename !== 'string') return 'file';
    
    const ext = filename.split('.').pop()?.toLowerCase();
    if (!ext) return 'file';
    
    const imageExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'];
    const videoExts = ['mp4', 'webm', 'mov', 'avi'];
    const audioExts = ['mp3', 'wav', 'ogg'];
    
    if (imageExts.includes(ext)) return 'image';
    if (videoExts.includes(ext)) return 'file';
    if (audioExts.includes(ext)) return 'file';
    return 'file';
  };

  // Convert API messages to frontend Message format
  const convertApiMessage = useCallback((msg: Message | DmMessage | GdmMessage): Message => {
    // Get user avatar from online users or use default
    const getUserAvatar = (username: string): string | undefined => {
      // Check if user is in online users list
      const onlineUser = onlineUsers.find(u => u.username === username);
      return onlineUser?.avatar || user?.avatar;
    };

    // Extract sender information based on message type
    let senderId: string;
    let senderName: string;
    
    if ('username' in msg) {
      // Message type (public messages)
      senderId = msg.username;
      senderName = msg.username;
    } else if ('from_user' in msg) {
      // DmMessage type
      senderId = msg.from_user;
      senderName = msg.from_user;
    } else if ('username' in msg) {
      // GdmMessage type
      senderId = msg.username as string;
      senderName = msg.username as string;
    } else {
      senderId = '';
      senderName = 'Unknown';
    }

    return {
      id: String(msg.id),
      content: ('text' in msg) ? msg.text : '',
      senderId,
      senderName,
      senderAvatar: getUserAvatar(senderId),
      timestamp: ('created_at' in msg) ? new Date(msg.created_at) : new Date(),
      isOwn: senderId === user?.username,
      reactions: ('reactions' in msg) ? msg.reactions : [],
      attachment: ('attachment' in msg) ? {
        type: getAttachmentType(msg.attachment as string),
        url: `/uploads/${msg.attachment}`,
        name: typeof msg.attachment === 'string' ? msg.attachment : msg.attachment?.name || ''
      } : undefined,
      replyTo: ('reply_to' in msg && msg.reply_to) ? {
        id: String(msg.reply_to),
        content: (msg.reply_to as any)?.text || '',
        senderName: (msg.reply_to as any)?.username || (msg.reply_to as any)?.from_user || 'Unknown',
      } : undefined,
    };
  }, [onlineUsers, user]);

  // Load initial data
  const loadData = useCallback(async () => {
    if (!user) return;
    
    setIsLoading(true);
    try {
      // Load public messages
      const publicMsgs = await messagesApi.getPublicMessages();
      setPublicMessages(publicMsgs.map(m => convertApiMessage(m)));

      // Load DM peers
      const dmPeers = await messagesApi.getDmPeers();
      
      // Load GDM threads
      const gdmThreads = await messagesApi.getGdmThreads();

      // Load online users
      let onlineUsers: OnlineUser[] = [];
      try {
        onlineUsers = await usersApi.getOnlineUsers();
      } catch (e) {
        console.warn('Could not load online users');
      }

      // Build chat list
      const chatList: Chat[] = [
        {
          id: 'public',
          name: 'Public Chat',
          isGroup: true,
          lastMessage: publicMsgs[publicMsgs.length - 1]?.text || 'Start chatting!',
          lastMessageTime: publicMsgs[publicMsgs.length - 1]?.created_at 
            ? new Date(publicMsgs[publicMsgs.length - 1].created_at) 
            : new Date(),
          unreadCount: 0,
          members: onlineUsers.map(u => ({
            id: u.username,
            name: u.username,
            isOnline: true
          }))
        },
        ...dmPeers.map(peer => {
          const onlineUser = onlineUsers.find(u => u.username === peer);
          return {
            id: `dm-${peer}`,
            name: peer,
            isGroup: false,
            lastMessage: 'Direct message',
            lastMessageTime: new Date(),
            unreadCount: 0,
            members: onlineUser ? [{
              id: peer,
              name: peer,
              isOnline: true,
              lastSeen: new Date()
            }] : [{
              id: peer,
              name: peer,
              isOnline: false
            }]
          };
        }),
        ...gdmThreads.map(thread => {
          const threadMessages = gdmMessages[String(thread.id)] || [];
          const latestMessage = threadMessages[threadMessages.length - 1];
          
          return {
            id: `gdm-${thread.id}`,
            name: thread.name,
            isGroup: true,
            lastMessage: latestMessage?.content || 'Group message',
            lastMessageTime: latestMessage?.timestamp || new Date(),
            unreadCount: 0,
            members: thread.members?.map(m => ({ id: m, name: m, isOnline: false })),
          };
        }),
      ];
      
      setChats(chatList);
    } catch (error) {
      console.error('Failed to load chat data:', error);
    } finally {
      setIsLoading(false);
    }
  }, [user, convertApiMessage]);

  useEffect(() => {
    if (isAuthenticated && user) {
      loadData();
    }
  }, [isAuthenticated, user, loadData]);

  // Socket event handlers
  useEffect(() => {
    if (!isAuthenticated || !user) return;

    connectSocket();

    const unsubPublicMsg = onPublicMessage((msg: SocketMessage) => {
      const newMsg = convertApiMessage(msg as ApiMessage);
      setPublicMessages(prev => [...prev, newMsg]);
    });

    const unsubDmMsg = onDmMessage((msg) => {
      const peer = msg.from_user === user.username ? msg.to_user : msg.from_user;
      const newMsg = convertApiMessage(msg as DmMessage);
      setDmMessages(prev => ({
        ...prev,
        [peer]: [...(prev[peer] || []), newMsg],
      }));
    });

    const unsubGdmMsg = onGdmMessage((msg) => {
      const newMsg: Message = {
        id: String(msg.id),
        content: msg.text || '',
        senderId: msg.username,
        senderName: msg.username,
        timestamp: msg.created_at ? new Date(msg.created_at) : new Date(),
        isOwn: msg.username === user.username,
        reactions: [],
        isEdited: 'edited' in msg && typeof msg.edited === 'number' ? msg.edited > 0 : undefined,
      };
      
      setGdmMessages(prev => {
        const threadMessages = prev[String(msg.tid)] || [];
        // Remove optimistic message if it exists (for own messages)
        const filteredMessages = msg.username === user.username 
          ? threadMessages.filter(m => !m.id.startsWith('temp-'))
          : threadMessages;
        
        return {
          ...prev,
          [String(msg.tid)]: [...filteredMessages, newMsg],
        };
      });
    });

    const unsubTyping = onTyping((data) => {
      if (data.username !== user.username) {
        setTypingUsers(prev => prev.includes(data.username) ? prev : [...prev, data.username]);
      }
    });

    const unsubStopTyping = onStopTyping((data) => {
      setTypingUsers(prev => prev.filter(u => u !== data.username));
    });

    const unsubUserList = onUserListRefresh((data) => {
      // Handle user list refresh events
      if (data.online) {
        // User came online
        toast(`${data.online} is now online`);
      }
      if (data.offline) {
        // User went offline
        toast(`${data.offline} is now offline`);
      }
    });

    // Call event handlers
    const unsubIncomingCall = onIncomingCall((callData) => {
      setIncomingCall({
        ...callData,
        call_type: callData.call_type as 'voice' | 'video'
      });
      setShowIncomingCallModal(true);
      toast(`${callData.from_user} is calling you...`, {
        action: {
          label: 'Answer',
          onClick: () => {
            // Auto-answer logic could go here
          }
        }
      });
    });

    const unsubCallAnswered = onCallAnswered((data) => {
      if (data.answer) {
        // Call was accepted
        setActiveCall({
          callId: data.call_id,
          remoteUser: data.by_user,
          callType: incomingCall?.call_type || 'voice'
        });
        setShowIncomingCallModal(false);
      } else {
        // Call was declined
        toast(`${data.by_user} declined the call`);
        setShowIncomingCallModal(false);
      }
    });

    const unsubCallEnded = onCallEnded((data) => {
      toast(`Call ended by ${data.by_user}`);
      setActiveCall(null);
      setIncomingCall(null);
      setShowIncomingCallModal(false);
    });

    const unsubCallError = onCallError((data) => {
      toast.error(`Call error: ${data.error}`);
      setShowIncomingCallModal(false);
    });

    const unsubMessageEdited = onMessageEdited((data) => {
      // Update message in state when edited
      const updateMessageInArray = (messages: Message[]) => {
        return messages.map(msg => 
          msg.id === String(data.id) 
            ? { ...msg, content: data.content, edited: true, editedAt: data.edited_at }
            : msg
        );
      };

      setPublicMessages(prev => updateMessageInArray(prev));
      
      // Update DM messages
      setDmMessages(prev => {
        const updated = { ...prev };
        Object.keys(updated).forEach(key => {
          updated[key] = updateMessageInArray(updated[key]);
        });
        return updated;
      });

      // Update GDM messages
      setGdmMessages(prev => {
        const updated = { ...prev };
        Object.keys(updated).forEach(key => {
          updated[Number(key)] = updateMessageInArray(updated[Number(key)]);
        });
        return updated;
      });

      toast.info(`Message edited by ${data.edited_by}`);
    });

    const unsubMessageDeleted = onMessageDeleted((data) => {
      // Remove message from state when deleted
      const removeMessageFromArray = (messages: Message[]) => {
        return messages.filter(msg => msg.id !== String(data.id));
      };

      setPublicMessages(prev => removeMessageFromArray(prev));
      
      // Update DM messages
      setDmMessages(prev => {
        const updated = { ...prev };
        Object.keys(updated).forEach(key => {
          updated[key] = removeMessageFromArray(updated[key]);
        });
        return updated;
      });

      // Update GDM messages
      setGdmMessages(prev => {
        const updated = { ...prev };
        Object.keys(updated).forEach(key => {
          updated[Number(key)] = removeMessageFromArray(updated[Number(key)]);
        });
        return updated;
      });

      toast.info(`Message deleted by ${data.deleted_by}`);
    });

    const unsubSystemMsg = onSystemMessage((msg) => {
      setShowIncomingCallModal(false);
      // Handle system messages including call notifications
      if (msg.text.includes('call started')) {
        toast.info(msg.text);
      }
    });

    const unsubGdmThreadsRefresh = onGdmThreadsRefresh((data) => {
      if (data.deleted) {
        // Remove the deleted group from state
        setGdmThreads(prev => prev.filter(thread => thread.id !== data.deleted));
        toast.info('Group chat deleted');
      } else {
        // Refresh all GDM threads
        loadData();
      }
    });

    return () => {
      unsubPublicMsg();
      unsubDmMsg();
      unsubGdmMsg();
      unsubTyping();
      unsubStopTyping();
      unsubUserList();
      unsubSystemMsg();
      unsubGdmThreadsRefresh();
      unsubIncomingCall();
      unsubCallAnswered();
      unsubCallEnded();
      unsubCallError();
      unsubMessageEdited();
      unsubMessageDeleted();
    };
  }, [isAuthenticated, user, convertApiMessage, loadData]);

  const handleSelectChat = useCallback(async (chatId: string) => {
    setSelectedChatId(chatId || null);
    
    if (!chatId || !user) return;

    // Load messages for selected chat
    if (chatId.startsWith('dm-')) {
      const peer = chatId.replace('dm-', '');
      try {
        const msgs = await messagesApi.getDmMessages(peer);
        setDmMessages(prev => ({
          ...prev,
          [peer]: msgs.map(m => convertApiMessage(m)),
        }));
      } catch (e) {
        console.error('Failed to load DM messages:', e);
      }
    } else if (chatId.startsWith('gdm-')) {
      const tid = parseInt(chatId.replace('gdm-', ''));
      try {
        const msgs = await messagesApi.getGdmMessages(tid);
        setGdmMessages(prev => ({
          ...prev,
          [String(tid)]: msgs.map(m => convertApiMessage(m)),
        }));
      } catch (e) {
        console.error('Failed to load GDM messages:', e);
      }
    }

    // Clear unread count
    setChats(prev =>
      prev.map(chat =>
        chat.id === chatId ? { ...chat, unreadCount: 0 } : chat
      )
    );
  }, [user, convertApiMessage]);

  const handleSendMessage = useCallback(async (content: string, attachments?: File[]) => {
    if (!selectedChatId || !user) return;
    if (!content.trim() && (!attachments || attachments.length === 0)) return;

    let attachmentFilename: string | undefined;

    // Upload attachments if any
    if (attachments && attachments.length > 0) {
      try {
        const result = await uploadFile(attachments[0]);
        attachmentFilename = result.filename;
      } catch (error) {
        console.error('Failed to upload file:', error);
        toast.error('Failed to upload file');
        return;
      }
    }

    // Add optimistic update for GDM messages
    if (selectedChatId.startsWith('gdm-')) {
      const tid = parseInt(selectedChatId.replace('gdm-', ''));
      const optimisticMessage: Message = {
        id: `temp-${Date.now()}`,
        content: content,
        senderId: user.username,
        senderName: user.username,
        senderAvatar: user.avatar,
        timestamp: new Date(),
        isOwn: true,
        reactions: [],
      };
      
      setGdmMessages(prev => ({
        ...prev,
        [String(tid)]: [...(prev[String(tid)] || []), optimisticMessage],
      }));
    }

    // Add optimistic update for public messages
    if (selectedChatId === 'public') {
      const optimisticMessage: Message = {
        id: `temp-${Date.now()}`,
        content,
        senderId: user.username,
        senderName: user.username,
        senderAvatar: user.avatar,
        timestamp: new Date(),
        isOwn: true,
        reactions: [],
      };
      
      setPublicMessages(prev => [...prev, optimisticMessage]);
    } else if (selectedChatId.startsWith('dm-')) {
      const peer = selectedChatId.replace('dm-', '');
      sendDmMessage(peer, content, attachmentFilename);
    } else if (selectedChatId.startsWith('gdm-')) {
      const tid = parseInt(selectedChatId.replace('gdm-', ''));
      sendGdmMessage(tid, content, attachmentFilename);
    }
  }, [selectedChatId, user]);

  const handleReact = useCallback(async (messageId: string, emoji: string) => {
    if (!selectedChatId || !user) return;

    // For now, just show a toast - reactions functionality needs backend integration
    toast.info(`Reaction ${emoji} on message ${messageId} - Feature coming soon`);
  }, [selectedChatId, user]);

  const getCurrentMessages = useCallback((): Message[] => {
    if (selectedChatId === 'public') {
      return publicMessages;
    } else if (selectedChatId?.startsWith('dm-')) {
      const peer = selectedChatId.replace('dm-', '');
      return dmMessages[peer] || [];
    } else if (selectedChatId?.startsWith('gdm-')) {
      const tid = parseInt(selectedChatId.replace('gdm-', ''));
      return gdmMessages[tid] || [];
    }
    return [];
  }, [selectedChatId, publicMessages, dmMessages, gdmMessages]);

  const currentUser = useMemo(() => ({
    id: user?.username || '',
    name: user?.username || '',
    avatar: user?.avatar
  }), [user]);

  if (authLoading || isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <Loader2 className="w-8 h-8 animate-spin text-primary mx-auto mb-4" />
          <p className="text-muted-foreground">Loading Chatter...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  return (
    <>
      {/* Active Call Interface */}
      {activeCall && (
        <CallInterface
          callId={activeCall.callId}
          remoteUser={activeCall.remoteUser}
          callType={activeCall.callType}
          onEnd={() => setActiveCall(null)}
        />
      )}
      
      {/* Incoming Call Modal */}
      <IncomingCallModal
        isOpen={showIncomingCallModal}
        onClose={() => setShowIncomingCallModal(false)}
        callData={incomingCall}
      />
      
      {/* User Profile Modal */}
      <ProfileModal
        isOpen={profileModalOpen}
        onClose={() => setProfileModalOpen(false)}
        username={profileUsername}
      />
      
      {/* Group Profile Modal */}
      <GroupProfileModal
        isOpen={groupProfileModalOpen}
        onClose={() => setGroupProfileModalOpen(false)}
        groupId={groupProfileInfo.id}
        groupName={groupProfileInfo.name}
      />
      
      {/* Main Chat Interface */}
      <ChatContainer
        chats={chats}
        messages={getCurrentMessages()}
        selectedChatId={selectedChatId}
        typingUsers={typingUsers}
        currentUser={currentUser}
        onSelectChat={handleSelectChat}
        onSendMessage={handleSendMessage}
        onReact={handleReact}
        onViewProfile={(username) => {
          // Check if this is a group chat
          const chat = chats.find(c => c.name === username);
          if (chat?.isGroup) {
            setGroupProfileInfo({ id: chat.id, name: chat.name });
            setGroupProfileModalOpen(true);
          } else {
            setProfileUsername(username);
            setProfileModalOpen(true);
          }
        }}
      />
    </>
  );
};

export default Index;
