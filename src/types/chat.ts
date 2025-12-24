export interface User {
  id: string;
  name: string;
  username?: string;
  avatar?: string;
  bio?: string;
  status?: string;
  email?: string;
  isOnline: boolean;
  lastSeen?: Date;
}

export interface Reaction {
  emoji: string;
  users: string[];
}

export interface Message {
  id: string;
  content: string;
  senderId: string;
  senderName: string;
  senderAvatar?: string;
  timestamp: Date;
  isOwn: boolean;
  reactions: Reaction[];
  isEdited?: boolean;
  edited?: number;
  replyTo?: {
    id: string;
    content: string;
    senderName: string;
  };
  attachment?: {
    type: "image" | "file" | "link";
    url: string;
    name?: string;
    previewUrl?: string;
  };
}

export interface Chat {
  id: string;
  name: string;
  avatar?: string;
  isGroup: boolean;
  lastMessage?: string;
  lastMessageTime?: Date;
  unreadCount: number;
  members?: User[];
  isTyping?: string[];
}
