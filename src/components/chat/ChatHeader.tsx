import { Phone, Video, MoreVertical, ArrowLeft, Search, Bell, BellOff, User, Users } from "lucide-react";
import { Avatar } from "./Avatar";
import { Chat } from "@/types/chat";
import { cn } from "@/lib/utils";
import { startCallDm } from '@/lib/socket';
import { toast } from "sonner";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useState } from 'react';

interface ChatHeaderProps {
  chat: Chat;
  onBack?: () => void;
  isMobile?: boolean;
  onViewProfile?: (username: string) => void;
  onToggleUsers?: () => void;
  usersSidebarOpen?: boolean;
}

export function ChatHeader({ chat, onBack, isMobile, onViewProfile, onToggleUsers, usersSidebarOpen }: ChatHeaderProps) {
  const [showSearch, setShowSearch] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const handleSearch = () => {
    setShowSearch(!showSearch);
    if (!showSearch) {
      setSearchQuery('');
    }
  };

  const typingText =
    chat.isTyping && chat.isTyping.length > 0
      ? chat.isTyping.length === 1
        ? `${chat.isTyping[0]} is typing...`
        : `${chat.isTyping.length} people typing...`
      : null;

  const handleCall = () => {
    if (!chat?.name) {
      toast.error('Cannot call - no user selected');
      return;
    }

    try {
      startCallDm(chat.name);
      toast.success(`Calling ${chat.name}...`);
    } catch (error) {
      toast.error('Failed to start call');
    }
  };

  const handleVideoCall = () => {
    if (!chat?.name) {
      toast.error('Cannot call - no user selected');
      return;
    }

    try {
      startCallDm(chat.name);
      toast.success(`Video calling ${chat.name}...`);
    } catch (error) {
      toast.error('Failed to start video call');
    }
  };

  return (
    <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-card/50 backdrop-blur-sm">
      <div className="flex items-center gap-3">
        {isMobile && onBack && (
          <button
            onClick={onBack}
            className="p-2 -ml-2 rounded-lg hover:bg-muted transition-colors"
            aria-label="Go back"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
        )}

        <Avatar
          src={chat.avatar}
          name={chat.name}
          size="md"
          isOnline={!chat.isGroup}
        />

        <div>
          <h1 className="font-semibold text-foreground">{chat.name}</h1>
          <p
            className={cn(
              "text-xs",
              typingText ? "text-primary animate-pulse" : "text-muted-foreground"
            )}
          >
            {typingText || (chat.isGroup ? `${chat.members?.length || 0} members` : "Online")}
          </p>
        </div>
      </div>

      <div className="flex items-center gap-1">
        {showSearch ? (
          <div className="flex items-center gap-2 p-2 bg-muted rounded-lg">
            <input
              type="text"
              placeholder="Search in chat..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="flex-1 bg-background border border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2"
              autoFocus
            />
            <button
              onClick={() => setShowSearch(false)}
              className="p-2 rounded hover:bg-muted transition-colors"
            >
              Cancel
            </button>
          </div>
        ) : (
          <button
            className="p-2 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
            onClick={handleSearch}
            aria-label="Search in chat"
          >
            <Search className="w-5 h-5" />
          </button>
        )}
      </div>
      <div className="flex items-center gap-2">
        <button
          onClick={handleCall}
          className="p-2 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
          aria-label="Voice call"
        >
          <Phone className="w-5 h-5" />
        </button>
        <button
          onClick={handleVideoCall}
          className="p-2 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
          aria-label="Video call"
        >
          <Video className="w-5 h-5" />
        </button>
        <button
          onClick={onToggleUsers}
          className={cn(
            "p-2 rounded-lg transition-colors",
            usersSidebarOpen 
              ? "bg-primary text-primary-foreground" 
              : "text-muted-foreground hover:bg-muted hover:text-foreground"
          )}
          aria-label="Toggle users sidebar"
        >
          <Users className="w-5 h-5" />
        </button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              className="p-2 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
              aria-label="More options"
            >
              <MoreVertical className="w-5 h-5" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem>
              <BellOff className="w-4 h-4 mr-2" />
              Mute notifications
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => onViewProfile?.(chat.name)}>
              <User className="w-4 h-4 mr-2" />
              {chat.isGroup ? 'View group info' : 'View profile'}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => {
              // Clear chat functionality
              if (window.confirm('Are you sure you want to clear this chat? This action cannot be undone.')) {
                // Clear messages from state
                if (chat.id === 'public') {
                  // Clear public chat
                  window.location.reload();
                } else if (chat.id.startsWith('dm-')) {
                  // Clear DM chat
                  const peer = chat.id.replace('dm-', '');
                  // This would need an API call to clear DM messages
                  console.log('Clear DM chat with:', peer);
                } else if (chat.id.startsWith('gdm-')) {
                  // Clear group chat
                  const threadId = chat.id.replace('gdm-', '');
                  // This would need an API call to clear group messages
                  console.log('Clear group chat with:', threadId);
                }
              }
            }}>
              Clear chat
            </DropdownMenuItem>
            <DropdownMenuItem className="text-destructive">Block user</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  );
}
