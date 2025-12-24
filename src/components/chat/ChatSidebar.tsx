import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Search, Plus, Settings, MessageSquare, Users, Hash, Shield, LogOut, UserPlus } from "lucide-react";
import { cn } from "@/lib/utils";
import { Chat } from "@/types/chat";
import { messagesApi } from "@/lib/api";
import { Avatar } from "./Avatar";
import { PresenceIndicator } from "./PresenceIndicator";
import { ThemeToggle } from "./ThemeToggle";
import { format, isToday, isYesterday } from "date-fns";
import { useAuth } from "@/contexts/AuthContext";
import { useOnlineUsers } from "@/hooks/useOnlineUsers";
import { sendDmMessage } from "@/lib/socket";
import { toast } from "sonner";
import { GroupContextMenu } from "./GroupContextMenu";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface ChatSidebarProps {
  chats: Chat[];
  selectedChatId: string | null;
  onSelectChat: (chatId: string) => void;
  currentUser: { name: string; avatar?: string };
}

const formatLastMessageTime = (date?: Date) => {
  if (!date) return "";
  if (isToday(date)) return format(date, "h:mm a");
  if (isYesterday(date)) return "Yesterday";
  return format(date, "MMM d");
};

export function ChatSidebar({
  chats,
  selectedChatId,
  onSelectChat,
  currentUser,
}: ChatSidebarProps) {
  const [search, setSearch] = useState("");
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const { isUserOnline, onlineUsers } = useOnlineUsers();
  
  // New conversation dialog state
  const [newDmDialog, setNewDmDialog] = useState(false);
  const [newGdmDialog, setNewGdmDialog] = useState(false);
  const [dmUsername, setDmUsername] = useState("");
  const [gdmName, setGdmName] = useState("");
  const [gdmMembers, setGdmMembers] = useState("");

  const filteredChats = chats.filter((chat) =>
    chat.name.toLowerCase().includes(search.toLowerCase())
  );

  const handleCreateDm = async () => {
    if (!dmUsername.trim()) return;
    try {
      // Send an initial message to create the DM conversation
      sendDmMessage(dmUsername.trim(), "Started conversation");
      toast.success(`Started conversation with ${dmUsername}`);
      setNewDmDialog(false);
      setDmUsername("");
      // Select the DM chat
      onSelectChat(`dm-${dmUsername}`);
    } catch (error) {
      toast.error("Failed to create conversation");
    }
  };

  const handleCreateGdm = async () => {
    if (!gdmName.trim() || !gdmMembers.trim()) return;
    try {
      const members = gdmMembers.split(',').map(m => m.trim()).filter(m => m);
      const result = await messagesApi.createGdmThread(gdmName, members);
      if (result.ok) {
        toast.success(`Group chat "${gdmName}" created`);
        setNewGdmDialog(false);
        setGdmName("");
        setGdmMembers("");
        // Navigate to the new group chat
        window.location.href = `/chat?gdm=${result.id}`;
      }
    } catch (error) {
      toast.error("Failed to create group chat");
    }
  };

  return (
    <div className="flex flex-col h-full bg-chat-sidebar border-r border-border">
      {/* Header */}
      <div className="p-4 border-b border-border">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Avatar src={currentUser.avatar} name={currentUser.name} isOnline />
            <div>
              <h2 className="font-semibold text-foreground">{currentUser.name}</h2>
              <p className="text-xs text-muted-foreground">Online</p>
            </div>
          </div>
          <div className="flex items-center gap-1">
            {/* Search */}
            <div className="relative mr-2">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search conversations..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-40 pl-10 pr-4 py-2 rounded-lg bg-muted border-0 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
            <ThemeToggle />
            <button
              onClick={() => navigate('/settings')}
              className="p-2 rounded-lg hover:bg-muted transition-colors text-muted-foreground"
              aria-label="Settings"
            >
              <Settings className="w-5 h-5" />
            </button>
            {(user?.isAdmin || user?.isSuperadmin) && (
              <button
                onClick={() => navigate('/admin')}
                className="p-2 rounded-lg hover:bg-muted transition-colors text-muted-foreground"
                aria-label="Admin Dashboard"
              >
                <Shield className="w-5 h-5" />
              </button>
            )}
            <button
              onClick={logout}
              className="p-2 rounded-lg hover:bg-muted transition-colors text-muted-foreground"
              aria-label="Logout"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>

      {/* Chat list */}
      <div className="flex-1 overflow-y-auto py-2">
        <div className="px-3 mb-2 space-y-1">
          <button 
            onClick={() => setNewDmDialog(true)}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-xl text-sm text-primary hover:bg-primary/10 transition-colors"
          >
            <UserPlus className="w-4 h-4" />
            New Direct Message
          </button>
          <button 
            onClick={() => setNewGdmDialog(true)}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-xl text-sm text-primary hover:bg-primary/10 transition-colors"
          >
            <Users className="w-4 h-4" />
            New Group Chat
          </button>
        </div>

        <div className="px-3 space-y-1">
          {filteredChats.map((chat) => {
            // For DM chats, get the peer username and check if online
            const isDm = chat.id.startsWith('dm-');
            const peerUsername = isDm ? chat.id.replace('dm-', '') : '';
            const isPeerOnline = isDm ? isUserOnline(peerUsername) : false;
            
            return (
              <>
                {chat.isGroup ? (
                  <GroupContextMenu
                    key={chat.id}
                    groupId={chat.id}
                    groupName={chat.name}
                    isOwner={false} // TODO: Determine ownership from API
                    onGroupUpdate={() => {
                      // Refresh chat list if needed
                    }}
                  >
                    <motion.button
                      whileHover={{ scale: 1.01 }}
                      whileTap={{ scale: 0.99 }}
                      onClick={() => onSelectChat(chat.id)}
                      className={cn(
                        "w-full flex items-center gap-3 p-3 rounded-xl transition-all text-left",
                        selectedChatId === chat.id
                          ? "bg-primary/10 border border-primary/20"
                          : "hover:bg-muted"
                      )}
                    >
                      <div className="relative">
                        <Avatar
                          src={chat.avatar}
                          name={chat.name}
                          isOnline={isDm ? isPeerOnline : undefined}
                        />
                        {chat.isGroup && (
                          <div className="absolute -bottom-1 -right-1 w-5 h-5 rounded-full bg-secondary flex items-center justify-center">
                            <Users className="w-3 h-3 text-secondary-foreground" />
                          </div>
                        )}
                      </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-foreground truncate">
                          {chat.name}
                        </span>
                        <span className="text-[11px] text-muted-foreground">
                          {formatLastMessageTime(chat.lastMessageTime)}
                        </span>
                      </div>
                      <div className="flex items-center justify-between mt-0.5">
                        <p className="text-sm text-muted-foreground truncate max-w-[180px]">
                          {chat.isTyping && chat.isTyping.length > 0
                            ? `${chat.isTyping[0]} is typing...`
                            : chat.lastMessage || "No messages yet"}
                        </p>
                        {chat.unreadCount > 0 && (
                          <span className="min-w-[20px] h-5 flex items-center justify-center px-1.5 rounded-full bg-primary text-primary-foreground text-xs font-medium">
                            {chat.unreadCount > 99 ? "99+" : chat.unreadCount}
                          </span>
                        )}
                      </div>
                      </div>
                    </motion.button>
                  </GroupContextMenu>
                ) : (
                  <motion.button
                    key={chat.id}
                    whileHover={{ scale: 1.01 }}
                    whileTap={{ scale: 0.99 }}
                    onClick={() => onSelectChat(chat.id)}
                    className={cn(
                      "w-full flex items-center gap-3 p-3 rounded-xl transition-all text-left",
                      selectedChatId === chat.id
                        ? "bg-primary/10 border border-primary/20"
                        : "hover:bg-muted"
                    )}
                  >
                    <div className="relative">
                      <Avatar
                        src={chat.avatar}
                        name={chat.name}
                        isOnline={isPeerOnline}
                      />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-foreground truncate">
                          {chat.name}
                        </span>
                        <span className="text-[11px] text-muted-foreground">
                          {formatLastMessageTime(chat.lastMessageTime)}
                        </span>
                      </div>
                      <div className="flex items-center justify-between mt-0.5">
                        <p className="text-sm text-muted-foreground truncate max-w-[180px]">
                          {chat.isTyping && chat.isTyping.length > 0
                            ? `${chat.isTyping[0]} is typing...`
                            : chat.lastMessage || "No messages yet"}
                        </p>
                        {chat.unreadCount > 0 && (
                          <span className="min-w-[20px] h-5 flex items-center justify-center px-1.5 rounded-full bg-primary text-primary-foreground text-xs font-medium">
                            {chat.unreadCount > 99 ? "99+" : chat.unreadCount}
                          </span>
                        )}
                      </div>
                    </div>
                  </motion.button>
                )}
              </>
            );
          })}
        </div>
      </div>

      {/* New DM Dialog */}
      <Dialog open={newDmDialog} onOpenChange={setNewDmDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Direct Message</DialogTitle>
            <DialogDescription>
              Start a conversation with another user.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="dm-username">Username</Label>
              <Input
                id="dm-username"
                placeholder="Enter username"
                value={dmUsername}
                onChange={(e) => setDmUsername(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleCreateDm()}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setNewDmDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreateDm} disabled={!dmUsername.trim()}>
              Start Chat
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* New Group Chat Dialog */}
      <Dialog open={newGdmDialog} onOpenChange={setNewGdmDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Group Chat</DialogTitle>
            <DialogDescription>
              Create a group chat with multiple users.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="gdm-name">Group Name</Label>
              <Input
                id="gdm-name"
                placeholder="Enter group name"
                value={gdmName}
                onChange={(e) => setGdmName(e.target.value)}
              />
            </div>
            <div>
              <Label htmlFor="gdm-members">Members</Label>
              <Input
                id="gdm-members"
                placeholder="user1, user2, user3"
                value={gdmMembers}
                onChange={(e) => setGdmMembers(e.target.value)}
              />
              <p className="text-xs text-muted-foreground mt-1">
                Separate usernames with commas
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setNewGdmDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreateGdm} disabled={!gdmName.trim() || !gdmMembers.trim()}>
              Create Group
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
