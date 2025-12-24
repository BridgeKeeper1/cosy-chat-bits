import { useState, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ChatSidebar } from "./ChatSidebar";
import { ChatHeader } from "./ChatHeader";
import { MessageList } from "./MessageList";
import { ChatInput } from "./ChatInput";
import { UsersSidebar } from "./UsersSidebar";
import { MessageSquare, Users } from "lucide-react";
import { cn } from "@/lib/utils";
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from "@/components/ui/resizable";
import { Chat } from "@/types/chat";
import { Message } from "@/types/chat";

// Mobile detection hook
const useMediaQuery = (query: string) => {
  const [matches, setMatches] = useState(false);

  useEffect(() => {
    const media = window.matchMedia(query);
    if (media.matches !== matches) {
      setMatches(media.matches);
    }
    const listener = () => setMatches(media.matches);
    window.addEventListener("resize", listener);
    return () => window.removeEventListener("resize", listener);
  }, [matches, query]);

  return matches;
};

// Sidebar size persistence
const DEFAULT_SIDEBAR_SIZE = 25;
const DEFAULT_CHAT_SIZE = 55;
const MIN_SIDEBAR_SIZE = 15;
const MAX_SIDEBAR_SIZE = 40;
const MIN_CHAT_SIZE = 30;

const getSavedSidebarSize = () => {
  try {
    const saved = localStorage.getItem('chat-sidebar-size');
    return saved ? parseFloat(saved) : DEFAULT_SIDEBAR_SIZE;
  } catch {
    return DEFAULT_SIDEBAR_SIZE;
  }
};

const getSavedChatSize = () => {
  try {
    const saved = localStorage.getItem('chat-panel-size');
    return saved ? parseFloat(saved) : DEFAULT_CHAT_SIZE;
  } catch {
    return DEFAULT_CHAT_SIZE;
  }
};

const saveSidebarSize = (size: number) => {
  try {
    localStorage.setItem('chat-sidebar-size', size.toString());
  } catch {
    // Silently fail
  }
};

const saveChatSize = (size: number) => {
  try {
    localStorage.setItem('chat-panel-size', size.toString());
  } catch {
    // Silently fail
  }
};

const resetSidebarSizes = () => {
  try {
    localStorage.removeItem('chat-sidebar-size');
    localStorage.removeItem('chat-panel-size');
  } catch {
    // Silently fail
  }
};

// Export reset function for use in settings
export const resetChatSidebarSizes = resetSidebarSizes;

interface ChatContainerProps {
  chats: Chat[];
  messages: Message[];
  selectedChatId: string | null;
  typingUsers: string[];
  currentUser: { id: string; name: string; avatar?: string };
  onSelectChat: (chatId: string) => void;
  onSendMessage: (content: string, attachments?: File[]) => void;
  onReact: (messageId: string, emoji: string) => void;
  onViewProfile: (username: string) => void;
  onReply?: (message: Message) => void;
  onCancelReply?: () => void;
}

export function ChatContainer({
  chats,
  messages,
  selectedChatId,
  typingUsers,
  currentUser,
  onSelectChat,
  onSendMessage,
  onReact,
  onViewProfile,
  onReply,
  onCancelReply,
}: ChatContainerProps) {
  const [replyTo, setReplyTo] = useState<Message | null>(null);
  const [showSidebar, setShowSidebar] = useState(true);
  const [usersSidebarOpen, setUsersSidebarOpen] = useState(false);
  const [sidebarSize, setSidebarSize] = useState(getSavedSidebarSize());
  const [chatSize, setChatSize] = useState(getSavedChatSize());

  // Save sizes when they change
  const handleSidebarResize = (size: number) => {
    setSidebarSize(size);
    saveSidebarSize(size);
  };

  const handleChatResize = (size: number) => {
    setChatSize(size);
    saveChatSize(size);
  };

  // Reset sizes function
  const resetSizes = () => {
    resetSidebarSizes();
    setSidebarSize(DEFAULT_SIDEBAR_SIZE);
    setChatSize(DEFAULT_CHAT_SIZE);
  };

  const isMobile = useMediaQuery("(max-width: 768px)");

  const selectedChat = chats.find((c) => c.id === selectedChatId);

  const handleReply = (message: Message) => {
    setReplyTo(message);
  };

  const handleCancelReply = () => {
    setReplyTo(null);
  };

  const handleSend = (content: string, attachments?: File[]) => {
    onSendMessage(content, attachments);
    setReplyTo(null);
  };

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      {isMobile ? (
        // Mobile layout - keep existing behavior
        <>
          {/* Sidebar */}
          <AnimatePresence mode="wait">
            {(!isMobile || (isMobile && !selectedChatId)) && (
              <motion.div
                initial={{ x: -300, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                exit={{ x: -300, opacity: 0 }}
                transition={{ type: "spring", damping: 25, stiffness: 200 }}
                className="w-full md:w-80 lg:w-96 shrink-0"
              >
                <ChatSidebar
                  chats={chats}
                  selectedChatId={selectedChatId}
                  onSelectChat={onSelectChat}
                  currentUser={currentUser}
                />
              </motion.div>
            )}
          </AnimatePresence>

          {/* Main chat area */}
          <AnimatePresence mode="wait">
            {selectedChat ? (
              <motion.div
                key={selectedChatId}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.2 }}
                className="flex-1 flex flex-col min-w-0"
              >
                <ChatHeader
                  chat={selectedChat}
                  onToggleUsers={() => setUsersSidebarOpen(!usersSidebarOpen)}
                  usersSidebarOpen={usersSidebarOpen}
                />
                <MessageList
                  messages={messages}
                  typingUsers={typingUsers}
                  onReact={onReact}
                  onReply={handleReply}
                  onViewProfile={onViewProfile}
                />
                <ChatInput
                  onSend={handleSend}
                  replyTo={replyTo}
                  onCancelReply={handleCancelReply}
                />
              </motion.div>
            ) : (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex-1 flex items-center justify-center"
              >
                <div className="text-center">
                  <MessageSquare className="w-16 h-16 mx-auto mb-4 text-muted-foreground" />
                  <h2 className="text-2xl font-semibold mb-2">Welcome to Chatter</h2>
                  <p className="text-muted-foreground">Select a chat to start messaging</p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Users Sidebar */}
          <AnimatePresence>
            {usersSidebarOpen && (
              <motion.div
                initial={{ x: 300, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                exit={{ x: 300, opacity: 0 }}
                transition={{ type: "spring", damping: 25, stiffness: 200 }}
                className="w-80 shrink-0"
              >
                <UsersSidebar isOpen={usersSidebarOpen} onToggle={() => setUsersSidebarOpen(!usersSidebarOpen)} />
              </motion.div>
            )}
          </AnimatePresence>
        </>
      ) : (
        // Desktop layout - use resizable panels
        <ResizablePanelGroup direction="horizontal" className="h-full">
          <ResizablePanel 
            defaultSize={sidebarSize} 
            minSize={MIN_SIDEBAR_SIZE} 
            maxSize={MAX_SIDEBAR_SIZE} 
            className="shrink-0"
            onResize={handleSidebarResize}
          >
            <ChatSidebar
              chats={chats}
              selectedChatId={selectedChatId}
              onSelectChat={onSelectChat}
              currentUser={currentUser}
            />
          </ResizablePanel>
          
          <ResizableHandle withHandle />
          
          <ResizablePanel 
            defaultSize={chatSize} 
            minSize={MIN_CHAT_SIZE}
            onResize={handleChatResize}
          >
            {selectedChat ? (
              <div className="flex-1 flex flex-col h-full">
                <ChatHeader
                  chat={selectedChat}
                  onToggleUsers={() => setUsersSidebarOpen(!usersSidebarOpen)}
                  usersSidebarOpen={usersSidebarOpen}
                />
                <MessageList
                  messages={messages}
                  typingUsers={typingUsers}
                  onReact={onReact}
                  onReply={handleReply}
                  onViewProfile={onViewProfile}
                />
                <ChatInput
                  onSend={handleSend}
                  replyTo={replyTo}
                  onCancelReply={handleCancelReply}
                />
              </div>
            ) : (
              <div className="flex-1 flex items-center justify-center h-full">
                <div className="text-center">
                  <MessageSquare className="w-16 h-16 mx-auto mb-4 text-muted-foreground" />
                  <h2 className="text-2xl font-semibold mb-2">Welcome to Chatter</h2>
                  <p className="text-muted-foreground">Select a chat to start messaging</p>
                </div>
              </div>
            )}
          </ResizablePanel>
          
          <UsersSidebar isOpen={usersSidebarOpen} onToggle={() => setUsersSidebarOpen(!usersSidebarOpen)} />
        </ResizablePanelGroup>
      )}
    </div>
  );
}
