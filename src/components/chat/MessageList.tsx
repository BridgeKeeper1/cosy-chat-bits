import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Message } from "@/types/chat";
import { MessageBubble } from "./MessageBubble";
import { TypingIndicator } from "./TypingIndicator";
import { MessageContextMenu } from "../ui/MessageContextMenu";
import { ChevronDown } from "lucide-react";
import { format, isSameDay } from "date-fns";

interface MessageListProps {
  messages: Message[];
  typingUsers: string[];
  onReact: (messageId: string, emoji: string) => void;
  onReply: (message: Message) => void;
  onEdit?: (messageId: string, content: string) => void;
  onDelete?: (messageId: string) => void;
  onViewProfile?: (username: string) => void;
}

export function MessageList({
  messages,
  typingUsers = [],
  onReact,
  onReply,
  onEdit,
  onDelete,
  onViewProfile,
}: MessageListProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [showScrollButton, setShowScrollButton] = useState(false);
  const [isAtBottom, setIsAtBottom] = useState(true);

  const scrollToBottom = (smooth = true) => {
    if (containerRef.current) {
      containerRef.current.scrollTo({
        top: containerRef.current.scrollHeight,
        behavior: smooth ? "smooth" : "auto",
      });
    }
  };

  useEffect(() => {
    if (isAtBottom) {
      scrollToBottom(false);
    }
  }, [messages, isAtBottom]);

  const handleScroll = () => {
    if (containerRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
      const atBottom = scrollHeight - scrollTop - clientHeight < 100;
      setIsAtBottom(atBottom);
      setShowScrollButton(!atBottom);
    }
  };

  // Group messages by date
  const groupedMessages: { date: Date; messages: Message[] }[] = [];
  messages.forEach((message) => {
    const lastGroup = groupedMessages[groupedMessages.length - 1];
    if (lastGroup && isSameDay(lastGroup.date, message.timestamp)) {
      lastGroup.messages.push(message);
    } else {
      groupedMessages.push({ date: message.timestamp, messages: [message] });
    }
  });

  return (
    <div className="relative flex-1 overflow-hidden">
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="h-full overflow-y-auto scroll-smooth"
      >
        <div className="py-4 space-y-4">
          {groupedMessages.map((group, groupIndex) => (
            <div key={groupIndex}>
              {/* Date separator */}
              <div className="flex items-center justify-center my-4">
                <div className="px-3 py-1 rounded-full bg-muted text-xs text-muted-foreground">
                  {format(group.date, "MMMM d, yyyy")}
                </div>
              </div>

              {/* Messages */}
              {group.messages.map((message, index) => {
                const prevMessage = group.messages[index - 1];
                const showAvatar =
                  !prevMessage ||
                  prevMessage.senderId !== message.senderId ||
                  message.timestamp.getTime() - prevMessage.timestamp.getTime() >
                    5 * 60 * 1000;

                return (
                  <MessageContextMenu
                    key={message.id}
                    message={message}
                    onEdit={onEdit}
                    onDelete={onDelete}
                    onReact={onReact}
                    onReply={onReply}
                    onViewProfile={onViewProfile}
                  >
                    <MessageBubble
                      key={message.id}
                      message={message}
                      showAvatar={showAvatar}
                      onReact={onReact}
                      onReply={onReply}
                    />
                  </MessageContextMenu>
                );
              })}
            </div>
          ))}

          <AnimatePresence>
            {typingUsers.length > 0 && <TypingIndicator names={typingUsers} />}
          </AnimatePresence>
        </div>
      </div>

      {/* Scroll to bottom button */}
      <AnimatePresence>
        {showScrollButton && (
          <motion.button
            initial={{ opacity: 0, scale: 0.8, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.8, y: 10 }}
            onClick={() => scrollToBottom()}
            className="absolute bottom-4 right-4 p-3 rounded-full bg-primary text-primary-foreground shadow-lg shadow-primary/25 hover:shadow-xl hover:shadow-primary/30 transition-shadow"
            aria-label="Scroll to bottom"
          >
            <ChevronDown className="w-5 h-5" />
          </motion.button>
        )}
      </AnimatePresence>
    </div>
  );
}
