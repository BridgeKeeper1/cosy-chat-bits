import { useState } from "react";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { Message } from "@/types/chat";
import { Avatar } from "./Avatar";
import { MessageReactions } from "./MessageReactions";
import { Check, CheckCheck, MoreHorizontal, Reply, Smile, Copy, Trash2, FileText, Download, Image as ImageIcon } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { format, isToday, isYesterday } from "date-fns";

interface MessageBubbleProps {
  message: Message;
  showAvatar?: boolean;
  onReact: (messageId: string, emoji: string) => void;
  onReply: (message: Message) => void;
}

const formatMessageTime = (date: Date) => {
  if (isToday(date)) {
    return format(date, "h:mm a");
  } else if (isYesterday(date)) {
    return `Yesterday ${format(date, "h:mm a")}`;
  }
  return format(date, "MMM d, h:mm a");
};

export function MessageBubble({
  message,
  showAvatar = true,
  onReact,
  onReply,
}: MessageBubbleProps) {
  const [showActions, setShowActions] = useState(false);
  const quickReactions = ["👍", "❤️", "😂", "😮", "😢", "🔥"];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.2 }}
      className={cn(
        "group flex gap-2 px-4 py-1 hover:bg-muted/30 transition-colors",
        message.isOwn ? "flex-row-reverse" : "flex-row"
      )}
      onMouseEnter={() => setShowActions(true)}
      onMouseLeave={() => setShowActions(false)}
    >
      {showAvatar ? (
        <Avatar
          src={message.senderAvatar}
          name={message.senderName}
          size="sm"
          className="mt-1"
        />
      ) : (
        <div className="w-8" />
      )}

      <div
        className={cn(
          "flex flex-col max-w-[70%]",
          message.isOwn ? "items-end" : "items-start"
        )}
      >
        {showAvatar && !message.isOwn && (
          <span className="text-xs font-medium text-muted-foreground mb-1 px-1">
            {message.senderName}
          </span>
        )}

        {message.replyTo && (
          <div className="flex items-center gap-1 text-xs text-muted-foreground mb-1 px-2 py-1 rounded bg-muted/50 border-l-2 border-primary">
            <Reply className="w-3 h-3" />
            <span className="font-medium">{message.replyTo.senderName}:</span>
            <span className="truncate max-w-[150px]">{message.replyTo.content}</span>
          </div>
        )}

        <div className="relative">
          <div
            className={cn(
              "px-4 py-2.5 rounded-2xl break-words",
              message.isOwn
                ? "message-bubble-own rounded-br-md"
                : "message-bubble-other rounded-bl-md"
            )}
          >
            {message.attachment && (
              <div className="mb-2">
                {message.attachment.type === "image" && (
                  <a href={message.attachment.url} target="_blank" rel="noopener noreferrer">
                    <img
                      src={message.attachment.url}
                      alt={message.attachment.name || "Image"}
                      className="rounded-lg max-w-full max-h-60 object-cover cursor-pointer hover:opacity-90 transition-opacity"
                    />
                  </a>
                )}
                {message.attachment.type === "file" && (
                  <a
                    href={message.attachment.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    download
                    className="flex items-center gap-2 p-3 rounded-lg bg-background/50 hover:bg-background/80 transition border border-border"
                  >
                    <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                      <FileText className="w-5 h-5 text-primary" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{message.attachment.name || 'File'}</p>
                      <p className="text-xs text-muted-foreground">Click to download</p>
                    </div>
                    <Download className="w-4 h-4 text-muted-foreground" />
                  </a>
                )}
                {message.attachment.type === "link" && message.attachment.previewUrl && (
                  <a
                    href={message.attachment.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block p-2 rounded-lg bg-background/50 hover:bg-background/80 transition"
                  >
                    <img
                      src={message.attachment.previewUrl}
                      alt="Link preview"
                      className="rounded w-full h-32 object-cover mb-2"
                    />
                    <span className="text-sm text-primary underline">
                      {message.attachment.name || message.attachment.url}
                    </span>
                  </a>
                )}
              </div>
            )}

            <div 
              className="text-[15px] leading-relaxed whitespace-pre-wrap"
              dangerouslySetInnerHTML={{ __html: message.content }}
            />
          </div>

          {/* Quick action buttons */}
          <motion.div
            initial={false}
            animate={{ opacity: showActions ? 1 : 0 }}
            className={cn(
              "absolute top-1/2 -translate-y-1/2 flex items-center gap-0.5 bg-card border border-border rounded-lg shadow-lg p-0.5",
              message.isOwn ? "-left-24" : "-right-24"
            )}
          >
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  className="p-1.5 rounded hover:bg-muted transition-colors"
                  aria-label="Add reaction"
                >
                  <Smile className="w-4 h-4 text-muted-foreground" />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align={message.isOwn ? "end" : "start"} className="p-2">
                <div className="flex gap-1">
                  {quickReactions.map((emoji) => (
                    <button
                      key={emoji}
                      onClick={() => onReact(message.id, emoji)}
                      className="p-1.5 hover:bg-muted rounded transition-colors text-lg"
                    >
                      {emoji}
                    </button>
                  ))}
                </div>
              </DropdownMenuContent>
            </DropdownMenu>

            <button
              onClick={() => onReply(message)}
              className="p-1.5 rounded hover:bg-muted transition-colors"
              aria-label="Reply"
            >
              <Reply className="w-4 h-4 text-muted-foreground" />
            </button>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  className="p-1.5 rounded hover:bg-muted transition-colors"
                  aria-label="More options"
                >
                  <MoreHorizontal className="w-4 h-4 text-muted-foreground" />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align={message.isOwn ? "end" : "start"}>
                <DropdownMenuItem>
                  <Copy className="w-4 h-4 mr-2" />
                  Copy text
                </DropdownMenuItem>
                {message.isOwn && (
                  <DropdownMenuItem className="text-destructive">
                    <Trash2 className="w-4 h-4 mr-2" />
                    Delete
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          </motion.div>
        </div>

        <MessageReactions
          reactions={message.reactions}
          onReact={(emoji) => onReact(message.id, emoji)}
        />

        <div
          className={cn(
            "flex items-center gap-1.5 mt-1 px-1",
            message.isOwn ? "flex-row-reverse" : "flex-row"
          )}
        >
          <span className="text-[10px] text-muted-foreground">
            {formatMessageTime(message.timestamp)}
          </span>
          {message.isEdited && (
            <span className="text-[10px] text-muted-foreground">(edited)</span>
          )}
          {message.isOwn && (
            <CheckCheck className="w-3.5 h-3.5 text-primary" />
          )}
        </div>
      </div>
    </motion.div>
  );
}
