import { useState, useRef, KeyboardEvent } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Send, Smile, Paperclip, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Message } from "@/types/chat";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

interface ChatInputProps {
  onSend: (content: string, attachments?: File[]) => void;
  replyTo?: Message | null;
  onCancelReply?: () => void;
  disabled?: boolean;
}

const QUICK_EMOJIS = ["😊", "😂", "❤️", "👍", "🎉", "🔥", "👏", "🙏", "😍", "🤔", "😢", "😮", "🎊", "✨", "💪", "🚀"];

export function ChatInput({
  onSend,
  replyTo,
  onCancelReply,
  disabled,
}: ChatInputProps) {
  const [message, setMessage] = useState("");
  const [attachments, setAttachments] = useState<File[]>([]);
  const [showEmoji, setShowEmoji] = useState(false);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSubmit = () => {
    if (message.trim() || attachments.length > 0) {
      onSend(message.trim(), attachments);
      setMessage("");
      setAttachments([]);
    }
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const handleEmojiSelect = (emoji: string) => {
    setMessage((prev) => prev + emoji);
    inputRef.current?.focus();
    setShowEmoji(false);
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    setAttachments((prev) => [...prev, ...files]);
    e.target.value = "";
  };

  const removeAttachment = (index: number) => {
    setAttachments((prev) => prev.filter((_, i) => i !== index));
  };

  return (
    <div className="px-4 pb-4 pt-2">
      <AnimatePresence>
        {replyTo && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="mb-2 flex items-center gap-2 px-3 py-2 rounded-lg bg-muted border-l-2 border-primary"
          >
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-muted-foreground">
                Replying to {replyTo.senderName}
              </p>
              <p className="text-sm truncate">{replyTo.content}</p>
            </div>
            <button
              onClick={onCancelReply}
              className="p-1 rounded hover:bg-background/50 transition-colors"
              aria-label="Cancel reply"
            >
              <X className="w-4 h-4" />
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Attachment previews */}
      <AnimatePresence>
        {attachments.length > 0 && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="mb-2 flex flex-wrap gap-2"
          >
            {attachments.map((file, index) => (
              <div
                key={index}
                className="relative group rounded-lg overflow-hidden bg-muted"
              >
                {file.type.startsWith("image/") ? (
                  <img
                    src={URL.createObjectURL(file)}
                    alt={file.name}
                    className="w-20 h-20 object-cover"
                  />
                ) : (
                  <div className="w-20 h-20 flex items-center justify-center text-xs text-center p-2">
                    {file.name}
                  </div>
                )}
                <button
                  onClick={() => removeAttachment(index)}
                  className="absolute top-1 right-1 p-1 rounded-full bg-destructive text-destructive-foreground opacity-0 group-hover:opacity-100 transition-opacity"
                  aria-label="Remove attachment"
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
            ))}
          </motion.div>
        )}
      </AnimatePresence>

      <div className="chat-input-wrapper">
        <div className="flex items-end gap-2 p-2">
          <div className="flex items-center gap-1">
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileSelect}
              multiple
              className="hidden"
              accept="image/*,.pdf,.doc,.docx,.txt"
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              className="p-2 rounded-xl hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
              aria-label="Attach file"
              disabled={disabled}
            >
              <Paperclip className="w-5 h-5" />
            </button>

            <Popover open={showEmoji} onOpenChange={setShowEmoji}>
              <PopoverTrigger asChild>
                <button
                  className="p-2 rounded-xl hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                  aria-label="Add emoji"
                  disabled={disabled}
                >
                  <Smile className="w-5 h-5" />
                </button>
              </PopoverTrigger>
              <PopoverContent
                side="top"
                align="start"
                className="w-auto p-3"
              >
                <div className="grid grid-cols-8 gap-1">
                  {QUICK_EMOJIS.map((emoji) => (
                    <button
                      key={emoji}
                      onClick={() => handleEmojiSelect(emoji)}
                      className="w-8 h-8 flex items-center justify-center text-lg hover:bg-muted rounded transition-colors"
                    >
                      {emoji}
                    </button>
                  ))}
                </div>
              </PopoverContent>
            </Popover>
          </div>

          <textarea
            ref={inputRef}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type a message..."
            disabled={disabled}
            rows={1}
            className={cn(
              "flex-1 bg-transparent border-0 resize-none focus:outline-none focus:ring-0",
              "placeholder:text-muted-foreground text-foreground",
              "min-h-[40px] max-h-[120px] py-2.5 px-1"
            )}
            style={{ overflow: "auto" }}
          />

          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={handleSubmit}
            disabled={disabled || (!message.trim() && attachments.length === 0)}
            className={cn(
              "p-3 rounded-xl transition-all",
              message.trim() || attachments.length > 0
                ? "bg-primary text-primary-foreground shadow-lg shadow-primary/25"
                : "bg-muted text-muted-foreground"
            )}
            aria-label="Send message"
          >
            <Send className="w-5 h-5" />
          </motion.button>
        </div>
      </div>
    </div>
  );
}
