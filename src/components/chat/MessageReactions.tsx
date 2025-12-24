import { cn } from "@/lib/utils";
import { Reaction } from "@/types/chat";
import { motion, AnimatePresence } from "framer-motion";

interface MessageReactionsProps {
  reactions: Reaction[];
  onReact: (emoji: string) => void;
}

export function MessageReactions({ reactions, onReact }: MessageReactionsProps) {
  if (reactions.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-1 mt-1 px-1">
      <AnimatePresence>
        {reactions.map((reaction) => (
          <motion.button
            key={reaction.emoji}
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            exit={{ scale: 0 }}
            whileHover={{ scale: 1.1 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => onReact(reaction.emoji)}
            className={cn(
              "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs",
              "bg-muted hover:bg-muted/80 transition-colors",
              "border border-border"
            )}
          >
            <span>{reaction.emoji}</span>
            <span className="font-medium text-muted-foreground">
              {reaction.users.length}
            </span>
          </motion.button>
        ))}
      </AnimatePresence>
    </div>
  );
}
