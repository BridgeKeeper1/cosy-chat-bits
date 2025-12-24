import { cn } from "@/lib/utils";

interface PresenceIndicatorProps {
  isOnline: boolean;
  size?: "sm" | "md" | "lg";
  className?: string;
  showLabel?: boolean;
}

const sizeClasses = {
  sm: "w-2 h-2",
  md: "w-2.5 h-2.5",
  lg: "w-3 h-3",
};

export function PresenceIndicator({
  isOnline,
  size = "md",
  className,
  showLabel = false,
}: PresenceIndicatorProps) {
  return (
    <div className={cn("flex items-center gap-1.5", className)}>
      <span
        className={cn(
          "rounded-full ring-2 ring-background",
          sizeClasses[size],
          isOnline ? "bg-emerald-500" : "bg-muted-foreground"
        )}
        aria-label={isOnline ? "Online" : "Offline"}
      />
      {showLabel && (
        <span className={cn(
          "text-xs",
          isOnline ? "text-emerald-500" : "text-muted-foreground"
        )}>
          {isOnline ? "Online" : "Offline"}
        </span>
      )}
    </div>
  );
}
