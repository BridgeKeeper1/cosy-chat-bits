import { useState } from 'react';
import { cn } from "@/lib/utils";

interface AvatarProps {
  src?: string;
  name: string;
  size?: "sm" | "md" | "lg";
  isOnline?: boolean;
  className?: string;
}

const sizeClasses = {
  sm: "w-8 h-8 text-xs",
  md: "w-10 h-10 text-sm",
  lg: "w-12 h-12 text-base",
};

const getInitials = (name: string) => {
  return name
    .split(" ")
    .map((n) => n[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);
};

const getAvatarColor = (name: string) => {
  const colors = [
    "bg-rose-500",
    "bg-pink-500",
    "bg-fuchsia-500",
    "bg-purple-500",
    "bg-indigo-500",
    "bg-blue-500",
    "bg-sky-500",
    "bg-cyan-500",
    "bg-teal-500",
    "bg-emerald-500",
    "bg-green-500",
    "bg-lime-500",
    "bg-yellow-500",
    "bg-amber-500",
    "bg-orange-500",
    "bg-red-500",
  ];
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash);
  }
  return colors[Math.abs(hash) % colors.length];
};

const getAvatarUrl = (src?: string) => {
  if (!src) return undefined;
  if (src.includes('/uploads/')) {
    const baseUrl = src.split('?')[0];
    const timestamp = Date.now();
    return `${baseUrl}?t=${timestamp}`;
  }
  const baseUrl = src.startsWith('/') ? src : `/uploads/${src}`;
  const timestamp = Date.now();
  return `${baseUrl}?t=${timestamp}`;
};

export function Avatar({ src, name, size = "md", isOnline, className }: AvatarProps) {
  const [showFallback, setShowFallback] = useState(false);
  const avatarUrl = getAvatarUrl(src);

  return (
    <div className={cn("relative inline-flex shrink-0", className)}>
      {avatarUrl && !showFallback ? (
        <img
          src={avatarUrl}
          alt={name}
          className={cn(
            "rounded-full object-cover ring-2 ring-background",
            sizeClasses[size]
          )}
          onError={() => setShowFallback(true)}
        />
      ) : (
        <div
          className={cn(
            "rounded-full flex items-center justify-center font-semibold text-white ring-2 ring-background",
            sizeClasses[size],
            getAvatarColor(name)
          )}
        >
          {getInitials(name)}
        </div>
      )}
      {isOnline !== undefined && (
        <span
          className={cn(
            "absolute bottom-0 right-0 block rounded-full ring-2 ring-background",
            size === "sm" ? "w-2.5 h-2.5" : "w-3 h-3",
            isOnline ? "bg-emerald-500" : "bg-muted-foreground"
          )}
        />
      )}
    </div>
  );
}
