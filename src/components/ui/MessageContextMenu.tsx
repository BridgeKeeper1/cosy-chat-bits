import React, { useState, useRef, useEffect } from 'react';
import { ContextMenu, ContextMenuContent, ContextMenuItem, ContextMenuTrigger } from './context-menu';
import { Button } from './button';
import { Copy, Edit, Trash2, MessageSquare, User, Reply } from 'lucide-react';
import { adminApi } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';

interface MessageContextMenuProps {
  children: React.ReactNode;
  message: {
    id: string;
    content: string;
    senderId: string;
    senderName: string;
    isOwn: boolean;
    reactions?: any[];
  };
  onEdit?: (messageId: string, content: string) => void;
  onDelete?: (messageId: string) => void;
  onReact?: (messageId: string, emoji: string) => void;
  onReply?: (message: any) => void;
  onViewProfile?: (username: string) => void;
}

export function MessageContextMenu({ 
  children, 
  message, 
  onEdit, 
  onDelete, 
  onReact, 
  onReply, 
  onViewProfile 
}: MessageContextMenuProps) {
  const { user } = useAuth();
  const [isEditing, setIsEditing] = useState(false);
  const [editContent, setEditContent] = useState(message.content);
  const [copied, setCopied] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  const emojis = ['❤️', '👍', '😂', '😮', '😢', '😡'];

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsEditing(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(message.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error('Failed to copy text:', error);
    }
  };

  const handleDelete = async () => {
    if (onDelete) {
      if (message.isOwn || user?.role === 'superadmin') {
        await onDelete(message.id);
      }
    }
  };

  const handleEdit = () => {
    if (onEdit && (message.isOwn || user?.role === 'superadmin')) {
      setIsEditing(true);
      setEditContent(message.content);
    }
  };

  const handleEmojiReact = async (emoji: string) => {
    if (onReact) {
      await onReact(message.id, emoji);
    }
  };

  const handleSaveEdit = async () => {
    if (onEdit && editContent.trim() !== message.content) {
      await onEdit(message.id, editContent.trim());
      setIsEditing(false);
    }
  };

  const handleReply = () => {
    if (onReply) {
      onReply(message);
    }
  };

  const handleViewProfile = () => {
    if (onViewProfile) {
      onViewProfile(message.senderName);
    }
  };

  const canEdit = message.isOwn || user?.role === 'superadmin';
  const canDelete = message.isOwn || user?.role === 'superadmin';

  return (
    <>
      <ContextMenu>
        <ContextMenuTrigger asChild>
          {children}
        </ContextMenuTrigger>
        <ContextMenuContent className="w-48" ref={menuRef}>
          {/* Reply */}
          <ContextMenuItem onClick={handleReply}>
            <Reply className="w-4 h-4 mr-2" />
            Reply
          </ContextMenuItem>

          {/* React */}
          <ContextMenuItem>
            <div className="flex items-center justify-between w-full">
              <span>React</span>
              <div className="flex gap-1">
                {emojis.map(emoji => (
                  <button
                    key={emoji}
                    onClick={() => handleEmojiReact(emoji)}
                    className="p-1 hover:bg-muted rounded text-sm"
                  >
                    {emoji}
                  </button>
                ))}
              </div>
            </div>
          </ContextMenuItem>

          {/* Copy */}
          <ContextMenuItem onClick={handleCopy}>
            <Copy className="w-4 h-4 mr-2" />
            {copied ? 'Copied!' : 'Copy'}
          </ContextMenuItem>

          {/* Edit */}
          {canEdit && (
            <>
              {isEditing ? (
                <div className="p-2">
                  <textarea
                    value={editContent}
                    onChange={(e) => setEditContent(e.target.value)}
                    className="w-full p-2 border rounded text-sm resize-none"
                    rows={3}
                    autoFocus
                  />
                  <div className="flex gap-2 mt-2">
                    <Button size="sm" onClick={handleSaveEdit}>
                      Save
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => setIsEditing(false)}>
                      Cancel
                    </Button>
                  </div>
                </div>
              ) : (
                <ContextMenuItem onClick={handleEdit}>
                  <Edit className="w-4 h-4 mr-2" />
                  Edit
                </ContextMenuItem>
              )}
            </>
          )}

          {/* Delete */}
          {canDelete && (
            <ContextMenuItem onClick={handleDelete} className="text-destructive">
              <Trash2 className="w-4 h-4 mr-2" />
              Delete
            </ContextMenuItem>
          )}

          {/* View Profile */}
          <ContextMenuItem onClick={handleViewProfile}>
            <User className="w-4 h-4 mr-2" />
            View Profile
          </ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>
    </>
  );
}
