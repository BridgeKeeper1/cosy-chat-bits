import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Hash, Settings, Users, UserMinus, Crown, Trash2, Lock, Unlock, Edit, Eye, EyeOff } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { messagesApi } from '@/lib/api';
import { toast } from 'sonner';
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@/components/ui/context-menu';

interface GroupContextMenuProps {
  children: React.ReactNode;
  groupId: string;
  groupName: string;
  isOwner?: boolean;
  onGroupUpdate?: () => void;
}

export function GroupContextMenu({ 
  children, 
  groupId, 
  groupName, 
  isOwner = false, 
  onGroupUpdate 
}: GroupContextMenuProps) {
  const { user } = useAuth();
  const [showSettings, setShowSettings] = useState(false);
  const [showMembers, setShowMembers] = useState(false);
  const [members, setMembers] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);

  const tid = parseInt(groupId.replace('gdm-', ''));

  useEffect(() => {
    if (showMembers) {
      loadMembers();
    }
  }, [showMembers]);

  const loadMembers = async () => {
    setLoading(true);
    try {
      const members = await messagesApi.getGdmMembers(tid);
      setMembers(members);
    } catch (error) {
      toast.error('Failed to load members');
    } finally {
      setLoading(false);
    }
  };

  const handleLockGroup = async () => {
    try {
      await messagesApi.lockGroup(tid);
      toast.success('Group locked');
      onGroupUpdate?.();
    } catch (error) {
      toast.error('Failed to lock group');
    }
  };

  const handleUnlockGroup = async () => {
    try {
      await messagesApi.unlockGroup(tid);
      toast.success('Group unlocked');
      onGroupUpdate?.();
    } catch (error) {
      toast.error('Failed to unlock group');
    }
  };

  const handleRemoveMember = async (username: string) => {
    try {
      await messagesApi.removeMember(tid, username);
      toast.success(`Removed ${username} from group`);
      loadMembers();
      onGroupUpdate?.();
    } catch (error) {
      toast.error('Failed to remove member');
    }
  };

  const handleTransferOwnership = async (newOwner: string) => {
    try {
      await messagesApi.transferOwnership(tid, newOwner);
      toast.success(`Transferred ownership to ${newOwner}`);
      loadMembers();
      onGroupUpdate?.();
    } catch (error) {
      toast.error('Failed to transfer ownership');
    }
  };

  const handleDeleteGroup = async () => {
    if (!confirm('Are you sure you want to delete this group? This action cannot be undone.')) {
      return;
    }
    try {
      await messagesApi.deleteGroup(tid);
      toast.success('Group deleted');
      onGroupUpdate?.();
    } catch (error) {
      toast.error('Failed to delete group');
    }
  };

  const canManageGroup = isOwner || user?.isSuperadmin;

  return (
    <>
      <ContextMenu>
        <ContextMenuTrigger asChild>
          {children}
        </ContextMenuTrigger>
        <ContextMenuContent className="w-64">
          <div className="flex items-center gap-2 px-2 py-1.5 text-sm font-medium">
            <Hash className="w-4 h-4" />
            {groupName}
          </div>
          <ContextMenuSeparator />
          
          <ContextMenuItem onClick={() => setShowSettings(true)}>
            <Edit className="w-4 h-4 mr-2" />
            Edit Group Info
          </ContextMenuItem>
          
          <ContextMenuItem onClick={() => setShowMembers(true)}>
            <Users className="w-4 h-4 mr-2" />
            View Members
          </ContextMenuItem>
          
          {canManageGroup && (
            <>
              <ContextMenuSeparator />
              {isOwner && (
                <ContextMenuItem onClick={handleLockGroup}>
                  <Lock className="w-4 h-4 mr-2" />
                  Lock Group
                </ContextMenuItem>
              )}
              {isOwner && (
                <ContextMenuItem onClick={handleUnlockGroup}>
                  <Unlock className="w-4 h-4 mr-2" />
                  Unlock Group
                </ContextMenuItem>
              )}
              {user?.isSuperadmin && (
                <ContextMenuItem onClick={handleDeleteGroup} className="text-red-600">
                  <Trash2 className="w-4 h-4 mr-2" />
                  Delete Group
                </ContextMenuItem>
              )}
            </>
          )}
        </ContextMenuContent>
      </ContextMenu>

      {/* Group Settings Modal */}
      <AnimatePresence>
        {showSettings && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
            onClick={() => setShowSettings(false)}
          >
            <motion.div
              initial={{ scale: 0.95 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0.95 }}
              className="bg-background border rounded-lg p-6 max-w-md w-full mx-4"
              onClick={(e) => e.stopPropagation()}
            >
              <h3 className="text-lg font-semibold mb-4">Group Settings</h3>
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium">Group Name</label>
                  <p className="text-sm text-muted-foreground">{groupName}</p>
                </div>
                <div>
                  <label className="text-sm font-medium">Group ID</label>
                  <p className="text-sm text-muted-foreground">#{tid}</p>
                </div>
                <div>
                  <label className="text-sm font-medium">Your Role</label>
                  <p className="text-sm text-muted-foreground">
                    {isOwner ? 'Owner' : user?.isSuperadmin ? 'Superadmin' : 'Member'}
                  </p>
                </div>
              </div>
              <div className="flex justify-end gap-2 mt-6">
                <button
                  onClick={() => setShowSettings(false)}
                  className="px-4 py-2 text-sm border rounded-md hover:bg-muted"
                >
                  Close
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Members Modal */}
      <AnimatePresence>
        {showMembers && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
            onClick={() => setShowMembers(false)}
          >
            <motion.div
              initial={{ scale: 0.95 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0.95 }}
              className="bg-background border rounded-lg p-6 max-w-md w-full mx-4 max-h-[400px] overflow-hidden"
              onClick={(e) => e.stopPropagation()}
            >
              <h3 className="text-lg font-semibold mb-4">Group Members ({members.length})</h3>
              <div className="space-y-2 max-h-[300px] overflow-y-auto">
                {loading ? (
                  <p className="text-sm text-muted-foreground">Loading members...</p>
                ) : (
                  members.map((member) => (
                    <div
                      key={member}
                      className="flex items-center justify-between p-2 rounded-md hover:bg-muted"
                    >
                      <div className="flex items-center gap-2">
                        <div className="w-8 h-8 rounded-full bg-muted flex items-center justify-center text-sm">
                          {member.charAt(0).toUpperCase()}
                        </div>
                        <span className="text-sm">{member}</span>
                        {member === groupName.split(' ')[0] && (
                          <Crown className="w-4 h-4 text-yellow-500" />
                        )}
                      </div>
                      {canManageGroup && member !== user?.username && (
                        <div className="flex gap-1">
                          {isOwner && member !== user?.username && (
                            <button
                              onClick={() => handleTransferOwnership(member)}
                              className="p-1 rounded hover:bg-muted"
                              title="Transfer ownership"
                            >
                              <Crown className="w-3 h-3" />
                            </button>
                          )}
                          <button
                            onClick={() => handleRemoveMember(member)}
                            className="p-1 rounded hover:bg-muted text-red-500"
                            title="Remove member"
                          >
                            <UserMinus className="w-3 h-3" />
                          </button>
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
              <div className="flex justify-end gap-2 mt-4">
                <button
                  onClick={() => setShowMembers(false)}
                  className="px-4 py-2 text-sm border rounded-md hover:bg-muted"
                >
                  Close
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
