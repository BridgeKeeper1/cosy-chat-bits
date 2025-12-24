import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Hash, Users, Calendar, MessageSquare, Crown, Settings, Lock, Unlock } from 'lucide-react';
import { messagesApi } from '@/lib/api';
import { toast } from 'sonner';
import { useAuth } from '@/contexts/AuthContext';

interface GroupProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
  groupId: string;
  groupName: string;
}

interface GroupProfile {
  id: number;
  name: string;
  created_by: string;
  created_at: string;
  invite_code?: string;
  member_count: number;
  is_locked: boolean;
  members: string[];
}

export function GroupProfileModal({ isOpen, onClose, groupId, groupName }: GroupProfileModalProps) {
  const [profile, setProfile] = useState<GroupProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const { user } = useAuth();

  useEffect(() => {
    if (isOpen && groupId) {
      loadGroupProfile();
    }
  }, [isOpen, groupId]);

  const loadGroupProfile = async () => {
    try {
      setIsLoading(true);
      const tid = parseInt(groupId.replace('gdm-', ''));
      
      // Get group members
      const members = await messagesApi.getGdmMembers(tid);
      
      // Create profile object
      const profileData: GroupProfile = {
        id: tid,
        name: groupName,
        created_by: 'Unknown', // This would need to be fetched from backend
        created_at: 'Unknown', // This would need to be fetched from backend
        member_count: members.length,
        is_locked: false, // This would need to be fetched from backend
        members: members
      };
      
      setProfile(profileData);
    } catch (error) {
      console.error('Error loading group profile:', error);
      toast.error('Failed to load group information');
    } finally {
      setIsLoading(false);
    }
  };

  const isOwner = profile?.created_by === user?.username;
  const isSuperadmin = user?.isSuperadmin;
  const canManageGroup = isOwner || isSuperadmin;

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
        onClick={onClose}
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="bg-background border rounded-lg shadow-xl max-w-md w-full mx-4 max-h-[80vh] overflow-hidden"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="p-6 border-b">
            <div className="flex items-center gap-4">
              <div className="w-16 h-16 rounded-full bg-secondary flex items-center justify-center">
                <Hash className="w-8 h-8 text-secondary-foreground" />
              </div>
              <div className="flex-1">
                <h2 className="text-xl font-semibold">{profile?.name || groupName}</h2>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-sm text-muted-foreground">
                    Group Chat • #{profile?.id || 'Unknown'}
                  </span>
                  {profile?.is_locked && (
                    <Lock className="w-4 h-4 text-muted-foreground" />
                  )}
                </div>
              </div>
              {canManageGroup && (
                <button
                  onClick={() => {
                    // This would open group settings
                    toast.info('Group settings can be accessed via right-click menu');
                  }}
                  className="p-2 rounded-lg hover:bg-muted"
                >
                  <Settings className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>

          {/* Content */}
          <div className="p-6">
            {isLoading ? (
              <div className="text-center py-8">
                <div className="animate-spin w-6 h-6 border-2 border-primary border-t-transparent rounded-full mx-auto mb-4"></div>
                <p className="text-muted-foreground">Loading group information...</p>
              </div>
            ) : profile ? (
              <div className="space-y-6">
                {/* Stats */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center p-3 bg-muted rounded-lg">
                    <Users className="w-6 h-6 mx-auto mb-2 text-muted-foreground" />
                    <div className="text-2xl font-bold">{profile.member_count}</div>
                    <div className="text-xs text-muted-foreground">Members</div>
                  </div>
                  <div className="text-center p-3 bg-muted rounded-lg">
                    <MessageSquare className="w-6 h-6 mx-auto mb-2 text-muted-foreground" />
                    <div className="text-2xl font-bold">—</div>
                    <div className="text-xs text-muted-foreground">Messages</div>
                  </div>
                </div>

                {/* Information */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Created by</span>
                    <div className="flex items-center gap-1">
                      <span className="text-sm font-medium">{profile.created_by}</span>
                      {profile.created_by === user?.username && (
                        <Crown className="w-4 h-4 text-yellow-500" />
                      )}
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Created</span>
                    <span className="text-sm">{profile.created_at}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Status</span>
                    <div className="flex items-center gap-1">
                      {profile.is_locked ? (
                        <>
                          <Lock className="w-4 h-4 text-orange-500" />
                          <span className="text-sm">Locked</span>
                        </>
                      ) : (
                        <>
                          <Unlock className="w-4 h-4 text-green-500" />
                          <span className="text-sm">Open</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>

                {/* Members List */}
                <div>
                  <h3 className="font-medium mb-3">Members ({profile.members.length})</h3>
                  <div className="max-h-40 overflow-y-auto space-y-2">
                    {profile.members.map((member) => (
                      <div
                        key={member}
                        className="flex items-center justify-between p-2 rounded-lg hover:bg-muted"
                      >
                        <div className="flex items-center gap-2">
                          <div className="w-6 h-6 rounded-full bg-muted flex items-center justify-center text-xs">
                            {member.charAt(0).toUpperCase()}
                          </div>
                          <span className="text-sm">{member}</span>
                        </div>
                        {member === profile.created_by && (
                          <Crown className="w-3 h-3 text-yellow-500" />
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Actions */}
                {canManageGroup && (
                  <div className="pt-4 border-t">
                    <p className="text-xs text-muted-foreground mb-3">
                      As {isOwner ? 'owner' : 'superadmin'}, you can manage this group by right-clicking on it in the sidebar.
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-8">
                <p className="text-muted-foreground">Failed to load group information</p>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="p-6 border-t flex justify-end">
            <button
              onClick={onClose}
              className="px-4 py-2 text-sm border rounded-md hover:bg-muted"
            >
              Close
            </button>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
