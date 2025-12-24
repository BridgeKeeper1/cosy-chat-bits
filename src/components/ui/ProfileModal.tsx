import React, { useState, useEffect } from 'react';
import { Modal, ModalContent, ModalHeader, ModalTitle, ModalBody, ModalFooter } from './dialog';
import { Button } from './button';
import { Badge } from './badge';
import { Calendar, Mail, MessageCircle, User as UserIcon, Clock } from 'lucide-react';
import { usersApi } from '@/lib/api';

interface ProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
  username: string;
}

interface UserProfile {
  username: string;
  role: string;
  bio: string | null;
  status: string | null;
  avatar: string | null;
  last_seen: string | null;
  language: string;
  allow_dm_nonfriends: boolean;
  created_at: string;
  is_online: boolean;
  message_count: number;
  dm_count: number;
  is_me: boolean;
}

export function ProfileModal({ isOpen, onClose, username }: ProfileModalProps) {
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    if (isOpen && username) {
      loadProfile();
    }
  }, [isOpen, username]);

  const loadProfile = async () => {
    try {
      setIsLoading(true);
      const response = await usersApi.getUserProfile(username);
      if (response.ok) {
        setProfile(response.user);
      } else {
        console.error('Failed to load profile:', response.error);
      }
    } catch (error) {
      console.error('Error loading profile:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const getStatusColor = (status: string | null, isOnline: boolean) => {
    if (isOnline) return 'bg-green-500';
    if (!status) return 'bg-gray-500';
    switch (status.toLowerCase()) {
      case 'online': return 'bg-green-500';
      case 'away': return 'bg-yellow-500';
      case 'busy': return 'bg-red-500';
      case 'invisible': return 'bg-gray-500';
      default: return 'bg-gray-500';
    }
  };

  const getStatusText = (status: string | null, isOnline: boolean) => {
    if (isOnline) return 'Online';
    if (!status) return 'Offline';
    return status.charAt(0).toUpperCase() + status.slice(1);
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleDateString();
  };

  if (isLoading) {
    return (
      <Modal open={isOpen} onOpenChange={onClose}>
        <ModalContent className="sm:max-w-md">
          <ModalHeader>
            <ModalTitle>Loading Profile...</ModalTitle>
          </ModalHeader>
          <ModalBody className="flex justify-center py-8">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-300 border-t-blue-600"></div>
          </ModalBody>
        </ModalContent>
      </Modal>
    );
  }

  if (!profile) {
    return (
      <Modal open={isOpen} onOpenChange={onClose}>
        <ModalContent className="sm:max-w-md">
          <ModalHeader>
            <ModalTitle>Profile Not Found</ModalTitle>
          </ModalHeader>
          <ModalBody className="text-center py-8">
            <p className="text-gray-600">Unable to load profile for {username}</p>
          </ModalBody>
          <ModalFooter>
            <Button onClick={onClose}>Close</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    );
  }

  return (
    <Modal open={isOpen} onOpenChange={onClose}>
      <ModalContent className="sm:max-w-lg">
        <ModalHeader>
          <ModalTitle className="flex items-center gap-3">
            <div className="flex items-center gap-3">
              <div className="relative">
                {profile.avatar ? (
                  <img
                    src={profile.avatar}
                    alt={profile.username}
                    className="w-16 h-16 rounded-full object-cover"
                  />
                ) : (
                  <div className="w-16 h-16 rounded-full bg-gray-300 flex items-center justify-center">
                    <UserIcon className="w-8 h-8 text-gray-600" />
                  </div>
                )}
                <div
                  className={`absolute bottom-0 right-0 w-4 h-4 rounded-full border-2 border-white ${getStatusColor(
                    profile.status,
                    profile.is_online
                  )}`}
                />
              </div>
              <div>
                <h3 className="text-lg font-semibold">{profile.username}</h3>
                <div className="flex items-center gap-2">
                  <Badge variant={profile.role === 'superadmin' ? 'destructive' : 'secondary'}>
                    {profile.role}
                  </Badge>
                  <span className="text-sm text-gray-600">
                    {getStatusText(profile.status, profile.is_online)}
                  </span>
                </div>
              </div>
            </div>
          </ModalTitle>
        </ModalHeader>
        <ModalBody className="space-y-6">
          {/* Bio Section */}
          <div>
            <h4 className="font-medium mb-2 flex items-center gap-2">
              <UserIcon className="w-4 h-4" />
              About
            </h4>
            <p className="text-gray-700 bg-gray-50 p-3 rounded-lg">
              {profile.bio || 'No bio set'}
            </p>
          </div>

          {/* Stats Section */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-blue-50 p-4 rounded-lg">
              <div className="flex items-center gap-2 text-blue-700 mb-2">
                <MessageCircle className="w-4 h-4" />
                <span className="font-medium">Messages</span>
              </div>
              <div className="text-2xl font-bold text-blue-900">
                {profile.message_count.toLocaleString()}
              </div>
            </div>
            
            <div className="bg-green-50 p-4 rounded-lg">
              <div className="flex items-center gap-2 text-green-700 mb-2">
                <Mail className="w-4 h-4" />
                <span className="font-medium">DMs</span>
              </div>
              <div className="text-2xl font-bold text-green-900">
                {profile.dm_count.toLocaleString()}
              </div>
            </div>
          </div>

          {/* Details Section */}
          <div className="space-y-3">
            <h4 className="font-medium mb-3">Details</h4>
            
            <div className="flex items-center justify-between py-2 border-b">
              <span className="text-gray-600 flex items-center gap-2">
                <Calendar className="w-4 h-4" />
                Joined
              </span>
              <span className="font-medium">{formatDate(profile.created_at)}</span>
            </div>
            
            <div className="flex items-center justify-between py-2 border-b">
              <span className="text-gray-600 flex items-center gap-2">
                <Clock className="w-4 h-4" />
                Last Seen
              </span>
              <span className="font-medium">
                {profile.is_online ? 'Now' : formatDate(profile.last_seen)}
              </span>
            </div>
            
            <div className="flex items-center justify-between py-2">
              <span className="text-gray-600">Language</span>
              <span className="font-medium uppercase">{profile.language}</span>
            </div>
            
            <div className="flex items-center justify-between py-2">
              <span className="text-gray-600">DM Settings</span>
              <span className="font-medium">
                {profile.allow_dm_nonfriends ? 'Open' : 'Friends Only'}
              </span>
            </div>
          </div>
        </ModalBody>
        <ModalFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}
