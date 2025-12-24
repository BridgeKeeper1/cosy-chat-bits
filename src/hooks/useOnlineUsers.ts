import { useState, useEffect, useCallback } from 'react';
import { usersApi, OnlineUser } from '@/lib/api';
import { onUserListRefresh } from '@/lib/socket';

export function useOnlineUsers() {
  const [onlineUsers, setOnlineUsers] = useState<OnlineUser[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const fetchOnlineUsers = useCallback(async () => {
    try {
      const users = await usersApi.getOnlineUsers();
      setOnlineUsers(users);
    } catch (error) {
      console.error('Failed to fetch online users:', error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchOnlineUsers();

    // Subscribe to real-time user list updates
    const unsubscribe = onUserListRefresh(() => {
      fetchOnlineUsers();
    });

    // Poll every 30 seconds as backup
    const interval = setInterval(fetchOnlineUsers, 30000);

    return () => {
      unsubscribe();
      clearInterval(interval);
    };
  }, [fetchOnlineUsers]);

  const isUserOnline = useCallback((username: string): boolean => {
    return onlineUsers.some(u => u.username === username);
  }, [onlineUsers]);

  const getUserPresence = useCallback((username: string): 'online' | 'offline' => {
    const user = onlineUsers.find(u => u.username === username);
    return user ? 'online' : 'offline';
  }, [onlineUsers]);

  return {
    onlineUsers,
    isLoading,
    isUserOnline,
    getUserPresence,
    refetch: fetchOnlineUsers,
  };
}
