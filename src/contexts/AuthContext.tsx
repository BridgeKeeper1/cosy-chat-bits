import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { authApi } from '@/lib/api';
import { connectSocket, disconnectSocket } from '@/lib/socket';

interface User {
  username: string;
  isAdmin: boolean;
  isSuperadmin: boolean;
  role: string;
  avatar?: string;
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [connectionError, setConnectionError] = useState<string | null>(null);

  const checkAuth = useCallback(async () => {
    try {
      setConnectionError(null);
      const whoami = await authApi.whoami();
      if (whoami.effective) {
        // Get role information
        let isAdmin = false;
        let isSuperadmin = false;
        
        try {
          const roleInfo = await authApi.getMyRole();
          isAdmin = roleInfo.is_admin || false;
          isSuperadmin = roleInfo.is_superadmin || false;
        } catch {
          // Role endpoint might not be available
        }

        setUser({
          username: whoami.effective,
          isAdmin,
          isSuperadmin,
          role: whoami.is_superadmin ? 'superadmin' : 'user',
          avatar: whoami.avatar,
          bio: whoami.bio,
          status: whoami.status,
        });
        
        // Connect socket when authenticated
        connectSocket();
      } else {
        setUser(null);
        disconnectSocket();
      }
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Connection failed';
      if (errorMessage.includes('Cannot connect') || errorMessage.includes('Failed to fetch')) {
        setConnectionError('Cannot connect to server. Ensure Flask is running on localhost:5000 with CORS enabled.');
      }
      setUser(null);
      disconnectSocket();
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  const login = async (username: string, password: string) => {
    await authApi.login(username, password);
    await checkAuth();
  };

  const register = async (username: string, password: string, email?: string) => {
    await authApi.register(username, password, email);
    // After registration, log in
    await login(username, password);
  };

  const logout = async () => {
    await authApi.logout();
    setUser(null);
    disconnectSocket();
  };

  const refreshUser = async () => {
    await checkAuth();
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated: !!user,
        login,
        register,
        logout,
        checkAuth,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
