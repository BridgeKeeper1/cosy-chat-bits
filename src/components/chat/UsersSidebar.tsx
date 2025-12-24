import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Users, User, Shield, Crown, Circle, X } from "lucide-react";
import { Avatar } from "./Avatar";
import { cn } from "@/lib/utils";
import { usersApi } from "@/lib/api";
import { onUserListRefresh } from "@/lib/socket";

interface UserListEntry {
  username: string;
  role: string;
  last_seen?: string;
  avatar?: string;
  is_online?: boolean;
  bio?: string;
  status?: string;
}

interface UsersSidebarProps {
  isOpen: boolean;
  onToggle: () => void;
}

export function UsersSidebar({ isOpen, onToggle }: UsersSidebarProps) {
  const [users, setUsers] = useState<UserListEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    const fetchUsers = async (isRefresh = false) => {
      try {
        console.log('Fetching users...');
        if (isRefresh) {
          setRefreshing(true);
        } else {
          setLoading(true);
        }
        
        const response = await usersApi.getAllUsers();
        console.log('Users API response:', response);
        console.log('Response type:', typeof response);
        console.log('Is array?', Array.isArray(response));
        
        // Extract users array from API response
        let usersArray;
        if (response && typeof response === 'object' && 'users' in response) {
          usersArray = response.users;
        } else if (Array.isArray(response)) {
          usersArray = response;
        } else {
          console.error('Unexpected API response format:', response);
          usersArray = [];
        }
        
        console.log('Users array:', usersArray);
        console.log('Users array type:', typeof usersArray);
        console.log('Is users array?', Array.isArray(usersArray));
        
        if (!Array.isArray(usersArray)) {
          console.error('usersArray is not an array:', usersArray);
          usersArray = [];
        }
        
        // Transform API response to match UserListEntry interface
        const transformedUsers: UserListEntry[] = usersArray.map((user: any) => ({
          username: user.username,
          role: user.role,
          last_seen: user.last_seen || undefined,
          avatar: user.avatar,
          bio: user.bio,
          status: user.status,
          is_online: user.status === 'online' || false
        }));
        
        console.log('Transformed users:', transformedUsers);
        setUsers(transformedUsers);
      } catch (error) {
        console.error("Failed to fetch users:", error);
      } finally {
        if (isRefresh) {
          setRefreshing(false);
        } else {
          setLoading(false);
        }
      }
    };

    fetchUsers(false); // Initial load
    // Refresh users list every 2 minutes instead of 30 seconds
    const interval = setInterval(() => fetchUsers(true), 120000);
    
    // Listen for real-time socket events but debounce them
    let refreshTimeout: NodeJS.Timeout;
    const unsubUserListRefresh = onUserListRefresh(() => {
      console.log('User list refresh event received');
      // Debounce rapid refresh events
      clearTimeout(refreshTimeout);
      refreshTimeout = setTimeout(() => fetchUsers(true), 1000);
    });

    return () => {
      clearInterval(interval);
      unsubUserListRefresh?.();
    };
  }, []);

  const filteredUsers = users.filter(user =>
    user.username && user.username.toLowerCase().includes(filter.toLowerCase())
  );

  const onlineUsers = filteredUsers.filter(user => user.is_online);
  const offlineUsers = filteredUsers.filter(user => !user.is_online);

  const getRoleIcon = (role: string) => {
    if (role === 'superadmin') return <Crown className="w-3 h-3 text-yellow-500" />;
    if (role === 'admin') return <Shield className="w-3 h-3 text-blue-500" />;
    return <User className="w-3 h-3 text-gray-400" />;
  };

  const formatLastSeen = (dateString?: string) => {
    if (!dateString) return "Never";
    
    try {
      const date = new Date(dateString);
      if (isNaN(date.getTime())) return "Unknown";
      
      const now = new Date();
      const diffMs = now.getTime() - date.getTime();
      const diffMins = Math.floor(diffMs / 60000);
      
      if (diffMins < 1) return "Just now";
      if (diffMins < 60) return `${diffMins}m ago`;
      if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
      return `${Math.floor(diffMins / 1440)}d ago`;
    } catch (error) {
      return "Unknown";
    }
  };

  const UserEntry = ({ user }: { user: UserListEntry }) => (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      className={cn(
        "flex items-center gap-3 p-2 rounded-lg transition-colors",
        "hover:bg-muted/50 cursor-pointer"
      )}
    >
      <div className="relative">
        <Avatar 
          src={user.avatar} 
          name={user.username} 
          size="sm"
        />
        <div className={cn(
          "absolute -bottom-1 -right-1 w-3 h-3 rounded-full border-2 border-background",
          user.is_online ? "bg-green-500" : "bg-gray-400"
        )} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-medium text-sm truncate">{user.username}</span>
          {getRoleIcon(user.role)}
        </div>
        {user.bio && (
          <p className="text-xs text-muted-foreground truncate mt-1">{user.bio}</p>
        )}
        <span className="text-xs text-muted-foreground">
          {user.is_online ? "Online" : `Last seen ${formatLastSeen(user.last_seen)}`}
        </span>
      </div>
    </motion.div>
  );

  if (!isOpen) {
    return (
      <button
        onClick={onToggle}
        className="fixed right-4 top-1/2 -translate-y-1/2 z-40 p-3 rounded-full bg-primary text-primary-foreground shadow-lg hover:scale-110 transition-transform"
        aria-label="Toggle users sidebar"
      >
        <Users className="w-5 h-5" />
      </button>
    );
  }

  return (
    <>
      <div
        className="fixed inset-0 bg-black/50 z-40 lg:hidden"
        onClick={onToggle}
      />
      <motion.div
        initial={{ x: "100%" }}
        animate={{ x: 0 }}
        exit={{ x: "100%" }}
        className="fixed right-0 top-0 h-full w-80 bg-background border-l border-border z-50 flex flex-col"
      >
        {/* Header */}
        <div className="p-4 border-b border-border">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold text-lg flex items-center gap-2">
              <Users className="w-5 h-5" />
              Users ({filteredUsers.length})
            </h2>
            <button
              onClick={onToggle}
              className="p-2 rounded-lg hover:bg-muted transition-colors"
              aria-label="Close sidebar"
            >
              ×
            </button>
          </div>
          
          {/* Search */}
          <input
            type="text"
            placeholder="Search users..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-muted border-0 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>

        {/* Users List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
          ) : (
            <AnimatePresence mode="wait">
              <motion.div
                key={filteredUsers.length}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.2 }}
              >
                {refreshing && (
                  <div className="flex items-center justify-center py-2">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary/50"></div>
                    <span className="text-xs text-muted-foreground ml-2">Refreshing...</span>
                  </div>
                )}
                
                {/* Online Users */}
                {onlineUsers.length > 0 && (
                  <div>
                    <h3 className="text-sm font-medium text-muted-foreground mb-2 flex items-center gap-2">
                      <Circle className="w-2 h-2 fill-green-500 text-green-500" />
                      Online ({onlineUsers.length})
                    </h3>
                    <div className="space-y-1">
                      {onlineUsers.map(user => (
                        <UserEntry key={user.username} user={user} />
                      ))}
                    </div>
                  </div>
                )}

                {/* Offline Users */}
                {offlineUsers.length > 0 && (
                  <div>
                    <h3 className="text-sm font-medium text-muted-foreground mb-2 flex items-center gap-2">
                      <Circle className="w-2 h-2 fill-gray-400 text-gray-400" />
                      Offline ({offlineUsers.length})
                    </h3>
                    <div className="space-y-1">
                      {offlineUsers.map(user => (
                        <UserEntry key={user.username} user={user} />
                      ))}
                    </div>
                  </div>
                )}
              </motion.div>
            </AnimatePresence>
          )}
        </div>
      </motion.div>
    </>
  );
}
