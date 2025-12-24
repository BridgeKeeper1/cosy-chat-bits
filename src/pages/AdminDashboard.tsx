import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, Users, UserPlus, Clock, MessageSquare, Settings, Ban, AlertTriangle, Trash2, ArrowLeft, RefreshCw, Search, ChevronDown, Key, Send 
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { adminApi, AdminOnlineUser } from '@/lib/api';

export default function AdminDashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();
  
  const [onlineUsers, setOnlineUsers] = useState<AdminOnlineUser[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  
  // Dialogs
  const [timeoutDialog, setTimeoutDialog] = useState<{ open: boolean; username: string }>({ open: false, username: '' });
  const [timeoutMinutes, setTimeoutMinutes] = useState('5');
  const [broadcastDialog, setBroadcastDialog] = useState(false);
  const [broadcastText, setBroadcastText] = useState('');
  const [createUserDialog, setCreateUserDialog] = useState(false);
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'user' });
  const [resetPasswordDialog, setResetPasswordDialog] = useState<{ open: boolean; username: string }>({ open: false, username: '' });
  const [newPassword, setNewPassword] = useState('');
  const [viewMessagesDialog, setViewMessagesDialog] = useState(false);
  const [allMessages, setAllMessages] = useState<any[]>([]);
  const [togglesDialog, setTogglesDialog] = useState(false);
  const [bansDialog, setBansDialog] = useState(false);
  const [banUsername, setBanUsername] = useState('');
  const [banReason, setBanReason] = useState('');
  const [bannedUsers, setBannedUsers] = useState<string[]>([]);
  const [toggles, setToggles] = useState<Record<string, string>>({});

  // Check admin access
  useEffect(() => {
    if (!user?.isAdmin && !user?.isSuperadmin) {
      navigate('/chat');
    }
  }, [user, navigate]);

  const fetchOnlineUsers = useCallback(async () => {
    try {
      const data = await adminApi.getOnlineUsers();
      setOnlineUsers(data.online || []);
    } catch (error) {
      console.error('Failed to fetch online users:', error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const fetchBannedUsers = useCallback(async () => {
    try {
      const data = await adminApi.getBannedUsers();
      setBannedUsers(data.banned_users || []);
    } catch (error) {
      console.error('Failed to fetch banned users:', error);
    }
  }, []);

  useEffect(() => {
    fetchOnlineUsers();
    const interval = setInterval(fetchOnlineUsers, 5000);
    return () => clearInterval(interval);
  }, [fetchOnlineUsers]);

  useEffect(() => {
    if (bansDialog) {
      fetchBannedUsers();
    }
  }, [bansDialog, fetchBannedUsers]);

  const handleBan = async (username: string) => {
    try {
      await adminApi.banUser(username);
      toast({ title: 'User banned', description: `${username} has been banned` });
      fetchOnlineUsers();
    } catch (error: any) {
      toast({ title: 'Error', description: error.message, variant: 'destructive' });
    }
  };

  const handleUnban = async (username: string) => {
    try {
      await adminApi.unbanUser(username);
      toast({ title: 'User unbanned', description: `${username} has been unbanned` });
      fetchBannedUsers();
      fetchOnlineUsers();
    } catch (error: any) {
      toast({ title: 'Error', description: error.message, variant: 'destructive' });
    }
  };

  const handleTrueBan = async (username: string, clientId?: string) => {
    try {
      await adminApi.trueBan(username, clientId);
      toast({ title: 'True ban applied', description: `${username} has been fully banned (user + device + IPs)` });
      fetchOnlineUsers();
    } catch (error: any) {
      toast({ title: 'Error', description: error.message, variant: 'destructive' });
    }
  };

  const handleTimeout = async () => {
    try {
      await adminApi.timeoutUser(timeoutDialog.username, parseInt(timeoutMinutes));
      toast({ title: 'Timeout applied', description: `${timeoutDialog.username} timed out for ${timeoutMinutes} minutes` });
      setTimeoutDialog({ open: false, username: '' });
      setTimeoutMinutes('5');
    } catch (error: any) {
      toast({ title: 'Error', description: error.message, variant: 'destructive' });
    }
  };

  const handleBroadcast = async () => {
    if (!broadcastText.trim()) return;
    try {
      await adminApi.broadcastMessage(broadcastText);
      toast({ title: 'Broadcast sent', description: 'Message sent to all users' });
      setBroadcastDialog(false);
      setBroadcastText('');
    } catch (error: any) {
      toast({ title: 'Error', description: error.message, variant: 'destructive' });
    }
  };

  const handleCreateUser = async () => {
    if (!newUser.username.trim() || !newUser.password) return;
    try {
      const result = await adminApi.createUser(newUser.username, newUser.password, newUser.role);
      if (result.ok && result.username) {
        toast({ title: 'User created', description: `${result.username} has been created successfully` });
        setCreateUserDialog(false);
        setNewUser({ username: '', password: '', role: 'user' });
        // Refresh the online users list to show the new user
        fetchOnlineUsers();
      } else {
        toast({ title: 'Error', description: 'Failed to create user', variant: 'destructive' });
      }
    } catch (error: any) {
      toast({ title: 'Error', description: error.message || 'Failed to create user', variant: 'destructive' });
    }
  };

  const handleResetPassword = async () => {
    if (!newPassword) return;
    try {
      await adminApi.resetPassword(resetPasswordDialog.username, newPassword);
      toast({ title: 'Password reset', description: `Password for ${resetPasswordDialog.username} has been reset` });
      setResetPasswordDialog({ open: false, username: '' });
      setNewPassword('');
    } catch (error: any) {
      toast({ title: 'Error', description: error.message, variant: 'destructive' });
    }
  };

  const handleViewMessages = async () => {
    try {
      const messages = await adminApi.getAllMessages();
      setAllMessages(messages);
      setViewMessagesDialog(true);
    } catch (error: any) {
      toast({ title: 'Error', description: error.message, variant: 'destructive' });
    }
  };

  const handleLoadToggles = async () => {
    try {
      const settings = await adminApi.getToggles();
      setToggles(settings);
      setTogglesDialog(true);
    } catch (error: any) {
      toast({ title: 'Error', description: error.message, variant: 'destructive' });
    }
  };

  const handleSaveToggles = async () => {
    try {
      await adminApi.updateSettings(toggles);
      toast({ title: 'Toggles saved successfully' });
      setTogglesDialog(false);
    } catch (error) {
      toast({ 
        title: 'Failed to save toggles', 
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive' 
      });
    }
  };

  const handleBanUser = async () => {
    if (!banUsername.trim()) {
      toast({ title: 'Please enter a username', variant: 'destructive' });
      return;
    }
    try {
      await adminApi.banUser(banUsername.trim());
      toast({ title: `User ${banUsername} banned successfully` });
      setBanUsername('');
      setBanReason('');
    } catch (error) {
      toast({ 
        title: 'Failed to ban user', 
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive' 
      });
    }
  };

  const handleTimeoutUser = async () => {
    if (!banUsername.trim()) {
      toast({ title: 'Please enter a username', variant: 'destructive' });
      return;
    }
    try {
      const minutes = parseInt(timeoutMinutes);
      if (isNaN(minutes) || minutes <= 0) {
        toast({ title: 'Please enter a valid timeout duration', variant: 'destructive' });
        return;
      }
      await adminApi.timeoutUser(banUsername.trim(), minutes);
      toast({ title: `User ${banUsername} timed out for ${minutes} minutes` });
      setBanUsername('');
      setBanReason('');
      setTimeoutMinutes('5');
    } catch (error) {
      toast({ 
        title: 'Failed to timeout user', 
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive' 
      });
    }
  };

  const handleToggleChange = (key: string, value: string) => {
    setToggles(prev => ({ ...prev, [key]: value }));
  };

  const handleToggleImmunity = async (username: string) => {
    try {
      const result = await adminApi.toggleImmunity(username);
      toast({ 
        title: 'Immunity toggled', 
        description: `${username} is now ${result.immune ? 'immune' : 'not immune'} to bans` 
      });
      fetchOnlineUsers();
    } catch (error: any) {
      toast({ title: 'Error', description: error.message, variant: 'destructive' });
    }
  };

  const filteredUsers = onlineUsers.filter(u => 
    u.username.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (!user?.isAdmin && !user?.isSuperadmin) {
    return null;
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <div className="border-b border-border bg-card">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button variant="ghost" size="icon" onClick={() => navigate('/chat')}>
              <ArrowLeft className="w-5 h-5" />
            </Button>
            <div className="flex items-center gap-2">
              <Shield className="w-6 h-6 text-primary" />
              <h1 className="text-xl font-bold">Admin Dashboard</h1>
            </div>
            {user?.isSuperadmin && (
              <Badge variant="secondary" className="bg-purple-500/20 text-purple-400">
                Superadmin
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={fetchOnlineUsers}>
              <RefreshCw className="w-4 h-4 mr-2" />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setBroadcastDialog(true)}>
              <Send className="w-4 h-4 mr-2" />
              Broadcast
            </Button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 py-6">
        <Tabs defaultValue="users" className="space-y-6">
          <TabsList className="grid w-full max-w-md grid-cols-2">
            <TabsTrigger value="users">
              <Users className="w-4 h-4 mr-2" />
              Online Users
            </TabsTrigger>
            <TabsTrigger value="moderation">
              <Ban className="w-4 h-4 mr-2" />
              Moderation
            </TabsTrigger>
          </TabsList>

          {/* Online Users Tab */}
          <TabsContent value="users" className="space-y-4">
            <div className="flex items-center gap-4">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search users..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10"
                />
              </div>
              <Badge variant="outline">{onlineUsers.length} online</Badge>
            </div>

            <div className="grid gap-3">
              {isLoading ? (
                <div className="text-center py-8 text-muted-foreground">Loading...</div>
              ) : filteredUsers.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">No users found</div>
              ) : (
                filteredUsers.map((onlineUser) => (
                  <motion.div
                    key={onlineUser.username}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="bg-card border border-border rounded-lg p-4"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-full bg-primary/20 flex items-center justify-center">
                          <span className="text-primary font-medium">
                            {onlineUser.username[0]?.toUpperCase()}
                          </span>
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{onlineUser.username}</span>
                            {onlineUser.immune && (
                              <Badge variant="secondary" className="bg-green-500/20 text-green-400 text-xs">
                                Immune
                              </Badge>
                            )}
                            {onlineUser.device_banned && (
                              <Badge variant="destructive" className="text-xs">Device Banned</Badge>
                            )}
                          </div>
                          <div className="text-xs text-muted-foreground space-x-3">
                            {onlineUser.ip && <span>IP: {onlineUser.ip}</span>}
                            {onlineUser.client_id && <span>CID: {onlineUser.client_id.slice(0, 8)}...</span>}
                          </div>
                        </div>
                      </div>

                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="outline" size="sm">
                            Actions
                            <ChevronDown className="w-4 h-4 ml-2" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => setTimeoutDialog({ open: true, username: onlineUser.username })}>
                            <Clock className="w-4 h-4 mr-2" />
                            Timeout
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleBan(onlineUser.username)}>
                            <Ban className="w-4 h-4 mr-2" />
                            Ban User
                          </DropdownMenuItem>
                          <DropdownMenuItem 
                            onClick={() => handleTrueBan(onlineUser.username, onlineUser.client_id)}
                            className="text-destructive"
                          >
                            <AlertTriangle className="w-4 h-4 mr-2" />
                            True Ban (All)
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem onClick={() => setResetPasswordDialog({ open: true, username: onlineUser.username })}>
                            <Key className="w-4 h-4 mr-2" />
                            Reset Password
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleToggleImmunity(onlineUser.username)}>
                            <Shield className="w-4 h-4 mr-2" />
                            Toggle Immunity
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </motion.div>
                ))
              )}
            </div>
          </TabsContent>

          {/* Moderation Tab */}
          <TabsContent value="moderation" className="space-y-4">
            <div className="max-h-[80vh] overflow-y-auto">
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                <div className="bg-card border border-border rounded-lg p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 rounded-lg bg-yellow-500/20 flex items-center justify-center">
                      <Clock className="w-5 h-5 text-yellow-500" />
                    </div>
                    <h3 className="font-semibold">Quick Timeout</h3>
                  </div>
                  <p className="text-sm text-muted-foreground mb-4">
                    Temporarily mute a user from sending messages.
                  </p>
                  <Button variant="outline" className="w-full" onClick={() => setTimeoutDialog({ open: true, username: '' })}>
                    Apply Timeout
                  </Button>
                </div>

                <div className="bg-card border border-border rounded-lg p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 rounded-lg bg-red-500/20 flex items-center justify-center">
                      <Ban className="w-5 h-5 text-red-500" />
                    </div>
                    <h3 className="font-semibold">Ban Management</h3>
                  </div>
                  <p className="text-sm text-muted-foreground mb-4">
                    Ban or unban users from the platform.
                  </p>
                  <Button variant="outline" className="w-full" onClick={() => setBansDialog(true)}>
                    Manage Bans
                  </Button>
                </div>

                <div className="bg-card border border-border rounded-lg p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center">
                      <Settings className="w-5 h-5 text-blue-500" />
                    </div>
                    <h3 className="font-semibold">Admin Settings</h3>
                  </div>
                  <p className="text-sm text-muted-foreground mb-4">
                    Manage platform toggles and configuration.
                  </p>
                  <Button variant="outline" className="w-full" onClick={handleLoadToggles}>
                    Manage Toggles
                  </Button>
                </div>
                
                <div className="bg-card border border-border rounded-lg p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 rounded-lg bg-green-500/20 flex items-center justify-center">
                      <MessageSquare className="w-5 h-5 text-green-500" />
                    </div>
                    <h3 className="font-semibold">View Messages</h3>
                  </div>
                  <p className="text-sm text-muted-foreground mb-4">
                    View recent messages across all chats.
                  </p>
                  <Button variant="outline" className="w-full" onClick={handleViewMessages}>
                    View Messages
                  </Button>
                </div>

                <div className="bg-card border border-border rounded-lg p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center">
                      <UserPlus className="w-5 h-5 text-purple-500" />
                    </div>
                    <h3 className="font-semibold">Create User</h3>
                  </div>
                  <p className="text-sm text-muted-foreground mb-4">
                    Create a new user account.
                  </p>
                  <Button variant="outline" className="w-full" onClick={() => setCreateUserDialog(true)}>
                    Create User
                  </Button>
                </div>

                <div className="bg-card border border-border rounded-lg p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 rounded-lg bg-orange-500/20 flex items-center justify-center">
                      <Key className="w-5 h-5 text-orange-500" />
                    </div>
                    <h3 className="font-semibold">Reset Password</h3>
                  </div>
                  <p className="text-sm text-muted-foreground mb-4">
                    Reset user password.
                  </p>
                  <Button variant="outline" className="w-full" onClick={() => setResetPasswordDialog({ open: true, username: '' })}>
                    Reset Password
                  </Button>
                </div>
              </div>
            </div>
          </TabsContent>

          {/* Users Tab */}
          <TabsContent value="users" className="space-y-4">
            <div className="flex items-center gap-4">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search users..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10"
                />
              </div>
              <Badge variant="outline">{onlineUsers.length} online</Badge>
            </div>

            <div className="grid gap-3">
              {isLoading ? (
                <div className="text-center py-8 text-muted-foreground">Loading...</div>
              ) : filteredUsers.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">No users found</div>
              ) : (
                filteredUsers.map((onlineUser) => (
                  <motion.div
                    key={onlineUser.username}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="bg-card border border-border rounded-lg p-4"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-full bg-primary/20 flex items-center justify-center">
                          <span className="text-primary font-medium">
                            {onlineUser.username[0]?.toUpperCase()}
                          </span>
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{onlineUser.username}</span>
                            {onlineUser.immune && (
                              <Badge variant="secondary" className="bg-green-500/20 text-green-400 text-xs">
                                Immune
                              </Badge>
                            )}
                            {onlineUser.device_banned && (
                              <Badge variant="destructive" className="text-xs">Device Banned</Badge>
                            )}
                          </div>
                          <div className="text-xs text-muted-foreground space-x-3">
                            {onlineUser.ip && <span>IP: {onlineUser.ip}</span>}
                            {onlineUser.client_id && <span>CID: {onlineUser.client_id.slice(0, 8)}...</span>}
                          </div>
                        </div>
                      </div>

                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="outline" size="sm">
                            Actions
                            <ChevronDown className="w-4 h-4 ml-2" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => setTimeoutDialog({ open: true, username: onlineUser.username })}>
                            <Clock className="w-4 h-4 mr-2" />
                            Timeout
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleBan(onlineUser.username)}>
                            <Ban className="w-4 h-4 mr-2" />
                            Ban User
                          </DropdownMenuItem>
                          <DropdownMenuItem 
                            onClick={() => handleTrueBan(onlineUser.username, onlineUser.client_id)}
                            className="text-destructive"
                          >
                            <AlertTriangle className="w-4 h-4 mr-2" />
                            True Ban (All)
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem onClick={() => setResetPasswordDialog({ open: true, username: onlineUser.username })}>
                            <Key className="w-4 h-4 mr-2" />
                            Reset Password
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleToggleImmunity(onlineUser.username)}>
                            <Shield className="w-4 h-4 mr-2" />
                            Toggle Immunity
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </motion.div>
                ))
              )}
            </div>
          </TabsContent>
        </Tabs>
      </div>

      {/* Timeout Dialog */}
      <Dialog open={timeoutDialog.open} onOpenChange={(open) => setTimeoutDialog({ ...timeoutDialog, open })}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Timeout User</DialogTitle>
            <DialogDescription>
              Temporarily prevent a user from sending messages.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            {!timeoutDialog.username && (
              <div className="space-y-2">
                <Label>Username</Label>
                <Input
                  placeholder="Enter username"
                  value={timeoutDialog.username}
                  onChange={(e) => setTimeoutDialog({ ...timeoutDialog, username: e.target.value })}
                />
              </div>
            )}
            <div className="space-y-2">
              <Label>Duration (minutes)</Label>
              <Input
                type="number"
                value={timeoutMinutes}
                onChange={(e) => setTimeoutMinutes(e.target.value)}
                min="1"
                max="1440"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTimeoutDialog({ open: false, username: '' })}>
              Cancel
            </Button>
            <Button onClick={handleTimeout}>Apply Timeout</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Broadcast Dialog */}
      <Dialog open={broadcastDialog} onOpenChange={setBroadcastDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Broadcast Message</DialogTitle>
            <DialogDescription>
              Send a message to all online users.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>Message</Label>
              <Input
                placeholder="Enter your broadcast message"
                value={broadcastText}
                onChange={(e) => setBroadcastText(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBroadcastDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleBroadcast}>Send Broadcast</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create User Dialog */}
      <Dialog open={createUserDialog} onOpenChange={setCreateUserDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create User</DialogTitle>
            <DialogDescription>
              Create a new user account.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>Username</Label>
              <Input
                placeholder="Enter username"
                value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                maxLength={20}
              />
            </div>
            <div className="space-y-2">
              <Label>Password</Label>
              <Input
                type="password"
                placeholder="Enter password"
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateUserDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreateUser}>Create User</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Reset Password Dialog */}
      <Dialog open={resetPasswordDialog.open} onOpenChange={(open) => setResetPasswordDialog({ ...resetPasswordDialog, open })}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reset Password</DialogTitle>
            <DialogDescription>
              Reset password for {resetPasswordDialog.username}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>New Password</Label>
              <Input
                type="password"
                placeholder="Enter new password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setResetPasswordDialog({ open: false, username: '' })}>
              Cancel
            </Button>
            <Button onClick={handleResetPassword}>Reset Password</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* View Messages Dialog */}
      <Dialog open={viewMessagesDialog} onOpenChange={setViewMessagesDialog}>
        <DialogContent className="max-w-4xl max-h-[80vh]">
          <DialogHeader>
            <DialogTitle>All Messages</DialogTitle>
            <DialogDescription>
              View all messages in the system.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4 max-h-[60vh] overflow-y-auto">
            {allMessages.length === 0 ? (
              <p className="text-muted-foreground">No messages found.</p>
            ) : (
              allMessages.map((message) => (
                <div key={message.id} className="border-b border-border pb-2">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium">{message.username}</span>
                    <span className="text-xs text-muted-foreground">
                      {new Date(message.created_at).toLocaleString()}
                    </span>
                  </div>
                  <div 
                    className="text-sm"
                    dangerouslySetInnerHTML={{ __html: message.text }}
                  />
                </div>
              ))
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setViewMessagesDialog(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Admin Toggles Dialog */}
      <Dialog open={togglesDialog} onOpenChange={setTogglesDialog}>
        <DialogContent className="max-w-4xl max-h-[80vh]">
          <DialogHeader>
            <DialogTitle>Admin Toggles</DialogTitle>
            <DialogDescription>
              Manage platform configuration and feature toggles.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4 max-h-[60vh] overflow-y-auto">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {Object.entries(toggles).map(([key, value]) => {
                const isBoolean = value === '0' || value === '1' || value === 'true' || value === 'false';
                const isChecked = value === '1' || value === 'true';
                
                return (
                  <div key={key} className="flex items-center justify-between p-3 border rounded-lg">
                    <div>
                      <Label className="font-medium">{key}</Label>
                      <p className="text-xs text-muted-foreground mt-1">
                        {isBoolean ? 'Toggle feature on/off' : 'Text setting'}
                      </p>
                    </div>
                    {isBoolean ? (
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={(e) => handleToggleChange(key, e.target.checked ? '1' : '0')}
                        className="w-4 h-4"
                      />
                    ) : (
                      <Input
                        value={value}
                        onChange={(e) => handleToggleChange(key, e.target.value)}
                        className="w-32"
                      />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTogglesDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleSaveToggles}>
              Save Toggles
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bans Management Dialog */}
      <Dialog open={bansDialog} onOpenChange={setBansDialog}>
        <DialogContent className="max-w-4xl max-h-[80vh]">
          <DialogHeader>
            <DialogTitle>Ban Management</DialogTitle>
            <DialogDescription>
              Manage user bans and timeouts.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-6 py-4 max-h-[60vh] overflow-y-auto">
            {/* Ban New User Section */}
            <div className="space-y-4 border-b border-border pb-4">
              <h3 className="font-semibold">Ban New User</h3>
              <div className="grid grid-cols-1 gap-4">
                <div>
                  <Label htmlFor="banUsername">Username</Label>
                  <Input
                    id="banUsername"
                    value={banUsername}
                    onChange={(e) => setBanUsername(e.target.value)}
                    placeholder="Enter username to ban"
                  />
                </div>
                <div>
                  <Label htmlFor="banReason">Reason</Label>
                  <Input
                    id="banReason"
                    value={banReason}
                    onChange={(e) => setBanReason(e.target.value)}
                    placeholder="Ban reason (optional)"
                  />
                </div>
                <div>
                  <Label htmlFor="timeoutMinutes">Timeout (minutes)</Label>
                  <Input
                    id="timeoutMinutes"
                    value={timeoutMinutes}
                    onChange={(e) => setTimeoutMinutes(e.target.value)}
                    placeholder="Leave empty for permanent ban"
                    type="number"
                  />
                </div>
              </div>
              <div className="flex gap-2">
                <Button onClick={handleBanUser} variant="destructive">
                  Ban User
                </Button>
                <Button onClick={handleTimeoutUser} variant="outline">
                  Timeout User
                </Button>
              </div>
            </div>

            {/* Banned Users List Section */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="font-semibold">Currently Banned Users</h3>
                <Button variant="outline" size="sm" onClick={fetchBannedUsers}>
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Refresh
                </Button>
              </div>
              {bannedUsers.length === 0 ? (
                <p className="text-muted-foreground text-center py-4">No banned users found.</p>
              ) : (
                <div className="space-y-2">
                  {bannedUsers.map((username) => (
                    <div key={username} className="flex items-center justify-between p-3 border border-border rounded-lg">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-red-500/20 flex items-center justify-center">
                          <Ban className="w-4 h-4 text-red-500" />
                        </div>
                        <span className="font-medium">{username}</span>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleUnban(username)}
                        className="text-green-600 hover:text-green-700"
                      >
                        Unban
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBansDialog(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
} 
