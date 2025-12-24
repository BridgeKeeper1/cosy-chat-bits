// Flask Backend API Client

export const API_BASE = 'http://localhost:5000';

interface FetchOptions extends RequestInit {
  params?: Record<string, string>;
}

class ApiError extends Error {
  constructor(message: string, public status?: number, public isNetworkError = false) {
    super(message);
    this.name = 'ApiError';
  }
}

async function fetchApi<T>(endpoint: string, options: FetchOptions = {}): Promise<T> {
  const { params, ...fetchOptions } = options;
  
  let url = `${API_BASE}${endpoint}`;
  if (params) {
    const searchParams = new URLSearchParams(params);
    url += `?${searchParams.toString()}`;
  }

  try {
    const response = await fetch(url, {
      ...fetchOptions,
      credentials: 'include', // Include session cookies
      headers: {
        'Content-Type': 'application/json',
        ...fetchOptions.headers,
      },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Request failed' }));
      throw new ApiError(error.error || `HTTP ${response.status}`, response.status);
    }

    return response.json();
  } catch (error) {
    if (error instanceof ApiError) throw error;
    
    // Network error (CORS, server not running, etc.)
    throw new ApiError(
      'Cannot connect to server. Make sure Flask is running on localhost:5000 with CORS enabled.',
      undefined,
      true
    );
  }
}

// File upload helper
export async function uploadFile(file: File): Promise<{ ok: boolean; filename: string; url: string }> {
  const formData = new FormData();
  formData.append('file', file);
  
  const response = await fetch(`${API_BASE}/api/upload`, {
    method: 'POST',
    credentials: 'include',
    body: formData,
  });
  
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Upload failed' }));
    throw new ApiError(error.error || 'Upload failed', response.status);
  }
  
  return response.json();
}

// Auth API
export const authApi = {
  async login(username: string, password: string): Promise<{ ok: boolean }> {
    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);
    
    const response = await fetch(`${API_BASE}/login`, {
      method: 'POST',
      credentials: 'include',
      body: formData,
    });
    
    if (response.redirected || response.ok) {
      return { ok: true };
    }
    
    // Check if the response contains an error message
    const text = await response.text();
    if (text.includes('Invalid username or password') || text.includes('banned') || text.includes('blocked')) {
      throw new Error('Invalid username or password');
    }
    
    throw new Error('Login failed');
  },

  async register(username: string, password: string, email?: string): Promise<{ ok: boolean }> {
    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);
    if (email) {
      formData.append('email', email);
    }
    
    const response = await fetch(`${API_BASE}/register`, {
      method: 'POST',
      credentials: 'include',
      body: formData,
    });
    
    if (response.redirected || response.ok) {
      return { ok: true };
    }
    
    const text = await response.text();
    if (text.includes('Username taken')) {
      throw new Error('Username already taken');
    }
    throw new Error('Registration failed');
  },

  async logout(): Promise<void> {
    await fetch(`${API_BASE}/logout`, {
      credentials: 'include',
    });
  },

  async whoami(): Promise<{ session: string; is_superadmin: boolean; effective: string }> {
    return fetchApi('/api/whoami');
  },

  async getMyRole(): Promise<{ ok: boolean; is_admin: boolean; is_superadmin: boolean; role: string }> {
    return fetchApi('/api/me/role');
  },
};

// Messages API
export const messagesApi = {
  async getPublicMessages(): Promise<Message[]> {
    return fetchApi('/api/messages');
  },

  async getDmPeers(): Promise<string[]> {
    return fetchApi('/api/dm/peers');
  },

  async getDmMessages(peer: string): Promise<DmMessage[]> {
    return fetchApi('/api/dm/messages', { params: { peer } });
  },

  async getGdmThreads(): Promise<GdmThread[]> {
    return fetchApi('/api/gdm/threads');
  },

  async getGdmMessages(tid: number): Promise<GdmMessage[]> {
    return fetchApi('/api/gdm/messages', { params: { tid: String(tid) } });
  },

  async getGdmMembers(tid: number): Promise<string[]> {
    return fetchApi('/api/gdm/members', { params: { tid: String(tid) } });
  },

  async createGdmThread(name: string, users: string[]): Promise<{ ok: boolean; id: number; name: string }> {
    return fetchApi('/api/gdm/threads', {
      method: 'POST',
      body: JSON.stringify({ name, members: users }),
    });
  },

  async joinGdmByInvite(invite_code: string): Promise<{ id: number; name: string }> {
    return fetchApi('/api/gdm/join', {
      method: 'POST',
      body: JSON.stringify({ invite_code }),
    });
  },

  async leaveGdmThread(tid: number): Promise<{ ok: boolean }> {
    return fetchApi('/api/gdm/leave', {
      method: 'POST',
      body: JSON.stringify({ tid }),
    });
  },

  // Group management APIs
  async lockGroup(tid: number): Promise<{ ok: boolean }> {
    return fetchApi('/api/gdm/lock', {
      method: 'POST',
      body: JSON.stringify({ tid }),
    });
  },

  async unlockGroup(tid: number): Promise<{ ok: boolean }> {
    return fetchApi('/api/gdm/unlock', {
      method: 'POST',
      body: JSON.stringify({ tid }),
    });
  },

  async removeMember(tid: number, username: string): Promise<{ ok: boolean }> {
    return fetchApi('/api/gdm/remove_member', {
      method: 'POST',
      body: JSON.stringify({ tid, username }),
    });
  },

  async transferOwnership(tid: number, newOwner: string): Promise<{ ok: boolean }> {
    return fetchApi('/api/gdm/transfer', {
      method: 'POST',
      body: JSON.stringify({ tid, new_owner: newOwner }),
    });
  },

  async deleteGroup(tid: number): Promise<{ ok: boolean }> {
    return fetchApi('/api/gdm/delete', {
      method: 'POST',
      body: JSON.stringify({ tid }),
    });
  },

  async updateGroupInfo(tid: number, name?: string, description?: string): Promise<{ ok: boolean }> {
    const payload: any = { tid };
    if (name !== undefined) payload.name = name;
    if (description !== undefined) payload.description = description;
    return fetchApi('/api/gdm/update', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  // Admin message logs
  async getAllGroups(): Promise<{ ok: boolean; groups: any[] }> {
    return fetchApi('/api/admin/all_groups');
  },

  async getGroupMessages(threadId: number): Promise<{ ok: boolean; messages: any[] }> {
    return fetchApi(`/api/admin/group_messages/${threadId}`);
  },
};

// Users API
export const usersApi = {
  async getAllUsers(): Promise<{ ok: boolean; users: { username: string; role: string; last_seen?: string; avatar?: string; is_online?: boolean }[] }> {
    return fetchApi('/api/users_all');
  },

  async getOnlineUsers(): Promise<OnlineUser[]> {
    return fetchApi('/api/online');
  },

  async searchUsers(query: string): Promise<{ users: UserSearchResult[]; has_more: boolean }> {
    return fetchApi('/api/users/search', { params: { q: query } });
  },

  async getUserProfile(username: string): Promise<{ ok: boolean; user: any; error?: string }> {
    return fetchApi(`/api/users/${username}`);
  },

  async updateSettings(settings: UserSettings): Promise<{ ok: boolean }> {
    return fetchApi('/api/settings', {
      method: 'POST',
      body: JSON.stringify(settings),
    });
  },

  async uploadAvatar(file: File): Promise<{ ok: boolean; avatar: string }> {
    const formData = new FormData();
    formData.append('avatar', file);
    
    const response = await fetch(`${API_BASE}/api/upload/avatar`, {
      method: 'POST',
      credentials: 'include',
      body: formData,
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Upload failed' }));
      throw new ApiError(error.error || `HTTP ${response.status}`, response.status);
    }
    
    return response.json();
  },

  // Password Reset API
  async requestPasswordReset(username: string, email: string): Promise<{ ok: boolean; message?: string; token?: string }> {
    return fetchApi('/api/request_password_reset', {
      method: 'POST',
      body: JSON.stringify({ username, email }),
    });
  },

  async resetPasswordWithToken(username: string, token: string, password: string): Promise<{ ok: boolean; message?: string }> {
    return fetchApi('/api/reset_password', {
      method: 'POST',
      body: JSON.stringify({ username, token, password }),
    });
  },
};

// Admin API
export const adminApi = {
  async getOnlineUsers(): Promise<{ online: AdminOnlineUser[] }> {
    return fetchApi('/api/admin/online');
  },

  async getOnlineAdmins(): Promise<{ ok: boolean; admins: { username: string; role: string }[] }> {
    return fetchApi('/api/admins/online');
  },

  async banUser(username: string): Promise<{ ok: boolean }> {
    return fetchApi('/api/admin/ban', {
      method: 'POST',
      body: JSON.stringify({ type: 'user', action: 'ban', value: username }),
    });
  },

  async unbanUser(username: string): Promise<{ ok: boolean }> {
    return fetchApi('/api/admin/ban', {
      method: 'POST',
      body: JSON.stringify({ type: 'user', action: 'unban', value: username }),
    });
  },

  async trueBan(username: string, client_id?: string): Promise<{ ok: boolean }> {
    return fetchApi('/api/admin/true_ban', {
      method: 'POST',
      body: JSON.stringify({ user: username, client_id }),
    });
  },

  async trueUnban(username: string, client_id?: string): Promise<{ ok: boolean }> {
    return fetchApi('/api/admin/true_unban', {
      method: 'POST',
      body: JSON.stringify({ user: username, client_id }),
    });
  },

  async timeoutUser(username: string, minutes: number): Promise<{ ok: boolean }> {
    return fetchApi('/api/admin/timeout', {
      method: 'POST',
      body: JSON.stringify({ user: username, minutes }),
    });
  },

  async deleteMessage(messageId: number, type: 'public' | 'dm' | 'gdm' = 'public'): Promise<{ ok: boolean }> {
    return fetchApi('/api/admin/delete_message', {
      method: 'POST',
      body: JSON.stringify({ msg_id: messageId, type }),
    });
  },

  async editMessage(messageId: number, content: string): Promise<{ ok: boolean }> {
    return fetchApi('/api/admin/edit_message', {
      method: 'POST',
      body: JSON.stringify({ message_id: messageId, content }),
    });
  },

  async broadcastMessage(text: string): Promise<{ ok: boolean }> {
    return fetchApi('/api/admin/broadcast', {
      method: 'POST',
      body: JSON.stringify({ text }),
    });
  },

  async resetPassword(username: string, newPassword: string): Promise<{ ok: boolean }> {
    return fetchApi('/api/admin/reset_password', {
      method: 'POST',
      body: JSON.stringify({ username, new_password: newPassword }),
    });
  },

  async updateSettings(settings: Record<string, string>): Promise<{ ok: boolean }> {
    return fetchApi('/api/admin/settings', {
      method: 'POST',
      body: JSON.stringify(settings),
    });
  },

  async toggleImmunity(username: string): Promise<{ ok: boolean; immune: boolean }> {
    return fetchApi(`/api/admin/toggle_immunity/${username}`, { method: 'POST' });
  },

  async getToggles(): Promise<Record<string, string>> {
    return fetchApi('/api/admin/app_settings');
  },

  async saveToggles(toggles: Record<string, string>): Promise<{ ok: boolean }> {
    return fetchApi('/api/admin/toggles', {
      method: 'POST',
      body: JSON.stringify(toggles),
    });
  },

  async createUser(username: string, password: string, role?: string): Promise<{ ok: boolean; username?: string }> {
    return fetchApi('/api/admin/create_user', {
      method: 'POST',
      body: JSON.stringify({ 
        username, 
        password, 
        is_admin: role === 'admin' 
      }),
    });
  },

  async getBannedUsers(): Promise<{ banned_users: string[] }> {
    return fetchApi('/api/admin/banned_users');
  },

  // Reactions API
  async addReaction(messageId: number, messageType: string, emoji: string): Promise<{ ok: boolean }> {
    return fetchApi('/api/reactions/add', {
      method: 'POST',
      body: JSON.stringify({ message_id: messageId, message_type: messageType, emoji }),
    });
  },

  async removeReaction(messageId: number, messageType: string, emoji: string): Promise<{ ok: boolean }> {
    return fetchApi('/api/reactions/remove', {
      method: 'POST',
      body: JSON.stringify({ message_id: messageId, message_type: messageType, emoji }),
    });
  },

  async getReactions(messageId: number, messageType: string): Promise<Record<string, string[]>> {
    return fetchApi(`/api/reactions/${messageId}/${messageType}`);
  },

  async getAllMessages(): Promise<Message[]> {
    return fetchApi('/api/messages');
  },

  async getAllUsers(): Promise<{ username: string; role: string; last_seen?: string; avatar?: string; is_online?: boolean }[]> {
    const response = await fetchApi<{ ok: boolean; users: { username: string; role: string; last_seen?: string; avatar?: string; is_online?: boolean }[] }>('/api/users/all');
    return response.users || [];
  },
};

// Types
export interface Message {
  id: number;
  user_id: number;
  username: string;
  text: string;
  attachment?: string;
  created_at: string;
  reply_to?: number;
  reply_username?: string;
  reply_snippet?: string;
  edited?: number;
}

export interface DmMessage {
  id: number;
  from_user: string;
  to_user: string;
  text: string;
  attachment?: string;
  created_at: string;
  reply_to?: number;
  reply_username?: string;
  reply_snippet?: string;
  avatar?: string;
}

export interface GdmThread {
  id: number;
  name: string;
  created_by: string;
  members: string[];
  invite_code?: string;
  locked?: boolean;
}

export interface GdmMessage {
  id: number;
  username: string;
  text: string;
  attachment?: string;
  created_at: string;
  edited: number;
  reply_to?: number;
  reply_username?: string;
  reply_snippet?: string;
}

export interface OnlineUser {
  username: string;
  avatar?: string;
  avatar_url: string;
  bio?: string;
  status: string;
  presence: 'online' | 'idle' | 'dnd' | 'offline';
}

export interface UserSearchResult {
  username: string;
  avatar?: string;
  status: string;
  created_at: string;
  bio: string;
}

export interface UserSettings {
  new_username?: string;
  current_password?: string;
  new_password?: string;
  theme?: string;
  bio?: string;
  status?: string;
  language?: string;
  email?: string;
}

export interface AdminOnlineUser {
  username: string;
  private: string;
  public: string;
  immune: boolean;
  ip: string;
  client_id: string;
  device_banned: boolean;
  private_banned: boolean;
  public_banned: boolean;
}
