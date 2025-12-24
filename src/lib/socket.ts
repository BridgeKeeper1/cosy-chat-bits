import { io, Socket } from 'socket.io-client';
import { API_BASE } from './api';

let socket: Socket | null = null;

export interface SocketMessage {
  id: number;
  username: string;
  text: string;
  attachment?: string;
  created_at: string;
  reply_to?: number;
  reply_username?: string;
  reply_snippet?: string;
}

export interface SocketDmMessage {
  id: number;
  from_user: string;
  to_user: string;
  text: string;
  attachment?: string;
  created_at: string;
  reply_to?: number;
}

export interface SocketGdmMessage {
  tid: number;
  id: number;
  username: string;
  text: string;
  attachment?: string;
  created_at: string;
  reply_to?: number;
}

export interface TypingEvent {
  username: string;
  peer?: string;
  tid?: number;
}

export function getSocket(): Socket {
  if (!socket) {
    socket = io(API_BASE, {
      withCredentials: true,
      transports: ['websocket', 'polling'],
      autoConnect: false,
    });
  }
  return socket;
}

export function connectSocket(): void {
  const s = getSocket();
  if (!s.connected) {
    s.connect();
  }
}

export function disconnectSocket(): void {
  if (socket?.connected) {
    socket.disconnect();
  }
}

// Public chat
export function sendPublicMessage(text: string, attachment?: string, replyTo?: number): void {
  const s = getSocket();
  s.emit('send_message', { text, attachment, reply_to: replyTo });
}

export function sendTypingPublic(): void {
  const s = getSocket();
  s.emit('typing');
}

export function sendStopTypingPublic(): void {
  const s = getSocket();
  s.emit('stop_typing');
}

// Direct messages
export function sendDmMessage(peer: string, text: string, attachment?: string, replyTo?: number): void {
  const s = getSocket();
  s.emit('dm_send', { peer, text, attachment, reply_to: replyTo });
}

export function sendTypingDm(peer: string): void {
  const s = getSocket();
  s.emit('dm_typing', { peer });
}

export function sendStopTypingDm(peer: string): void {
  const s = getSocket();
  s.emit('dm_stop_typing', { peer });
}

// Group DMs
export function sendGdmMessage(tid: number, text: string, attachment?: string, replyTo?: number): void {
  const s = getSocket();
  s.emit('gdm_send', { tid, text, attachment, reply_to: replyTo });
}

export function sendTypingGdm(tid: number): void {
  const s = getSocket();
  s.emit('gdm_typing', { tid });
}

export function sendStopTypingGdm(tid: number): void {
  const s = getSocket();
  s.emit('gdm_stop_typing', { tid });
}

// Event listeners
type SocketEventCallback<T> = (data: T) => void;

export function onPublicMessage(callback: SocketEventCallback<SocketMessage>): () => void {
  const s = getSocket();
  s.on('new_message', callback);
  return () => s.off('new_message', callback);
}

export function onDmMessage(callback: SocketEventCallback<SocketDmMessage>): () => void {
  const s = getSocket();
  s.on('new_dm', callback);
  return () => s.off('new_dm', callback);
}

export function onGdmMessage(callback: SocketEventCallback<SocketGdmMessage>): () => void {
  const s = getSocket();
  s.on('gdm_new', callback);
  return () => s.off('gdm_new', callback);
}

export function onTyping(callback: SocketEventCallback<TypingEvent>): () => void {
  const s = getSocket();
  s.on('user_typing', callback);
  return () => s.off('user_typing', callback);
}

export function onStopTyping(callback: SocketEventCallback<TypingEvent>): () => void {
  const s = getSocket();
  s.on('user_stop_typing', callback);
  return () => s.off('user_stop_typing', callback);
}

export function onUserListRefresh(callback: SocketEventCallback<{ online?: string; offline?: string }>): () => void {
  const s = getSocket();
  s.on('user_list_refresh', callback);
  return () => s.off('user_list_refresh', callback);
}

export function onGdmThreadsRefresh(callback: SocketEventCallback<{ tid?: number; deleted?: number }>): () => void {
  const s = getSocket();
  s.on('gdm_threads_refresh', callback);
  return () => s.off('gdm_threads_refresh', callback);
}

export function onBroadcast(callback: SocketEventCallback<{ text: string; from: string }>): () => void {
  const s = getSocket();
  s.on('broadcast', callback);
  return () => s.off('broadcast', callback);
}

export function onConnect(callback: () => void): () => void {
  const s = getSocket();
  s.on('connect', callback);
  return () => s.off('connect', callback);
}

export function onDisconnect(callback: () => void): () => void {
  const s = getSocket();
  s.on('disconnect', callback);
  return () => s.off('disconnect', callback);
}

// Enhanced Call functionality
export function callUser(username: string, callType: 'voice' | 'video' = 'voice'): void {
  const s = getSocket();
  s.emit('call_user', { to_user: username, call_type: callType });
}

export function answerCall(callId: string, answer: boolean): void {
  const s = getSocket();
  s.emit('answer_call', { call_id: callId, answer });
}

export function endCall(callId: string): void {
  const s = getSocket();
  s.emit('end_call', { call_id: callId });
}

export function sendWebRTCSignal(toUser: string, type: string, data: any): void {
  const s = getSocket();
  s.emit('webrtc_signal', { to_user: toUser, type, data });
}

export function startCallDm(username: string): void {
  const s = getSocket();
  s.emit('call_start_dm', { to_user: username });
}

export function startCallGdm(threadId: number): void {
  const s = getSocket();
  s.emit('call_start_gdm', { thread_id: threadId });
}

export function onIncomingCall(callback: SocketEventCallback<{ call_id: string; from_user: string; call_type: string }>): () => void {
  const s = getSocket();
  s.on('incoming_call', callback);
  return () => s.off('incoming_call', callback);
}

export function onCallAnswered(callback: SocketEventCallback<{ call_id: string; by_user: string; answer: boolean }>): () => void {
  const s = getSocket();
  s.on('call_answered', callback);
  return () => s.off('call_answered', callback);
}

export function onCallEnded(callback: SocketEventCallback<{ call_id: string; by_user: string }>): () => void {
  const s = getSocket();
  s.on('call_ended', callback);
  return () => s.off('call_ended', callback);
}

export function onCallError(callback: SocketEventCallback<{ error: string }>): () => void {
  const s = getSocket();
  s.on('call_error', callback);
  return () => s.off('call_error', callback);
}

export function onWebRTCSignal(callback: SocketEventCallback<{ from_user: string; type: string; data: any }>): () => void {
  const s = getSocket();
  s.on('webrtc_signal', callback);
  return () => s.off('webrtc_signal', callback);
}

export function onCallStarted(callback: SocketEventCallback<{ type: string; from?: string; thread_id?: number }>): () => void {
  const s = getSocket();
  s.on('call_started', callback);
  return () => s.off('call_started', callback);
}

export function onSystemMessage(callback: SocketEventCallback<{ text: string }>): () => void {
  const s = getSocket();
  s.on('system_message', callback);
  return () => s.off('system_message', callback);
}

export function onMessageEdited(callback: SocketEventCallback<{ id: number; content: string; edited_at: string; edited_by: string }>): () => void {
  const s = getSocket();
  s.on('message_edited', callback);
  return () => s.off('message_edited', callback);
}

export function onMessageDeleted(callback: SocketEventCallback<{ id: number; deleted_by: string }>): () => void {
  const s = getSocket();
  s.on('message_deleted', callback);
  return () => s.off('message_deleted', callback);
}

export function onError(callback: () => void): () => void {
  const s = getSocket();
  s.on('connect_error', callback);
  return () => s.off('connect_error', callback);
}
