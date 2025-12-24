import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Search, Users, MessageSquare, Calendar, Trash2, Eye } from "lucide-react";
import { messagesApi } from "@/lib/api";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface Group {
  id: number;
  name: string;
  created_at: string;
  deleted_at?: string;
  created_by: string;
  creator_name: string;
  message_count: number;
  is_deleted: boolean;
}

interface GroupMessage {
  id: number;
  text: string;
  username: string;
  created_at: string;
  attachment?: string;
  reply_to?: number;
  edited_by?: string;
  edited_at?: string;
}

export function MessageLogsViewer() {
  const [activeTab, setActiveTab] = useState<'public' | 'groups'>('public');
  const [groups, setGroups] = useState<Group[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<Group | null>(null);
  const [groupMessages, setGroupMessages] = useState<GroupMessage[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [messageSearchTerm, setMessageSearchTerm] = useState('');

  useEffect(() => {
    if (activeTab === 'groups') {
      loadGroups();
    }
  }, [activeTab]);

  const loadGroups = async () => {
    try {
      setLoading(true);
      const response = await messagesApi.getAllGroups();
      if (response.ok) {
        setGroups(response.groups);
      } else {
        toast.error('Failed to load groups');
      }
    } catch (error) {
      toast.error('Error loading groups');
    } finally {
      setLoading(false);
    }
  };

  const loadGroupMessages = async (groupId: number) => {
    try {
      setLoading(true);
      const response = await messagesApi.getGroupMessages(groupId);
      if (response.ok) {
        setGroupMessages(response.messages);
      } else {
        toast.error('Failed to load group messages');
      }
    } catch (error) {
      toast.error('Error loading group messages');
    } finally {
      setLoading(false);
    }
  };

  const handleGroupClick = (group: Group) => {
    setSelectedGroup(group);
    loadGroupMessages(group.id);
  };

  const filteredGroups = groups.filter(group =>
    group.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredMessages = groupMessages.filter(message =>
    message.text.toLowerCase().includes(messageSearchTerm.toLowerCase()) ||
    message.username.toLowerCase().includes(messageSearchTerm.toLowerCase())
  );

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <div className="h-full flex flex-col bg-background">
      <div className="border-b p-4">
        <h1 className="text-2xl font-bold mb-4">Message Logs</h1>
        
        {/* Tab Navigation */}
        <div className="flex space-x-1 bg-muted p-1 rounded-lg">
          <button
            onClick={() => setActiveTab('public')}
            className={cn(
              "flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors",
              activeTab === 'public'
                ? "bg-background text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <MessageSquare className="w-4 h-4" />
            Public Messages
          </button>
          <button
            onClick={() => setActiveTab('groups')}
            className={cn(
              "flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors",
              activeTab === 'groups'
                ? "bg-background text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <Users className="w-4 h-4" />
            Group Messages
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-hidden">
        {activeTab === 'public' ? (
          <div className="h-full flex items-center justify-center p-8">
            <div className="text-center max-w-md">
              <MessageSquare className="w-16 h-16 mx-auto mb-4 text-muted-foreground" />
              <h2 className="text-xl font-semibold mb-2">Public Message Logs</h2>
              <p className="text-muted-foreground">
                Public message viewing functionality will be implemented here.
                This will show all public chat messages with search and filtering capabilities.
              </p>
            </div>
          </div>
        ) : (
          <div className="h-full flex">
            {/* Groups List */}
            <div className="w-80 border-r flex flex-col">
              <div className="p-4 border-b">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <input
                    type="text"
                    placeholder="Search groups..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 bg-muted border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                  />
                </div>
              </div>
              
              <div className="flex-1 overflow-y-auto">
                {loading && groups.length === 0 ? (
                  <div className="p-4 text-center text-muted-foreground">Loading groups...</div>
                ) : (
                  <div className="p-2 space-y-1">
                    {filteredGroups.map((group) => (
                      <motion.button
                        key={group.id}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        onClick={() => handleGroupClick(group)}
                        className={cn(
                          "w-full text-left p-3 rounded-lg transition-colors",
                          selectedGroup?.id === group.id
                            ? "bg-primary text-primary-foreground"
                            : "hover:bg-muted"
                        )}
                      >
                        <div className="flex items-start justify-between">
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2">
                              <h3 className="font-medium truncate">{group.name}</h3>
                              {group.is_deleted && (
                                <span className="px-1.5 py-0.5 text-xs bg-destructive text-destructive-foreground rounded">
                                  Deleted
                                </span>
                              )}
                            </div>
                            <div className="text-sm opacity-70">
                              {group.message_count} messages
                            </div>
                            <div className="text-xs opacity-60">
                              Created by {group.creator_name} • {formatDate(group.created_at)}
                            </div>
                          </div>
                        </div>
                      </motion.button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Messages View */}
            <div className="flex-1 flex flex-col">
              {selectedGroup ? (
                <>
                  <div className="p-4 border-b">
                    <div className="flex items-center justify-between mb-2">
                      <h2 className="text-lg font-semibold">{selectedGroup.name}</h2>
                      <div className="text-sm text-muted-foreground">
                        {groupMessages.length} messages
                      </div>
                    </div>
                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                      <input
                        type="text"
                        placeholder="Search messages..."
                        value={messageSearchTerm}
                        onChange={(e) => setMessageSearchTerm(e.target.value)}
                        className="w-full pl-10 pr-4 py-2 bg-muted border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                      />
                    </div>
                  </div>
                  
                  <div className="flex-1 overflow-y-auto p-4">
                    {loading ? (
                      <div className="text-center text-muted-foreground">Loading messages...</div>
                    ) : (
                      <div className="space-y-4">
                        {filteredMessages.map((message) => (
                          <motion.div
                            key={message.id}
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="p-3 bg-muted/50 rounded-lg"
                          >
                            <div className="flex items-start justify-between mb-2">
                              <div>
                                <span className="font-medium">{message.username}</span>
                                <span className="text-xs text-muted-foreground ml-2">
                                  {formatDate(message.created_at)}
                                </span>
                                {message.edited_by && (
                                  <span className="text-xs text-muted-foreground ml-2">
                                    (edited by {message.edited_by})
                                  </span>
                                )}
                              </div>
                            </div>
                            <div className="text-sm whitespace-pre-wrap">{message.text}</div>
                            {message.attachment && (
                              <div className="mt-2">
                                <div className="text-xs text-muted-foreground">Attachment: {message.attachment}</div>
                              </div>
                            )}
                          </motion.div>
                        ))}
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <div className="h-full flex items-center justify-center">
                  <div className="text-center text-muted-foreground">
                    <Users className="w-16 h-16 mx-auto mb-4 opacity-50" />
                    <p>Select a group to view its messages</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
