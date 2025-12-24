import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/contexts/AuthContext";
import { MessageCircle, Users, Shield, Zap } from "lucide-react";

const LandingPage = () => {
  const navigate = useNavigate();
  const { isAuthenticated, isLoading } = useAuth();

  useEffect(() => {
    // Only redirect if we know the auth state and user is authenticated
    if (!isLoading && isAuthenticated) {
      navigate("/chat");
    }
  }, [isAuthenticated, isLoading, navigate]);

  // Show loading while checking auth status
  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="text-center">
          <MessageCircle className="h-16 w-16 text-blue-600 mx-auto mb-4 animate-pulse" />
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  // Don't render landing page if authenticated (will redirect)
  if (isAuthenticated) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="container mx-auto px-4 py-16">
        <div className="text-center mb-16">
          <div className="flex justify-center mb-6">
            <MessageCircle className="h-16 w-16 text-blue-600" />
          </div>
          <h1 className="text-4xl md:text-6xl font-bold text-gray-900 mb-4">
            Chatter
          </h1>
          <p className="text-xl text-gray-600 mb-8 max-w-2xl mx-auto">
            Connect with friends in real-time. Experience seamless chat with voice calls, 
            group messaging, and more.
          </p>
          <div className="flex gap-4 justify-center">
            <Button 
              size="lg" 
              onClick={() => navigate("/auth")}
              className="bg-blue-600 hover:bg-blue-700"
            >
              Get Started
            </Button>
            <Button 
              variant="outline" 
              size="lg"
              onClick={() => navigate("/auth")}
            >
              Sign In
            </Button>
          </div>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
          <Card className="text-center">
            <CardHeader>
              <MessageCircle className="h-12 w-12 text-blue-600 mx-auto mb-2" />
              <CardTitle>Real-time Chat</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription>
                Instant messaging with friends and groups
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="text-center">
            <CardHeader>
              <Users className="h-12 w-12 text-green-600 mx-auto mb-2" />
              <CardTitle>Group Chats</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription>
                Create and join group conversations
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="text-center">
            <CardHeader>
              <Shield className="h-12 w-12 text-purple-600 mx-auto mb-2" />
              <CardTitle>Secure</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription>
                Your privacy and security come first
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="text-center">
            <CardHeader>
              <Zap className="h-12 w-12 text-yellow-600 mx-auto mb-2" />
              <CardTitle>Fast</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription>
                Lightning-fast message delivery
              </CardDescription>
            </CardContent>
          </Card>
        </div>

        <div className="text-center">
          <h2 className="text-3xl font-bold text-gray-900 mb-4">
            Ready to start chatting?
          </h2>
          <p className="text-gray-600 mb-6">
            Join thousands of users already connected on Chatter
          </p>
          <Button 
            size="lg" 
            onClick={() => navigate("/auth")}
            className="bg-blue-600 hover:bg-blue-700"
          >
            Join Chatter Now
          </Button>
        </div>
      </div>
    </div>
  );
};

export default LandingPage;
