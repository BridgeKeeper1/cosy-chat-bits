import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { toast } from "sonner";
import { usersApi } from "@/lib/api";
import { Key, Mail, ArrowLeft, CheckCircle } from "lucide-react";

export default function PasswordReset() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');
  const username = searchParams.get('username');
  
  const [step, setStep] = useState<'request' | 'reset'>('request');
  const [isLoading, setIsLoading] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    resetToken: token || ''
  });
  const [errors, setErrors] = useState<string[]>([]);
  const [success, setSuccess] = useState(false);

  const navigate = useNavigate();

  // If token and username are in URL, go directly to reset step
  useState(() => {
    if (token && username) {
      setFormData(prev => ({ ...prev, username, resetToken: token }));
      setStep('reset');
    }
  });

  const handleRequestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrors([]);
    
    if (!formData.username.trim() || !formData.email.trim()) {
      setErrors(['Username and email are required']);
      return;
    }

    if (!formData.email.includes('@') || !formData.email.includes('.')) {
      setErrors(['Please enter a valid email address']);
      return;
    }

    setIsLoading(true);
    try {
      const result = await usersApi.requestPasswordReset(formData.username.trim(), formData.email.trim());
      
      if (result.ok) {
        setSuccess(true);
        toast.success('Password reset instructions sent to your email');
        
        // In development, show the token for testing
        if (result.token && import.meta.env.DEV) {
          console.log('Reset token (development only):', result.token);
          setErrors([`Development mode: Token is ${result.token}`]);
        }
      } else {
        setErrors([result.message || 'Failed to request password reset']);
      }
    } catch (error: any) {
      const errorMessage = error.message || 'Failed to request password reset';
      setErrors([errorMessage]);
      toast.error(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrors([]);
    
    if (!formData.username.trim() || !formData.resetToken.trim() || !formData.password.trim()) {
      setErrors(['All fields are required']);
      return;
    }

    if (formData.password.length < 6) {
      setErrors(['Password must be at least 6 characters long']);
      return;
    }

    if (formData.password.trim() !== formData.confirmPassword.trim()) {
      setErrors(['Passwords do not match']);
      return;
    }

    setIsLoading(true);
    try {
      const result = await usersApi.resetPasswordWithToken(
        formData.username.trim(),
        formData.resetToken.trim(),
        formData.password
      );
      
      if (result.ok) {
        setSuccess(true);
        toast.success('Password reset successfully');
        
        // Redirect to auth after 2 seconds
        setTimeout(() => {
          navigate('/auth');
        }, 2000);
      } else {
        setErrors([result.message || 'Failed to reset password']);
      }
    } catch (error: any) {
      const errorMessage = error.message || 'Failed to reset password';
      setErrors([errorMessage]);
      toast.error(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  const handleInputChange = (field: string, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    setErrors([]);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-md">
        <div className="mb-6">
          <Button
            variant="ghost"
            onClick={() => navigate('/auth')}
            className="mb-4"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Login
          </Button>
        </div>

        <Card>
          <CardHeader className="text-center">
            <div className="mx-auto w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mb-4">
              <Key className="w-6 h-6 text-primary" />
            </div>
            <CardTitle className="text-2xl">
              {step === 'request' ? 'Reset Password' : 'Enter New Password'}
            </CardTitle>
            <CardDescription>
              {step === 'request' 
                ? 'Enter your username and email to receive password reset instructions'
                : 'Choose your new password'
              }
            </CardDescription>
          </CardHeader>

          <CardContent>
            {success ? (
              <div className="text-center space-y-4">
                <div className="mx-auto w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
                  <CheckCircle className="w-6 h-6 text-green-600" />
                </div>
                <div>
                  <h3 className="font-semibold text-lg mb-2">
                    {step === 'request' ? 'Reset Instructions Sent' : 'Password Reset Successfully'}
                  </h3>
                  <p className="text-muted-foreground">
                    {step === 'request' 
                      ? 'Check your email for password reset instructions.'
                      : 'You will be redirected to the login page shortly.'
                    }
                  </p>
                </div>
              </div>
            ) : (
              <form onSubmit={step === 'request' ? handleRequestSubmit : handleResetSubmit} className="space-y-4">
                {errors.length > 0 && (
                  <Alert variant="destructive">
                    <AlertDescription>
                      {errors.map((error, index) => (
                        <div key={index}>{error}</div>
                      ))}
                    </AlertDescription>
                  </Alert>
                )}

                {step === 'request' ? (
                  <>
                    <div className="space-y-2">
                      <Label htmlFor="username">Username</Label>
                      <Input
                        id="username"
                        type="text"
                        placeholder="Enter your username"
                        value={formData.username}
                        onChange={(e) => handleInputChange('username', e.target.value)}
                        required
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="email">Email</Label>
                      <Input
                        id="email"
                        type="email"
                        placeholder="Enter your email"
                        value={formData.email}
                        onChange={(e) => handleInputChange('email', e.target.value)}
                        required
                      />
                    </div>
                  </>
                ) : (
                  <>
                    <div className="space-y-2">
                      <Label htmlFor="resetToken">Reset Token</Label>
                      <Input
                        id="resetToken"
                        type="text"
                        placeholder="Enter reset token"
                        value={formData.resetToken}
                        onChange={(e) => handleInputChange('resetToken', e.target.value)}
                        required
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="password">New Password</Label>
                      <Input
                        id="password"
                        type="password"
                        placeholder="Enter new password"
                        value={formData.password}
                        onChange={(e) => handleInputChange('password', e.target.value)}
                        required
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="confirmPassword">Confirm Password</Label>
                      <Input
                        id="confirmPassword"
                        type="password"
                        placeholder="Confirm new password"
                        value={formData.confirmPassword}
                        onChange={(e) => handleInputChange('confirmPassword', e.target.value)}
                        required
                      />
                    </div>
                  </>
                )}

                <Button type="submit" className="w-full" disabled={isLoading}>
                  {isLoading ? (
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                      {step === 'request' ? 'Sending...' : 'Resetting...'}
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      {step === 'request' && <Mail className="w-4 h-4" />}
                      {step === 'request' ? 'Send Reset Instructions' : 'Reset Password'}
                    </div>
                  )}
                </Button>
              </form>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
