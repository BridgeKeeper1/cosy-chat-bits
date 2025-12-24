import React, { useState, useEffect } from 'react';
import { Modal, ModalContent, ModalHeader, ModalTitle, ModalBody, ModalFooter } from './dialog';
import { Button } from './button';
import { Phone, PhoneOff, Video, VideoOff } from 'lucide-react';
import { answerCall, endCall } from '@/lib/socket';

interface IncomingCallModalProps {
  isOpen: boolean;
  onClose: () => void;
  callData: {
    call_id: string;
    from_user: string;
    call_type: 'voice' | 'video';
  } | null;
}

export function IncomingCallModal({ isOpen, onClose, callData }: IncomingCallModalProps) {
  const [isRinging, setIsRinging] = useState(true);

  useEffect(() => {
    if (isOpen && callData) {
      // Simulate ringing sound effect
      const ringInterval = setInterval(() => {
        // Play ring sound here if needed
      }, 2000);

      return () => clearInterval(ringInterval);
    }
  }, [isOpen, callData]);

  const handleAccept = () => {
    setIsRinging(false);
    if (callData) {
      answerCall(callData.call_id, true);
      // Navigate to call interface or open call UI
      window.location.href = `/call/${callData.call_id}`;
    }
  };

  const handleDecline = () => {
    setIsRinging(false);
    if (callData) {
      answerCall(callData.call_id, false);
    }
    onClose();
  };

  if (!callData) return null;

  return (
    <Modal open={isOpen} onOpenChange={onClose}>
      <ModalContent className="sm:max-w-md">
        <ModalHeader className="text-center">
          <ModalTitle className="text-lg font-semibold">
            Incoming {callData.call_type === 'video' ? 'Video' : 'Voice'} Call
          </ModalTitle>
        </ModalHeader>
        <ModalBody className="text-center space-y-4">
          <div className="flex justify-center">
            <div className={`relative ${isRinging ? 'animate-pulse' : ''}`}>
              {callData.call_type === 'video' ? (
                <Video className="h-16 w-16 text-blue-500" />
              ) : (
                <Phone className="h-16 w-16 text-blue-500" />
              )}
              {isRinging && (
                <div className="absolute -top-1 -right-1">
                  <div className="h-3 w-3 bg-green-500 rounded-full animate-ping" />
                </div>
              )}
            </div>
          </div>
          
          <div className="space-y-2">
            <p className="text-2xl font-bold text-gray-900">
              {callData.from_user}
            </p>
            <p className="text-sm text-gray-500">
              {callData.call_type === 'video' ? 'Video' : 'Voice'} call...
            </p>
            {isRinging && (
              <p className="text-xs text-blue-600 animate-pulse">
                Ringing...
              </p>
            )}
          </div>
        </ModalBody>
        <ModalFooter className="flex justify-center gap-4">
          <Button
            variant="outline"
            size="lg"
            onClick={handleDecline}
            className="flex items-center gap-2 bg-red-50 hover:bg-red-100 text-red-600 border-red-200"
          >
            <PhoneOff className="h-4 w-4" />
            Decline
          </Button>
          <Button
            size="lg"
            onClick={handleAccept}
            className="flex items-center gap-2 bg-green-500 hover:bg-green-600 text-white"
          >
            {callData.call_type === 'video' ? (
              <Video className="h-4 w-4" />
            ) : (
              <Phone className="h-4 w-4" />
            )}
            Accept
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}
