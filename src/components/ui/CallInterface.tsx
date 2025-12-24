import React, { useState, useEffect, useRef } from 'react';
import { endCall, onCallEnded, onWebRTCSignal, sendWebRTCSignal } from '@/lib/socket';
import { Button } from './button';
import { Phone, PhoneOff, Mic, MicOff, Video, VideoOff, MessageSquare, Maximize2 } from 'lucide-react';
import { Modal, ModalContent, ModalHeader, ModalTitle, ModalBody, ModalFooter } from './dialog';

interface CallInterfaceProps {
  callId: string;
  remoteUser: string;
  callType: 'voice' | 'video';
  onEnd: () => void;
}

export function CallInterface({ callId, remoteUser, callType, onEnd }: CallInterfaceProps) {
  const [isConnected, setIsConnected] = useState(false);
  const [isMuted, setIsMuted] = useState(false);
  const [isVideoOff, setIsVideoOff] = useState(false);
  const [callDuration, setCallDuration] = useState(0);
  
  const localVideoRef = useRef<HTMLVideoElement>(null);
  const remoteVideoRef = useRef<HTMLVideoElement>(null);
  const localStreamRef = useRef<MediaStream | null>(null);
  const remoteStreamRef = useRef<MediaStream | null>(null);
  const peerConnectionRef = useRef<RTCPeerConnection | null>(null);

  useEffect(() => {
    const timer = setInterval(() => {
      setCallDuration(prev => prev + 1);
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    initializeCall();
    return () => {
      cleanupCall();
    };
  }, [callId, remoteUser]);

  const initializeCall = async () => {
    try {
      // Get user media
      const constraints = {
        audio: true,
        video: callType === 'video'
      };

      const localStream = await navigator.mediaDevices.getUserMedia(constraints);
      localStreamRef.current = localStream;

      if (localVideoRef.current && callType === 'video') {
        localVideoRef.current.srcObject = localStream;
      }

      // Create peer connection
      const pc = new RTCPeerConnection({
        iceServers: [
          { urls: 'stun:stun.l.google.com:19302' },
          { urls: 'stun:stun1.l.google.com:19302' }
        ]
      });

      peerConnectionRef.current = pc;

      // Add local stream to peer connection
      localStream.getTracks().forEach(track => {
        pc.addTrack(track, localStream);
      });

      // Handle remote stream
      pc.ontrack = (event) => {
        if (remoteVideoRef.current && event.streams[0]) {
          remoteVideoRef.current.srcObject = event.streams[0];
          remoteStreamRef.current = event.streams[0];
          setIsConnected(true);
        }
      };

      // Handle ICE candidates
      pc.onicecandidate = (event) => {
        if (event.candidate) {
          sendWebRTCSignal(remoteUser, 'ice-candidate', event.candidate);
        }
      };

      // Listen for WebRTC signals
      const unsubscribe = onWebRTCSignal((signal) => {
        if (signal.from_user === remoteUser) {
          handleWebRTCSignal(signal);
        }
      });

      // Listen for call end
      const unsubscribeEnd = onCallEnded(() => {
        onEnd();
      });

      return () => {
        unsubscribe();
        unsubscribeEnd();
      };
    } catch (error) {
      console.error('Failed to initialize call:', error);
    }
  };

  const handleWebRTCSignal = async (signal: any) => {
    const pc = peerConnectionRef.current;
    if (!pc) return;

    try {
      if (signal.type === 'offer') {
        await pc.setRemoteDescription(new RTCSessionDescription(signal.data));
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        sendWebRTCSignal(remoteUser, 'answer', answer);
      } else if (signal.type === 'answer') {
        await pc.setRemoteDescription(new RTCSessionDescription(signal.data));
      } else if (signal.type === 'ice-candidate') {
        await pc.addIceCandidate(new RTCIceCandidate(signal.data));
      }
    } catch (error) {
      console.error('Error handling WebRTC signal:', error);
    }
  };

  const cleanupCall = () => {
    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach(track => track.stop());
    }
    if (peerConnectionRef.current) {
      peerConnectionRef.current.close();
    }
  };

  const handleEndCall = () => {
    endCall(callId);
    onEnd();
  };

  const toggleMute = () => {
    if (localStreamRef.current) {
      const audioTrack = localStreamRef.current.getAudioTracks()[0];
      if (audioTrack) {
        audioTrack.enabled = !isMuted;
        setIsMuted(!isMuted);
      }
    }
  };

  const toggleVideo = () => {
    if (localStreamRef.current) {
      const videoTrack = localStreamRef.current.getVideoTracks()[0];
      if (videoTrack) {
        videoTrack.enabled = !isVideoOff;
        setIsVideoOff(!isVideoOff);
      }
    }
  };

  const formatDuration = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className="fixed inset-0 bg-black z-50 flex flex-col">
      {/* Remote Video */}
      <div className="flex-1 relative">
        {callType === 'video' ? (
          <video
            ref={remoteVideoRef}
            autoPlay
            playsInline
            className="w-full h-full object-cover"
          />
        ) : (
          <div className="w-full h-full flex items-center justify-center">
            <div className="text-center">
              <div className="w-24 h-24 bg-gray-700 rounded-full flex items-center justify-center mb-4 mx-auto">
                <span className="text-3xl font-bold text-white">
                  {remoteUser.charAt(0).toUpperCase()}
                </span>
              </div>
              <p className="text-white text-xl">{remoteUser}</p>
              <p className="text-gray-400 mt-2">
                {isConnected ? 'Connected' : 'Connecting...'}
              </p>
            </div>
          </div>
        )}

        {/* Local Video (for video calls) */}
        {callType === 'video' && (
          <div className="absolute bottom-4 right-4 w-32 h-24 bg-gray-800 rounded-lg overflow-hidden">
            <video
              ref={localVideoRef}
              autoPlay
              playsInline
              muted
              className="w-full h-full object-cover"
            />
          </div>
        )}

        {/* Call Duration */}
        <div className="absolute top-4 left-4 bg-black bg-opacity-50 text-white px-3 py-1 rounded-full">
          {formatDuration(callDuration)}
        </div>
      </div>

      {/* Controls */}
      <div className="bg-gray-900 p-4">
        <div className="flex justify-center items-center gap-4">
          <Button
            variant="outline"
            size="lg"
            onClick={toggleMute}
            className={`rounded-full w-12 h-12 ${isMuted ? 'bg-red-500 text-white' : 'bg-gray-700 text-white'}`}
          >
            {isMuted ? <MicOff className="h-5 w-5" /> : <Mic className="h-5 w-5" />}
          </Button>

          {callType === 'video' && (
            <Button
              variant="outline"
              size="lg"
              onClick={toggleVideo}
              className={`rounded-full w-12 h-12 ${isVideoOff ? 'bg-red-500 text-white' : 'bg-gray-700 text-white'}`}
            >
              {isVideoOff ? <VideoOff className="h-5 w-5" /> : <Video className="h-5 w-5" />}
            </Button>
          )}

          <Button
            variant="outline"
            size="lg"
            className="rounded-full w-12 h-12 bg-gray-700 text-white"
          >
            <MessageSquare className="h-5 w-5" />
          </Button>

          <Button
            variant="outline"
            size="lg"
            className="rounded-full w-12 h-12 bg-gray-700 text-white"
          >
            <Maximize2 className="h-5 w-5" />
          </Button>

          <Button
            size="lg"
            onClick={handleEndCall}
            className="rounded-full w-16 h-16 bg-red-500 hover:bg-red-600 text-white"
          >
            <PhoneOff className="h-6 w-6" />
          </Button>
        </div>
      </div>
    </div>
  );
}
