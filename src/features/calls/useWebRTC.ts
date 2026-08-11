import { useState, useRef, useCallback } from 'react';

export interface CallSignal {
  type: 'call_offer' | 'call_answer' | 'call_ice' | 'call_hangup';
  call_id: string;
  sdp?: RTCSessionDescriptionInit;
  candidate?: RTCIceCandidateInit;
  caller_name?: string;
}

export function useWebRTC(sendSignal: (payload: CallSignal) => void) {
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [remoteStream, setRemoteStream] = useState<MediaStream | null>(null);
  const [callState, setCallState] = useState<'idle' | 'calling' | 'ringing' | 'active'>('idle');
  const [pendingOffer, setPendingOffer] = useState<CallSignal | null>(null);
  
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const callIdRef = useRef<string | null>(null);
  const localStreamRef = useRef<MediaStream | null>(null);

  const createPeerConnection = useCallback(() => {
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
    });

    pc.onicecandidate = (event) => {
      if (event.candidate && callIdRef.current) {
        sendSignal({ type: 'call_ice', call_id: callIdRef.current, candidate: event.candidate.toJSON() });
      }
    };

    pc.ontrack = (event) => {
      setRemoteStream(event.streams[0]);
      setCallState('active');
    };

    return pc;
  }, [sendSignal]);

  const startCall = useCallback(async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      setLocalStream(stream);
      localStreamRef.current = stream;
      
      const pc = createPeerConnection();
      pcRef.current = pc;
      callIdRef.current = crypto.randomUUID();

      stream.getTracks().forEach(track => pc.addTrack(track, stream));

      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      
      sendSignal({ type: 'call_offer', call_id: callIdRef.current, sdp: offer, caller_name: 'Me' });
      setCallState('calling');
    } catch (e) {
      console.error("Failed to start call:", e);
      alert("Could not access camera/microphone.");
    }
  }, [createPeerConnection, sendSignal]);

  const acceptCall = useCallback(async () => {
    if (!pendingOffer) return;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      setLocalStream(stream);
      localStreamRef.current = stream;
      
      const pc = createPeerConnection();
      pcRef.current = pc;
      callIdRef.current = pendingOffer.call_id;

      stream.getTracks().forEach(track => pc.addTrack(track, stream));

      await pc.setRemoteDescription(new RTCSessionDescription(pendingOffer.sdp!));
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      
      sendSignal({ type: 'call_answer', call_id: pendingOffer.call_id, sdp: answer });
      setCallState('active');
      setPendingOffer(null);
    } catch (e) {
      console.error("Failed to accept call:", e);
      hangUp();
    }
  }, [pendingOffer, createPeerConnection, sendSignal]);

  const handleSignal = useCallback(async (signal: CallSignal) => {
    if (signal.type === 'call_offer') {
      setPendingOffer(signal);
      setCallState('ringing');
    } else if (signal.type === 'call_answer') {
      if (pcRef.current && signal.sdp) {
        await pcRef.current.setRemoteDescription(new RTCSessionDescription(signal.sdp));
      }
    } else if (signal.type === 'call_ice') {
      if (pcRef.current && signal.candidate) {
        await pcRef.current.addIceCandidate(new RTCIceCandidate(signal.candidate));
      }
    } else if (signal.type === 'call_hangup') {
      hangUp(false); // Don't send hangup back to avoid infinite loop
    }
  }, []);

  const hangUp = useCallback((sendHangup = true) => {
    if (pcRef.current) {
      pcRef.current.close();
      pcRef.current = null;
    }
    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach(track => track.stop());
      localStreamRef.current = null;
    }
    setLocalStream(null);
    setRemoteStream(null);
    setCallState('idle');
    setPendingOffer(null);
    
    if (sendHangup && callIdRef.current) {
      sendSignal({ type: 'call_hangup', call_id: callIdRef.current });
    }
    callIdRef.current = null;
  }, [sendSignal]);

  return { localStream, remoteStream, callState, pendingOffer, startCall, acceptCall, handleSignal, hangUp };
}