import { useRef, useEffect } from 'react';

interface CallOverlayProps {
  localStream: MediaStream | null;
  remoteStream: MediaStream | null;
  callState: string;
  pendingOffer: any;
  onAccept: () => void;
  onHangUp: () => void;
}

export default function CallOverlay({ localStream, remoteStream, callState, pendingOffer, onAccept, onHangUp }: CallOverlayProps) {
  const localVideoRef = useRef<HTMLVideoElement>(null);
  const remoteVideoRef = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    if (localVideoRef.current && localStream) {
      localVideoRef.current.srcObject = localStream;
    }
  }, [localStream]);

  useEffect(() => {
    if (remoteVideoRef.current && remoteStream) {
      remoteVideoRef.current.srcObject = remoteStream;
    }
  }, [remoteStream]);

  if (callState === 'idle') return null;

  return (
    <div className="fixed inset-0 z-[200] bg-[#0b141a] flex flex-col items-center justify-center">
      <video ref={remoteVideoRef} autoPlay playsInline className="absolute inset-0 w-full h-full object-cover" />
      
      {localStream && (
        <div className="absolute top-4 right-4 w-32 h-48 bg-black rounded-xl overflow-hidden shadow-lg z-10 border border-[#2a3942]">
          <video ref={localVideoRef} autoPlay playsInline muted className="w-full h-full object-cover" />
        </div>
      )}

      {callState === 'ringing' && pendingOffer && (
        <div className="absolute inset-0 z-20 bg-black/80 flex flex-col items-center justify-center gap-6">
          <p className="text-white text-2xl font-bold">Incoming Video Call...</p>
          <div className="flex gap-6">
            <button onClick={onAccept} className="w-16 h-16 rounded-full bg-[#00a884] hover:bg-[#06cf9c] flex items-center justify-center text-white text-2xl">📞</button>
            <button onClick={onHangUp} className="w-16 h-16 rounded-full bg-red-600 hover:bg-red-700 flex items-center justify-center text-white text-2xl">🚫</button>
          </div>
        </div>
      )}

      <div className="absolute bottom-10 flex gap-6 z-10">
        {/* FIX: Changed hangUp() to onHangUp() */}
        <button onClick={onHangUp} className="w-16 h-16 rounded-full bg-red-600 hover:bg-red-700 flex items-center justify-center text-white text-2xl shadow-lg">
          📞
        </button>
      </div>
      
      {callState === 'calling' && <p className="absolute top-10 text-white text-xl z-10 bg-black/50 px-4 py-2 rounded-full">Calling...</p>}
    </div>
  );
}