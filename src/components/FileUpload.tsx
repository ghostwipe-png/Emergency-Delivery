import { useRef, useState } from "react";
import { useAppContext } from "../context/AppContext";
import { api, errorMessage } from "../services/api";
import type { UploadResult } from "../types";

const MAX_SIZE = 100 * 1024 * 1024;
const ALLOWED_EXTENSIONS = ["pdf", "docx", "jpg", "jpeg", "png", "mp4"];

interface Props {
  onUploaded: (result: UploadResult) => void;
  disabled?: boolean;
}

export default function FileUpload({ onUploaded, disabled }: Props) {
  const { sessionToken } = useAppContext();
  const [dragOver, setDragOver] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  async function handleFile(file: File) {
    setError(null);
    const ext = file.name.split(".").pop()?.toLowerCase() ?? "";
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      setError("Unsupported file type. Allowed: PDF, DOCX, JPG, PNG, MP4.");
      return;
    }
    if (file.size > MAX_SIZE) {
      setError("File exceeds the 100 MB limit.");
      return;
    }
    if (!sessionToken) return;

    try {
      setBusy("Encrypting (AES-256-GCM) and uploading…");
      const bytes = new Uint8Array(await file.arrayBuffer());
      const result = await api.uploadFile(sessionToken, file.name, bytes);
      onUploaded(result);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  }

  async function handleNativeBrowse() {
    if (!sessionToken) return;
    setError(null);
    try {
      setBusy("Waiting for file selection…");
      const result = await api.pickAndUploadFile(sessionToken);
      if (result) onUploaded(result);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <div
        className={`panel-2 cursor-pointer rounded-2xl p-8 text-center transition-all duration-200 ${
          dragOver ? "bg-[#005c4b]/40" : "hover:bg-[#2a3942]"
        } ${disabled ? "pointer-events-none opacity-50" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          const file = e.dataTransfer.files?.[0];
          if (file) void handleFile(file);
        }}
        onClick={() => inputRef.current?.click()}
      >
        <div className="text-3xl">🗂️</div>
        <p className="mt-3 text-sm font-medium">Drop your document or video here</p>
        <p className="mt-1 text-xs text-[#8696a0]">
          PDF, DOCX, JPG, PNG, MP4 — up to 100 MB. Encrypted before it leaves this device.
        </p>
        <div className="mt-4 flex items-center justify-center gap-3">
          <button
            type="button"
            className="btn-secondary"
            disabled={busy !== null}
            onClick={(e) => {
              e.stopPropagation();
              inputRef.current?.click();
            }}
          >
            Choose file
          </button>
          <button
            type="button"
            className="btn-ghost"
            disabled={busy !== null}
            onClick={(e) => {
              e.stopPropagation();
              void handleNativeBrowse();
            }}
          >
            Native browser…
          </button>
        </div>
        {busy && <p className="mt-4 text-xs text-[#00a884]">{busy}</p>}
      </div>

      <input
        ref={inputRef}
        type="file"
        accept=".pdf,.docx,.jpg,.jpeg,.png,.mp4"
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) void handleFile(file);
          e.target.value = "";
        }}
      />

      {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
    </div>
  );
}