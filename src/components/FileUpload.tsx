import { useRef, useState, useCallback, useMemo, memo } from 'react';
import { useAppContext } from '../context/AppContext';
import { api, errorMessage } from '../services/api';
import type { UploadResult } from '../types';

// =============================================================================
// TYPES & INTERFACES
// =============================================================================

interface FileUploadProps {
  onUploaded: (result: UploadResult) => void;
  disabled?: boolean;
  maxSizeMB?: number;
  allowedExtensions?: string[];
}

interface FileInfo {
  name: string;
  size: number;
  type: string;
  preview?: string;
}

type UploadPhase = 'idle' | 'selecting' | 'encrypting' | 'uploading' | 'success' | 'error';

// =============================================================================
// CONSTANTS
// =============================================================================

const DEFAULT_MAX_SIZE_MB = 100;
const DEFAULT_ALLOWED_EXTENSIONS = ['pdf', 'docx', 'jpg', 'jpeg', 'png', 'mp4', 'webm'];

const MIME_TYPE_MAP: Record<string, string[]> = {
  pdf: ['application/pdf'],
  docx: [
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  ],
  jpg: ['image/jpeg'],
  jpeg: ['image/jpeg'],
  png: ['image/png'],
  mp4: ['video/mp4'],
  webm: ['video/webm'],
};

const FILE_ICONS: Record<string, string> = {
  pdf: '📄',
  docx: '📝',
  jpg: '🖼️',
  jpeg: '🖼️',
  png: '🖼️',
  mp4: '🎥',
  webm: '🎥',
  default: '📎',
};

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Structured logger for debugging
 */
const logger = {
  info: (msg: string, data?: any) => {
    console.log(`[FileUpload] ${msg}`, data || '');
  },
  error: (msg: string, error?: any) => {
    console.error(`[FileUpload] ${msg}`, error || '');
  },
  warn: (msg: string, data?: any) => {
    console.warn(`[FileUpload] ${msg}`, data || '');
  },
};

/**
 * Format bytes to human-readable string
 */
const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
};

/**
 * Get file extension from filename
 */
const getFileExtension = (filename: string): string => {
  return filename.split('.').pop()?.toLowerCase() ?? '';
};

/**
 * Get icon for file type
 */
const getFileIcon = (extension: string): string => {
  return FILE_ICONS[extension] || FILE_ICONS.default;
};

/**
 * Validate file extension
 */
const validateExtension = (filename: string, allowedExtensions: string[]): boolean => {
  const ext = getFileExtension(filename);
  return allowedExtensions.includes(ext);
};

/**
 * Validate MIME type
 */
const validateMimeType = (mimeType: string, extension: string): boolean => {
  const allowedMimes = MIME_TYPE_MAP[extension];
  if (!allowedMimes) return true; // Allow if we don't have MIME mapping
  return allowedMimes.includes(mimeType);
};

/**
 * Categorize errors for better user feedback
 */
function categorizeError(error: unknown): { type: string; message: string } {
  const msg = errorMessage(error).toLowerCase();

  if (msg.includes('validation') || msg.includes('invalid')) {
    return { type: 'validation', message: errorMessage(error) };
  }
  if (msg.includes('network') || msg.includes('timeout') || msg.includes('fetch')) {
    return { type: 'network', message: 'Network error. Please check your connection.' };
  }
  if (msg.includes('unauthorized') || msg.includes('session')) {
    return { type: 'auth', message: 'Session expired. Please log in again.' };
  }
  if (msg.includes('storage') || msg.includes('upload')) {
    return { type: 'storage', message: 'Upload failed. Please try again.' };
  }
  if (msg.includes('size') || msg.includes('large')) {
    return { type: 'size', message: errorMessage(error) };
  }
  if (msg.includes('type') || msg.includes('format')) {
    return { type: 'format', message: errorMessage(error) };
  }

  return { type: 'unknown', message: errorMessage(error) };
}

// =============================================================================
// SUB-COMPONENTS
// =============================================================================

/**
 * Error display component with categorization
 */
const ErrorDisplay = memo(({ error, onDismiss }: { error: string; onDismiss?: () => void }) => {
  const categorized = categorizeError(error);

  const iconMap: Record<string, string> = {
    validation: '⚠️',
    network: '🌐',
    auth: '🔐',
    storage: '💾',
    size: '📏',
    format: '📋',
    unknown: '❌',
  };

  const colorMap: Record<string, string> = {
    validation: 'border-yellow-900/50 bg-yellow-900/20 text-yellow-200',
    network: 'border-blue-900/50 bg-blue-900/20 text-blue-200',
    auth: 'border-red-900/50 bg-red-900/20 text-red-200',
    storage: 'border-purple-900/50 bg-purple-900/20 text-purple-200',
    size: 'border-orange-900/50 bg-orange-900/20 text-orange-200',
    format: 'border-pink-900/50 bg-pink-900/20 text-pink-200',
    unknown: 'border-red-900/50 bg-red-900/20 text-red-200',
  };

  return (
    <div
      role="alert"
      className={`mt-3 p-4 rounded-xl border ${colorMap[categorized.type]} flex items-start gap-3`}
    >
      <span className="text-xl" aria-hidden="true">{iconMap[categorized.type]}</span>
      <div className="flex-1">
        <p className="text-sm font-medium">{categorized.message}</p>
      </div>
      {onDismiss && (
        <button
          onClick={onDismiss}
          className="text-sm opacity-60 hover:opacity-100 transition-opacity"
          aria-label="Dismiss error"
        >
          ✕
        </button>
      )}
    </div>
  );
});

/**
 * File info card component
 */
const FileInfoCard = memo(({
  file,
  onRemove,
}: {
  file: FileInfo;
  onRemove?: () => void;
}) => {
  const extension = getFileExtension(file.name);
  const icon = getFileIcon(extension);

  return (
    <div className="mt-4 panel-2 bg-[#202c33] rounded-xl p-4 flex items-center gap-4">
      {file.preview ? (
        <img
          src={file.preview}
          alt={file.name}
          className="w-16 h-16 object-cover rounded-lg"
        />
      ) : (
        <div className="w-16 h-16 bg-[#111b21] rounded-lg flex items-center justify-center text-3xl" aria-hidden="true">
          {icon}
        </div>
      )}
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-[#e9edef] truncate" title={file.name}>
          {file.name}
        </p>
        <p className="text-xs text-[#8696a0] mt-1">
          {formatBytes(file.size)} • {extension.toUpperCase()}
        </p>
      </div>
      {onRemove && (
        <button
          onClick={onRemove}
          className="btn-ghost px-3 py-1.5 rounded-lg bg-[#111b21] text-red-400 text-xs hover:bg-red-900/20 transition-colors"
          aria-label={`Remove ${file.name}`}
        >
          Remove
        </button>
      )}
    </div>
  );
});

/**
 * Upload progress indicator
 */
const UploadProgress = memo(({ phase, message }: { phase: UploadPhase; message?: string }) => {
  if (phase === 'idle' || phase === 'success' || phase === 'error') return null;

  const phaseMessages: Record<UploadPhase, string> = {
    idle: '',
    selecting: 'Waiting for file selection...',
    encrypting: 'Encrypting with AES-256-GCM...',
    uploading: 'Uploading securely...',
    success: 'Upload complete!',
    error: 'Upload failed',
  };

  const displayMessage = message || phaseMessages[phase];

  return (
    <div className="mt-4 flex items-center justify-center gap-3" role="status" aria-live="polite">
      <div className="w-4 h-4 border-2 border-[#202c33] border-t-[#00a884] rounded-full animate-spin" aria-hidden="true" />
      <p className="text-xs text-[#00a884] font-medium">{displayMessage}</p>
    </div>
  );
});

// =============================================================================
// MAIN COMPONENT
// =============================================================================

const FileUpload: React.FC<FileUploadProps> = ({
  onUploaded,
  disabled = false,
  maxSizeMB = DEFAULT_MAX_SIZE_MB,
  allowedExtensions = DEFAULT_ALLOWED_EXTENSIONS,
}) => {
  const { sessionToken } = useAppContext();

  // State
  const [dragOver, setDragOver] = useState(false);
  const [phase, setPhase] = useState<UploadPhase>('idle');
  const [error, setError] = useState<string | null>(null);
  const [uploadedFile, setUploadedFile] = useState<FileInfo | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Memoized computed values
  const maxSizeBytes = useMemo(() => maxSizeMB * 1024 * 1024, [maxSizeMB]);
  const acceptString = useMemo(
    () => allowedExtensions.map((ext) => `.${ext}`).join(','),
    [allowedExtensions]
  );

  // ===========================================================================
  // FILE VALIDATION
  // ===========================================================================

  const validateFile = useCallback(
    (file: File): { valid: boolean; error?: string } => {
      const extension = getFileExtension(file.name);

      // Validate extension
      if (!validateExtension(file.name, allowedExtensions)) {
        return {
          valid: false,
          error: `Unsupported file type. Allowed: ${allowedExtensions.join(', ').toUpperCase()}.`,
        };
      }

      // Validate MIME type
      if (!validateMimeType(file.type, extension)) {
        return {
          valid: false,
          error: 'File format does not match extension.',
        };
      }

      // Validate size
      if (file.size > maxSizeBytes) {
        return {
          valid: false,
          error: `File exceeds the ${maxSizeMB} MB limit.`,
        };
      }

      // Validate non-empty
      if (file.size === 0) {
        return {
          valid: false,
          error: 'File is empty.',
        };
      }

      return { valid: true };
    },
    [allowedExtensions, maxSizeBytes, maxSizeMB]
  );

  // ===========================================================================
  // FILE HANDLING
  // ===========================================================================

  const handleFile = useCallback(
    async (file: File) => {
      setError(null);
      setUploadedFile(null);

      logger.info('Processing file', { name: file.name, size: file.size, type: file.type });

      // Validate file
      const validation = validateFile(file);
      if (!validation.valid) {
        logger.warn('File validation failed', { error: validation.error });
        setError(validation.error!);
        setPhase('error');
        return;
      }

      if (!sessionToken) {
        logger.error('No session token available');
        setError('Session required. Please log in.');
        setPhase('error');
        return;
      }

      try {
        setPhase('encrypting');

        // Create preview for images
        let preview: string | undefined;
        if (file.type.startsWith('image/')) {
          preview = URL.createObjectURL(file);
        }

        const fileInfo: FileInfo = {
          name: file.name,
          size: file.size,
          type: file.type,
          preview,
        };

        setUploadedFile(fileInfo);
        setPhase('uploading');

        logger.info('Starting file upload', { name: file.name });
        const bytes = new Uint8Array(await file.arrayBuffer());
        const result = await api.uploadFile(sessionToken, file.name, bytes);

        setPhase('success');
        logger.info('File uploaded successfully', { fileKey: result.file_key });

        // Call success callback
        onUploaded(result);

        // Clean up preview URL after a delay
        if (preview) {
          setTimeout(() => URL.revokeObjectURL(preview), 5000);
        }
      } catch (e) {
        const categorized = categorizeError(e);
        logger.error('File upload failed', categorized);
        setError(categorized.message);
        setPhase('error');
      }
    },
    [sessionToken, validateFile, onUploaded]
  );

  const handleNativeBrowse = useCallback(async () => {
    if (!sessionToken) {
      logger.error('No session token available');
      setError('Session required. Please log in.');
      setPhase('error');
      return;
    }

    setError(null);
    setUploadedFile(null);
    setPhase('selecting');

    try {
      logger.info('Opening native file picker');
      const result = await api.pickAndUploadFile(sessionToken);

      if (result) {
        setPhase('success');
        logger.info('File uploaded via native picker', { fileKey: result.file_key });

        // Create file info from result
        const fileInfo: FileInfo = {
          name: result.file_name || 'Uploaded file',
          size: result.file_size || 0,
          type: result.file_type || 'application/octet-stream',
        };
        setUploadedFile(fileInfo);

        onUploaded(result);
      } else {
        setPhase('idle');
        logger.info('Native file picker cancelled');
      }
    } catch (e) {
      const categorized = categorizeError(e);
      logger.error('Native file picker failed', categorized);
      setError(categorized.message);
      setPhase('error');
    }
  }, [sessionToken, onUploaded]);

  const handleInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) {
        void handleFile(file);
      }
      // Reset input value to allow selecting the same file again
      e.target.value = '';
    },
    [handleFile]
  );

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setDragOver(false);

      const file = e.dataTransfer.files?.[0];
      if (file) {
        logger.info('File dropped', { name: file.name });
        void handleFile(file);
      }
    },
    [handleFile]
  );

  const handleRemoveFile = useCallback(() => {
    if (uploadedFile?.preview) {
      URL.revokeObjectURL(uploadedFile.preview);
    }
    setUploadedFile(null);
    setError(null);
    setPhase('idle');
    logger.info('File removed');
  }, [uploadedFile]);

  const handleDismissError = useCallback(() => {
    setError(null);
    setPhase('idle');
  }, []);

  const handleClick = useCallback(() => {
    if (!disabled && phase === 'idle') {
      inputRef.current?.click();
    }
  }, [disabled, phase]);

  // ===========================================================================
  // CLEANUP
  // ===========================================================================

  // Clean up preview URLs on unmount
  useMemo(() => {
    return () => {
      if (uploadedFile?.preview) {
        URL.revokeObjectURL(uploadedFile.preview);
        logger.info('Cleaned up preview URL on unmount');
      }
    };
  }, [uploadedFile]);

  // ===========================================================================
  // RENDER
  // ===========================================================================

  const isProcessing = phase === 'encrypting' || phase === 'uploading' || phase === 'selecting';
  const isSuccess = phase === 'success';

  return (
    <div>
      <div
        className={`panel-2 cursor-pointer rounded-2xl p-8 text-center transition-all duration-200 ${
          dragOver
            ? 'bg-[#005c4b]/40 border-2 border-dashed border-[#00a884]'
            : 'hover:bg-[#2a3942] border-2 border-dashed border-transparent'
        } ${disabled || isProcessing ? 'pointer-events-none opacity-50' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={handleClick}
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-label="File upload area. Click or drag and drop files here."
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            handleClick();
          }
        }}
      >
        <div className="text-5xl mb-4" aria-hidden="true">
          {dragOver ? '📥' : isSuccess ? '✅' : '🗂️'}
        </div>
        <p className="text-base font-semibold text-[#e9edef]">
          {dragOver
            ? 'Drop your file here'
            : isSuccess
            ? 'File uploaded successfully!'
            : 'Drop your document or video here'}
        </p>
        <p className="mt-2 text-xs text-[#8696a0]">
          {allowedExtensions.join(', ').toUpperCase()} — up to {maxSizeMB} MB. Encrypted before it leaves this device.
        </p>

        {!isSuccess && !isProcessing && (
          <div className="mt-6 flex items-center justify-center gap-3">
            <button
              type="button"
              className="btn-secondary px-4 py-2 rounded-lg bg-[#2a3942] text-[#e9edef] text-sm font-medium hover:bg-[#00a884] transition-colors focus:outline-none focus:ring-2 focus:ring-[#00a884] focus:ring-offset-2 focus:ring-offset-[#111b21]"
              disabled={isProcessing}
              onClick={(e) => {
                e.stopPropagation();
                inputRef.current?.click();
              }}
              aria-label="Choose file from browser"
            >
              Choose file
            </button>
            <button
              type="button"
              className="btn-ghost px-4 py-2 rounded-lg text-[#00a884] text-sm font-medium hover:text-[#06cf9c] transition-colors focus:outline-none focus:ring-2 focus:ring-[#00a884] focus:ring-offset-2 focus:ring-offset-[#111b21]"
              disabled={isProcessing}
              onClick={(e) => {
                e.stopPropagation();
                void handleNativeBrowse();
              }}
              aria-label="Choose file from native file picker"
            >
              Native browser…
            </button>
          </div>
        )}

        <UploadProgress phase={phase} />

        {isSuccess && uploadedFile && (
          <div className="mt-4 text-xs text-[#00a884] font-medium" role="status" aria-live="polite">
            ✓ {uploadedFile.name} uploaded successfully
          </div>
        )}
      </div>

      <input
        ref={inputRef}
        type="file"
        accept={acceptString}
        className="hidden"
        onChange={handleInputChange}
        disabled={disabled || isProcessing}
        aria-label="File input"
      />

      {uploadedFile && (
        <FileInfoCard file={uploadedFile} onRemove={isSuccess ? handleRemoveFile : undefined} />
      )}

      {error && <ErrorDisplay error={error} onDismiss={handleDismissError} />}
    </div>
  );
};

export default memo(FileUpload);