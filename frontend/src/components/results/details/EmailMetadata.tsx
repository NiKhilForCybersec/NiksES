/**
 * EmailMetadata Component
 * 
 * Displays basic email metadata (subject, date, recipients, etc.).
 */

import React from 'react';

interface EmailMetadataProps {
  email: any;
  className?: string;
}

export function EmailMetadata({ email, className = '' }: EmailMetadataProps) {
  if (!email) {
    return null;
  }

  const formatDate = (dateString: string | undefined): string => {
    if (!dateString) return 'Unknown';
    try {
      return new Date(dateString).toLocaleString();
    } catch {
      return dateString;
    }
  };

  const formatRecipients = (recipients: any[]): string => {
    if (!recipients || recipients.length === 0) return 'None';
    return recipients
      .slice(0, 3)
      .map(r => r.email || r.raw)
      .join(', ') + (recipients.length > 3 ? ` +${recipients.length - 3} more` : '');
  };

  return (
    <div className={`bg-gray-800 rounded-lg p-4 ${className}`}>
      {/* Subject */}
      <div className="mb-4">
        <div className="text-sm text-gray-400 mb-1">Subject</div>
        <div className="text-gray-200 font-medium">{email.subject || '(No Subject)'}</div>
      </div>

      {/* Grid layout for other fields */}
      <div className="grid grid-cols-2 gap-4 text-sm">
        {/* Date */}
        <div>
          <div className="text-gray-400 mb-1">Date</div>
          <div className="text-gray-200">{formatDate(email.date)}</div>
        </div>

        {/* Message ID */}
        <div>
          <div className="text-gray-400 mb-1">Message-ID</div>
          <div className="text-gray-200 truncate font-mono text-xs" title={email.message_id}>
            {email.message_id || 'None'}
          </div>
        </div>

        {/* To */}
        <div>
          <div className="text-gray-400 mb-1">To</div>
          <div className="text-gray-200 truncate" title={formatRecipients(email.to_recipients)}>
            {formatRecipients(email.to_recipients)}
          </div>
        </div>

        {/* CC */}
        {email.cc_recipients && email.cc_recipients.length > 0 && (
          <div>
            <div className="text-gray-400 mb-1">CC</div>
            <div className="text-gray-200 truncate" title={formatRecipients(email.cc_recipients)}>
              {formatRecipients(email.cc_recipients)}
            </div>
          </div>
        )}

        {/* Attachments */}
        <div>
          <div className="text-gray-400 mb-1">Attachments</div>
          <div className="text-gray-200">
            {email.attachments?.length || 0} file{email.attachments?.length !== 1 ? 's' : ''}
          </div>
        </div>

        {/* URLs */}
        <div>
          <div className="text-gray-400 mb-1">URLs Found</div>
          <div className="text-gray-200">
            {email.urls?.length || 0} URL{email.urls?.length !== 1 ? 's' : ''}
          </div>
        </div>
      </div>

      {/* Body Preview */}
      {email.body_text && (
        <div className="mt-4 pt-4 border-t border-gray-700">
          <div className="text-sm text-gray-400 mb-2">Body Preview</div>
          <div className="text-gray-300 text-sm bg-gray-900 rounded p-3 max-h-32 overflow-y-auto whitespace-pre-wrap">
            {email.body_text.slice(0, 500)}{email.body_text.length > 500 ? '...' : ''}
          </div>
        </div>
      )}
    </div>
  );
}

export default EmailMetadata;
