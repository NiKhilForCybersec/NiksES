/**
 * CopyButton Component
 * 
 * TODO: Implement in Session 10
 */

import React from 'react';

interface CopyButtonProps {
  children?: React.ReactNode;
  className?: string;
}

export function CopyButton({ children, className }: CopyButtonProps) {
  // TODO: Implement in Session 10
  return (
    <div className={className}>
      {children}
    </div>
  );
}

export default CopyButton;
