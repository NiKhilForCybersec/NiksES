/**
 * EmptyState Component
 * 
 * TODO: Implement in Session 10
 */

import React from 'react';

interface EmptyStateProps {
  children?: React.ReactNode;
  className?: string;
}

export function EmptyState({ children, className }: EmptyStateProps) {
  // TODO: Implement in Session 10
  return (
    <div className={className}>
      {children}
    </div>
  );
}

export default EmptyState;
