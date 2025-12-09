/**
 * Badge Component
 * 
 * TODO: Implement in Session 10
 */

import React from 'react';

interface BadgeProps {
  children?: React.ReactNode;
  className?: string;
}

export function Badge({ children, className }: BadgeProps) {
  // TODO: Implement in Session 10
  return (
    <div className={className}>
      {children}
    </div>
  );
}

export default Badge;
