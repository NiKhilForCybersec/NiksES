/**
 * Tooltip Component
 * 
 * TODO: Implement in Session 10
 */

import React from 'react';

interface TooltipProps {
  children?: React.ReactNode;
  className?: string;
}

export function Tooltip({ children, className }: TooltipProps) {
  // TODO: Implement in Session 10
  return (
    <div className={className}>
      {children}
    </div>
  );
}

export default Tooltip;
