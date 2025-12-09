/**
 * Spinner Component
 * 
 * TODO: Implement in Session 10
 */

import React from 'react';

interface SpinnerProps {
  children?: React.ReactNode;
  className?: string;
}

export function Spinner({ children, className }: SpinnerProps) {
  // TODO: Implement in Session 10
  return (
    <div className={className}>
      {children}
    </div>
  );
}

export default Spinner;
