/**
 * Button Component
 * 
 * TODO: Implement in Session 10
 */

import React from 'react';

interface ButtonProps {
  children?: React.ReactNode;
  className?: string;
}

export function Button({ children, className }: ButtonProps) {
  // TODO: Implement in Session 10
  return (
    <div className={className}>
      {children}
    </div>
  );
}

export default Button;
