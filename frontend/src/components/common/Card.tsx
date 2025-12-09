/**
 * Card Component
 * 
 * TODO: Implement in Session 10
 */

import React from 'react';

interface CardProps {
  children?: React.ReactNode;
  className?: string;
}

export function Card({ children, className }: CardProps) {
  // TODO: Implement in Session 10
  return (
    <div className={className}>
      {children}
    </div>
  );
}

export default Card;
