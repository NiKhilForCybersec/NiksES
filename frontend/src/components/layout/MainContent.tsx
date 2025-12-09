/**
 * MainContent Component
 * 
 * TODO: Implement in Session 10
 */

import React from 'react';

interface MainContentProps {
  children?: React.ReactNode;
  className?: string;
}

export function MainContent({ children, className }: MainContentProps) {
  // TODO: Implement in Session 10
  return (
    <div className={className}>
      {children}
    </div>
  );
}

export default MainContent;
