/**
 * Tabs Component
 * 
 * TODO: Implement in Session 10
 */

import React from 'react';

interface TabsProps {
  children?: React.ReactNode;
  className?: string;
}

export function Tabs({ children, className }: TabsProps) {
  // TODO: Implement in Session 10
  return (
    <div className={className}>
      {children}
    </div>
  );
}

export default Tabs;
