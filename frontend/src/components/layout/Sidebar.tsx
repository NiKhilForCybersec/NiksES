/**
 * Sidebar Component
 * 
 * TODO: Implement in Session 10
 */

import React from 'react';

interface SidebarProps {
  children?: React.ReactNode;
  className?: string;
}

export function Sidebar({ children, className }: SidebarProps) {
  // TODO: Implement in Session 10
  return (
    <div className={className}>
      {children}
    </div>
  );
}

export default Sidebar;
