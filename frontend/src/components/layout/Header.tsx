/**
 * Header Component
 * 
 * TODO: Implement in Session 10
 */

import React from 'react';

interface HeaderProps {
  children?: React.ReactNode;
  className?: string;
}

export function Header({ children, className }: HeaderProps) {
  // TODO: Implement in Session 10
  return (
    <div className={className}>
      {children}
    </div>
  );
}

export default Header;
