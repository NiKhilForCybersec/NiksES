/**
 * Footer Component
 * 
 * TODO: Implement in Session 10
 */

import React from 'react';

interface FooterProps {
  children?: React.ReactNode;
  className?: string;
}

export function Footer({ children, className }: FooterProps) {
  // TODO: Implement in Session 10
  return (
    <div className={className}>
      {children}
    </div>
  );
}

export default Footer;
