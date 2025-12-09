/**
 * Modal Component
 * 
 * TODO: Implement in Session 10
 */

import React from 'react';

interface ModalProps {
  children?: React.ReactNode;
  className?: string;
}

export function Modal({ children, className }: ModalProps) {
  // TODO: Implement in Session 10
  return (
    <div className={className}>
      {children}
    </div>
  );
}

export default Modal;
