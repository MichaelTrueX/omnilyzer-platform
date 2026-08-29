import * as DialogPrimitive from "@radix-ui/react-dialog";
import type { ReactElement, ReactNode } from "react";

export type DialogProps = {
  trigger: ReactElement;
  title: string;
  description: string;
  children?: ReactNode;
};

export function Dialog({ trigger, title, description, children }: DialogProps) {
  return (
    <DialogPrimitive.Root>
      <DialogPrimitive.Trigger asChild>{trigger}</DialogPrimitive.Trigger>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 bg-overlay" />
        <DialogPrimitive.Content className="fixed left-1/2 top-1/2 grid w-11/12 max-w-md -translate-x-1/2 -translate-y-1/2 gap-control rounded-dialog bg-surface-raised p-dialog text-text-primary focus:outline-none">
          <DialogPrimitive.Title className="text-title font-bold">{title}</DialogPrimitive.Title>
          <DialogPrimitive.Description className="text-body text-text-secondary">{description}</DialogPrimitive.Description>
          {children}
          <DialogPrimitive.Close className="inline-flex min-h-hit-target min-w-hit-target items-center justify-center justify-self-end rounded-control border border-border-control bg-surface px-control-inline text-label font-semibold text-text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus">
            Close
          </DialogPrimitive.Close>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}

