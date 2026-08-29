import type { ComponentProps } from "react";

export type ButtonProps = Omit<ComponentProps<"button">, "className" | "style"> & {
  variant?: "primary" | "secondary" | "danger";
};

const variants = {
  primary: "border-action-primary bg-action-primary text-action-primary-foreground hover:bg-action-primary-hover",
  secondary: "border-border-control bg-surface text-text-primary hover:bg-canvas",
  danger: "border-danger bg-danger text-danger-foreground",
} as const;

export function Button({ variant = "primary", type = "button", ...props }: ButtonProps) {
  return (
    <button
      type={type}
      className={`inline-flex min-h-hit-target items-center justify-center rounded-control border px-control-inline py-control-block text-label font-semibold focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${variants[variant]}`}
      {...props}
    />
  );
}

