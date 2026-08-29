import { useId, type ComponentProps } from "react";

export type TextFieldProps = Omit<ComponentProps<"input">, "className" | "style"> & {
  label: string;
  hint?: string;
  error?: string;
};

export function TextField({ label, hint, error, id: suppliedId, ...props }: TextFieldProps) {
  const generatedId = useId();
  const id = suppliedId ?? generatedId;
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [hintId, errorId].filter(Boolean).join(" ") || undefined;

  return (
    <div className="grid gap-control text-text-primary">
      <label className="text-label font-semibold" htmlFor={id}>{label}</label>
      <input
        id={id}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        className="min-h-hit-target rounded-control border border-border-control bg-canvas px-control-inline py-control-block text-body text-text-primary outline-none focus-visible:ring-2 focus-visible:ring-focus"
        {...props}
      />
      {hint && <span id={hintId} className="text-label text-text-secondary">{hint}</span>}
      {error && <span id={errorId} className="text-label font-semibold text-danger">{error}</span>}
    </div>
  );
}

