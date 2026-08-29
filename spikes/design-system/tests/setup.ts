import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

afterEach(cleanup);

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperty(globalThis, "ResizeObserver", { value: ResizeObserverStub });
Object.defineProperty(globalThis, "PointerEvent", { value: MouseEvent });
Object.defineProperty(HTMLElement.prototype, "hasPointerCapture", { value: () => false });
Object.defineProperty(HTMLElement.prototype, "setPointerCapture", { value: () => undefined });
Object.defineProperty(HTMLElement.prototype, "releasePointerCapture", { value: () => undefined });
Object.defineProperty(HTMLElement.prototype, "scrollIntoView", { value: () => undefined });

