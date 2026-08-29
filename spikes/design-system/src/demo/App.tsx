import { Button, Dialog, TextField } from "../index";

function ThemeFixture({ theme }: { theme: "light" | "dark" }) {
  return (
    <section data-theme={theme} className="grid gap-dialog bg-canvas p-dialog text-text-primary">
      <h2 className="text-title font-bold">{theme === "light" ? "Light" : "Dark"} semantic theme</h2>
      <div className="flex flex-wrap gap-control">
        <Button>Primary</Button>
        <Button variant="secondary">Secondary</Button>
        <Button variant="danger">Danger</Button>
      </div>
      <TextField label="Evidence field" hint="Semantic component fixture" />
      <Dialog
        trigger={<Button variant="secondary">Open dialog</Button>}
        title="Architecture dialog"
        description="Radix behavior is available only through the Omnilyzer wrapper."
      >
        <p className="text-body">The same component source consumes this theme's semantic values.</p>
      </Dialog>
    </section>
  );
}

export function App() {
  return (
    <main className="grid min-h-screen grid-cols-1 lg:grid-cols-2">
      <ThemeFixture theme="light" />
      <ThemeFixture theme="dark" />
    </main>
  );
}

