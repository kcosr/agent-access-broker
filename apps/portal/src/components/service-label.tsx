// A service's display name followed by its ID (muted, monospace) when they differ.

export function ServiceLabel({ service, name }: { service: string; name: string | undefined }) {
  if (!name || name === service) return <span className="wb-mono">{service}</span>;
  return (
    <>
      {name} <span className="wb-mono wb-muted">{service}</span>
    </>
  );
}
