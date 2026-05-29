type ThreatCrushContext = {
  config?: Record<string, unknown>;
  emit?: (event: ThreatEvent) => Promise<void> | void;
  getState?: <T = unknown>(key: string) => Promise<T | null> | T | null;
  setState?: (key: string, value: unknown) => Promise<void> | void;
  log?: {
    info?: (message: string, meta?: unknown) => void;
    warn?: (message: string, meta?: unknown) => void;
    error?: (message: string, meta?: unknown) => void;
  };
};

type ThreatEvent = {
  module: string;
  category: string;
  severity: "low" | "medium" | "high" | "critical";
  message: string;
  details: Record<string, unknown>;
};

type KevCatalog = {
  title?: string;
  dateReleased?: string;
  count?: number;
  vulnerabilities?: KevEntry[];
};

type KevEntry = {
  cveID: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  shortDescription?: string;
  requiredAction?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
};

const DEFAULT_FEED =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

let ctx: ThreatCrushContext | null = null;
let timer: ReturnType<typeof setInterval> | null = null;

function configString(key: string, fallback: string): string {
  const value = ctx?.config?.[key];
  return typeof value === "string" && value.trim() ? value : fallback;
}

function configNumber(key: string, fallback: number): number {
  const value = ctx?.config?.[key];
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
}

async function getState<T>(key: string, fallback: T): Promise<T> {
  const value = await ctx?.getState?.<T>(key);
  return value == null ? fallback : value;
}

function sortKevEntries(entries: KevEntry[]): KevEntry[] {
  return [...entries].sort((a, b) => {
    const byDate = String(a.dateAdded || "").localeCompare(String(b.dateAdded || ""));
    return byDate || String(a.cveID).localeCompare(String(b.cveID));
  });
}

async function pollKevCatalog(): Promise<void> {
  if (!ctx) return;

  const feedUrl = configString("feed_url", DEFAULT_FEED);
  const maxEvents = Math.max(1, Math.floor(configNumber("max_events_per_poll", 25)));
  const response = await fetch(feedUrl, {
    headers: { Accept: "application/json", "User-Agent": "threatcrush-cisa-kev-watch/0.1.0" },
  });

  if (!response.ok) {
    throw new Error(`CISA KEV feed returned ${response.status}`);
  }

  const catalog = (await response.json()) as KevCatalog;
  const entries = sortKevEntries(catalog.vulnerabilities || []);
  const lastSeenDate = await getState<string>("last_seen_date", "");
  const seenCves = new Set(await getState<string[]>("seen_cves", []));

  const fresh = entries
    .filter((entry) => entry.cveID && !seenCves.has(entry.cveID))
    .filter((entry) => !lastSeenDate || String(entry.dateAdded || "") >= lastSeenDate)
    .slice(-maxEvents);

  for (const entry of fresh) {
    await ctx.emit?.({
      module: "cisa-kev-watch",
      category: "vulnerability",
      severity: "high",
      message: `CISA KEV: ${entry.cveID} added for ${entry.product || "unknown product"}`,
      details: {
        cve: entry.cveID,
        vendor_project: entry.vendorProject || null,
        product: entry.product || null,
        vulnerability_name: entry.vulnerabilityName || null,
        date_added: entry.dateAdded || null,
        due_date: entry.dueDate || null,
        known_ransomware_campaign_use: entry.knownRansomwareCampaignUse || null,
        required_action: entry.requiredAction || null,
        description: entry.shortDescription || null,
        source: feedUrl,
      },
    });
    seenCves.add(entry.cveID);
  }

  const newestDate = entries.at(-1)?.dateAdded || lastSeenDate;
  await ctx.setState?.("last_seen_date", newestDate);
  await ctx.setState?.("seen_cves", Array.from(seenCves).slice(-1000));
  ctx.log?.info?.("CISA KEV poll complete", { total: entries.length, emitted: fresh.length });
}

export async function init(context: ThreatCrushContext): Promise<void> {
  ctx = context;
}

export async function start(): Promise<void> {
  const intervalSeconds = Math.max(60, Math.floor(configNumber("poll_interval_seconds", 3600)));
  await pollKevCatalog();
  timer = setInterval(() => {
    pollKevCatalog().catch((error) => {
      ctx?.log?.error?.("CISA KEV poll failed", { error: String(error) });
    });
  }, intervalSeconds * 1000);
}

export async function stop(): Promise<void> {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}

