import { createTelegramClient } from './client.js';
import { createNexusClient } from './nexusClient.js';
import {
  parseCommand,
  formatHelp,
  formatHealth,
  formatVulns,
  formatChains,
  formatConflicts,
  formatExploitable,
  formatSearch,
} from './format.js';

/** One command -> one reply string. Never throws - errors become a reply. */
export async function handleCommand(command, args, nexus) {
  switch (command) {
    case 'start':
    case 'help':
      return formatHelp();

    case 'health': {
      const res = await nexus.health();
      return res.ok ? formatHealth(res.data) : `⚠️ ${res.error}`;
    }

    case 'vulns': {
      if (!args) return 'Usage: `/vulns <domain>`';
      const res = await nexus.vulnsForDomain(args.toLowerCase());
      return res.ok ? formatVulns(args, res.data) : `⚠️ ${res.error}`;
    }

    case 'chains': {
      const res = await nexus.chains();
      return res.ok ? formatChains(res.data) : `⚠️ ${res.error}`;
    }

    case 'conflicts': {
      const res = await nexus.conflicts();
      return res.ok ? formatConflicts(res.data) : `⚠️ ${res.error}`;
    }

    case 'exploitable': {
      const res = await nexus.exploitable();
      return res.ok ? formatExploitable(res.data) : `⚠️ ${res.error}`;
    }

    case 'search': {
      if (!args || args.length < 2) return 'Usage: `/search <at least 2 characters>`';
      const res = await nexus.search(args);
      return res.ok ? formatSearch(args, res.data) : `⚠️ ${res.error}`;
    }

    default:
      return `Unknown command /${command}. Try /help.`;
  }
}

/**
 * Long-polls Telegram for new messages and replies, forever. No webhook, no
 * public endpoint required - safe to run anywhere that can reach
 * api.telegram.org and the local nexus API.
 */
export async function runBot({
  token = process.env.TELEGRAM_BOT_TOKEN,
  nexusApiUrl = process.env.NEXUS_API_URL,
} = {}) {
  const telegram = createTelegramClient(token);
  const nexus = createNexusClient(nexusApiUrl);

  const me = await telegram.getMe();
  console.log(`[telegram] logged in as @${me.username}`);

  let offset = 0;
  for (;;) {
    let updates;
    try {
      updates = await telegram.getUpdates(offset);
    } catch (err) {
      console.error('[telegram] getUpdates failed:', err.message);
      await new Promise((resolve) => setTimeout(resolve, 3000));
      continue;
    }

    for (const update of updates) {
      offset = update.update_id + 1;

      const text = update.message?.text;
      const chatId = update.message?.chat?.id;
      if (!text || !chatId) continue;

      const parsed = parseCommand(text);
      if (!parsed) continue;

      let reply;
      try {
        reply = await handleCommand(parsed.command, parsed.args, nexus);
      } catch (err) {
        console.error(`[telegram] /${parsed.command} failed:`, err.message);
        reply = '⚠️ Something went wrong handling that. Try again.';
      }

      try {
        await telegram.sendMessage(chatId, reply);
      } catch (err) {
        console.error('[telegram] sendMessage failed:', err.message);
      }
    }
  }
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  if (!process.env.TELEGRAM_BOT_TOKEN) {
    console.error('TELEGRAM_BOT_TOKEN is not set. Get one from @BotFather and add it to .env.');
    process.exit(1);
  }
  runBot().catch((err) => {
    console.error('[telegram] fatal:', err.message);
    process.exit(1);
  });
}
