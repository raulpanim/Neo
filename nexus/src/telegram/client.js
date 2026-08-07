import axios from 'axios';

/** Thin wrapper over the Telegram Bot API - long polling, no webhook needed. */
export function createTelegramClient(token) {
  if (!token) throw new Error('TELEGRAM_BOT_TOKEN is required.');

  const http = axios.create({
    baseURL: `https://api.telegram.org/bot${token}`,
    timeout: 35_000, // > the 30s long-poll timeout below
  });

  async function call(method, params) {
    const { data } = await http.get(`/${method}`, { params });
    if (!data.ok) throw new Error(data.description || `${method} failed.`);
    return data.result;
  }

  return {
    getMe: () => call('getMe'),
    /** Long-polls for new updates. Resolves to [] on the 30s idle timeout. */
    getUpdates: (offset) => call('getUpdates', { offset, timeout: 30 }),
    async sendMessage(chatId, text) {
      const { data } = await http.post('/sendMessage', {
        chat_id: chatId,
        text,
        parse_mode: 'Markdown',
        disable_web_page_preview: true,
      });
      if (!data.ok) throw new Error(data.description || 'sendMessage failed.');
      return data.result;
    },
  };
}
