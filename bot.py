"""
Telegram bot front-end for the infrastructure-graph feature.

Reuses build_infra_graph()/validate_target() from app.py so the bot and the
web dashboard share one implementation. Reads TELEGRAM_BOT_TOKEN from the
environment — set it on the host running this process, never commit it.

For authorized security research only.
"""
import io
import logging
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from app import build_infra_graph, validate_target

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

WELCOME = (
    "🛰️ *Infrastructure graph bot*\n\n"
    "Send me a domain you're authorized to inspect (e.g. `example.com`) and "
    "I'll map its subdomains, related IPs, and IP org/ASN info using crt.sh, "
    "urlscan.io, and IPinfo.\n\n"
    "For authorized security research only."
)

NODE_COLORS = {"domain": "#5eb0ff", "subdomain": "#38c977", "ip": "#f0a340"}


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_markdown(WELCOME)


def render_graph_png(nodes, edges) -> io.BytesIO:
    graph = nx.Graph()
    colors = []
    labels = {}
    for n in nodes:
        graph.add_node(n["id"])
        colors.append(NODE_COLORS.get(n["type"], "#93a0b3"))
        labels[n["id"]] = n["label"]
    for e in edges:
        graph.add_edge(e["source"], e["target"])

    pos = nx.spring_layout(graph, seed=7, k=0.9)
    fig, ax = plt.subplots(figsize=(9, 6), facecolor="#0f1216")
    ax.set_facecolor("#0f1216")
    nx.draw_networkx_edges(graph, pos, ax=ax, edge_color="#2a303a")
    nx.draw_networkx_nodes(graph, pos, ax=ax, node_color=colors, node_size=350)
    nx.draw_networkx_labels(graph, pos, labels=labels, ax=ax, font_size=7, font_color="#e6e9ee")
    ax.axis("off")

    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return buf


async def handle_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    target = (update.message.text or "").strip().lower()
    if not validate_target("domain", target):
        await update.message.reply_markdown(
            "That doesn't look like a valid domain. Try e.g. `example.com`."
        )
        return

    await update.message.reply_text(f"Building graph for {target}…")
    result = build_infra_graph(target)
    if not result["ok"]:
        await update.message.reply_text(result["error"])
        return

    nodes, edges = result["nodes"], result["edges"]
    png = render_graph_png(nodes, edges)
    caption = f"{len(nodes)} nodes, {len(edges)} edges for {target}."
    await update.message.reply_photo(photo=png, caption=caption)


def main() -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit(
            "TELEGRAM_BOT_TOKEN is not set. Export it in your host environment "
            "before running the bot (do not hardcode it here)."
        )
    application = Application.builder().token(token).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_domain))
    logger.info("Bot starting…")
    application.run_polling()


if __name__ == "__main__":
    main()
