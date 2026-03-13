"""
Blockchain transaction flow diagram generator.

Consumes flow_graph from blockchain_investigation (nodes: id, label, type;
edges: from, to, amount, unit, date_str, count). Produces HTML with circular
nodes (primary, counterparty, wallet), directed edges with amount/date,
Diverg Sec branding.
"""

from __future__ import annotations

import json
import math
from pathlib import Path


def _layout_nodes(nodes: list[dict], edges: list[dict]) -> dict[str, tuple[float, float]]:
    """Simple left-to-right layered layout. Primary -> layer 0, others by distance from primary."""
    by_id = {n["id"]: n for n in nodes}
    primary_id = next((n["id"] for n in nodes if n.get("type") == "primary"), None)
    if not primary_id:
        primary_id = nodes[0]["id"] if nodes else None
    # BFS layers from primary (outgoing)
    layers: dict[str, int] = {}
    if primary_id:
        layers[primary_id] = 0
        frontier = [primary_id]
        for dist in range(1, 10):
            next_frontier = []
            for aid in frontier:
                for e in edges:
                    if e.get("from") == aid and e.get("to") and e["to"] not in layers:
                        layers[e["to"]] = dist
                        next_frontier.append(e["to"])
            frontier = next_frontier
            if not frontier:
                break
    # Any node not reached gets max layer
    max_layer = max(layers.values()) if layers else 0
    for n in nodes:
        if n["id"] not in layers:
            layers[n["id"]] = max_layer + 1
    # Position: layer -> x; within layer spread y
    layer_to_nodes: dict[int, list[str]] = {}
    for nid, layer in layers.items():
        layer_to_nodes.setdefault(layer, []).append(nid)
    pos = {}
    node_width, node_height = 100, 64
    margin_x, margin_y = 140, 80
    for layer, nids in sorted(layer_to_nodes.items()):
        for i, nid in enumerate(nids):
            x = margin_x + layer * (node_width + 90)
            y = margin_y + i * (node_height + 50) - (len(nids) - 1) * (node_height + 50) / 2
            pos[nid] = (x, y)
    return pos


def render_flow_diagram_html(
    flow_graph: dict,
    title: str = "Blockchain transaction flow",
    target_label: str = "",
    output_path: str | Path | None = None,
    logo_src: str = "neuro-logo.png",
) -> str:
    """
    Render flow_graph to HTML. Returns HTML string; if output_path set, writes file.
    flow_graph: {"nodes": [{"id","label","type"}], "edges": [{"from","to","amount","unit","date_str","count"}]}
    logo_src: path to logo image (e.g. ../content/neuro-logo.png when saving to results/).
    """
    nodes = flow_graph.get("nodes") or []
    edges = flow_graph.get("edges") or []
    if not nodes and not edges:
        return "<!DOCTYPE html><html><body><p>No flow data.</p></body></html>"

    pos = _layout_nodes(nodes, edges)
    # SVG viewBox
    all_x = [p[0] for p in pos.values()]
    all_y = [p[1] for p in pos.values()]
    min_x = min(all_x) - 80
    max_x = max(all_x) + 80
    min_y = min(all_y) - 60
    max_y = max(all_y) + 60
    width = max(800, max_x - min_x + 160)
    height = max(500, max_y - min_y + 120)

    node_radius = 28
    # Shift positions to be in first quadrant for SVG
    for nid in pos:
        x, y = pos[nid]
        pos[nid] = (x - min_x + 60, y - min_y + 60)

    lines = []
    lines.append("<!DOCTYPE html>")
    lines.append('<html lang="en"><head><meta charset="UTF-8"><title>' + _esc(title) + "</title>")
    lines.append("<style>")
    lines.append("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f1419; color: #e7e9ea; margin: 0; padding: 24px; }")
    lines.append(".diagram-wrap { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; overflow: auto; }")
    lines.append(".title { font-size: 18px; font-weight: 700; color: #fff; margin-bottom: 8px; }")
    lines.append(".subtitle { font-size: 12px; color: #8b949e; margin-bottom: 16px; }")
    lines.append(".foot { margin-top: 16px; font-size: 11px; color: #6e7681; }")
    lines.append(".brand { position: absolute; top: 16px; right: 20px; display: flex; align-items: center; gap: 8px; }")
    lines.append(".brand img { height: 24px; width: auto; }")
    lines.append(".brand-tag { font-size: 10px; font-weight: 600; letter-spacing: 0.08em; color: #58a6ff; }")
    lines.append(".diagram-wrap { position: relative; }")
    lines.append("</style></head><body><div class='diagram-wrap'>")
    lines.append(f"<div class='brand'><img src='{_esc(logo_src)}' alt='' /><span class='brand-tag'>DIVERG SEC</span></div>")
    lines.append(f"<div class='title'>{_esc(title)}</div>")
    if target_label:
        lines.append(f"<div class='subtitle'>{_esc(target_label)}</div>")
    lines.append(f"<svg width='100%' viewBox='0 0 {width} {height}' xmlns='http://www.w3.org/2000/svg'>")

    # Edges (so they render under nodes)
    for e in edges:
        fr, to = e.get("from"), e.get("to")
        if fr not in pos or to not in pos:
            continue
        x1, y1 = pos[fr]
        x2, y2 = pos[to]
        mid_x, mid_y = (x1 + x2) / 2, (y1 + y2) / 2
        amount = e.get("amount", 0)
        unit = e.get("unit", "?")
        date_str = e.get("date_str", "")
        count = e.get("count", 1)
        label = f"{amount:.2f} {unit}" if amount else unit
        if count > 1:
            label += f" ({count})"
        if date_str:
            label += f" · {date_str}"
        # Curved path for arrow
        dx, dy = x2 - x1, y2 - y1
        perp = (-dy * 0.2, dx * 0.2)
        cpx = mid_x + perp[0]
        cpy = mid_y + perp[1]
        path_d = f"M{x1},{y1} Q{cpx},{cpy} {x2},{y2}"
        lines.append(f"<path d='{path_d}' fill='none' stroke='#484f58' stroke-width='1.5'/>")
        # Arrowhead
        angle = math.atan2(y2 - mid_y, x2 - mid_x)
        ax = x2 - (node_radius + 4) * math.cos(angle)
        ay = y2 - (node_radius + 4) * math.sin(angle)
        lines.append(f"<polygon points='{ax},{ay} {ax-10},{ay-6} {ax-10},{ay+6}' fill='#58a6ff'/>")
        # Edge label
        lines.append(f"<text x='{mid_x}' y='{mid_y - 6}' text-anchor='middle' fill='#8b949e' font-size='10'>{_esc(label[:40])}</text>")

    # Nodes
    for n in nodes:
        nid = n.get("id", "")
        if nid not in pos:
            continue
        x, y = pos[nid]
        ntype = n.get("type", "wallet")
        label = (n.get("label") or nid)[:20]
        if len(nid) > 16:
            addr_short = nid[:6] + "…" + nid[-4:]
        else:
            addr_short = nid
        # Node circle: primary = red ring, counterparty = green ring, wallet = blue
        if ntype == "primary":
            lines.append(f"<circle cx='{x}' cy='{y}' r='{node_radius + 4}' fill='none' stroke='#f85149' stroke-width='3'/>")
        elif ntype == "counterparty":
            lines.append(f"<circle cx='{x}' cy='{y}' r='{node_radius + 4}' fill='none' stroke='#3fb950' stroke-width='2'/>")
        else:
            lines.append(f"<circle cx='{x}' cy='{y}' r='{node_radius + 2}' fill='none' stroke='#58a6ff' stroke-width='1.5'/>")
        lines.append(f"<circle cx='{x}' cy='{y}' r='{node_radius}' fill='#1c2128' stroke='#30363d'/>")
        lines.append(f"<text x='{x}' y='{y - 5}' text-anchor='middle' fill='#e7e9ea' font-size='11' font-weight='600'>{_esc(label)}</text>")
        lines.append(f"<text x='{x}' y='{y + 10}' text-anchor='middle' fill='#8b949e' font-size='9'>{_esc(addr_short)}</text>")

    # Primary / deployer annotation
    for n in nodes:
        if n.get("type") != "primary":
            continue
        nid = n.get("id", "")
        if nid not in pos:
            continue
        x, y = pos[nid]
        lines.append(f"<rect x='{x - 52}' y='{y - node_radius - 28}' width='104' height='22' rx='4' fill='#f8514922' stroke='#f85149'/>")
        lines.append(f"<text x='{x}' y='{y - node_radius - 13}' text-anchor='middle' fill='#f85149' font-size='10' font-weight='600'>Primary / Deployer</text>")

    lines.append("</svg>")
    lines.append("<div class='foot'>Diverg Sec</div>")
    lines.append("</div></body></html>")

    html = "\n".join(lines)

    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")
    return html


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
