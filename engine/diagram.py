"""
Bastion engine/diagram.py — Network architecture diagram generator.
Uses networkx + matplotlib. Falls back to SVG if matplotlib unavailable.
"""
import logging
import os
from typing import List

logger = logging.getLogger("diagram")


def generate_architecture_diagram(parse_results: list, output_path: str) -> dict:
    """
    Generate a network architecture diagram PNG.
    Returns {success, path, node_count, edge_count} or {success: False, error: str}.
    """
    try:
        import networkx as nx
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches

        return _generate_matplotlib_diagram(parse_results, output_path)
    except ImportError as e:
        logger.warning(f"matplotlib/networkx not available: {e}. Falling back to SVG.")
        return generate_svg_fallback(parse_results, output_path)
    except Exception as e:
        logger.error(f"Diagram generation error: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


def _generate_matplotlib_diagram(parse_results: list, output_path: str) -> dict:
    """Generate diagram using matplotlib and networkx."""
    try:
        import networkx as nx
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches

        G = nx.DiGraph()

        # Collect nodes
        devices = []
        all_zones = {}
        all_edges = []

        # Add internet node
        G.add_node("INTERNET", node_type="internet", label="Internet",
                   color="#E7716F")

        for pr in parse_results:
            device_name = pr.hostname or pr.filename
            devices.append(device_name)
            G.add_node(device_name, node_type="firewall",
                       label=device_name, color="#c8921f")

            interfaces = pr.metadata.get("interfaces", {})
            for iface_name, iface_data in interfaces.items():
                zone_id = f"zone:{iface_name}"
                sec_level = 0
                if isinstance(iface_data, dict):
                    sec_level = iface_data.get("security_level", 50)
                    ip = iface_data.get("ip", "")
                else:
                    ip = ""

                # Color by security level
                if sec_level == 0:
                    color = "#E7716F"    # external — red
                elif sec_level >= 90:
                    color = "#92D050"    # internal — green
                else:
                    color = "#FFC000"    # DMZ / medium — amber

                G.add_node(zone_id, node_type="zone", label=iface_name,
                           color=color, device=device_name, ip=ip,
                           sec_level=sec_level)
                all_zones[iface_name] = zone_id

                # Edge: firewall to zone
                G.add_edge(device_name, zone_id, label="", color="#888888",
                           style="solid")

            # Add edges from rules
            for rule in pr.rules[:100]:  # limit for diagram clarity
                if rule.action == "permit" and rule.enabled:
                    src_zone = rule.src_zone
                    dst_zone = rule.dst_zone
                    if src_zone and dst_zone:
                        src_id = all_zones.get(src_zone, src_zone)
                        dst_id = all_zones.get(dst_zone, dst_zone)
                        if src_id and dst_id and src_id in G and dst_id in G:
                            G.add_edge(src_id, dst_id, label="permit",
                                       color="#92D050", style="solid")

            # Connect internet to lowest-security zone
            internet_zone = None
            min_sec = 101
            for iface_name, iface_data in interfaces.items():
                if isinstance(iface_data, dict):
                    sl = iface_data.get("security_level", 50)
                    if sl < min_sec:
                        min_sec = sl
                        internet_zone = iface_name
            if internet_zone:
                zone_id = all_zones.get(internet_zone)
                if zone_id:
                    G.add_edge("INTERNET", zone_id, label="",
                               color="#E7716F", style="dashed")

        if len(G.nodes) == 0:
            return generate_svg_fallback(parse_results, output_path)

        # Layout
        try:
            pos = nx.spring_layout(G, k=3, iterations=50, seed=42)
        except Exception:
            pos = nx.random_layout(G, seed=42)

        fig, ax = plt.subplots(figsize=(16, 10.67), dpi=150)
        fig.patch.set_facecolor("#111009")
        ax.set_facecolor("#1a1a12")

        # Draw nodes
        node_colors = [G.nodes[n].get("color", "#888888") for n in G.nodes]
        nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors,
                               node_size=800, alpha=0.9)

        # Draw labels
        labels = {n: G.nodes[n].get("label", n)[:20] for n in G.nodes}
        nx.draw_networkx_labels(G, pos, labels, ax=ax,
                                font_size=7, font_color="#f0e8d0")

        # Draw edges
        edge_colors = [G.edges[e].get("color", "#888888") for e in G.edges]
        nx.draw_networkx_edges(G, pos, ax=ax, edge_color=edge_colors,
                               arrows=True, arrowsize=15, alpha=0.7,
                               connectionstyle="arc3,rad=0.1")

        # Legend
        legend_items = [
            mpatches.Patch(color="#c8921f", label="Firewall"),
            mpatches.Patch(color="#E7716F", label="External / Internet"),
            mpatches.Patch(color="#FFC000", label="DMZ / Semi-trusted"),
            mpatches.Patch(color="#92D050", label="Internal / Trusted"),
        ]
        ax.legend(handles=legend_items, loc="lower right",
                  facecolor="#1a1a12", edgecolor="#c8921f",
                  labelcolor="#f0e8d0", fontsize=8)

        ax.set_title("Network Architecture — Bastion Analysis",
                     color="#c8921f", fontsize=14, pad=16)
        ax.axis("off")

        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches="tight",
                    facecolor="#111009")
        plt.close(fig)

        return {
            "success": True,
            "path": output_path,
            "node_count": len(G.nodes),
            "edge_count": len(G.edges),
        }

    except Exception as e:
        logger.error(f"_generate_matplotlib_diagram error: {e}", exc_info=True)
        return generate_svg_fallback(parse_results, output_path)


def generate_svg_fallback(parse_results: list, output_path: str) -> dict:
    """
    Generate a simple SVG architecture diagram as fallback.
    """
    try:
        # Collect devices and zones
        devices = []
        for pr in parse_results:
            device_name = pr.hostname or pr.filename
            interfaces = list(pr.metadata.get("interfaces", {}).keys())
            devices.append({"name": device_name, "zones": interfaces})

        svg_parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<svg xmlns="http://www.w3.org/2000/svg" '
            'width="800" height="500" viewBox="0 0 800 500">',
            '<rect width="800" height="500" fill="#111009"/>',
            '<text x="400" y="30" fill="#c8921f" font-size="18" '
            'text-anchor="middle" font-family="Arial" font-weight="bold">'
            'Network Architecture — Bastion Analysis</text>',
        ]

        # Internet node
        svg_parts.append(
            '<rect x="20" y="200" width="100" height="50" rx="8" '
            'fill="#E7716F" opacity="0.8"/>'
            '<text x="70" y="230" fill="white" font-size="11" '
            'text-anchor="middle" font-family="Arial">Internet</text>'
        )

        x_offset = 180
        for dev in devices:
            # Firewall box
            svg_parts.append(
                f'<rect x="{x_offset}" y="190" width="120" height="70" rx="6" '
                f'fill="#c8921f" opacity="0.8"/>'
                f'<text x="{x_offset + 60}" y="220" fill="white" '
                f'font-size="10" text-anchor="middle" font-family="Arial">'
                f'{_svg_esc(dev["name"][:18])}</text>'
                f'<text x="{x_offset + 60}" y="235" fill="white" '
                f'font-size="9" text-anchor="middle" font-family="Arial">'
                f'[Firewall]</text>'
            )
            # Arrow from internet
            svg_parts.append(
                f'<line x1="120" y1="225" x2="{x_offset}" y2="225" '
                f'stroke="#888" stroke-width="1.5" '
                f'marker-end="url(#arrow)"/>'
            )

            # Zones
            zone_colors = ["#92D050", "#FFC000", "#E7716F", "#888888"]
            for zi, zone in enumerate(dev["zones"][:4]):
                zx = x_offset + 150 + zi * 120
                zy = 160 + zi * 70
                zc = zone_colors[zi % len(zone_colors)]
                svg_parts.append(
                    f'<rect x="{zx}" y="{zy}" width="100" height="40" rx="5" '
                    f'fill="{zc}" opacity="0.7"/>'
                    f'<text x="{zx + 50}" y="{zy + 25}" fill="white" '
                    f'font-size="9" text-anchor="middle" font-family="Arial">'
                    f'{_svg_esc(zone[:16])}</text>'
                    f'<line x1="{x_offset + 120}" y1="225" x2="{zx}" '
                    f'y2="{zy + 20}" stroke="#888" stroke-width="1" '
                    f'stroke-dasharray="4,2"/>'
                )
            x_offset += 600

        # Arrow marker def
        svg_parts.insert(3,
            '<defs><marker id="arrow" markerWidth="8" markerHeight="8" '
            'refX="6" refY="3" orient="auto">'
            '<path d="M0,0 L0,6 L9,3 z" fill="#888"/>'
            '</marker></defs>'
        )

        svg_parts.append('</svg>')
        svg_content = "\n".join(svg_parts)

        # Save as SVG (rename output_path to .svg)
        svg_path = output_path.replace(".png", ".svg")
        if not svg_path.endswith(".svg"):
            svg_path = output_path + ".svg"

        with open(svg_path, "w", encoding="utf-8") as f:
            f.write(svg_content)

        # Also write a minimal PNG placeholder if possible
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            fig, ax = plt.subplots(figsize=(8, 5))
            fig.patch.set_facecolor("#111009")
            ax.set_facecolor("#111009")
            ax.text(0.5, 0.5, "Architecture diagram generated\n(SVG fallback active)",
                    ha="center", va="center", color="#c8921f", fontsize=14,
                    transform=ax.transAxes)
            ax.axis("off")
            plt.savefig(output_path, dpi=150, bbox_inches="tight",
                        facecolor="#111009")
            plt.close(fig)
        except Exception:
            pass

        return {
            "success": True,
            "path": svg_path,
            "node_count": len(devices),
            "edge_count": 0,
        }

    except Exception as e:
        logger.error(f"generate_svg_fallback error: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


def _svg_esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
