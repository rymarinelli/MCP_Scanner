"""Render repository graphs into lightweight visualisations."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from string import Template
from typing import Dict, Optional, Sequence


def load_graph(path: Path) -> Dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_html(graph: Dict[str, object]) -> str:
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    graph_json = json.dumps({"nodes": nodes, "edges": edges})
    template = Template(
        """<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <title>Repository Knowledge Graph</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #0f172a; color: #e2e8f0; }
    header { padding: 1rem 2rem; background: #1e293b; box-shadow: 0 2px 6px rgba(15, 23, 42, 0.5); }
    h1 { margin: 0; font-size: 1.5rem; }
    #graph { width: 100vw; height: 90vh; }
    .tooltip { position: absolute; pointer-events: none; background: rgba(15, 23, 42, 0.9); color: #e2e8f0; padding: 0.5rem; border-radius: 0.5rem; font-size: 0.85rem; border: 1px solid rgba(148, 163, 184, 0.5); }
  </style>
  <script src=\"https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js\" integrity=\"sha512-z9wQ6ttuPAHyBs+K6TfGsDz3jHK5vVsQt1zArhcXd1LSeX776BF3/f6/Dr7guPmyAnbcW2CYwiVdc+GqORdzlg==\" crossorigin=\"anonymous\" referrerpolicy=\"no-referrer\"></script>
</head>
<body>
  <header>
    <h1>Repository Knowledge Graph</h1>
  </header>
  <svg id=\"graph\"></svg>
  <div id=\"tooltip\" class=\"tooltip\" style=\"opacity:0\"></div>
  <script>
    const graph = $graph_json;
    const svg = d3.select('#graph');
    const width = window.innerWidth;
    const height = window.innerHeight * 0.9;
    svg.attr('viewBox', [0, 0, width, height]);

    const color = d => d.type === 'file' ? '#38bdf8' : d.type === 'function' ? '#c084fc' : '#f97316';
    const linkColor = d => d.type === 'imports' ? '#f97316' : d.type === 'calls' ? '#22d3ee' : '#94a3b8';

    const simulation = d3.forceSimulation(graph.nodes)
      .force('link', d3.forceLink(graph.edges).id(d => d.id).distance(120).strength(0.4))
      .force('charge', d3.forceManyBody().strength(-220))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(50));

    const tooltip = d3.select('#tooltip');

    const links = svg.append('g')
      .attr('stroke-opacity', 0.7)
      .selectAll('line')
      .data(graph.edges)
      .join('line')
      .attr('stroke', linkColor)
      .attr('stroke-width', 1.5);

    const nodesSel = svg.append('g')
      .attr('stroke', '#0f172a')
      .attr('stroke-width', 1.5)
      .selectAll('circle')
      .data(graph.nodes)
      .join('circle')
      .attr('r', d => d.type === 'file' ? 18 : 12)
      .attr('fill', color)
      .call(d3.drag()
        .on('start', event => dragstarted(event, simulation))
        .on('drag', event => dragged(event))
        .on('end', event => dragended(event, simulation)));

    nodesSel.append('title').text(d => d.label);

    nodesSel.on('mouseover', (event, d) => {
      tooltip.transition().duration(150).style('opacity', 0.95);
      const props = Object.entries(d.properties || {}).map(([key, value]) => '<div><strong>' + key + '</strong>: ' + value + '</div>').join('');
      tooltip.html('<div><strong>' + d.label + '</strong></div><div style="opacity:0.75">' + d.type + '</div>' + props);
      tooltip.style('left', (event.pageX + 16) + 'px');
      tooltip.style('top', (event.pageY - 16) + 'px');
    });

    nodesSel.on('mousemove', (event) => {
      tooltip.style('left', (event.pageX + 16) + 'px');
      tooltip.style('top', (event.pageY - 16) + 'px');
    });

    nodesSel.on('mouseout', () => {
      tooltip.transition().duration(150).style('opacity', 0);
    });

    simulation.on('tick', () => {
      links
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);

      nodesSel
        .attr('cx', d => d.x)
        .attr('cy', d => d.y);
    });

    function dragstarted(event, simulation) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      event.subject.fx = event.subject.x;
      event.subject.fy = event.subject.y;
    }

    function dragged(event) {
      event.subject.fx = event.x;
      event.subject.fy = event.y;
    }

    function dragended(event, simulation) {
      if (!event.active) simulation.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
    }
  </script>
</body>
</html>
"""
    )
    return template.substitute(graph_json=graph_json)


def write_html(graph: Dict[str, object], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    html = build_html(graph)
    output_path.write_text(html, encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Render repository knowledge graph")
    parser.add_argument("--input", type=Path, default=Path("reports/rag/raw_graph.json"), help="Graph JSON input")
    parser.add_argument("--output", type=Path, default=Path("reports/rag/rag_graph.html"), help="HTML output path")
    args = parser.parse_args(argv)

    graph = load_graph(args.input)
    write_html(graph, args.output)


if __name__ == "__main__":
    main()
