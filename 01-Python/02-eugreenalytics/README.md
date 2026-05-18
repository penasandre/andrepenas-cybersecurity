# euGreenalytics — European Electricity Market Analytics

> Data analytics platform providing real-time and historical intelligence on European electricity markets and renewable energy — built as an independent public resource for energy professionals.

**Live platform:** [eugreenalytics.com](https://eugreenalytics.com)

---

## What it does

euGreenalytics collects data from public European energy market platforms, processes it with a Python pipeline, and publishes interactive dashboards on a static website.

**Dashboards:**
- Day-Ahead Price Monitor — monthly and hourly price trends for Belgium, France, Germany, Netherlands, Spain, Portugal (Jan 2022–present)
- Negative Price Monitor — heatmaps and cumulative trends of negative electricity prices per country
- Imbalance Price Monitor — Belgian TSO balancing market data

---

## Stack

| Layer | Technology |
|-------|-----------|
| Data processing | Python · pandas |
| Visualizations | Plotly |
| Website | HTML · CSS · GitHub Pages |

**Data sources:** ENTSO-E Transparency Platform · OMIE · Energy-charts (Fraunhofer ISE) · IRENA

---

## Pipeline

Data flows from public platforms → Python processing scripts → Plotly charts → static HTML served on GitHub Pages.

The pipeline covers extraction, validation, transformation, and chart generation — split across multiple Python scripts by phase.

---

## Scope

| Dimension | Detail |
|-----------|--------|
| Countries | Belgium, France, Germany, Netherlands, Spain, Portugal |
| Period | January 2022 – present |
| Granularity | Hourly, daily, monthly aggregates |
