# ACE-T-SPECTRUM: Advanced Cyber-Enabled Threat Intelligence Platform

**Welcome to the ACE-T-SPECTRUM project wiki!**

ACE-T-SPECTRUM is a comprehensive Open-Source Intelligence (OSINT) platform designed for cyber threat intelligence analysis. It provides real-time monitoring of threat intelligence feeds and social media sources, with automated data ingestion, graph-based correlation, and interactive 3D visualization capabilities.

[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20Windows-lightgrey.svg)](https://github.com/gs-ai/ACE-T)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/gs-ai/ACE-T/blob/main/LICENSE)
[![Framework](https://img.shields.io/badge/Framework-Three.js-orange.svg)](https://threejs.org/)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Data Sources](#data-sources)
- [Visualization](#visualization)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

ACE-T-SPECTRUM transforms raw threat intelligence data into actionable insights through:

- **Automated Data Ingestion**: Real-time collection from Reddit, pastebin, threat feeds, and other sources
- **Graph-Based Analysis**: Automatic correlation and linking of indicators across sources
- **3D Visualization**: Interactive Three.js interface for exploring threat relationships
- **Modular Design**: Extensible architecture for adding new data sources and analysis modules

The platform processes indicators of compromise (IOCs), threat alerts, and intelligence data, storing them in a SQLite database with SQLAlchemy ORM for efficient querying and analysis.

---

## 🚀 Key Features

### Data Ingestion & Processing
- **Multi-Source Support**: Reddit subreddits, pastebin, threat intelligence feeds (ThreatFox, URLhaus, etc.)
- **Real-time Monitoring**: Continuous ingestion with configurable polling intervals
- **Data Normalization**: Standardized processing pipeline for all input sources
- **Deduplication**: SHA-256 and simhash-based fingerprinting to prevent duplicate alerts

### Graph Analysis & Correlation
- **Cross-Source Linking**: Automatic correlation of indicators across different feeds
- **Relationship Mapping**: Graph-based representation of threat actor connections
- **Temporal Analysis**: Time-based analysis of threat evolution
- **Clustering Algorithms**: Intelligent grouping of related threats

### 3D Visualization Interface
- **Interactive 3D Graphs**: Three.js-powered visualization with rotation, zoom, and pan
- **Color-Coded Nodes**: Threat severity and source-based color schemes
- **Stable Positioning**: Consistent layout algorithms for reproducible views
- **Real-time Updates**: Live graph updates as new data is ingested

### Data Management
- **SQLite Storage**: Robust database backend with SQLAlchemy ORM
- **Retention Policies**: Configurable data aging and pruning
- **Export Capabilities**: JSON, graph data, and timeline exports
- **Backup & Recovery**: Comprehensive data persistence and recovery options

---

## 🏗️ Architecture

### Core Components

```
ACE-T-SPECTRUM/
├── core/                 # Core processing engine
├── adapters/            # Data source adapters
├── spectrum_core/       # 3D visualization math
├── spectrum_graph/      # Graph generation and physics
├── spectrum_export/     # Data export utilities
├── gui/                 # Web interface files
├── pipeline/           # Data processing pipeline
├── db/                 # Database utilities
└── data/               # Data storage and cache
```

### Data Flow

1. **Ingestion**: Adapters collect data from various sources (Reddit, threat feeds, etc.)
2. **Processing**: Data is normalized and enriched through the processing pipeline
3. **Correlation**: Cross-source analysis identifies relationships and patterns
4. **Storage**: Processed data is stored in SQLite database with metadata
5. **Visualization**: 3D graph generation for interactive analysis

### Key Modules

- **Adapters**: Modular data collectors for different sources
- **Core Engine**: Central processing and correlation logic
- **Spectrum Math**: 3D positioning and physics calculations
- **Graph Builder**: Relationship mapping and graph construction
- **Export System**: Data serialization and export utilities

---

## 🏃 Quick Start

### Prerequisites
- Python 3.11+
- SQLite 3
- Modern web browser (for 3D visualization)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/gs-ai/ACE-T.git
   cd ACE-T
   ```

2. **Set up the environment:**
   ```bash
   # Using conda (recommended)
   conda env create -f environment.yml
   conda activate ace-t-env

   # Or using pip
   pip install -r requirements.txt
   ```

3. **Initialize the database:**
   ```bash
   python -m ace_t_spectrum init-db
   ```

4. **Run a test ingestion:**
   ```bash
   python ACE-T-SPECTRUM.py --test-run
   ```

5. **Launch the visualization:**
   ```bash
   python -m http.server 8000
   # Open http://localhost:8000/gui/ace_t_spectrum_3d.html
   ```

### Basic Usage

```bash
# Run full ingestion pipeline
python ACE-T-SPECTRUM.py

# Process specific sources
python ACE-T-SPECTRUM.py --sources reddit,pastebin

# Generate 3D visualization data
python spectrum_export/build_graph_3d.py

# Export data
python export/bundle.py
```

---

## 📡 Data Sources

ACE-T-SPECTRUM supports multiple intelligence sources:

### Social Media
- **Reddit**: Subreddit monitoring with comment and post analysis
- **Telegram**: Channel monitoring (planned)
- **Discord**: Server monitoring (planned)

### Threat Intelligence Feeds
- **ThreatFox**: Malware IOCs and indicators
- **URLhaus**: Malicious URL database
- **OpenIOC**: Structured threat indicators
- **MISP**: Community threat sharing

### Document Sources
- **Pastebin**: Code and text sharing monitoring
- **Rentry**: Anonymous paste service
- **GitHub**: Repository and issue monitoring

### Custom Sources
The modular adapter system allows easy addition of new data sources through the `adapters/` directory.

---

## 🎨 Visualization

### 3D Graph Interface

The core visualization is powered by Three.js and provides:

- **Interactive Navigation**: Mouse/touch controls for rotation, zoom, and pan
- **Color Schemes**: Multiple color palettes for different data types
- **Filtering**: Real-time filtering by source, threat level, or time range
- **Animation**: Smooth transitions and updates
- **Export**: Save current view as image or data

### Graph Physics

- **Force-Directed Layout**: Natural node positioning based on relationships
- **Clustering**: Automatic grouping of related nodes
- **Stable Positioning**: Consistent layouts across sessions
- **Performance Optimization**: Efficient rendering for large graphs

### Data Views

- **Timeline View**: Temporal analysis of threat evolution
- **Source View**: Per-source data visualization
- **Correlation View**: Cross-source relationship mapping
- **Geographic View**: Location-based threat mapping (planned)

---

## ⚙️ Configuration

### Main Configuration (`config.yml`)

```yaml
# Data retention settings
retention:
  days: 30

# Data sources
sources:
  reddit:
    enabled: true
    subreddits: ["cybersecurity", "netsec", "malware"]
  threat_feeds:
    enabled: true
    feeds: ["threatfox", "urlhaus"]

# Visualization settings
spectrum:
  colors: "threat_level"
  physics: "force_directed"
```

### Environment Variables

- `ACE_T_RETENTION_DAYS`: Data retention period
- `ACE_T_DB_PATH`: SQLite database location
- `ACE_T_LOG_LEVEL`: Logging verbosity

---

## 🤝 Contributing

We welcome contributions! See our [Contributing Guide](contributing.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

### Adding New Sources

1. Create a new adapter in `adapters/`
2. Implement the standard interface
3. Add configuration options
4. Update documentation

### Testing

```bash
# Run all tests
pytest

# Run specific test suite
pytest tests/test_adapters.py

# Test with coverage
pytest --cov=spectrum_core --cov-report=html
```

---

## 🔧 Troubleshooting

### Common Issues

**Visualization not loading:**
- Ensure modern browser with WebGL support
- Check browser console for JavaScript errors
- Verify Three.js library is accessible

**Data ingestion failing:**
- Check network connectivity
- Verify API credentials (if required)
- Review logs for specific error messages

**Database errors:**
- Ensure SQLite is installed
- Check file permissions on data directory
- Run database migration if needed

**Performance issues:**
- Reduce graph size with filtering
- Check system resources (RAM, CPU)
- Optimize configuration settings

### Getting Help

- **Issues**: [GitHub Issues](https://github.com/gs-ai/ACE-T/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gs-ai/ACE-T/discussions)
- **Documentation**: Check the wiki pages linked below

---

## 📚 Additional Documentation

- **[Architecture Details](architecture.md)** - Deep dive into system components
- **[API Reference](api.md)** - Module and function documentation
- **[Configuration Guide](configuration.md)** - Advanced configuration options
- **[Deployment Guide](deployment.md)** - Production deployment instructions
- **[Security](security.md)** - Security considerations and best practices

---

## 📈 Project Status

- **Version**: 1.0.0 (Development)
- **Python Support**: 3.11+
- **License**: MIT
- **Maintainers**: gs-ai / ACE-T Team
- **Last Updated**: January 21, 2026

---

*ACE-T-SPECTRUM: Transforming threat intelligence into actionable 3D insights.*</content>
<parameter name="filePath">/Users/mbaosint/Desktop/Projects/ACE-T/ACE-T-SPECTRUM/docs/ACE-T-SPECTRUM-Wiki-Home.md