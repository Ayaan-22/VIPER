# VIPER Vision Architecture

```mermaid
flowchart LR
    A["Packet Capture"] --> B["Queue"]
    B --> C["Packet Processor"]
    C --> D["Detectors"]
    D --> E["AlertHandler"]
    E --> F["JSON Logs"]
    A --> G["PCAP Writer"]
    E --> R["Reporter"]
    F --> H["Historical Log Parser"]
    H --> I["Dashboard Analytics Services"]
    I --> J["Dashboard API"]
    J --> K["SSE / WebSocket"]
    K --> L["VIPER Vision UI"]
    M["Demo Data Generator"] --> I
    I --> N["HTML Report Generator"]
```

The Scapy capture callback remains lightweight: it only enqueues packets and writes PCAP data. Detection continues through the existing queue, worker threads, detectors, `AlertHandler`, JSON logs, and reports.

VIPER Vision consumes the existing log pipeline. It normalizes alert records and `packet_stats` records, then derives top talkers, protocol distribution, timeline events, suspicious connection groups, port-scan views, and report summaries.

This preserves the original NIDS engine while adding a richer visualization layer.
