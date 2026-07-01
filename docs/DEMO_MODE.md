# VIPER Vision Demo Mode

Demo mode makes the dashboard useful without raw packet capture, Administrator/root privileges, Npcap, or live traffic.

```bash
python dashboard/app.py --demo
python main.py --dashboard-demo
docker-compose --profile demo up dashboard-demo
```

Demo data includes simulated:

- Packet summary
- Port scan
- SYN flood
- UDP flood
- ICMP flood
- Brute-force attempt
- Statistical anomaly
- Protocol breakdown
- Attack timeline
- Suspicious connection groups

The UI labels demo mode clearly so simulated traffic is not mistaken for real monitoring output.
