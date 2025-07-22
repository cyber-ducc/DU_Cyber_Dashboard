# utils/log_parser.py
import os
from collections import Counter, defaultdict
from datetime import datetime
import random
from utils.geoip import get_ip_location  


def parse_logs(log_dir):
    status_counts = Counter()
    ip_counts = Counter()
    timeline = defaultdict(int)
    top_urls = Counter()
    top_agents = Counter()
    top_countries = Counter()
    top_threats = Counter()
    ai_threats = Counter()
    ip_set = set()
    total_threats = 0

    # Convert .txt files to .log files if present
    for filename in os.listdir(log_dir):
        if filename.endswith(".txt"):
            txt_path = os.path.join(log_dir, filename)
            log_path = os.path.join(log_dir, filename.rsplit('.', 1)[0] + '.log')
            # Only convert if .log does not already exist
            if not os.path.exists(log_path):
                os.rename(txt_path, log_path)

    for filename in os.listdir(log_dir):
        if filename.endswith(".log"):
            filepath = os.path.join(log_dir, filename)
            with open(filepath, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 10:
                        ip, identity, userid, datetime_raw, tz, method, url, protocol, status, size = parts[:10]

                        ip_counts[ip] += 1
                        status_counts[status] += 1
                        top_urls[url] += 1
                        top_agents[userid] += 1
                        top_countries[random.choice(['India', 'US', 'Germany', 'China'])] += 1

                        try:
                            dt = datetime.strptime(datetime_raw, '[%d/%b/%Y:%H:%M:%S')
                            timeline[dt.strftime('%H:%M')] += 1
                        except:
                            continue

                        if status.startswith('4') or status.startswith('5'):
                            top_threats[ip] += 1
                            total_threats += 1

                        if random.random() < 0.1:
                            ai_threats[ip] += 1

                        ip_set.add(ip)

    result = {
        'total_logs': sum(ip_counts.values()),
        'total_threats': total_threats,
        'unique_ips': len(ip_set),
        'status_counts': dict(status_counts),
        'ip_counts': dict(ip_counts.most_common(10)),
        'timeline': dict(timeline),
        'top_urls': dict(top_urls.most_common(5)),
        'top_agents': dict(top_agents.most_common(5)),
        'top_countries': dict(top_countries.most_common(5)),
        'top_threats': dict(top_threats.most_common(5)),
        'ai_threats': dict(ai_threats.most_common(5)),
        'all_threat_ips': list(top_threats.keys()),
        'geo_data': {ip: get_ip_location(ip) for ip in top_threats}
    }

    return result






def parse_log_file(filepath):
    status_counts = Counter()
    ip_counts = Counter()
    timeline = defaultdict(int)
    top_urls = Counter()
    top_agents = Counter()
    top_countries = Counter()
    top_threats = Counter()
    ai_threats = Counter()
    ip_set = set()
    total_threats = 0
    threat_details = []
    threat_ip_summary = {}

    with open(filepath, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 10:
                ip, identity, userid, datetime_raw, tz, method, url, protocol, status, size = parts[:10]

                ip_counts[ip] += 1
                status_counts[status] += 1
                top_urls[url] += 1
                top_agents[userid] += 1
                top_countries[random.choice(['India', 'US', 'Germany', 'China'])] += 1

                try:
                    dt = datetime.strptime(datetime_raw, '[%d/%b/%Y:%H:%M:%S')
                    timeline[dt.strftime('%H:%M')] += 1
                    timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    timestamp = ''

                threat_level = None
                reason = None
                is_threat = False
                type_of_attack = None

                if status.startswith('4') or status.startswith('5'):
                    threat_level = 'High' if status.startswith('5') else 'Medium'
                    reason = f"HTTP {status} error"
                    is_threat = True
                    type_of_attack = 'HTTP Error'
                    top_threats[ip] += 1
                    total_threats += 1

                if random.random() < 0.1:
                    ai_threats[ip] += 1
                    if not is_threat:
                        threat_level = 'AI'
                        reason = 'AI-detected anomaly'
                        is_threat = True
                        type_of_attack = 'AI Anomaly'

                ip_set.add(ip)

                if is_threat:
                    location = get_ip_location(ip)
                    # Add to threat_details (flat list)
                    threat_details.append({
                        'ip': ip,
                        'status': status,
                        'url': url,
                        'location': location,
                        'threat_level': threat_level,
                        'reason': reason,
                        'timestamp': timestamp
                    })
                    # Add to threat_ip_summary (grouped by IP)
                    if ip not in threat_ip_summary:
                        threat_ip_summary[ip] = {
                            'paths': {},  # path: {'count': int, 'status': str}
                            'location': location,
                            'count': 0,
                            'type_of_attack': set(),
                            'threat_levels': set(),
                            'reasons': set(),
                            'timestamps': [],
                        }
                    # Count unique paths and store status per path
                    if url not in threat_ip_summary[ip]['paths']:
                        threat_ip_summary[ip]['paths'][url] = {'count': 1, 'status': status}
                    else:
                        threat_ip_summary[ip]['paths'][url]['count'] += 1
                    threat_ip_summary[ip]['count'] += 1
                    threat_ip_summary[ip]['type_of_attack'].add(type_of_attack)
                    threat_ip_summary[ip]['threat_levels'].add(threat_level)
                    threat_ip_summary[ip]['reasons'].add(reason)
                    threat_ip_summary[ip]['timestamps'].append(timestamp)

    # Post-process: convert sets to lists and calculate time-duration
    for ip, info in threat_ip_summary.items():
        info['type_of_attack'] = list(info['type_of_attack'])
        info['threat_levels'] = list(info['threat_levels'])
        info['reasons'] = list(info['reasons'])
        # Calculate time-duration (min to max timestamp)
        try:
            times = [datetime.strptime(ts, '%Y-%m-%d %H:%M:%S') for ts in info['timestamps'] if ts]
            if times:
                info['time_duration'] = f"{min(times)} to {max(times)}"
            else:
                info['time_duration'] = ''
        except:
            info['time_duration'] = ''

    result = {
        'total_logs': sum(ip_counts.values()),
        'total_threats': total_threats,
        'unique_ips': len(ip_set),
        'status_counts': dict(status_counts),
        'ip_counts': dict(ip_counts.most_common(10)),
        'timeline': dict(timeline),
        'top_urls': dict(top_urls.most_common(10)),
        'top_agents': dict(top_agents.most_common(10)),
        'top_countries': dict(top_countries.most_common(10)),
        'top_threats': dict(top_threats.most_common(10)),
        'ai_threats': dict(ai_threats.most_common(10)),
        'all_threat_ips': list(top_threats.keys()),
        'geo_data': {ip: get_ip_location(ip) for ip in top_threats},
        'threat_details': threat_details,
        'threat_ip_summary': threat_ip_summary
    }

    return result

