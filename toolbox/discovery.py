import nmap

def discover_hosts(network_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=network_range, arguments='-sn')
    hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']
    return hosts

def discover_services(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sV')
    services = {}
    for host in nm.all_hosts():
        services[host] = nm[host]
    return services

def os_detection(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-O')
    os_info = {}
    for host in nm.all_hosts():
        os_info[host] = nm[host]
    return os_info

def parallel_scan(hosts, scan_function):
    from concurrent.futures import ThreadPoolExecutor
    results = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_host = {executor.submit(scan_function, host): host for host in hosts}
        for future in future_to_host:
            host = future_to_host[future]
            try:
                results[host] = future.result()
            except Exception as exc:
                results[host] = str(exc)
    return results
