import logging
import socket
import whois
import dns.resolver
import nmap

# Set up logging
logging.basicConfig(level=logging.INFO)

def get_info(domain):
    """
    Get information about a domain, including its IP address and WHOIS data.
    
    Args:
        domain (str): The domain name to query
        
    Returns:
        str: JSON formatted string with domain information
    """
    try:
        logging.info(f"Getting info for domain: {domain}")
        
        # Get IP address
        ip_address = socket.gethostbyname(domain)
        
        # Get WHOIS information
        w = whois.whois(domain)
        
        # Format the result
        result = {
            "domain": domain,
            "ip_address": ip_address,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date)
        }
        
        import json
        return json.dumps(result, indent=2)
    except Exception as e:
        logging.error(f"Error in get_info: {str(e)}")
        return f"Error getting information for {domain}: {str(e)}"

def scan_network(ip_address):
    """
    Scan a network for open ports.
    
    Args:
        ip_address (str): The IP address to scan
        
    Returns:
        str: JSON formatted string with scan results
    """
    try:
        logging.info(f"Scanning network for IP: {ip_address}")
        
        # Initialize the port scanner
        scanner = nmap.PortScanner()
        
        # Scan the most common ports
        scanner.scan(ip_address, '22-443')
        
        # Format the results
        result = {
            "ip_address": ip_address,
            "hostname": scanner[ip_address].hostname() if ip_address in scanner.all_hosts() else "Unknown",
            "state": scanner[ip_address].state() if ip_address in scanner.all_hosts() else "Unknown",
            "open_ports": []
        }
        
        # Add information about open ports
        if ip_address in scanner.all_hosts():
            for protocol in scanner[ip_address].all_protocols():
                for port in scanner[ip_address][protocol]:
                    if scanner[ip_address][protocol][port]['state'] == 'open':
                        port_info = {
                            "port": port,
                            "service": scanner[ip_address][protocol][port]['name'],
                            "state": scanner[ip_address][protocol][port]['state']
                        }
                        result["open_ports"].append(port_info)
        
        import json
        return json.dumps(result, indent=2)
    except Exception as e:
        logging.error(f"Error in scan_network: {str(e)}")
        return f"Error scanning network for {ip_address}: {str(e)}"

def check_vulnerability(domain):
    """
    Check for basic vulnerabilities in a domain.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        str: JSON formatted string with vulnerability check results
    """
    try:
        logging.info(f"Checking vulnerabilities for domain: {domain}")
        
        # Check for SPF record
        spf_record = None
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                if 'spf' in rdata.to_text().lower():
                    spf_record = rdata.to_text()
                    break
        except Exception as e:
            logging.warning(f"Error checking SPF record: {str(e)}")
        
        # Check for DMARC record
        dmarc_record = None
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in answers:
                if 'dmarc' in rdata.to_text().lower():
                    dmarc_record = rdata.to_text()
                    break
        except Exception as e:
            logging.warning(f"Error checking DMARC record: {str(e)}")
        
        # Check for MX records
        mx_records = []
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_records.append(str(rdata.exchange))
        except Exception as e:
            logging.warning(f"Error checking MX records: {str(e)}")
        
        # Format the results
        result = {
            "domain": domain,
            "email_security": {
                "spf_record": spf_record,
                "dmarc_record": dmarc_record,
                "mx_records": mx_records
            },
            "vulnerabilities": []
        }
        
        # Check for email security vulnerabilities
        if not spf_record:
            result["vulnerabilities"].append({
                "type": "Email Security",
                "severity": "Medium",
                "description": "Missing SPF record. This could allow email spoofing."
            })
        
        if not dmarc_record:
            result["vulnerabilities"].append({
                "type": "Email Security",
                "severity": "Medium",
                "description": "Missing DMARC record. This could allow email spoofing and phishing."
            })
        
        import json
        return json.dumps(result, indent=2)
    except Exception as e:
        logging.error(f"Error in check_vulnerability: {str(e)}")
        return f"Error checking vulnerabilities for {domain}: {str(e)}"

def sql_injection(url):
    """
    Check for SQL injection vulnerabilities in a URL.
    This is a simplified simulation and should not be used for actual testing.
    
    Args:
        url (str): The URL to check
        
    Returns:
        str: JSON formatted string with SQL injection check results
    """
    try:
        logging.info(f"Checking SQL injection for URL: {url}")
        
        # In a real scenario, we would test the URL with SQL injection payloads
        # This is a simplified simulation
        
        # Format the results
        result = {
            "url": url,
            "test_performed": "Simulated SQL injection test",
            "vulnerabilities": [
                {
                    "type": "Demonstration",
                    "severity": "Info",
                    "description": "This is a simulated SQL injection test. In a real security test, " +
                                  "we would send different SQL payloads and analyze the responses."
                }
            ]
        }
        
        import json
        return json.dumps(result, indent=2)
    except Exception as e:
        logging.error(f"Error in sql_injection: {str(e)}")
        return f"Error checking SQL injection for {url}: {str(e)}"

# Map function names to actual functions
available_functions = {
    "get_info": get_info,
    "scan_network": scan_network,
    "check_vulnerability": check_vulnerability,
    "sql_injection": sql_injection
}