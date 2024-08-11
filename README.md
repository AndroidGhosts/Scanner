import click
import ipaddress
import concurrent.futures
import http.client
import threading
import ssl
import time
from tqdm import tqdm
from colorama import Fore, Style


bg = ''
G = bg+'\033[32m'

print(G+'''

 The script analyzes the addresses of connections running on your network via port 80 and 443, and addresses that give a response such as 302, 301 and others can be skipped. The addresses that connect can also be saved to a file.
 
 

 #Cloudflare:
1. 104.16.0.0 => 104.31.255.255
2. 103.21.244.0 => 103.21.247.255
3. 103.22.200.0 => 103.22.203.255
4. 103.31.4.0 => 103.31.7.255
5. 141.101.64.0 => 141.101.127.255
6. 108.162.192.0 => 108.162.255.255
7. 190.93.240.0 => 190.93.255.255
8. 188.114.96.0 => 188.114.111.255
9. 197.234.240.0 => 197.234.243.255
10. 198.41.128.0 => 198.41.255.255
11. 162.158.0.0 => 162.159.255.255
12. 172.64.0.0 => 172.71.255.255
13. 131.0.72.0 => 131.0.75.255
 
 #cloudfronet

1. 120.52.22.96 => 120.52.22.127
2. 205.251.249.0 => 205.251.249.255
3. 180.163.57.128 => 180.163.57.191
4. 204.246.168.0 => 204.246.171.255
5. 111.13.171.128 => 111.13.171.191
6. 18.160.0.0 => 18.161.255.255
7. 205.251.252.0 => 205.251.253.255
8. 54.192.0.0 => 54.193.255.255
9. 204.246.173.0 => 204.246.173.255
10. 54.230.200.0 => 54.230.207.255
11. 120.253.240.192 => 120.253.240.255
12. 116.129.226.128 => 116.129.226.191
13. 130.176.0.0 => 130.176.127.255
14. 108.156.0.0 => 108.159.255.255
15. 99.86.0.0 => 99.86.255.255
16. 205.251.200.0 => 205.251.207.255
17. 13.32.0.0 => 13.35.255.255
18. 120.253.245.128 => 120.253.245.191
19. 13.224.0.0 => 13.227.255.255
20. 70.132.0.0 => 70.135.255.255
21. 15.158.0.0 => 15.158.255.255
22. 111.13.171.192 => 111.13.171.255
23. 13.249.0.0 => 13.249.255.255
24. 18.238.0.0 => 18.239.255.255
25. 18.244.0.0 => 18.245.255.255
26. 205.251.208.0 => 205.251.223.255
27. 65.9.128.0 => 65.9.191.255
28. 130.176.128.0 => 130.176.191.255
29. 58.254.138.0 => 58.254.138.127
30. 54.230.208.0 => 54.230.223.255
31. 3.160.0.0 => 3.163.255.255
32. 116.129.226.0 => 116.129.226.127
33. 52.222.128.0 => 52.222.255.255
34. 18.164.0.0 => 18.165.255.255
35. 111.13.185.32 => 111.13.185.63
36. 64.252.128.0 => 64.252.191.255
37. 205.251.254.0 => 205.251.254.255
38. 54.230.224.0 => 54.230.255.255
39. 71.152.0.0 => 71.152.127.255
40. 216.137.32.0 => 216.137.63.255
41. 204.246.172.0 => 204.246.172.255
42. 18.172.0.0 => 18.173.255.255
43. 120.52.39.128 => 120.52.39.159
44. 118.193.97.64 => 118.193.97.127
45. 18.154.0.0 => 18.155.255.255
46. 54.240.128.0 => 54.241.255.255
47. 205.251.250.0 => 205.251.251.255
48. 180.163.57.0 => 180.163.57.127
49. 52.46.0.0 => 52.47.255.255
50. 52.82.128.0 => 52.82.159.255
51. 54.230.0.0 => 54.230.127.255
52. 54.230.128.0 => 54.230.191.255
53. 54.239.128.0 => 54.239.191.255
54. 130.176.224.0 => 130.176.239.255
55. 36.103.232.128 => 36.103.232.191
56. 52.84.0.0 => 52.85.255.255
57. 143.204.0.0 => 143.204.255.255
58. 144.220.0.0 => 144.221.255.255
59. 120.52.153.192 => 120.52.153.255
60. 119.147.182.0 => 119.147.182.127
61. 120.232.236.0 => 120.232.236.63
62. 54.239.192.0 => 54.239.223.255
63. 18.64.0.0 => 18.67.255.255
64. 120.52.12.64 => 120.52.12.127
65. 99.84.0.0 => 99.85.255.255
66. 130.176.192.0 => 130.176.223.255
67. 52.124.128.0 => 52.124.255.255
68. 204.246.164.0 => 204.246.167.255
69. 13.35.0.0 => 13.35.255.255
70. 204.246.174.0 => 204.246.175.255
71. 36.103.232.0 => 36.103.232.127
72. 119.147.182.128 => 119.147.182.191
73. 118.193.97.128 => 118.193.97.255
74. 120.232.236.0 => 120.232.236.63
75. 204.246.176.0 => 204.246.191.255
76. 65.8.0.0 => 65.8.255.255
77. 65.9.0.0 => 65.9.127.255
78. 108.138.0.0 => 108.139.255.255
79. 120.253.241.160 => 120.253.241.191
80. 64.252.64.0 => 64.252.127.255
81. 13.113.196.64 => 13.113.196.127
82. 13.113.203.0 => 13.113.203.255
83. 52.199.127.192 => 52.199.127.255
84. 13.124.199.0 => 13.124.199.255
85. 3.35.130.128 => 3.35.130.255
86. 52.78.247.128 => 52.78.247.191
87. 13.233.177.192 => 13.233.177.255
88. 15.207.13.128 => 15.207.13.255
89. 15.207.213.128 => 15.207.213.255
90. 52.66.194.128 => 52.66.194.191
91. 13.228.69.0 => 13.228.69.255
92. 52.220.191.0 => 52.220.191.63
93. 13.210.67.128 => 13.210.67.191
94. 13.54.63.128 => 13.54.63.191
95. 43.218.56.128 => 43.218.56.191
96. 43.218.56.192 => 43.218.56.255
97. 43.218.56.64 => 43.218.56.127
98. 43.218.71.0 => 43.218.71.63
99. 99.79.169.0 => 99.79.169.255
100. 18.192.142.0 => 18.192.143.255
101. 35.158.136.0 => 35.158.136.255
102. 52.57.254.0 => 52.57.254.255
103. 13.48.32.0 => 13.48.32.255
104. 18.200.212.0 => 18.200.213.255
105. 52.212.248.0 => 52.212.248.63
106. 3.10.17.128 => 3.10.17.255
107. 3.11.53.0 => 3.11.53.255
108. 52.56.127.0 => 52.56.127.127
109. 15.188.184.0 => 15.188.184.255
110. 52.47.139.0 => 52.47.139.255
111. 3.29.40.128 => 3.29.40.191
112. 3.29.40.192 => 3.29.40.255
113. 3.29.40.64 => 3.29.40.127
114. 3.29.57.0 => 3.29.57.63
115. 18.229.220.192 => 18.229.220.255
116. 54.233.255.128 => 54.233.255.191
117. 3.231.2.0 => 3.231.2.127
118. 3.234.232.224 => 3.234.232.255
119. 3.236.169.192 => 3.236.169.255
120. 3.236.48.0 => 3.236.49.255
121. 34.195.252.0 => 34.195.252.255
122. 34.226.14.0 => 34.226.14.255
123. 13.59.250.0 => 13.59.250.63
124. 18.216.170.128 => 18.216.170.255
125. 3.128.93.0 => 3.128.93.255
126. 3.134.215.0 => 3.134.215.255
127. 52.15.127.128 => 52.15.127.191
128. 3.101.158.0 => 3.101.159.255
129. 52.52.191.128 => 52.52.191.191
130. 34.216.51.0 => 34.216.51.127
131. 34.223.12.224 => 34.223.12.255
132. 34.223.80.192 => 34.223.80.255
133. 35.162.63.192 => 35.162.63.255
134. 35.167.191.128 => 35.167.191.191
135. 44.227.178.0 => 44.227.178.255
136. 44.234.108.128 => 44.234.108.255
137. 44.234.90.252 => 44.234.90.255
 
 # fastly

1. 103.244.50.0 => 103.244.50.255
2. 103.245.222.0 => 103.245.223.255
3. 103.245.224.0 => 103.245.224.255
4. 104.156.80.0 => 104.156.95.255
5. 140.248.64.0 => 140.248.127.255
6. 140.248.128.0 => 140.248.255.255
7. 146.75.0.0 => 146.75.127.255
8. 151.101.0.0 => 151.101.255.255
9. 157.52.64.0 => 157.52.127.255
10. 167.82.0.0 => 167.82.127.255
11. 167.82.128.0 => 167.82.143.255
12. 167.82.160.0 => 167.82.175.255
13. 167.82.224.0 => 167.82.239.255
14. 172.111.64.0 => 172.111.127.255
15. 185.31.16.0 => 185.31.19.255
16. 199.27.72.0 => 199.27.79.255
17. 199.232.0.0 => 199.232.255.255
 
 #akamaighost
 

1. 2.16.0.0 => 2.23.255.255
2. 23.0.0.0 => 23.15.255.255
3. 23.192.0.0 => 23.223.255.255
4. 23.32.0.0 => 23.63.255.255
5. 23.64.0.0 => 23.67.255.255
6. 23.72.0.0 => 23.79.255.255
7. 88.221.0.0 => 88.221.255.255
8. 95.100.0.0 => 95.101.255.255
9. 96.6.0.0 => 96.7.255.255
10. 184.24.0.0 => 184.31.255.255
11. 184.84.0.0 => 184.87.255.255
12. 104.64.0.0 => 104.80.255.255
13. 104.81.0.0 => 104.110.255.255
14. 104.111.0.0 => 104.127.255.255
15. 104.75.128.0 => 104.75.191.255
16. 185.5.160.0 => 185.5.163.255
17. 23.220.200.0 => 23.220.210.255
18. 96.17.176.0 => 96.17.179.255
19. 178.174.128.0 => 178.174.255.255
20. 86.124.0.0 => 86.125.255.255

telegram_channel_link = 'https://t.me/Android_Ghosts'




        ██████╗  ██╗  ██╗ ██████╗ ███████╗████████╗███████╗
        ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔════╝
        ██║  ███╗███████║██║   ██║███████╗   ██║   ███████╗
        ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ╚════██║
        ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ███████║
         ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝👻
                                         Scrpit .V2
                                        ANDROID.GHOSTS👻


'''+G)

# Add your Telegram channel link here
telegram_channel_link = 'https://t.me/Android_Ghosts'

# Global variables for statistics
total_attempts = 0
successful_attempts = 0
failed_attempts = 0
excluded_addresses_count = 0
working_addresses_count = 0
output_filename = ""  # Variable to store the output file name
working_addresses = []

def save_result_to_file(ip, port, status_code, output_file, exception_msg=None, exception_ip=None):
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{ip}"
    
    with open(output_file, 'a') as file:
        if exception_msg and exception_ip:
            file.write(f"{exception_ip}:{port} x Exception: {exception_msg}\n")
        else:
            file.write(f"{url}   \n")

def check_ip_reachability(ip, port, output_file, excluded_status_codes, bar, http_method, notification_ip):
    global total_attempts, successful_attempts, failed_attempts, working_addresses, excluded_addresses_count, working_addresses_count
    
    try:
        if port == 443:
            connection = http.client.HTTPSConnection(ip, context=ssl._create_unverified_context(), timeout=4)
        else:
            connection = http.client.HTTPConnection(ip, timeout=4)

        connection.request(http_method, "/")
        response = connection.getresponse()
        total_attempts += 1

        # Check if the response status is excluded
        if response.status in excluded_status_codes:
            excluded_addresses_count += 1
            tqdm.write(f"{Fore.YELLOW}      {ip}:{port} - Excluded Status Code: {response.status}{Style.RESET_ALL}")
            return

        # Save the IP regardless of the response status
        tqdm.write(f"{Fore.GREEN}      {ip}:{port} ✓ - Status Code: {response.status}{Style.RESET_ALL}")
        save_result_to_file(ip, port, response.status, output_file)
        
        # Check if the exception message contains "SSLV3_ALERT_HANDSHAKE_FAILURE"
        if "SSLV3_ALERT_HANDSHAKE_FAILURE" in response.read().decode("utf-8"):
            working_addresses.append(ip)
            working_addresses_count += 1
        
        # Check if notification IP is specified and the connection is successful
        if notification_ip and ip == notification_ip:
            # Send notification here
            print(f"Successful connection to {ip} on port {port}. Sending notification...")
        
        successful_attempts += 1
        bar.update(1)

    except (http.client.HTTPException, ConnectionError, TimeoutError, ssl.SSLError) as e:
        failed_attempts += 1
        exception_msg = str(e)
        if "SSLV3_ALERT_HANDSHAKE_FAILURE" in exception_msg:
            tqdm.write(f"{Fore.RED}      {ip}:{port} ✗ - Exception: {Style.RESET_ALL}")
            save_result_to_file(ip, port, None, output_file, ip)
        bar.update(1)

@click.command()
@click.option('--start-ip', prompt=f'{Fore.YELLOW}Enter the start IP address of the range{Style.RESET_ALL}', help='Start IP address of the range')
@click.option('--end-ip', prompt=f'{Fore.YELLOW}Enter the end IP address of the range{Style.RESET_ALL}', help='End IP address of the range')
@click.option('--scan-ports', prompt=f'{Fore.YELLOW}Enter the ports to scan (443, 80){Style.RESET_ALL}', help='Ports to scan')
@click.option('--num-threads', default=100, type=int, show_default=True, prompt=f'{Fore.YELLOW}Enter the number of threads{Style.RESET_ALL}', help='Number of threads')
@click.option('--output-file', default='output.txt', type=str, show_default=True, prompt=f'{Fore.YELLOW}Enter the output file name{Style.RESET_ALL}', help='Output file name')
@click.option('--skip-status-codes', default='302,or 0', type=str, show_default=True, prompt=f'{Fore.YELLOW}Enter the status codes to skip (comma separated){Style.RESET_ALL}', help='Status codes to skip')
@click.option('--http-method', type=click.Choice(['GET', 'POST', 'HEAD']), default='GET', show_default=True, prompt=f'{Fore.YELLOW}Enter the HTTP method to use (GET/POST/HEAD){Style.RESET_ALL}', help='HTTP method to use in the request')
@click.option('--notification-ip', type=str, default='', help='Custom IP address to send notification upon successful connection')
def main(start_ip, end_ip, scan_ports, num_threads, output_file, skip_status_codes, http_method, notification_ip):
    global output_filename, start_time
    output_filename = output_file
    start_time = time.time()

    total_ips = int(ipaddress.IPv4Address(end_ip)) - int(ipaddress.IPv4Address(start_ip)) + 1

    ports_to_scan = [int(port.strip()) for port in scan_ports.split(',')]
    skip_status_codes = [int(code.strip()) for code in skip_status_codes.split(',')]

    tqdm.write(f"{Fore.YELLOW}Scanning IPs from {start_ip} to {end_ip} for ports {scan_ports} using {http_method} method...{Style.RESET_ALL}")

    check_ip_range(start_ip, end_ip, output_file, total_ips, num_threads, skip_status_codes, ports_to_scan, http_method, notification_ip)
    print_statistics(total_ips)

def check_ip_range(start_ip, end_ip, output_file, total_ips, num_threads, excluded_status_codes, ports_to_scan, http_method, notification_ip):
    start_address = ipaddress.IPv4Address(start_ip)
    end_address = ipaddress.IPv4Address(end_ip)

    ips = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start_address), int(end_address) + 1)]

    with tqdm(total=total_ips, desc="Progress", unit="IPs") as bar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            for port in ports_to_scan:
                futures = [executor.submit(check_ip_reachability, ip, port, output_file, excluded_status_codes, bar, http_method, notification_ip) for ip in ips]
                concurrent.futures.wait(futures)

def print_statistics(total_ips):
    global total_attempts, successful_attempts, failed_attempts, excluded_addresses_count, working_addresses_count, output_filename
    tqdm.write(f"\n{Fore.CYAN}Final Statistics:{Style.RESET_ALL}")
    tqdm.write(f"{Fore.MAGENTA}Total Attempts: {total_attempts}{Style.RESET_ALL}")
    tqdm.write(f"{Fore.GREEN}Successful Attempts: {successful_attempts}{Style.RESET_ALL}")
    tqdm.write(f"{Fore.RED}Failed Attempts: {failed_attempts}{Style.RESET_ALL}")
    success_rate = (successful_attempts / total_attempts) * 100 if total_attempts > 0 else 0
    tqdm.write(f"{Fore.MAGENTA}Success Rate: {success_rate:.2f}%{Style.RESET_ALL}")
    tqdm.write(f"{Fore.YELLOW}Excluded Addresses: {excluded_addresses_count}{Style.RESET_ALL}")
    tqdm.write(f"{Fore.CYAN}Working Addresses: {working_addresses_count}{Style.RESET_ALL}")
    tqdm.write(f"{Fore.RED}Failed Addresses: {failed_attempts}{Style.RESET_ALL}")
    tqdm.write(f"{Fore.CYAN}Execution Time: {time.time() - start_time:.2f} seconds{Style.RESET_ALL}") 
    tqdm.write(f"{Fore.YELLOW}Output File: {output_filename}{Style.RESET_ALL}")
    tqdm.write(f"{Fore.YELLOW}Telegram Channel: {telegram_channel_link}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
