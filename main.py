import re
import json
import csv
from bs4 import BeautifulSoup

def read_file_content(filepath):
    """Reads a file and returns its content."""
    with open(filepath, 'r') as file:
        return file.readlines()

def write_content_to_file(filepath, content):
    """Writes content to a file."""
    with open(filepath, 'w') as file:
        file.write(content)

def extract_urls_and_status_codes(log_data):
    """Extracts URLs and status codes from log data."""
    url_status_list = []
    error_404_count = {}
    for line in log_data:
        match = re.search(r'"(GET|POST) (\S+) HTTP/1.1" (\d+)', line)
        if match:
            url = match.group(2)
            status = match.group(3)
            url_status_list.append((url, status))
            if status == "404":
                error_404_count[url] = error_404_count.get(url, 0) + 1
    return url_status_list, error_404_count

def save_urls_and_status_report(url_status_list):
    """Saves all URLs and status codes in a file."""
    content = "\n".join([f"URL: {url} | Status: {status}" for url, status in url_status_list])
    write_content_to_file('url_status_report.txt', content)

def save_404_errors_to_csv(error_404_count):
    """Saves URLs with 404 errors to a CSV file."""
    with open('malware_candidates.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["URL", "404 Count"])
        for url, count in error_404_count.items():
            writer.writerow([url, count])

def extract_blacklisted_domains_from_html(html_file):
    """Extracts blacklisted domains from an HTML file."""
    with open(html_file, 'r') as file:
        soup = BeautifulSoup(file, 'html.parser')
    return {li.text for li in soup.find_all('li')}

def save_blacklisted_alerts(url_status_list, blacklisted_domains):
    """Saves alerts for blacklisted URLs in a JSON file."""
    matching_blacklist_urls = [url for url, _ in url_status_list if any(domain in url for domain in blacklisted_domains)]
    alert_data = [{"url": url, "status": status} for url, status in url_status_list if url in matching_blacklist_urls]
    with open('alert.json', 'w') as file:
        json.dump(alert_data, file, indent=4)
    return matching_blacklist_urls

def generate_summary_report(url_status_list, error_404_count, matching_blacklist_urls):
    """Saves a summary report in a JSON file."""
    summary_data = {
        "all_urls_with_status": [{"url": url, "status": status} for url, status in url_status_list],
        "urls_404_with_counts": [{"url": url, "count": count} for url, count in error_404_count.items()],
        "blacklisted_matching_urls": [{"url": url, "status": status} for url, status in url_status_list if url in matching_blacklist_urls]
    }
    with open('summary_report.json', 'w') as file:
        json.dump(summary_data, file, indent=4)

def move_html_content_to_text_and_clear(html_file, txt_file):
    """Transfers HTML content to a text file and clears the HTML file."""
    with open(html_file, 'r+') as file:
        soup = BeautifulSoup(file, 'html.parser')
        blacklisted_domains = "\n".join([li.text for li in soup.find_all('li')])
        write_content_to_file(txt_file, blacklisted_domains)
        file.truncate(0)
    return blacklisted_domains

# Main Program Flow
log_data = read_file_content('access_log.txt')
url_status_list, error_404_count = extract_urls_and_status_codes(log_data)
save_urls_and_status_report(url_status_list)
save_404_errors_to_csv(error_404_count)

blacklisted_domains = extract_blacklisted_domains_from_html('threat_feed.html')
matching_blacklist_urls = save_blacklisted_alerts(url_status_list, blacklisted_domains)
generate_summary_report(url_status_list, error_404_count, matching_blacklist_urls)

move_html_content_to_text_and_clear('threat_feed.html', 'threat_feed.txt')
