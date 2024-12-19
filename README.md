
---

# **Log Analysis and Threat Detection**

This project performs system log analysis, identifies potential malware candidates, and compares them with a blacklist of domains using Python. The program processes an access log file and a threat intelligence HTML feed to generate actionable insights.

---

## **Features**

1. **Regex-based Log Analysis**
   - Extracts URLs and their HTTP status codes from a log file.
   - Identifies URLs with `404` status codes and counts their occurrences.

2. **File Manipulation**
   - Saves all extracted URLs and status codes to `url_status_report.txt`.
   - Saves URLs with `404` errors and their counts to `malware_candidates.csv`.

3. **Web Scraping**
   - Extracts blacklisted domains from a provided HTML feed.
   - Compares URLs from the log file against the blacklist.

4. **JSON Data Handling**
   - Generates `alert.json` with matching blacklisted URLs, their status, and occurrence counts.
   - Creates a `summary_report.json` summarizing the results.

---

## **Project Structure**

```plaintext
.
├── access_log.txt         # Input log file
├── threat_feed.html       # Input HTML file with blacklisted domains
├── main.py                # Main Python script
├── requirements.txt       # Python dependencies
├── url_status_report.txt  # Output file with URLs and status codes
├── malware_candidates.csv # Output CSV file for 404 URLs
├── alert.json             # Output JSON for blacklisted URL matches
├── summary_report.json    # Output JSON summarizing the results
└── README.md              # Project documentation
```

---

## **Getting Started**

### **Prerequisites**
- Python 3.7 or later
- A virtual environment (optional but recommended)

### **Setup**

1. Clone the repository:
   ```bash
   git clone https://github.com/Nuranss/LAB2.git
   cd LAB2
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   venv\Scripts\activate    # Windows
   source venv/bin/activate # macOS/Linux
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Place the input files (`access_log.txt` and `threat_feed.html`) in the project root.

---

## **Usage**

Run the script to analyze logs and generate output files:

```bash
python main.py
```

### **Output Files**
- **`url_status_report.txt`**: List of all URLs and their status codes.
- **`malware_candidates.csv`**: URLs with `404` errors and their counts.
- **`alert.json`**: Matching blacklisted URLs with details.
- **`summary_report.json`**: Summary of the analysis.

---

## **How It Works**

1. **Log Analysis**:
   - Extracts HTTP requests and status codes using Regex.
   - Filters and counts `404` errors.

2. **Blacklist Comparison**:
   - Scrapes blacklisted domains from an HTML feed.
   - Matches extracted URLs with blacklisted domains.

3. **JSON and File Outputs**:
   - Outputs actionable insights and summaries in `JSON`, `CSV`, and `TXT` formats.

---

## **Dependencies**

The project uses the following Python libraries:
- `re`: Regex operations
- `json`: JSON data handling
- `csv`: File manipulation
- `bs4`: Web scraping with BeautifulSoup

---

## **Author**

- **Nuran**

For contact nuransgrov@gmail.com

--- 

