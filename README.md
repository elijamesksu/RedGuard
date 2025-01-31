### Advanced Malware Analysis & Detection with ClamAV & YARA on RHEL 9  

## Project Overview  
This project focuses on real-time malware scanning, automated threat detection, and forensic analysis in a RHEL 9 environment. I configured ClamAV Daemon for on-access scanning, implemented custom YARA rules to detect malicious patterns, and automated scheduled security scans using cron jobs.

### Objectives  
- Implement real-time malware scanning with ClamAV  
- Automate virus definition updates  
- Set up custom YARA rules for advanced threat detection  
- Schedule automated malware scans  
- Test system security using the EICAR test file  

## Technologies Used  
- RHEL 9 – Enterprise Linux environment  
- ClamAV – Open-source antivirus for Linux  
- YARA – Malware analysis and pattern-matching tool  
- Cron jobs – Automated scheduled scans  
- Systemd Services – Real-time scanning  

## Step-by-Step Implementation  

### 1. Install & Configure ClamAV  
ClamAV is a powerful open-source antivirus engine designed for detecting malware.  

#### 1.1 Install ClamAV on RHEL 9  
```bash
sudo dnf install -y clamav clamav-update clamav-server clamav-server-systemd
```
#### 1.2 Update ClamAV Signatures  
```bash
sudo freshclam
```
Ensure freshclam runs automatically:  
```bash
sudo systemctl enable --now clamav-freshclam
```
#### 1.3 Verify Installation  
```bash
clamscan --version
```

### 2. Test ClamAV with EICAR Malware Sample  
The EICAR test file is a harmless string used to test antivirus software.  

#### 2.1 Download the EICAR Test File  
```bash
curl -o /home/eicar.com "https://secure.eicar.org/eicar.com"
```
#### 2.2 Run a ClamAV Scan  
```bash
sudo clamscan -r /home
```
Expected output:  
```
/home/eicar.com: Eicar-Test-Signature FOUND
```
#### 2.3 Automatically Remove Detected Malware  
```bash
sudo clamscan --remove -r /home
```

### 3. Set Up ClamAV Daemon for Real-Time Scanning  
By default, ClamAV runs only on demand. We enable real-time scanning with the ClamAV Daemon.  

#### 3.1 Enable & Start ClamAV Daemon  
```bash
sudo systemctl enable --now clamd@scan
```
#### 3.2 Check ClamAV Daemon Status  
```bash
sudo systemctl status clamd@scan
```

### 4. Create Custom YARA Rules for Advanced Malware Detection  
YARA is a tool for defining and detecting malware patterns.  

#### 4.1 Install YARA  
```bash
sudo dnf install -y yara
```
#### 4.2 Create a Custom YARA Rule  
```bash
sudo nano /home/custom-malware.yar
```
Paste the following rule:  
```yara
rule Detect_Malicious_Strings
{
    strings:
        $malicious_string = "malware"
        $suspicious_cmd = "rm -rf /"
    condition:
        any of them
}
```
#### 4.3 Test the YARA Rule  
```bash
echo "This is a malware test file" > /home/testfile.txt
yara /home/custom-malware.yar /home/testfile.txt
```
Expected output:  
```
Detect_Malicious_Strings /home/testfile.txt
```

### 5. Automate Malware Scanning  
Cron jobs schedule ClamAV and YARA scans automatically.  

#### 5.1 Schedule Daily ClamAV Scans  
```bash
crontab -e
```
Add this line to scan `/home` daily at 2 AM:  
```
0 2 * * * clamscan -r /home --remove
```

#### 5.2 Schedule YARA Scans Every 6 Hours  
```bash
crontab -e
```
Add:  
```
0 */6 * * * yara /home/custom-malware.yar /home > /var/log/yara_scan.log
```

### 6. Test the System with Simulated Malware  
- Run ClamAV and YARA scans manually  
- Check logs for detections  
- Ensure scheduled scans are working  

#### 6.1 Run a Final ClamAV Scan  
```bash
sudo clamscan -r /home
```
#### 6.2 Run a Final YARA Scan  
```bash
yara /home/custom-malware.yar /home
```

## Key Takeaways  
- Proactive malware defense using ClamAV and YARA  
- Automated scanning and removal of detected threats  
- Real-time monitoring and logging to enhance security  
- Custom rule creation for advanced detection  
