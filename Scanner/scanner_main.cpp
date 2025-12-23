#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <regex>

using namespace std;
namespace fs = filesystem;

// Vulnerable keyword patterns with word boundaries
struct KeywordPattern {
    string keyword;
    regex pattern;
};

// Pre-compiled regex patterns for performance
vector<KeywordPattern> VULNERABLE_PATTERNS = {
    {"RSA", regex(R"(\bRSA\b)", regex_constants::icase)},
    {"AES-128", regex(R"(\bAES-128\b)", regex_constants::icase)},
    {"MD5", regex(R"(\bMD5\b)", regex_constants::icase)},
    {"DES", regex(R"(\bDES\b)", regex_constants::icase)},
    {"SHA1", regex(R"(\bSHA1\b)", regex_constants::icase)},
    {"SHA-1", regex(R"(\bSHA-1\b)", regex_constants::icase)}
};

// File extensions to scan
const vector<string> SCAN_EXTENSIONS = {
    ".cpp", ".h", ".hpp", ".c",
    ".py",
    ".java",
    ".js", ".jsx", ".ts", ".tsx"
};

// Structure to hold scan results
struct ScanResult {
    string filename;
    string keyword;
    int line_number;
    string line_content;
};

// Check if file has a scannable extension
bool is_scannable_file(const fs::path& filepath) {
    string extension = filepath.extension().string();
    transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
    
    for (const auto& ext : SCAN_EXTENSIONS) {
        if (extension == ext) {
            return true;
        }
    }
    return false;
}

// Scan a single file for vulnerable keywords using regex
vector<ScanResult> scan_file(const fs::path& filepath) {
    vector<ScanResult> results;
    ifstream file(filepath);
    
    if (!file.is_open()) {
        return results;
    }
    
    string line;
    int line_number = 0;
    
    while (getline(file, line)) {
        line_number++;
        
        // Check each vulnerable pattern using regex
        for (const auto& pattern : VULNERABLE_PATTERNS) {
            if (regex_search(line, pattern.pattern)) {
                ScanResult result;
                result.filename = filepath.string();
                result.keyword = pattern.keyword;
                result.line_number = line_number;
                result.line_content = line;
                results.push_back(result);
            }
        }
    }
    
    file.close();
    return results;
}

// Recursively scan directory
vector<ScanResult> scan_directory(const fs::path& directory) {
    vector<ScanResult> all_results;
    int files_scanned = 0;
    
    try {
        for (const auto& entry : fs::recursive_directory_iterator(directory)) {
            if (entry.is_regular_file() && is_scannable_file(entry.path())) {
                files_scanned++;
                cout << "[SCANNING] " << entry.path().filename().string() << endl;
                
                vector<ScanResult> file_results = scan_file(entry.path());
                all_results.insert(all_results.end(), file_results.begin(), file_results.end());
            }
        }
    } catch (const fs::filesystem_error& e) {
        cerr << "[ERROR] Filesystem error: " << e.what() << endl;
    }
    
    cout << "\n[INFO] Total files scanned: " << files_scanned << endl;
    return all_results;
}

// Write results to console and log file
void report_results(const vector<ScanResult>& results, const string& log_file) {
    ofstream log(log_file);
    
    if (!log.is_open()) {
        cerr << "[ERROR] Could not create log file: " << log_file << endl;
        return;
    }
    
    // Write header
    string header = "==========================================================\n"
                   "  QUANTUM SCANNER - CRYPTOGRAPHIC VULNERABILITY AUDIT\n"
                   "  Scan Date: " + string(__DATE__) + "\n"
                   "==========================================================\n";
    
    cout << "\n" << header;
    log << header << "\n";
    
    if (results.empty()) {
        string no_issues = "[SUCCESS] No vulnerable cryptographic patterns detected!\n";
        cout << no_issues;
        log << no_issues;
    } else {
        cout << "\n[WARNINGS] Found " << results.size() << " potential vulnerabilities:\n\n";
        log << "[WARNINGS] Found " << results.size() << " potential vulnerabilities:\n\n";
        
        for (const auto& result : results) {
            string warning = "[WARNING] Found " + result.keyword + 
                           " in " + result.filename + 
                           " at line " + to_string(result.line_number) + "\n" +
                           "  > " + result.line_content + "\n";
            
            cout << warning << endl;
            log << warning << endl;
        }
        
        // Summary
        string summary = "\n==========================================================\n"
                        "SUMMARY:\n"
                        "  Total Vulnerabilities: " + to_string(results.size()) + "\n"
                        "  Action Required: Review and upgrade to quantum-safe algorithms\n"
                        "==========================================================\n";
        
        cout << summary;
        log << summary;
    }
    
    log.close();
    cout << "\n[INFO] Report saved to: " << log_file << endl;
}

void show_help() {
    cout << "==========================================================" << endl;
    cout << "  QUANTUM SCANNER - Cryptographic Vulnerability Scanner" << endl;
    cout << "  Detects outdated cryptographic algorithms in code" << endl;
    cout << "==========================================================" << endl;
    cout << "\nUSAGE:" << endl;
    cout << "  QuantumScanner <directory_path>" << endl;
    cout << "\nDESCRIPTION:" << endl;
    cout << "  Recursively scans directory for vulnerable crypto patterns:" << endl;
    cout << "    - RSA (Vulnerable to Quantum Attacks)" << endl;
    cout << "    - AES-128 (Weak variant of AES)" << endl;
    cout << "    - MD5 (Broken hash function)" << endl;
    cout << "    - DES (Obsolete encryption)" << endl;
    cout << "    - SHA1/SHA-1 (Weak hash function)" << endl;
    cout << "\n  Scans files: .cpp, .h, .py, .java, .js, .ts, etc." << endl;
    cout << "\n  Output: Console + audit_report.txt" << endl;
    cout << "\nEXAMPLE:" << endl;
    cout << "  QuantumScanner C:\\Projects\\MyApp" << endl;
    cout << "  QuantumScanner ." << endl;
    cout << "==========================================================" << endl;
}

int main(int argc, char* argv[]) {
    // Check arguments
    if (argc < 2) {
        show_help();
        return 1;
    }
    
    string directory_path = argv[1];
    
    // Check if help requested
    if (directory_path == "help" || directory_path == "--help" || directory_path == "-h") {
        show_help();
        return 0;
    }
    
    // Validate directory exists
    if (!fs::exists(directory_path)) {
        cerr << "[ERROR] Directory not found: " << directory_path << endl;
        return 1;
    }
    
    if (!fs::is_directory(directory_path)) {
        cerr << "[ERROR] Path is not a directory: " << directory_path << endl;
        return 1;
    }
    
    cout << "==========================================================" << endl;
    cout << "  QUANTUM SCANNER - Starting Analysis" << endl;
    cout << "  Target: " << fs::absolute(directory_path) << endl;
    cout << "==========================================================" << endl;
    cout << endl;
    
    // Scan directory
    vector<ScanResult> results = scan_directory(directory_path);
    
    // Generate report
    report_results(results, "audit_report.txt");
    
    return results.empty() ? 0 : 1;
}
