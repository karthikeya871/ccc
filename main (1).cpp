#include <iostream>
#include <fstream>
#include <queue>
#include <unordered_map>
#include <string>
#include <vector>

using namespace std;

// -------------------- TRIE NODE --------------------
class TrieNode {
public:
    TrieNode* children[128];
    bool isEndOfWord;

    TrieNode() {
        isEndOfWord = false;
        for (int i = 0; i < 128; i++) {
            children[i] = NULL;
        }
    }
};

// -------------------- TRIE CLASS --------------------
class Trie {
private:
    TrieNode* root;

public:
    Trie() {
        root = new TrieNode();
    }

    // Insert suspicious pattern
    void insert(string word) {
        TrieNode* current = root;

        for (char ch : word) {
            if (current->children[(int)ch] == NULL) {
                current->children[(int)ch] = new TrieNode();
            }
            current = current->children[(int)ch];
        }

        current->isEndOfWord = true;
    }

    // Search if pattern exists in log
    bool searchInText(string text) {
        for (int i = 0; i < text.length(); i++) {
            TrieNode* current = root;
            int j = i;

            while (j < text.length() && current->children[(int)text[j]] != NULL) {
                current = current->children[(int)text[j]];

                if (current->isEndOfWord) {
                    return true;
                }

                j++;
            }
        }

        return false;
    }
};

// -------------------- EXTRACT IP --------------------
string extractIP(string log) {
    size_t ipPos = log.find("IP=");

    if (ipPos == string::npos) {
        return "Unknown";
    }

    string ip = "";

    for (size_t i = ipPos + 3; i < log.length() && log[i] != ' '; i++) {
        ip += log[i];
    }

    return ip;
}

// -------------------- MAIN FUNCTION --------------------
int main() {

    ifstream file("logs.txt");

    if (!file) {
        cout << "Error opening logs.txt file!" << endl;
        return 1;
    }

    queue<string> logQueue;
    unordered_map<string, int> failedAttempts;
    string line;

    // -------------------- LOAD LOGS INTO QUEUE --------------------
    while (getline(file, line)) {
        logQueue.push(line);
    }

    file.close();

    // -------------------- CREATE TRIE --------------------
    Trie suspiciousPatterns;

    // SQL Injection patterns
    suspiciousPatterns.insert("' OR '1'='1");
    suspiciousPatterns.insert("DROP TABLE");
    suspiciousPatterns.insert("UNION SELECT");

    // Dangerous commands
    suspiciousPatterns.insert("sudo rm -rf");
    suspiciousPatterns.insert("shutdown");
    suspiciousPatterns.insert("wget malicious");

    cout << "----- MINI IDS STARTED -----" << endl;

    // -------------------- PROCESS LOGS --------------------
    while (!logQueue.empty()) {

        string currentLog = logQueue.front();
        logQueue.pop();

        cout << "\nProcessing Log: " << currentLog << endl;

        string ip = extractIP(currentLog);

        // -------------------- BRUTE FORCE DETECTION --------------------
        if (currentLog.find("Failed login") != string::npos) {
            failedAttempts[ip]++;

            if (failedAttempts[ip] >= 3) {
                cout << "[ALERT] Brute Force Attack Detected from IP: " << ip << endl;
            }
        }

        // -------------------- SQL / COMMAND DETECTION --------------------
        if (suspiciousPatterns.searchInText(currentLog)) {
            cout << "[ALERT] Suspicious Activity Detected from IP: " << ip << endl;
        }
    }

    cout << "\n----- IDS SCAN COMPLETED -----" << endl;

    return 0;
}