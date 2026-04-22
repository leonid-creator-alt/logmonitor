// backend/cpp_module/parser.cpp
#include <iostream>
#include <string>
#include <regex>
//#include <sstream>
//#include <ctime>

using namespace std;

// Структура для хранения распаршенного лога
struct ParsedLog {
    string timestamp;
    string level;      // "Error", "Warning", "Info"
    string source;     // "System", "Application"
    string message;
    string raw_line;
    bool is_error;
};

// Функция для парсинга одной строки лога Windows
ParsedLog parseWindowsLogLine(const string& line) {
    ParsedLog result;
    result.raw_line = line;
    result.is_error = false;
    
    // Пример: "Error 2025-04-06T10:15:30.000000000Z Service Control Manager 7036 Service started"
    regex pattern(R"((\w+)\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+([\w\s]+?)\s+(\d+)\s+(.+))");
    
    smatch matches;
    if (regex_search(line, matches, pattern)) {
        result.level = matches[1];           // Error/Warning/Info
        result.timestamp = matches[2];       // ISO timestamp
        result.source = matches[3];          // Source (e.g., "Service Control Manager")
        result.message = matches[5];         // Message
        
        if (result.level == "Error") {
            result.is_error = true;
        }
    } else {
        // Если не подошел паттерн, пробуем альтернативный
        result.level = "Info";
        result.source = "Unknown";
        result.message = line;
        result.is_error = false;
    }
    
    return result;
}

// Функция для проверки, является ли событие критическим
bool isCritical(const ParsedLog& log) {
    if (log.is_error) return true;
    
    // Ключевые слова для алертов
    vector<string> keywords = {"fail", "crash", "timeout", "out of memory", "disk full"};
    for (const auto& kw : keywords) {
        if (log.message.find(kw) != string::npos) {
            return true;
        }
    }
    return false;
}

// Главная функция: читает из stdin, пишет в stdout
int main() {
    string line;
    
    // Читаем строки из stdin (пока не закроют)
    while (getline(cin, line)) {
        // Парсим строку
        ParsedLog parsed = parseWindowsLogLine(line);
        
        // Формируем JSON-вывод для Go
        cout << "PARSED|" 
             << parsed.timestamp << "|"
             << parsed.level << "|"
             << parsed.source << "|"
             << parsed.message << "|"
             << (parsed.is_error ? "true" : "false") << "|"
             << (isCritical(parsed) ? "true" : "false")
             << endl;
    }
    
    return 0;
}