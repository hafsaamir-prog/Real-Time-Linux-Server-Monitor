#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <numeric>
#include <filesystem>
#include <unistd.h>
#include <sys/statvfs.h>
#include <ncurses.h>

using std::string;
using std::vector;
namespace fs = std::filesystem;

// ============================================================================
// 1. DATA STRUCTURES & CONFIGURATION CONSTANTS
// ============================================================================
enum class Severity { NOMINAL, WARNING, CRITICAL };

struct Alert {
    string message;
    Severity severity;
};

struct Threshold {
    float warning;
    float critical;
};

struct NetIface {
    string name;
    unsigned long long rx_bytes{0};
    unsigned long long tx_bytes{0};
    double rx_rate_kbps{0.0};
    double tx_rate_kbps{0.0};
};

struct MetricSnapshot {
    float cpu_util;
    float mem_util;
    float disk_util;
    double net_rx_kbps;
    double net_tx_kbps;
};

// ============================================================================
// 2. DATA FORMATTING HELPERS
// ============================================================================
class Format {
public:
    static string TwoDigits(int n) {
        char buf[4];
        snprintf(buf, sizeof(buf), "%02d", n);
        return buf;
    }

    static string ElapsedTime(long seconds) {
        long h = seconds / 3600;
        long m = (seconds % 3600) / 60;
        long s = seconds % 60;
        return TwoDigits(static_cast<int>(h)) + ":" +
               TwoDigits(static_cast<int>(m)) + ":" +
               TwoDigits(static_cast<int>(s));
    }

    static string KBtoHuman(long kb) {
        char buf[32];
        if (kb >= 1024L * 1024) {
            snprintf(buf, sizeof(buf), "%.1f GB", static_cast<double>(kb) / (1024.0 * 1024.0));
        } else if (kb >= 1024) {
            snprintf(buf, sizeof(buf), "%.1f MB", static_cast<double>(kb) / 1024.0);
        } else {
            snprintf(buf, sizeof(buf), "%ld KB", kb);
        }
        return buf;
    }
};

// ============================================================================
// 3. LOGGING ENGINE (With In-Memory Buffering & Hourly Analytics Math)
// ============================================================================
class Logger {
private:
    string logs_dir_{"./logs/"};
    vector<MetricSnapshot> snapshots_;
    time_t last_summary_time_;

    void EnsureLogsDir() const {
        if (!fs::exists(logs_dir_)) {
            fs::create_directories(logs_dir_);
        }
    }

    string CurrentTimestamp() const {
        auto t = std::time(nullptr);
        auto* tm = std::localtime(&t);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
        return buf;
    }

    string CurrentHourString() const {
        auto t = std::time(nullptr);
        auto* tm = std::localtime(&t);
        char buf[20];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d_%H", tm);
        return buf;
    }

    double avg(float MetricSnapshot::* member) const {
        if (snapshots_.empty()) return 0.0;
        double sum = 0.0;
        for (const auto& s : snapshots_) {
            sum += s.*member;
        }
        return sum / snapshots_.size();
    }

    double avg_double(double MetricSnapshot::* member) const {
        if (snapshots_.empty()) return 0.0;
        double sum = 0.0;
        for (const auto& s : snapshots_) {
            sum += s.*member;
        }
        return sum / snapshots_.size();
    }

public:
    Logger() {
        EnsureLogsDir();
        last_summary_time_ = std::time(nullptr);
    }

    void LogAlert(const Alert& alert) const {
        string path = logs_dir_ + "events.txt";
        std::ofstream file(path, std::ios::app);
        if (file.is_open()) {
            file << "[" << CurrentTimestamp() << "] [CRITICAL] " << alert.message << "\n";
        }
    }

    void RecordSnapshot(const MetricSnapshot& snap) {
        snapshots_.push_back(snap);
    }

    void MaybeWriteHourlySummary() {
        time_t now = std::time(nullptr);
        if (now - last_summary_time_ >= 3600) {
            if (snapshots_.empty()) return;

            double avg_cpu  = avg(&MetricSnapshot::cpu_util)  * 100.0;
            double avg_mem  = avg(&MetricSnapshot::mem_util)  * 100.0;
            double avg_disk = avg(&MetricSnapshot::disk_util) * 100.0;
            double avg_rx   = avg_double(&MetricSnapshot::net_rx_kbps);
            double avg_tx   = avg_double(&MetricSnapshot::net_tx_kbps);

            float max_cpu = 0, max_mem = 0;
            for (const auto& s : snapshots_) {
                if (s.cpu_util > max_cpu) max_cpu = s.cpu_util;
                if (s.mem_util > max_mem) max_mem = s.mem_util;
            }

            string path = logs_dir_ + "summary_" + CurrentHourString() + ".txt";
            std::ofstream file(path);
            if (file.is_open()) {
                file << "===============================================\n";
                file << "   ServerPulse Hourly Statistical Analytics\n";
                file << "   Generated: " << CurrentTimestamp() << "\n";
                file << "   Samples Consolidated: " << snapshots_.size() << "\n";
                file << "===============================================\n\n";
                file << std::fixed << std::setprecision(1);
                file << "CPU Performance:\n  Mean: " << avg_cpu << "%\n  Peak: " << (max_cpu * 100.0f) << "%\n\n";
                file << "RAM Performance:\n  Mean: " << avg_mem << "%\n  Peak: " << (max_mem * 100.0f) << "%\n\n";
                file << "Storage Delta Check:\n  Mean Saturation: " << avg_disk << "%\n\n";
                file << "Network Throughput Profiles:\n  Avg Rx: " << avg_rx << " KB/s\n  Avg Tx: " << avg_tx << " KB/s\n";
            }
            snapshots_.clear();
            last_summary_time_ = now;
        }
    }
};

// ============================================================================
// 4. LOW-LEVEL OPERATING SYSTEM FILE PARSERS
// ============================================================================
class LinuxParser {
public:
    static string Kernel() {
        std::ifstream stream("/proc/version");
        string os, version, kernel;
        if (stream >> os >> version >> kernel) return kernel;
        return "Unknown";
    }

    static string OperatingSystem() {
        std::ifstream stream("/etc/os-release");
        string line;
        while (std::getline(stream, line)) {
            if (line.compare(0, 13, "PRETTY_NAME=") == 0) {
                string name = line.substr(14);
                name.pop_back(); // Remove closing trailing quote
                return name;
            }
        }
        return "Linux";
    }

    static float MemoryUtilization() {
        std::ifstream stream("/proc/meminfo");
        string line, key;
        long long value;
        long long total = 0, available = 0;
        while (std::getline(stream, line)) {
            std::istringstream iss(line);
            iss >> key >> value;
            if (key == "MemTotal:")     total = value;
            if (key == "MemAvailable:") available = value;
            if (total > 0 && available > 0) break;
        }
        if (total > 0) return static_cast<float>(total - available) / total;
        return 0.0f;
    }

    static long UpTime() {
        std::ifstream stream("/proc/uptime");
        long uptime = 0;
        if (stream >> uptime) return uptime;
        return 0;
    }

    static vector<int> Pids() {
        vector<int> pids;
        for (const auto& entry : fs::directory_iterator("/proc")) {
            if (entry.is_directory()) {
                string filename = entry.path().filename().string();
                if (std::all_of(filename.begin(), filename.end(), ::isdigit)) {
                    pids.push_back(std::stoi(filename));
                }
            }
        }
        return pids;
    }
};

// ============================================================================
// 5. METRIC HARWARE MONITORING COMPONENTS
// ============================================================================
class Processor {
private:
    unsigned long long prev_active_{0}, prev_idle_{0};
    vector<int> history_;
public:
    double Utilization() {
        std::ifstream file("/proc/stat");
        string cpu;
        unsigned long long user, nice, sys, idle, iowait, irq, softirq, steal;
        if (file >> cpu >> user >> nice >> sys >> idle >> iowait >> irq >> softirq >> steal) {
            unsigned long long active = user + nice + sys + irq + softirq + steal;
            unsigned long long total_idle = idle + iowait;
            
            unsigned long long delta_active = active - prev_active_;
            unsigned long long delta_idle = total_idle - prev_idle_;
            unsigned long long delta_total = delta_active + delta_idle;

            prev_active_ = active;
            prev_idle_ = total_idle;

            double util = (delta_total > 0) ? static_cast<double>(delta_active) / delta_total : 0.0;
            
            history_.push_back(static_cast<int>(util * 100.0));
            if (history_.size() > 15) history_.erase(history_.begin());
            return util;
        }
        return 0.0;
    }
    const vector<int>& GetHistory() const { return history_; }
};

class Process {
private:
    int pid_;
    long hz_;
    double cpu_util_{0.0};
public:
    Process(int pid, long hz) : pid_(pid), hz_(hz) { CalculateCpu(); }

    int Pid() const { return pid_; }
    
    string User() const {
        std::ifstream stream("/proc/" + std::to_string(pid_) + "/status");
        string line, key;
        while (std::getline(stream, line)) {
            std::istringstream iss(line);
            iss >> key;
            if (key == "Uid:") {
                int uid;
                iss >> uid;
                if (uid == 0) return "root";
                return std::to_string(uid);
            }
        }
        return "?";
    }

    string Command() const {
        std::ifstream stream("/proc/" + std::to_string(pid_) + "/cmdline");
        string cmd;
        std::getline(stream, cmd);
        if (cmd.empty()) return "[kernel_task]";
        std::replace(cmd.begin(), cmd.end(), '\0', ' ');
        if (cmd.length() > 25) return cmd.substr(0, 22) + "...";
        return cmd;
    }

    void CalculateCpu() {
        std::ifstream stream("/proc/" + std::to_string(pid_) + "/stat");
        string token;
        vector<string> stats;
        while (stream >> token) stats.push_back(token);
        if (stats.size() < 22) return;

        unsigned long utime = std::stoul(stats[13]);
        unsigned long stime = std::stoul(stats[14]);
        unsigned long long starttime = std::stoull(stats[21]);

        long uptime = LinuxParser::UpTime();
        unsigned long long total_time = utime + stime;
        double elapsed_seconds = uptime - (static_cast<double>(starttime) / hz_);

        if (elapsed_seconds > 0) {
            cpu_util_ = (static_cast<double>(total_time) / hz_) / elapsed_seconds;
        }
    }

    double CpuUtilization() const { return cpu_util_; }

    long RamKB() const {
        std::ifstream stream("/proc/" + std::to_string(pid_) + "/status");
        string line, key;
        while (std::getline(stream, line)) {
            std::istringstream iss(line);
            iss >> key;
            if (key == "VmRSS:") {
                long kb;
                iss >> kb;
                return kb;
            }
        }
        return 0;
    }
};

class DiskMonitor {
public:
    float Utilization() {
        struct statvfs buf;
        if (statvfs("/", &buf) == 0) {
            unsigned long long total = buf.f_blocks * buf.f_frsize;
            unsigned long long free = buf.f_bfree * buf.f_frsize;
            if (total > 0) return static_cast<float>(total - free) / total;
        }
        return 0.0f;
    }
};

class NetworkMonitor {
private:
    unsigned long long prev_rx_{0}, prev_tx_{0};
    double rx_rate_{0}, tx_rate_{0};
    time_t prev_time_{0};
public:
    NetworkMonitor() { prev_time_ = std::time(nullptr); }
    
    void Refresh() {
        std::ifstream stream("/proc/net/dev");
        string line;
        time_t now = std::time(nullptr);
        double elapsed = std::difftime(now, prev_time_);
        if (elapsed <= 0) elapsed = 1.0;

        while (std::getline(stream, line)) {
            if (line.find("eth0:") != string::npos || line.find("wlan0:") != string::npos || line.find("enp") != string::npos) {
                std::istringstream iss(line);
                string iface;
                unsigned long long rx{0}, tx{0}, dummy;
                iss >> iface >> rx >> dummy >> dummy >> dummy >> dummy >> dummy >> dummy >> dummy >> tx;

                if (prev_rx_ > 0 && prev_tx_ > 0) {
                    rx_rate_ = static_cast<double>(rx - prev_rx_) / elapsed / 1024.0;
                    tx_rate_ = static_cast<double>(tx - prev_tx_) / elapsed / 1024.0;
                }
                prev_rx_ = rx;
                prev_tx_ = tx;
                prev_time_ = now;
                return;
            }
        }
    }
    double RxRate() const { return rx_rate_; }
    double TxRate() const { return tx_rate_; }
};

// ============================================================================
// 6. THRESHOLD ALERTING SUBSYSTEM (AlertManager)
// ============================================================================
class AlertManager {
private:
    Threshold cpu_thresh_{0.75f, 0.90f};
    Threshold mem_thresh_{0.80f, 0.95f};
    Threshold disk_thresh_{0.85f, 0.95f};
    mutable vector<Alert> active_alerts_;
public:
    void Evaluate(float cpu, float mem, float disk, const Logger& logger) const {
        active_alerts_.clear();
        Check("CPU", cpu, cpu_thresh_, logger);
        Check("Memory", mem, mem_thresh_, logger);
        Check("Disk", disk, disk_thresh_, logger);
    }

    void Check(const string& label, float val, const Threshold& t, const Logger& logger) const {
        Alert alert;
        if (val >= t.critical) {
            alert.message = label + " crossed critical threshold (" + std::to_string(static_cast<int>(val*100)) + "%)";
            alert.severity = Severity::CRITICAL;
            logger.LogAlert(alert);
            active_alerts_.push_back(alert);
        } else if (val >= t.warning) {
            alert.message = label + " warning buffer breached (" + std::to_string(static_cast<int>(val*100)) + "%)";
            alert.severity = Severity::WARNING;
            active_alerts_.push_back(alert);
        }
    }

    const vector<Alert>& ActiveAlerts() const { return active_alerts_; }
};

// ============================================================================
// 7. DATA PIPELINE SYNCHRONIZATION HUB (System Class)
// ============================================================================
class System {
private:
    Processor cpu_;
    DiskMonitor disk_;
    NetworkMonitor network_;
    AlertManager alerts_;
    Logger logger_;
    vector<Process> processes_;
    long hz_;
    string hostname_;
    string kernel_;
    string os_;
public:
    System() {
        hz_ = sysconf(_SC_CLK_TCK);
        if (hz_ <= 0) hz_ = 100;
        
        kernel_ = LinuxParser::Kernel();
        os_     = LinuxParser::OperatingSystem();
        
        std::ifstream hn("/proc/sys/kernel/hostname");
        if (hn.is_open()) std::getline(hn, hostname_);
        if (hostname_.empty()) hostname_ = "localhost";
    }

    void Refresh() {
        double cpu = cpu_.Utilization();
        float mem = LinuxParser::MemoryUtilization();
        float disk = disk_.Utilization();
        network_.Refresh();

        alerts_.Evaluate(cpu, mem, disk, logger_);

        MetricSnapshot snap{static_cast<float>(cpu), mem, disk, network_.RxRate(), network_.TxRate()};
        logger_.RecordSnapshot(snap);
        logger_.MaybeWriteHourlySummary();

        vector<int> pids = LinuxParser::Pids();
        processes_.clear();
        for (int pid : pids) {
            processes_.emplace_back(pid, hz_);
        }

        std::sort(processes_.begin(), processes_.end(), [](const Process& a, const Process& b) {
            return a.CpuUtilization() > b.CpuUtilization();
        });
    }

    Processor& Cpu() { return cpu_; }
    AlertManager& Alerts() { return alerts_; }
    vector<Process>& Processes() { return processes_; }
    double NetRx() const { return network_.RxRate(); }
    double NetTx() const { return network_.TxRate(); }
    string Hostname() const { return hostname_; }
    string Kernel() const { return kernel_; }
    string OS() const { return os_; }
};

// ============================================================================
// 8. NCURSES INTERFACE MULTI-PANEL VIEW MANAGER
// ============================================================================
class NCursesDisplay {
private:
    static void DrawProgressBar(WINDOW* win, float fraction, int y, int x, int width) {
        mvwprintw(win, y, x, "[");
        int filled = static_cast<int>(fraction * (width - 2));
        for (int i = 0; i < (width - 2); ++i) {
            if (i < filled) waddch(win, '#');
            else waddch(win, '.');
        }
        waddch(win, ']');
    }

public:
    static void Run(System& system, int refresh_ms) {
        initscr();
        noecho();
        cbreak();
        curs_set(0);
        start_color();
        
        init_pair(1, COLOR_GREEN, COLOR_BLACK);
        init_pair(2, COLOR_YELLOW, COLOR_BLACK);
        init_pair(3, COLOR_RED, COLOR_BLACK);
        init_pair(4, COLOR_CYAN, COLOR_BLACK);

        int rows, cols;
        getmaxyx(stdscr, rows, cols);
        nodelay(stdscr, TRUE); // Enable non-blocking keyboard input streams

        WINDOW* sys_win = newwin(9, cols, 0, 0);
        WINDOW* alert_win = newwin(4, cols, 9, 0);
        WINDOW* proc_win = newwin(rows - 14, cols, 13, 0);

        while (true) {
            int ch = getch();
            if (ch == 'q' || ch == 'Q') break;

            system.Refresh();

            wclear(sys_win);
            wclear(alert_win);
            wclear(proc_win);

            // 1. Draw Platform Core Window Context
            box(sys_win, 0, 0);
            wattron(sys_win, COLOR_PAIR(4) | A_BOLD);
            mvwprintw(sys_win, 0, 2, " ServerPulse Hardware Platform Vitals ");
            wattroff(sys_win, COLOR_PAIR(4) | A_BOLD);
            
            mvwprintw(sys_win, 2, 2, "Host: %s | OS: %s | Kernel: %s", 
                      system.Hostname().c_str(), system.OS().c_str(), system.Kernel().c_str());

            float cpu = system.Cpu().GetHistory().empty() ? 0.0f : system.Cpu().GetHistory().back() / 100.0f;
            float mem = LinuxParser::MemoryUtilization();
            float disk = DiskMonitor().Utilization();

            mvwprintw(sys_win, 4, 2, "CPU Util:  %5.1f%%", cpu * 100.0f);
            DrawProgressBar(sys_win, cpu, 4, 20, cols - 25);
            
            mvwprintw(sys_win, 5, 2, "RAM Util:  %5.1f%%", mem * 100.0f);
            DrawProgressBar(sys_win, mem, 5, 20, cols - 25);

            mvwprintw(sys_win, 6, 2, "Disk Sata: %5.1f%%", disk * 100.0f);
            DrawProgressBar(sys_win, disk, 6, 20, cols - 25);

            mvwprintw(sys_win, 7, 2, "Network NetIO: Rx: %.1f KB/s | Tx: %.1f KB/s", system.NetRx(), system.NetTx());

            // 2. Draw Active Operational Warning/Critical Alert Panels
            box(alert_win, 0, 0);
            wattron(alert_win, COLOR_PAIR(2) | A_BOLD);
            mvwprintw(alert_win, 0, 2, " Operating Exception Framework Alerts ");
            wattroff(alert_win, COLOR_PAIR(2) | A_BOLD);

            if (system.Alerts().ActiveAlerts().empty()) {
                wattron(alert_win, COLOR_PAIR(1));
                mvwprintw(alert_win, 1, 2, "[OK] All running thresholds are within safe nominal ranges.");
                wattroff(alert_win, COLOR_PAIR(1));
            } else {
                int line = 1;
                for (const auto& a : system.Alerts().ActiveAlerts()) {
                    int color = (a.severity == Severity::CRITICAL) ? 3 : 2;
                    wattron(alert_win, COLOR_PAIR(color));
                    mvwprintw(alert_win, line++, 2, "! %s", a.message.c_str());
                    wattroff(alert_win, COLOR_PAIR(color));
                    if (line >= 3) break;
                }
            }

            // 3. Draw Descending Resource Workload Process Matrix Table
            box(proc_win, 0, 0);
            wattron(proc_win, COLOR_PAIR(4) | A_BOLD);
            mvwprintw(proc_win, 0, 2, " Active Subsystem Processes (Sorted by Max CPU Load) ");
            wattroff(proc_win, COLOR_PAIR(4) | A_BOLD);

            mvwprintw(proc_win, 1, 2, "  PID      USER          CPU %%      RAM RSS      COMMAND");
            mvwprintw(proc_win, 2, 2, "  -------------------------------------------------------------");
            
            int display_count = std::min(rows - 18, static_cast<int>(system.Processes().size()));
            if (display_count > 12) display_count = 12; // Cap threshold values to safe view frames
            
            for (int i = 0; i < display_count; ++i) {
                const auto& p = system.Processes()[i];
                mvwprintw(proc_win, 3 + i, 2, "  %-8d %-12s %-10.1f %-12s %-30s", 
                          p.Pid(), p.User().c_str(), p.CpuUtilization() * 100.0, 
                          Format::KBtoHuman(p.RamKB()).c_str(), p.Command().c_str());
            }

            mvprintw(rows - 1, 2, "System Operations: [q / Q] Exit Shell Monitor Connection | Active Logs: ./logs/");
            
            wrefresh(sys_win);
            wrefresh(alert_win);
            wrefresh(proc_win);
            refresh();

            usleep(refresh_ms * 1000);
        }

        delwin(sys_win);
        delwin(alert_win);
        delwin(proc_win);
        endwin();
    }
};

// ============================================================================
// 9. CENTRAL EXECUTION ENTRY CONTROLLER
// ============================================================================
int main(int argc, char* argv[]) {
    int delay_ms = 1000;
    if (argc >= 2) {
        try {
            delay_ms = std::stoi(argv[1]);
            if (delay_ms < 100) delay_ms = 100;
        } catch (...) {
            std::cerr << "Execution Warning. Configuration format match parameter check: ./serverpulse [refresh_ms]\n";
            return 1;
        }
    }

    System system;
    NCursesDisplay::Run(system, delay_ms);
    return 0;
}