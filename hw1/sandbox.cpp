#include <iostream>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/mman.h>
#include <stdint.h>
#include <errno.h>
#include <string>
#include <fstream>
#include <cstdlib>
#include <vector>
#include <map>
#include <sstream>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <set>
#include <stdlib.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <elf.h>

using namespace std;
using libc_start_main_type = int (*)(int *(*)(int, char **, char **), int, char**, void (*)(), void (*)(), void (*)(), void*);

string base_address;
map<string, set<string>> blacklist;
vector<string> api_functions = {"open", "read", "write", "connect", "getaddrinfo", "system", "close"};
map<string, string> read_filter;  // (log name, history)

int LOGGER_FD;
string SANDBOX_CONFIG;


// Handle as C symbols, don't do name mangling.
extern "C" {
    int __libc_start_main(int *(main) (int, char **, char **),
                    int argc,
                    char * * ubp_av,
                    void (*init) (void),
                    void (*fini) (void),
                    void (*rtld_fini) (void),
                    void (*stack_end));
    
    void get_process_info();
    int fake_open(const char *, int, mode_t, ...);  // 2 overloading
    ssize_t fake_read(int, void *, size_t);
    ssize_t fake_write(int, const void *, size_t);
    int fake_connect(int, const struct sockaddr *, socklen_t);
    int fake_getaddrinfo(const char *,
                         const char *,
                         const struct addrinfo *,
                         struct addrinfo **);
    int fake_system(const char *);
    int close(int);
}

void get_process_info(string &process_name, string &base_address) {
    ifstream proc_self_maps("/proc/self/maps");

    if(proc_self_maps.is_open()) {
        string first_line;
        getline(proc_self_maps, first_line);
        base_address = first_line.substr(0, first_line.find("-"));
        process_name = first_line.substr(first_line.find("/"), (first_line.find("\n") - first_line.find("/")));

        proc_self_maps.close();
    } else {
        cerr << "Unable to open file: " << "/proc/self/maps" << '\n';
    }
    return;
}

string get_env(string const& env_name) {
    char const* val = getenv(env_name.c_str()); 
    return val == NULL ? string() : string(val);
}

void get_blacklist() {
    blacklist.clear();
    ifstream config(SANDBOX_CONFIG);
    string line;
    string cur_symbol = "";
    if(config.is_open()) {
        while(getline(config, line)) {
            if(line == "") {
                continue;
            } else if((line.find("BEGIN") != std::string::npos) && (line.find("-blacklist") != std::string::npos)) {
                cur_symbol = line.substr(line.find(" ")+1, (line.find("-")-line.find(" ")-1));
            } else if ((line.find("END") != std::string::npos) && (line.find("-blacklist") != std::string::npos)) {
                continue;
            } else {
                if(blacklist.find(cur_symbol) == blacklist.end()) {
                    set<string> init_vec;
                    init_vec.clear();
                    init_vec.insert(line.substr(0, line.length()));  // getline will not include '\n'
                    blacklist[cur_symbol] = init_vec;
                } else {
                    blacklist[cur_symbol].insert(line.substr(0, line.length()));
                }
            }
        }
        config.close();
    } else {
        cerr << "Unable to open file: " << SANDBOX_CONFIG << '\n';
    }
}

string get_stdout_from_cmd(string cmd) {
    string data;
    FILE * stream;
    const int max_buffer = 256;
    char buffer[max_buffer];
    cmd.append(" 2>&1"); // redirect(>&) stderr(2) to stdout(1)

    stream = popen(cmd.c_str(), "r");  // read output from pipe
    if (stream) {
        while (!feof(stream))
            if (fgets(buffer, max_buffer, stream) != NULL) data.append(buffer);
        pclose(stream);
    }
    return data;
}

vector<string> splitString(const string& str) {
    vector<string> tokens; 
    stringstream ss(str);
    string token;
    while (getline(ss, token, '\n')) {
        tokens.push_back(token);
    }
    return tokens;
}

int write_log(string log_str) {
    int ret = write(LOGGER_FD, log_str.c_str(), log_str.length());
    if (ret < 0) {
        perror("Error writing to LOGGER_FD");
    }
    return ret;
}

int fake_open(const char *pathname_char, int flags, ...) {
    // 1. files listed in the blacklist cannot be opened.
    //      -> If a file is in the blacklist, return -1 and set errno to EACCES.
    // 2. Note that for handling symbolic linked files,
    //    your implementation has to follow the links before performing the checks.
    // 3. write log - each function needs to write log for themselves
    
    // (1) find the file at the end of any chain of symlinks
    char resolved_path[PATH_MAX];
    memset(resolved_path, 0, sizeof(resolved_path));
    if (realpath(pathname_char, resolved_path) == NULL) {
        perror("realpath");
        exit(EXIT_FAILURE);
    }
    
    // (2) variadic variables & call open
    //      Use flag to define if the flag need to use third arg 'mode',
    //      if no use of the third arg 'mode', will not cause the undefined behavior of va_arg function
    //      refer to 'open' doc: we will find that only 'O_CREAT' and 'O_TMPFILE' mode will pass the third arg 'mode'
    //                           for other flags, set mode to 0 or omitted it is allowed
    va_list args;
    va_start(args, flags);
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE)) {
        mode = va_arg(args, mode_t);
    }
    va_end(args);

    // (3) block the files in the open-blacklist
    //     after mode since we need 'mode' in log info
    if(blacklist["open"].find(resolved_path) != blacklist["open"].end()) {
        write_log("[logger] open(\"" + string(pathname_char) + "\", " + to_string(flags) + ", " + to_string(mode) + ") = -1\n");  // return is set to -1
        errno = EACCES;
        return -1;
    }

    int ret = open(pathname_char, flags, mode);
    write_log("[logger] open(\"" + string(pathname_char) + "\", " + to_string(flags) + ", " + to_string(mode) + ") = " + to_string(ret) + "\n");

    return ret;
}

string get_buf_addr(const void *buf) {
    stringstream ss;
    ss << buf;
    return ss.str();
}

ssize_t fake_read(int fd, void *buf, size_t count) {
    pid_t pid = getpid();
    string log_file_name = to_string(pid) + "-" + to_string(fd) + "-read.log";

    int log_file_fd = open(log_file_name.c_str(), O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    if (log_file_fd == -1) {
        cerr << "Failed to open file" << endl;
        return 1;
    }

    if(read_filter.find(log_file_name) == read_filter.end()) {
        read_filter[log_file_name] = "";
    }

    int ret = read(fd, buf, count);
    char* read_content_buf = static_cast<char*>(buf);
    string read_content_str(read_content_buf);

    read_filter[log_file_name] += read_content_str;
    string keyword = *(blacklist["read"].begin());
    if(read_filter[log_file_name].find(keyword) != std::string::npos) {
        write_log("[logger] read(" + to_string(fd) + ", " + get_buf_addr((const void *)buf) + ", " + to_string(count) + ") = " + to_string(-1) + "\n");  // return is set to -1
        read_filter.erase(log_file_name); // erase filter history by key since the fd will be closed
        close(fd);
        close(log_file_fd);
        errno = EIO;
        return -1;
    }

    write(log_file_fd, buf, count);
    close(log_file_fd);

    // logger
    string buf_str = "";
    buf_str.append(static_cast<const char*>(buf), count);
    write_log("[logger] read(" + to_string(fd) + ", " + get_buf_addr((const void *)buf) + ", " + to_string(count) + ") = " + to_string(ret) + "\n");  // return is set to -1

    return ret;
}

// [spec]
//   1. Your implementation must log all content into a file.
//      The log file should be named in the format {pid}-{fd}-write.log and be created after an fd is opened.
//      (If an fd is used more than one time in a process, keep logging the content into the same log file.)
//   2. no blacklist action
// [process]
//   1. create '{pid}-{fd}-write.log' file if doesn't exist
//      -> if exist than append the content into the file
//   2. write log
ssize_t fake_write(int fd, const void *buf, size_t count) {
    pid_t pid = getpid();
    string log_file_name = to_string(pid) + "-" + to_string(fd) + "-write.log";

    int log_file_fd = open(log_file_name.c_str(), O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    if (log_file_fd == -1) {
        cerr << "Failed to open file" << endl;
        return 1;
    }

    write(log_file_fd, buf, count);
    int ret = write(fd, buf, count);

    // logger
    string buf_str = "";
    buf_str.append(static_cast<const char*>(buf), count);
    write_log("[logger] write(" + to_string(fd) + ", " + get_buf_addr(buf) + ", " + to_string(count) + ") = " + to_string(ret) + "\n");  // return is set to -1

    return ret;
}

string get_sockaddr_ip_str(const struct sockaddr *addr) {
    string ip_result;
    if (addr->sa_family == AF_INET) {  // IPv4
        char ip_4_char[INET_ADDRSTRLEN];
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip_4_char, INET_ADDRSTRLEN);
        string ip_4_str(ip_4_char);
        ip_result = ip_4_str;

    } else if (addr->sa_family == AF_INET6) {  // IPv6
        char ip_6_char[INET6_ADDRSTRLEN];
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_6_char, INET6_ADDRSTRLEN);
        string ip_6_str(ip_6_char);
        ip_result = ip_6_str;

    } else {
        printf("Unknown address family\n");
    }

    return ip_result;
}

// Get port from sockaddr structure
string get_port_str(const struct sockaddr *addr) {
    if (addr->sa_family == AF_INET) { // IPv4
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        return to_string(ntohs(sin->sin_port));
    } else if (addr->sa_family == AF_INET6) { // IPv6
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        return to_string(ntohs(sin6->sin6_port));
    } else {
        // Unknown address family -> will not have this case
        return "";
    }
}

int hostname_to_ip_list(vector<string> &ip_list, string hostname) {
    struct hostent *he;
    struct in_addr **addr_list;

    if ((he = gethostbyname(hostname.c_str())) == NULL) {
        herror("gethostbyname");
        return 1;
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    for (int i = 0; addr_list[i] != NULL; i++) {
        ip_list.push_back(string(inet_ntoa(*addr_list[i])));
    }

    return 0;
}

// Allow a user to block connection setup to specific IP addresses and PORT numbers.
// If the IP and PORT is blocked, return -1 and set errno to ECONNREFUSED.
// 1. use blacklist domain name -> ip list (不能反解), port
int fake_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

    bool block = false;
    for(auto hostname_port : blacklist["connect"]) {
        string hostname = hostname_port.substr(0, hostname_port.find(":"));
        string port = hostname_port.substr(hostname_port.find(":")+1, hostname_port.length() - hostname_port.find(":"));

        vector<string> ip_list;
        ip_list.clear();
        if(hostname_to_ip_list(ip_list, hostname) == -1) cout << "hostname_to_ip_list fail" << endl;

        for(auto ip : ip_list) {
            if(ip == get_sockaddr_ip_str(addr) && port == get_port_str(addr)) {
                block = true;
                break;
            }
        }
        if(block) break;
    }

    if(block) {
        write_log("[logger] connect(" + to_string(sockfd) + ", \"" + get_sockaddr_ip_str(addr) + "\", " + to_string(addrlen) + ") = " + to_string(-1) + "\n");  // return is set to -1
        errno = ECONNREFUSED;
        return -1;
    }

    int ret = connect(sockfd, addr, addrlen);
    write_log("[logger] connect(" + to_string(sockfd) + ", \"" + get_sockaddr_ip_str(addr) + "\", " + to_string(addrlen) + ") = " + to_string(ret) + "\n");  // return is set to -1

    return ret;
}


// still do the flag check
int fake_getaddrinfo(const char * node,
                     const char * service,
                     const struct addrinfo * hints,
                     struct addrinfo ** res) {
    char service_char[20];
    sprintf(service_char, "%s", service);
    string service_str(service_char);

    string hostname = "";
    if (!(hints -> ai_flags & AI_NUMERICHOST)) {
        string in_hostname(node);
        hostname = in_hostname;

        // check if hostname in the blacklist
        for(auto b_hostname : blacklist["getaddrinfo"]) {
            if(b_hostname == hostname) {
                write_log("[logger] getaddrinfo(\"" + hostname + "\", \"" + service_str + "\", " + get_buf_addr(hints) + ", " + get_buf_addr(res) + ") = " + to_string(EAI_NONAME) + "\n");
                return EAI_NONAME;
            }
        }
    }

    int ret = getaddrinfo(node, service, hints, res);
    write_log("[logger] getaddrinfo(\"" + hostname + "\", \"" + service_str + "\", " + get_buf_addr(hints) + ", " + get_buf_addr(res) + ") = " + to_string(ret) + "\n");

    return ret;
}


int fake_system(const char *command) {
    string command_str(command);
    write_log("[logger] system(\"" + command_str + ")\n");

    return system(command);
}


int fake_close(int fd) {
    pid_t pid = getpid();
    string log_file_name = to_string(pid) + "-" + to_string(fd) + "-read.log";

    if(read_filter.find(log_file_name) != read_filter.end()) {
        read_filter.erase(log_file_name);
    }

    return close(fd);
}

class hijack_got {
public:
    map<string, string> got_offset;

    hijack_got() {
        got_offset.clear();
        read_filter.clear();  // clear the filter at the beginning of the hijack
    }

    string get_got_offset_of_a_symbol(string symbol, const vector<string>& data) {
        symbol = " " + symbol + "@GLIBC";  // open != fopen
        for(auto line : data) {
            if(line.find(symbol) != std::string::npos) {
                return line.substr(0, line.find(" "));
            }
        }
        return "";
    }

    void get_got_offset(const vector<string>& data) {
        for(auto symbol : api_functions) got_offset[symbol] = get_got_offset_of_a_symbol(symbol, data);
    }

    // overwrite got address by api_symbol and the offset passed in
    //      1. use 'api_symbol' to know which function need to be hijack
    //          -> ex: api_symbol == 'open', we need to load the 'fake_open''s address in this file
    //      2. make a 'fake_open' first
    //         load the 'fake_open' address
    //         write 'fake_open' address into the got table by 'base_address + offset'
    //      3. only overwrite the got table of the process to call our api function,
    //         if we directly overwrite the original functions, we can not call the original functions after our operations.
    void overwrite_got_address(string api_symbol, string offset) {

        // 1. open the mprotect
        //      (1) get absolute got address -> for mprotect & overwrite
        //      (2) align absolute address to get mprotect start address
        uintptr_t got_abs_address = strtol(base_address.c_str(), NULL, 16) + strtol(offset.c_str(), NULL, 16);
        uintptr_t start_address = got_abs_address & ~(0xfff);  // align to 4096 in order to operate mprotect
        if (mprotect((void **)start_address, getpagesize() * 1, PROT_WRITE) == -1) {  // page_size * got_pages, 開一個 page 就夠寫這個 entry 了
            perror("mprotect");
            exit(1);
        }

        // 2. overwrite each function based on symbol
        if(api_symbol == "open") {
            int (*fake_open_ptr)(const char *, int, ...) = &fake_open;
            memcpy((void**)got_abs_address, &fake_open_ptr, 8);
        
        } else if (api_symbol == "read") {
            ssize_t (*fake_read_ptr)(int, void *, size_t) = &fake_read;
            memcpy((void**)got_abs_address, &fake_read_ptr, 8);

        } else if (api_symbol == "write") {
            ssize_t (*fake_write_ptr)(int, const void *, size_t) = &fake_write;
            memcpy((void**)got_abs_address, &fake_write_ptr, 8);

        } else if (api_symbol == "connect") {
            int (*fake_connect_ptr)(int, const struct sockaddr *, socklen_t) = &fake_connect;
            memcpy((void**)got_abs_address, &fake_connect_ptr, 8);

        } else if (api_symbol == "getaddrinfo") {
            int (*fake_getaddrinfo_ptr)(const char *,
                                        const char *,
                                        const struct addrinfo *,
                                        struct addrinfo **) = &fake_getaddrinfo;
            memcpy((void**)got_abs_address, &fake_getaddrinfo_ptr, 8);

        } else if (api_symbol == "system") {
            int (*fake_system_ptr)(const char *) = &fake_system;
            memcpy((void**)got_abs_address, &fake_system_ptr, 8);

        } else if (api_symbol == "close") {
            int (*fake_close_ptr)(int) = &fake_close;
            memcpy((void**)got_abs_address, &fake_close_ptr, 8);
        }
    }
};


/* without external program, perform GOT hacking */
void hijack_got_by_elf_h(string base_address, string elf_file_name) {

    // 1. read elf to memory -> or will error
    int fd = open(elf_file_name.c_str(), O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file");
        exit(1);
    }
    off_t size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        perror("Failed to get file size");
        exit(1);
    }
    void *map_start = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_start == MAP_FAILED) {
        perror("Failed to mmap file");
        exit(1);
    }

    // 2. read elf header
    //      elf_header.e_shnum: the number of entries in the section header table
    //      elf_header.e_shoff: byte offset from the beginning of the file to the section header table
    lseek(fd, 0, SEEK_SET);
    Elf64_Ehdr elf_header;
    read(fd, &elf_header, sizeof(elf_header));
    
    int section_num = elf_header.e_shnum;
    Elf64_Shdr section_headers[section_num];
    lseek(fd, elf_header.e_shoff, SEEK_SET);
    
    // 3. read section headers
    read(fd, section_headers, sizeof(Elf64_Shdr) * section_num);

    // 4. get the string table header
    //    from elf header:
    //      e_shstrndx: section header table index of the entry associated with the 'section name string table'
    //    from string table header:
    //      string_table_header.sh_offset: locate at the start of the string table
    uint16_t string_table_index = elf_header.e_shstrndx;
    if(string_table_index == SHN_XINDEX) string_table_index = section_headers[0].sh_link;
    Elf64_Shdr string_table_header = section_headers[string_table_index];
    char *string_table = (char *)malloc(string_table_header.sh_size);
    lseek(fd, string_table_header.sh_offset, SEEK_SET);
    read(fd, string_table, string_table_header.sh_size);

    // 5. iterate each section header and get the address & size & entry of each section
    Elf64_Addr got_address = 0, rela_address = 0, dynsym_address = 0, dynstr_address = 0;
    uint64_t got_size = 0, rela_size = 0, dynsym_size = 0, dynstr_size = 0;
    uint64_t rela_entry_size = 0;
    for(int i = 0; i < section_num; i++) {
        char *sectionName = string_table + section_headers[i].sh_name;
        if(section_headers[i].sh_type == SHT_PROGBITS && strcmp(".got", sectionName) == 0) {
            got_address = section_headers[i].sh_addr;
            // got_address = section_headers[i].sh_offset;
            got_size = section_headers[i].sh_size;

        } else if(section_headers[i].sh_type == SHT_RELA && strcmp(".rela.plt", sectionName) == 0) {
            rela_address = section_headers[i].sh_addr;
            // rela_address = section_headers[i].sh_offset;
            rela_size = section_headers[i].sh_size;
            rela_entry_size = section_headers[i].sh_entsize;

        } else if(section_headers[i].sh_type == SHT_DYNSYM && strcmp(".dynsym", sectionName) == 0) {
            dynsym_address = section_headers[i].sh_addr;
            // dynsym_address = section_headers[i].sh_offset;
            dynsym_size = section_headers[i].sh_size;

        } else if(section_headers[i].sh_type == SHT_STRTAB && strcmp(".dynstr", sectionName) == 0) {
            dynstr_address = section_headers[i].sh_addr;
            // dynsym_address = section_headers[i].sh_offset;
            dynstr_size = section_headers[i].sh_size;
        }
    }

    if(got_address == 0 || got_size == 0)
        perror("GOT table address and size");
    char* gotTable = (char*)((uintptr_t)map_start + got_address);

    if(rela_address == 0 || rela_size == 0)
        perror("rela table address and size");
    Elf64_Rela* rela_table = (Elf64_Rela *)((uintptr_t)map_start + rela_address);

    if(dynsym_address == 0 || dynsym_size == 0)
        perror("dynsym table address and size");
    Elf64_Sym* dynsym_table = (Elf64_Sym*)((uintptr_t)map_start + dynsym_address);

    if(dynstr_address == 0 || dynstr_size == 0)
        perror("dynstr address and size");
    char* dynstr_table = (char*)((uintptr_t)map_start + dynstr_address);
    

    Elf64_Addr offset = -1;
    for(int i = 0; i < rela_size / rela_entry_size; i++) {
        // r_info -> ELF64_R_SYM -> symbol_index(of dynsym table) -> st_name -> dynstr table
        int symbol_index = ELF64_R_SYM(rela_table[i].r_info);
        Elf64_Sym* sym = &dynsym_table[symbol_index];
        
        // 6. get st_name from .dynsym, and st_name is the offset of the symbol in .dynstr
        char* symbol_name = dynstr_table + sym->st_name;

        string symbol_name_str = symbol_name;
        void (*fakeAddr)();

        // get the offset of this symbol from rela.plt
        offset = rela_table[i].r_offset;
        void **got_abs_address = (void **)((uintptr_t)((uintptr_t)strtol(base_address.c_str(), NULL, 16)) + (uintptr_t)offset);
        
        uintptr_t got_abs_address_uintptr = reinterpret_cast<uintptr_t>(got_abs_address);

        uintptr_t align_address = got_abs_address_uintptr & ~(0xFFF);
        if(mprotect((void **)align_address, getpagesize() * 1, PROT_WRITE) == -1) {
            perror("mprotect");
        }

        if(symbol_name_str == "open") {
            int (*fake_open_ptr)(const char *, int, ...) = &fake_open;
            memcpy(got_abs_address, &fake_open_ptr, 8);

        } else if (symbol_name_str == "read") {
            ssize_t (*fake_read_ptr)(int, void *, size_t) = &fake_read;
            memcpy(got_abs_address, &fake_read_ptr, 8);

        } else if (symbol_name_str == "write") {
            ssize_t (*fake_write_ptr)(int, const void *, size_t) = &fake_write;
            memcpy(got_abs_address, &fake_write_ptr, 8);

        } else if (symbol_name_str == "connect") {
            int (*fake_connect_ptr)(int, const struct sockaddr *, socklen_t) = &fake_connect;
            memcpy(got_abs_address, &fake_connect_ptr, 8);

        } else if (symbol_name_str == "getaddrinfo") {
            int (*fake_getaddrinfo_ptr)(const char *,
                                        const char *,
                                        const struct addrinfo *,
                                        struct addrinfo **) = &fake_getaddrinfo;
            memcpy(got_abs_address, &fake_getaddrinfo_ptr, 8);

        } else if (symbol_name_str == "system") {
            int (*fake_system_ptr)(const char *) = &fake_system;
            memcpy(got_abs_address, &fake_system_ptr, 8);

        } else if (symbol_name_str == "close") {
            int (*fake_close_ptr)(int) = &fake_close;
            memcpy((void**)got_abs_address, &fake_close_ptr, 8);
        }
    }

    close(fd);
}

int __libc_start_main(int *(main) (int, char **, char **),
                      int argc,
                      char * * ubp_av,
                      void (*init) (void),
                      void (*fini) (void),
                      void (*rtld_fini) (void),
                      void (*stack_end)) {
    // load original __libc_start_main
    //      - dlopen - loads the dynamic shared object (shared library) file
    void *handle = dlopen("libc.so.6", RTLD_LAZY);

    if (handle == NULL) {
        fprintf(stderr, "Failed to open namespace\n");
        return 1;
    }

    //      - dlsym - get the address where that symbol is loaded into memory
    //                can use code_func as original function
    auto __libc_start_main_original = reinterpret_cast<libc_start_main_type>(dlsym(handle, "__libc_start_main"));
    if (__libc_start_main_original == NULL) {
        fprintf(stderr, "Failed to get symbol\n");
        dlclose((void *)__libc_start_main_original);
        return 1;
    }

    // get environment variable
    //      1. SANDBOX_CONFIG: The path of the configuration file for sandbox.so.
    //      2. LOGGER_FD: the file descriptor (fd) for logging messages.
    //
    //      get_env: return "" if env_name not found
    LOGGER_FD = stoi(get_env("LOGGER_FD"));
    SANDBOX_CONFIG = get_env("SANDBOX_CONFIG");

    // get blacklist
    get_blacklist();

    // get the executing cmd's ( = this process itself = the program run up by launcher and LDPRELOAD sandbox.so)
    //      1. program name
    //      2. base address
    string process_elf_file;
    get_process_info(process_elf_file, base_address);

    // parse ELF file of current process
    //      1. ELF file name (KNOWN): process_name
    //      2. use cmd on terminal: readelf -r $process_name
    //      3. need to unsetenv "LD_PRELOAD" first to make sure child process
    //         will not enter this __libc_start_main to form an infinite loop
    // string LD_PRELOAD = get_env("LD_PRELOAD");
    // cout << LD_PRELOAD << endl;  // ./sandbox.so
    unsetenv("LD_PRELOAD");

    // setenv back since we need the fake function to call system(child process) with LD_PRELOAD(inherited env)
    // so that the content can be log
    // 0: if the LD_PRELOAD env already exist, than don't change its value
    setenv("LD_PRELOAD", "./sandbox.so", 0);

    // new parse elf
    hijack_got_by_elf_h(base_address, process_elf_file);


    // find all API functions' GOT offset from "readelf -r $process_name" output
    //      1. API functions: open, read, write, connect, getaddrinfo, system
    // hijack_got hijack_got_mission = hijack_got();
    // hijack_got_mission.get_got_offset(got_info_from_elf);

    __libc_start_main_original(main, argc, ubp_av, init, fini, rtld_fini, stack_end);

    dlclose((void *)__libc_start_main_original);
    return 0;
}
