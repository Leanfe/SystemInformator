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
 * Функция проверяет есть-ли права администратора у процесса, или нет.
 * @return EXIT_FAILURE/EXIT_SUCCESS
 */
static bool checkAdmin();

/**
 * Функция, которая выполняет переданную команду от имени программы.
 * @param command команда для передачи.
 * @return EXIT_FAILURE -> Ошибка во время выполнения; EXIT_SUCCESS -> Всё прошло успешно.
 */
bool processCommand(char* command);

/**
 * Выводит информацию о системе на стандартный вывод.
 * @return EXIT_SUCCESS -> Если всё прошло успешно; EXIT_FAILURE -> Произошла ошибка.
 */
bool getInformation();

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
            return processCommand(optarg);
        }
    }

    return EXIT_SUCCESS;
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
    return EXIT_SUCCESS;
}

bool processCommand(char* command) {
    return EXIT_SUCCESS;
}