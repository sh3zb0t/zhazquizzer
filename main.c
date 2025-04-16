#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <termios.h>
#include <sys/wait.h>
#include <time.h>

#define MAX_LINE 256
#define MAX_OPCJI 20
#define MAX_PLIKOW 100

// Usuwa znak nowej linii z końca stringa (jakby był po fgets)
void przytnij_enter(char *str) {
    str[strcspn(str, "\n")] = '\0';
}

// Funkcja do wczytywania hasła – wyłącza echo terminala żeby nie było widać, co wpisujemy
void wczytaj_haslo(char *buf, size_t len) {
    struct termios oldt, newt;
    printf("\U0001F511 Podaj haslo do odszyfrowania quizu: ");
    fflush(stdout);

    // Wyłączenie wyświetlania wpisywanych znaków
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    fgets(buf, len, stdin);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");

    przytnij_enter(buf);
}

// Sprawdza, czy dany plik wygląda jak zaszyfrowany quiz
int czy_quiz_gpg(const char *nazwa) {
    return strncmp(nazwa, "Quiz", 4) == 0 && strstr(nazwa, ".gpg");
}

// Przeszukuje katalog w poszukiwaniu plików quizów i zapisuje ich nazwy do tablicy
int znajdz_quizy(char pliki[][MAX_LINE]) {
    DIR *dir = opendir(".");
    struct dirent *ent;
    int licznik = 0;

    if (!dir) return 0;

    while ((ent = readdir(dir)) && licznik < MAX_PLIKOW) {
        if (czy_quiz_gpg(ent->d_name)) {
            strncpy(pliki[licznik++], ent->d_name, MAX_LINE);
        }
    }
    closedir(dir);
    return licznik;
}

// Uruchamia proces GPG do odszyfrowania quizu, zwraca deskryptor pliku do odczytu
int uruchom_dekryptor(const char *plik, const char *haslo) {
    int p_in[2], p_out[2];
    if (pipe(p_in) || pipe(p_out)) {
        perror("pipe");
        return -1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // Dziecko przejmuje stdin i stdout
        dup2(p_in[0], 0);
        dup2(p_out[1], 1);
        close(p_in[1]); close(p_out[0]);
        execlp("gpg", "gpg", "--batch", "--yes", "--passphrase-fd", "0", "--decrypt", plik, NULL);
        perror("execlp");
        exit(1);
    }

    // Rodzic – podaje hasło przez pipe i zamyka deskryptory
    close(p_in[0]); close(p_out[1]);
    write(p_in[1], haslo, strlen(haslo));
    write(p_in[1], "\n", 1);
    close(p_in[1]);

    return p_out[0];
}

// Odczytuje jedną linię tekstu z deskryptora (czyli np. pytanie albo opcję)
int odczytaj_linie(int fd, char *buf, size_t len) {
    size_t i = 0;
    while (i < len - 1) {
        char c;
        if (read(fd, &c, 1) != 1) break;
        buf[i++] = c;
        if (c == '\n') break;
    }
    buf[i] = '\0';
    return i > 0;
}

// Wczytuje pełne pytanie z pliku: treść, odpowiedzi i numery poprawnych
int odczytaj_pytanie(int fd, char *pytanie, char **opcje, int *ile_opcji, int *poprawne, int *ile_poprawnych) {
    char linia[MAX_LINE];

    // Szukamy linijki zaczynającej się od "Q:"
    while (odczytaj_linie(fd, linia, sizeof(linia))) {
        if (strncmp(linia, "Q:", 2) == 0) break;
    }
    if (strncmp(linia, "Q:", 2) != 0) return 0;
    sscanf(linia, "Q: %[^\n]", pytanie);

    *ile_opcji = 0;
    // Wczytywanie odpowiedzi dopóki nie natkniemy się na "A:"
    while (odczytaj_linie(fd, linia, sizeof(linia)) && strncmp(linia, "A:", 2) != 0) {
        opcje[*ile_opcji] = malloc(MAX_LINE);
        strcpy(opcje[(*ile_opcji)++], linia);
    }

    // Parsowanie poprawnych odpowiedzi po "A:"
    *ile_poprawnych = 0;
    char *t = strtok(linia + 3, " ");
    while (t) {
        poprawne[(*ile_poprawnych)++] = atoi(t);
        t = strtok(NULL, " ");
    }

    return 1;
}

// Miesza odpowiedzi i aktualizuje indeksy poprawnych
void pomieszaj(char **opcje, int *poprawne, int n) {
    int *oryg = malloc(n * sizeof(int));
    for (int i = 0; i < n; ++i) oryg[i] = i;

    for (int i = n - 1; i > 0; --i) {
        int j = rand() % (i + 1);
        char *tmp = opcje[i]; opcje[i] = opcje[j]; opcje[j] = tmp;
        int ti = oryg[i]; oryg[i] = oryg[j]; oryg[j] = ti;
    }

    // Przeliczamy nowe indeksy poprawnych odpowiedzi po przetasowaniu
    int nowe[MAX_OPCJI], p = 0;
    for (int i = 0; i < n; ++i)
        for (int j = 0; j < MAX_OPCJI; ++j)
            if (poprawne[j] && oryg[i] + 1 == poprawne[j]) nowe[p++] = i + 1;

    memset(poprawne, 0, MAX_OPCJI * sizeof(int));
    for (int i = 0; i < p; ++i) poprawne[i] = nowe[i];

    free(oryg);
}

// Wczytuje odpowiedzi użytkownika i zapisuje je do tablicy
int wczytaj_odpowiedzi(int *odp) {
    char linia[MAX_LINE];
    fgets(linia, sizeof(linia), stdin);
    int ile_odp = 0;
    char *t = strtok(linia, " ");
    while (t) {
        odp[ile_odp++] = atoi(t);
        t = strtok(NULL, " ");
    }
    return ile_odp;
}

// Sprawdza, czy odpowiedzi użytkownika pasują do poprawnych
int porownaj(int *a, int la, int *b, int lb) {
    if (la != lb) return 0;
    for (int i = 0; i < la; ++i) {
        int trafione = 0;
        for (int j = 0; j < lb; ++j)
            if (a[i] == b[j]) trafione = 1;
    if (!trafione) return 0;
    }
    return 1;
}

// Porównuje odpowiedzi i wypisuje wynik cząstkowy
void ocen_odpowiedz(int *poprawne, int ile_pop, int *odp, int ile_odp, int *wynik, int razem, int nr_pytania) {
    if (porownaj(poprawne, ile_pop, odp, ile_odp)) {
        (*wynik)++;
        printf("\U00002705 Dobrze!\n");
    } else {
        printf("\u274C Pudlo.\n");
    }

    printf("\n|========= Postep ==========|\n");
    printf("\U0001F4C8 Pytanie: %d\n", nr_pytania);
    printf("\u2705 Poprawne: %d\n", *wynik);
    printf("\u274C Bledne: %d\n", razem - *wynik);
    printf("|===========================|\n");
}

// Funkcja pokazująca jedno pytanie z opcjami
void wyswietl_pytanie(const char *pytanie, char **opcje, int ile_opcji, int nr_pytania) {
    printf("|=======ShazQuizzerV4.2=======|\n\n");
    printf("\U0001F4CC %s\n\n", pytanie);
    for (int i = 0; i < ile_opcji; ++i)
        printf(" %d) %s", i + 1, opcje[i]);
    printf("\n\U0001F4DD Wpisz numery poprawnych odpowiedzi oddzielone spacją: ");
}

// Podsumowanie quizu
void wyswietl_podsumowanie(int wynik, int razem) {
    printf("\033[2J\033[H");
    printf("|=======ShazQuizzerV4.2=======|\n\n");
    printf("\U0001F389 Quiz zakonczony!\n\n");
    printf("\U0001F4CA Twoj wynik koncowy: %d/%d\n", wynik, razem);
    printf("\u2705 Poprawne: %d\n", wynik);
    printf("\u274C Bledne: %d\n", razem - wynik);
    printf("\n|========= KONIEC ==========|\n");
}

// Główna logika quizu: wczytywanie pytań, pokazywanie, zbieranie odpowiedzi, ocenianie
void uruchom_quiz(const char *plik) {
    char haslo[128];
    wczytaj_haslo(haslo, sizeof(haslo));

    int fd = uruchom_dekryptor(plik, haslo);
    if (fd < 0) return;

    char pytanie[MAX_LINE], linia[MAX_LINE];
    char *opcje[MAX_OPCJI];
    int poprawne[MAX_OPCJI], odp[MAX_OPCJI];
    int wynik = 0, razem = 0, nr_pytania = 0, ile_opcji = 0, ile_poprawnych = 0;

    while (odczytaj_pytanie(fd, pytanie, opcje, &ile_opcji, poprawne, &ile_poprawnych)) {
        pomieszaj(opcje, poprawne, ile_opcji);

        nr_pytania++;
        razem++;

        printf("\033[2J\033[H");
        wyswietl_pytanie(pytanie, opcje, ile_opcji, nr_pytania);

        int ile_odp = wczytaj_odpowiedzi(odp);

        printf("\033[2J\033[H");
        ocen_odpowiedz(poprawne, ile_poprawnych, odp, ile_odp, &wynik, razem, nr_pytania);

        printf("\n\U0001F51B  Nacisnij Enter, by przejsc dalej...");
        getchar();

        for (int i = 0; i < ile_opcji; ++i) free(opcje[i]);
        odczytaj_linie(fd, linia, sizeof(linia)); // separator między pytaniami
    }

    close(fd);
    wait(NULL);
    wyswietl_podsumowanie(wynik, razem);
}

// Główna funkcja programu: pokazuje dostępne quizy i uruchamia wybrany
int main() {
    srand(time(NULL));
    char pliki[MAX_PLIKOW][MAX_LINE];
    int ile = znajdz_quizy(pliki);

    if (ile == 0) {
        printf("Brak quizow.\n");
        return 1;
    }

    printf("\U0001F4DD Dostepne quizy:\n");
    for (int i = 0; i < ile; ++i) printf(" %d) %s\n", i + 1, pliki[i]);

    int wybor;
    printf("Wybierz numer quizu: ");
    scanf("%d", &wybor); getchar();

    if (wybor < 1 || wybor > ile) {
        printf("Nieprawidlowy wybor.\n");
        return 1;
    }

    uruchom_quiz(pliki[wybor - 1]);
    return 0;
}
