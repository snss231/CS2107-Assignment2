#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>

#define NAME_MAX_LENGTH 16
#define COMMAND_MAX_LENGTH 64

void setup();

struct Info {
    char  logger[COMMAND_MAX_LENGTH];
    int   total_count;
    float total_bmi;
};

struct Person {
    char name[NAME_MAX_LENGTH];
    int  age;
    int  gender;
    int  height;
    int  weight;
};

struct App {
    struct Person *list;
    struct Person selected;
    struct Info   stats;
} app;

char *read_str() {
    char *buffer = malloc(20);
    fflush(stdout);
    read(0, buffer, 20);
    return buffer;
}

int read_int() {
    char *choice = read_str();
    return atoi(choice);
}

void show_menu() {
    printf("\nI've made this application to store people's basic info, including height and weight.\n");
    printf("You can also calculate their BMI!!!\n");
    printf("Don't mind if I log down some statistics for research purposes?\n");
    printf("Just seeing the number of BMI scores and the average BMI calculated\n\n");

    printf("NOTE: please report any bugs to me!\n\n");

    printf("=======================\n");
    printf(" 1. Add person\n");
    printf(" 2. Delete person\n");
    printf(" 3. Calculate BMI\n");
    printf(" 4. Exit\n");
    printf("=======================\n");
}

void select_person() {
    printf("Index (0-19): ");
    int index = read_int();
    if (index < 0 || index > 19) {
        printf("Aha! Doing something bad huh?");
        return;
    }

    struct Person *p = &app.list[index];

    strcpy(app.selected.name, p->name);
    app.selected.age = p->age;
    app.selected.gender = p->gender;
    app.selected.height = p->height;
    app.selected.weight = p->weight;
}

void calculate_bmi() {
    // Convert to float
    float height = 1.0*app.selected.height/100.0;
    float weight = 1.0*app.selected.weight;

    float bmi = weight / (height * height);
    printf(">> BMI of %s is %.2f\n", app.selected.name, bmi);

    app.stats.total_count += 1;
    app.stats.total_bmi += bmi;
}

void add_person() {
    printf("Index (0-19): ");
    int index = read_int();
    if (index < 0 || index > 19) {
        printf("Aha! Doing something bad huh?");
        return;
    }

    printf("Name: ");
    char *name = read_str();
    strncpy((char *) app.list[index].name, name, NAME_MAX_LENGTH);  // Copy name over safely

    printf("Age: ");
    app.list[index].age = read_int();

    printf("Gender (female = 0, male = 1): ");
    app.list[index].gender = read_int();

    printf("Height: ");
    app.list[index].height = read_int();

    printf("Weight: ");
    app.list[index].weight = read_int();
}

void delete_person() {
    printf("Index (0-19): ");
    int index = read_int();
    if (index < 0 || index > 19) {
        printf("Aha! Doing something bad huh?");
        return;
    }

    memset((char *) app.list[index].name, 0, NAME_MAX_LENGTH);  // Set name to NULL bytes
    app.list[index].age = 0;
    app.list[index].gender = 0;
    app.list[index].height = 0;
    app.list[index].weight = 0;
}

int main() {
    setup();

    show_menu();

    app.list = (struct Person *) malloc(sizeof(struct Person) * 20);

    strcpy(app.stats.logger, "echo \"-- total: %d, average BMI: %.2f --\" >> log.txt");
    app.stats.total_bmi = 0;
    app.stats.total_count = 0;

    while(1) {
        printf("\nChoose action: ");
        int op = read_int();

        if (op == 1) {
            add_person();
        } else if (op == 2) {
            delete_person();
        } else if (op == 3) {
            select_person();
            calculate_bmi();
        } else if (op == 4) {
            break;
        } else {
            printf("What?\n");
        }
    }

    char command[COMMAND_MAX_LENGTH];
    snprintf(command, COMMAND_MAX_LENGTH, app.stats.logger,
             app.stats.total_count, app.stats.total_bmi / app.stats.total_count);

    system(command);

    exit(0);
}

void timeout() {
    printf("Time's up :(\n");
    exit(0);
}

void setup() {
    setvbuf(stdin,  NULL, _IONBF, 0);   // Switch off I/O buffering
    setvbuf(stdout, NULL, _IONBF, 0);   // Switch off I/O buffering
    setvbuf(stderr, NULL, _IONBF, 0);   // Switch off I/O buffering

    signal(SIGALRM, timeout);           // Set program to exit on timeout
    alarm(60);                          // Exit program after 30s
}
