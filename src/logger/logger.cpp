#include "logger.h"

#include <iostream>
#include <fstream>
#include <ctime>

using namespace std;

void initializeLogger()
{
    // Create/open the log file so it exists.
    ofstream logFile("logs/alerts.log", ios::app);

    if (!logFile.is_open())
    {
        cout << "Unable to initialize log file." << endl;
        return;
    }

    logFile.close();
}

void logAlert(const string& alert)
{
    ofstream logFile("logs/alerts.log", ios::app);

    if (!logFile.is_open())
    {
        cout << "Unable to open log file." << endl;
        return;
    }

    time_t now = time(nullptr);

    char timeBuffer[64];

    ctime_s(timeBuffer, sizeof(timeBuffer), &now);

    string timestamp(timeBuffer);

    timestamp.pop_back(); // Remove newline

    logFile << "[" << timestamp << "] "
            << alert << endl;

    logFile.close();
}