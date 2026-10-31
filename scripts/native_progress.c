// Test-only native custom action. Exercise the real installer UI/message pump,
// including cancellation, without replacing it with an external UI handler.
#include <windows.h>
#include <msi.h>
#include <msiquery.h>

UINT __stdcall ObserveProgress(MSIHANDLE install) {
    MSIHANDLE record = MsiCreateRecord(4);
    if (!record) return ERROR_INSTALL_FAILURE;
    MsiRecordSetInteger(record, 1, 0); // reset progress
    MsiRecordSetInteger(record, 2, 50);
    MsiRecordSetInteger(record, 3, 0);
    MsiRecordSetInteger(record, 4, 0);
    int response = MsiProcessMessage(install, INSTALLMESSAGE_PROGRESS, record);
    for (int tick = 0; tick < 50 && response != IDCANCEL; ++tick) {
        Sleep(200);
        MsiRecordSetInteger(record, 1, 2); // advance progress
        MsiRecordSetInteger(record, 2, 1);
        response = MsiProcessMessage(install, INSTALLMESSAGE_PROGRESS, record);
    }
    MsiCloseHandle(record);
    return response == IDCANCEL ? ERROR_INSTALL_USEREXIT : ERROR_SUCCESS;
}
