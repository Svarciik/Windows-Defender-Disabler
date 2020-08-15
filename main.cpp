#include <iostream>
#include <Windows.h>

auto main() -> int {
	SetConsoleTitleA("Windows Defender disabler");
	std::cout << "Windows Defender disabler\n\n";

	system("reg delete \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /f");
	system("reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiSpyware\" /t REG_DWORD /d \"1\" /f");
	system("reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiVirus\" /t REG_DWORD /d \"1\" /f");
	system("reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\MpEngine\" /v \"MpEnablePus\" /t REG_DWORD /d \"0\" /f");
	system("reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableBehaviorMonitori""ng\" /t REG_DWORD /d \"1\" /f");
	system("reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableIOAVProtection\""" /t REG_DWORD /d \"1\" /f");
	system("reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableOnAccessProtecti""on\" /t REG_DWORD /d \"1\" /f");
	system("reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableRealtimeMonitori""ng\" /t REG_DWORD /d \"1\" /f");
	system("reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableScanOnRealtimeEn""able\" /t REG_DWORD /d \"1\" /f");
	system("reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Reporting\" /v \"DisableEnhancedNotifications\" /t ""REG_DWORD /d \"1\" /f");
	system("reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet\" /v \"DisableBlockAtFirstSeen\" /t REG_DWORD /d \"1\" /f");
	system("reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet\" /v \"SpynetReporting\" /t REG_DWORD /d \"0\" /f");
	system("reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet\" /v \"SubmitSamplesConsent\" /t REG_DWORD /d \"0\" /f");
	system("reg add \"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger\" /v \"Start\" /t REG_DWORD /d \"0\" /f");
	system("reg add \"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderAuditLogger\" /v \"Start\" /t REG_DWORD /d \"0\" /f");
	system("schtasks /Change /TN \"Microsoft\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh\" /Disable");
	system("schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance\" /Disable");
	system("schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup\" /Disable");
	system("schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan\" /Disable");
	system("schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Verification\" /Disable");
	system("reg delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run\" /v \"Windows Defender\" /f");
	system("reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Windows Defender\" /f");
	system("reg delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"WindowsDefender\" /f");
	system("reg delete \"HKCR\\*\\shellex\\ContextMenuHandlers\\EPP\" /f");
	system("reg delete \"HKCR\\Directory\\shellex\\ContextMenuHandlers\\EPP\" /f");
	system("reg delete \"HKCR\\Drive\\shellex\\ContextMenuHandlers\\EPP\" /f");
	system("reg add \"HKLM\\System\\CurrentControlSet\\Services\\WdBoot\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
	system("reg add \"HKLM\\System\\CurrentControlSet\\Services\\WdFilter\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
	system("reg add \"HKLM\\System\\CurrentControlSet\\Services\\WdNisDrv\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
	system("reg add \"HKLM\\System\\CurrentControlSet\\Services\\WdNisSvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
	system("reg add \"HKLM\\System\\CurrentControlSet\\Services\\WinDefend\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
	system("reg add \"HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
	system("cls");

	std::cout << "Done\n";
	std::cin.get();
	return 0;
}