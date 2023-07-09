import subprocess

#############################################################################################
#######################                                            ##########################
#######################     System Security Checker Tool for App   ##########################
#######################                                            ##########################
#############################################################################################


def check_windows_defender_settings():
    try:
        output = subprocess.check_output('powershell -Command "(Get-MpPreference).DisableRealtimeMonitoring"', shell=True)
        output = output.decode('utf-8').strip()
        if output.lower() == 'false':
            return "Windows Defender Real-time Monitoring: Enabled"
        else:
            return "Windows Defender Real-time Monitoring: Disabled"
    except subprocess.CalledProcessError:
        return "Error occurred while checking Windows Defender settings."

def check_firewall_settings():
    try:
        output = subprocess.check_output('powershell -Command "(Get-NetFirewallProfile).Enabled"', shell=True)
        output = output.decode('utf-8').strip()

        firewall_profiles = {
            'Domain': False,
            'Private': False,
            'Public': False
        }

        if 'True' in output:
            enabled_profiles = subprocess.check_output('powershell -Command "(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $True}).Name"', shell=True)
            enabled_profiles = enabled_profiles.decode('utf-8').strip()
            enabled_profiles = enabled_profiles.split('\n')

            for profile in enabled_profiles:
                profile = profile.strip()
                if profile in firewall_profiles:
                    firewall_profiles[profile] = True

        result = "Firewall Settings:\n"
        for profile, enabled in firewall_profiles.items():
            if enabled:
                result += f"{profile}: Enabled\n"
            else:
                result += f"{profile}: Disabled\n"

        return result
    except subprocess.CalledProcessError:
        return "Error occurred while checking firewall settings."
