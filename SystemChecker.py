import subprocess

#############################################################################################
#######################                                            ##########################
#######################     System Security Checker Tool for App   ##########################
#######################                                            ##########################
#############################################################################################

def check_windows_defender_settings():
    try:
        # Run a PowerShell command to check if Windows Defender Real-time Monitoring is disabled
        output = subprocess.check_output('powershell -Command "(Get-MpPreference).DisableRealtimeMonitoring"', shell=True)
        output = output.decode('utf-8').strip()

        # Check the output of the PowerShell command
        if output.lower() == 'false':
            return "Windows Defender Real-time Monitoring: Enabled"
        else:
            return "Windows Defender Real-time Monitoring: Disabled"

    except subprocess.CalledProcessError:
        # An error occurred while running the PowerShell command
        return "Error occurred while checking Windows Defender settings."


def check_firewall_settings():
    try:
        # Run a PowerShell command to check if the firewall is enabled for different profiles
        output = subprocess.check_output('powershell -Command "(Get-NetFirewallProfile).Enabled"', shell=True)
        output = output.decode('utf-8').strip()

        # Create a dictionary to store the firewall settings for different profiles
        firewall_profiles = {
            'Domain': False,
            'Private': False,
            'Public': False
        }

        # Check if the firewall is enabled for each profile and update the dictionary
        if 'True' in output:
            enabled_profiles = subprocess.check_output('powershell -Command "(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $True}).Name"', shell=True)
            enabled_profiles = enabled_profiles.decode('utf-8').strip()
            enabled_profiles = enabled_profiles.split('\n')

            for profile in enabled_profiles:
                profile = profile.strip()
                if profile in firewall_profiles:
                    firewall_profiles[profile] = True

        # Prepare the result string with the firewall settings for each profile
        result = "Firewall Settings:\n"
        for profile, enabled in firewall_profiles.items():
            if enabled:
                result += f"{profile}: Enabled\n"
            else:
                result += f"{profile}: Disabled\n"

        return result

    except subprocess.CalledProcessError:
        # An error occurred while running the PowerShell command
        return "Error occurred while checking firewall settings."