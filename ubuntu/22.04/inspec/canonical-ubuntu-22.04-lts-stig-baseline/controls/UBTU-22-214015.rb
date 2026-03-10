control 'UBTU-22-214015' do
  title 'Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) removes all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Verify APT is configured to remove all software components after updated versions have been installed by using the following command:

     $ grep -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades
     Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
     Unattended-Upgrade::Remove-Unused-Dependencies "true";

If "Unattended-Upgrade::Remove-Unused-Kernel-Packages" and "Unattended-Upgrade::Remove-Unused-Dependencies" are not set to "true", are commented out, or are missing, this is a finding.'
  desc 'fix', 'Configure APT to remove all software components after updated versions have been installed.

Add or modify the following lines in the "/etc/apt/apt.conf.d/50unattended-upgrades" file:

Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64206r1044771_chk'
  tag severity: 'medium'
  tag gid: 'V-260477'
  tag rid: 'SV-260477r1044773_rule'
  tag stig_id: 'UBTU-22-214015'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-64114r1044772_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']

  aptconf = command('apt-config dump').stdout
  options = {
    # Parses key value pairs as beginning of line to space then the value inside of quotes
    assignment_regex: /^([^=]*?)\s"(.*?)";$/
  }
  describe parse_config(aptconf, options) do
    its('Unattended-Upgrade::Remove-Unused-Kernel-Packages') { should cmp true }
    its('Unattended-Upgrade::Remove-Unused-Dependencies') { should cmp true }
  end
end
