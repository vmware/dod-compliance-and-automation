control 'UBTU-24-100030' do
  title 'Ubuntu 24.04 LTS must not have the telnet package installed.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Ubuntu 24.04 LTS functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Verify the telnet package is not installed on Ubuntu 24.04 LTS with the following command:

$ dpkg -l | grep telnetd

If the telnetd package is installed, this is a finding.'
  desc 'fix', 'Remove the telnet package from Ubuntu 24.04 LTS with the following command:

$ sudo apt remove telnetd'
  impact 0.7
  tag check_id: 'C-74680r1066428_chk'
  tag severity: 'high'
  tag gid: 'V-270647'
  tag rid: 'SV-270647r1066430_rule'
  tag stig_id: 'UBTU-24-100030'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-74581r1066429_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  describe package('telnetd') do
    it { should_not be_installed }
  end
end
