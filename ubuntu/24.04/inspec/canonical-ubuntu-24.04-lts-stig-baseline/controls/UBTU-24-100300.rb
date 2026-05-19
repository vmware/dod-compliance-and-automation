control 'UBTU-24-100300' do
  title 'Ubuntu 24.04 LTS must have an application firewall installed in order to control remote access methods.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk, and make remote user access management difficult at best.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Ubuntu 24.04 LTS functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Verify that the Uncomplicated Firewall (ufw) is installed with the following command:

$ dpkg -l | grep ufw
ii  ufw         0.36.2-6     all     program for managing a Netfilter firewall

If the "ufw" package is not installed, ask the system administrator if another application firewall is installed.

If no application firewall is installed, this is a finding.'
  desc 'fix', 'Install the ufw by using the following command:

$ sudo apt install -y ufw'
  impact 0.5
  tag check_id: 'C-74687r1066449_chk'
  tag severity: 'medium'
  tag gid: 'V-270654'
  tag rid: 'SV-270654r1067143_rule'
  tag stig_id: 'UBTU-24-100300'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-74588r1067142_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']

  describe package('ufw') do
    it { should be_installed }
  end
end
