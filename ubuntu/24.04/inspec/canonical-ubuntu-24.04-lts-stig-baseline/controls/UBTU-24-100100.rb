control 'UBTU-24-100100' do
  title 'Ubuntu 24.04 LTS must use a file integrity tool to verify correct operation of all security functions.'
  desc 'Without verification, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to Ubuntu 24.04 LTS performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Verify that Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions with the following command:

$ dpkg -l | grep aide
ii  aide     0.18.6-2build2     amd64     Advanced Intrusion Detection Environment - dynamic binary
ii  aide-common     0.18.6-2build2     all     Advanced Intrusion Detection Environment - Common files

If AIDE is not installed, ask the system administrator how file integrity checks are performed on the system.

If there is no application installed to perform integrity checks, this is a finding.'
  desc 'fix', 'Install the "AIDE" file integrity package:

$ sudo apt install -y aide'
  impact 0.5
  tag check_id: 'C-74682r1067134_chk'
  tag severity: 'medium'
  tag gid: 'V-270649'
  tag rid: 'SV-270649r1067136_rule'
  tag stig_id: 'UBTU-24-100100'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-74583r1067135_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']

  describe package('aide') do
    it { should be_installed }
  end
end
