control 'UBTU-24-100910' do
  title 'Ubuntu 24.04 LTS must accept Personal Identity Verification (PIV) credentials managed through the Privileged Access Management (PAM)  framework.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DOD has mandated the use of the common access card (CAC) to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.'
  desc 'check', 'Verify the "libpam-pcks11" package is installed on the system with the following command:

$ dpkg -l | grep libpam-pkcs11
ii  libpam-pkcs11     0.6.12-2build3     amd64     Fully featured PAM module for using PKCS#11 smart cards

If the "libpam-pcks11" package is not installed, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to accept PIV credentials that are managed through the PAM framework.

Install the "libpam-pkcs11" package using the following command:

$ sudo apt install -y libpam-pkcs11'
  impact 0.5
  tag check_id: 'C-74706r1067162_chk'
  tag severity: 'medium'
  tag gid: 'V-270673'
  tag rid: 'SV-270673r1067164_rule'
  tag stig_id: 'UBTU-24-100910'
  tag gtitle: 'SRG-OS-000376-GPOS-00161'
  tag fix_id: 'F-74607r1067163_fix'
  tag 'documentable'
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']

  describe package('libpam-pkcs11') do
    it { should be_installed }
  end
end
