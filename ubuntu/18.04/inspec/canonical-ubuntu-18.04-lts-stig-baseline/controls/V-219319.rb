# encoding: UTF-8

control 'V-219319' do
  title "The Ubuntu operating system must accept Personal Identity Verification
(PIV) credentials."
  desc  "The use of PIV credentials facilitates standardization and reduces the
risk of unauthorized access.

    DoD has mandated the use of the CAC to support identity management and
personal authentication for systems covered under Homeland Security
Presidential Directive (HSPD) 12, as well as making the CAC a primary component
of layered protection for national security systems.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system accepts Personal Identity Verification
(PIV) credentials.

    Check that the \"opensc-pcks11\" package is installed on the system with
the following command:

    # dpkg -l | grep opensc-pkcs11

    ii opensc-pkcs11:amd64 0.15.0-1Ubuntu1 amd64 Smart card utilities with
support for PKCS#15 compatible cards

    If the \"opensc-pcks11\" package is not installed, this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to accept Personal Identity
Verification (PIV) credentials.

    Install the \"opensc-pkcs11\" package using the following command:

    # sudo apt-get install opensc-pkcs11
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000376-GPOS-00161'
  tag gid: 'V-219319'
  tag rid: 'SV-219319r508662_rule'
  tag stig_id: 'UBTU-18-010432'
  tag fix_id: 'F-21043r305286_fix'
  tag cci: ['SV-109965', 'V-100861', 'CCI-001953']
  tag nist: ['IA-2 (12)']

  describe package('opensc-pkcs11') do
    it { should be_installed }
  end
end

