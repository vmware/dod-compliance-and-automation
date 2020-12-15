# encoding: UTF-8

control 'V-219161' do
  title "The Ubuntu operating system must have an application firewall
installed in order to control remote access methods."
  desc  "Remote access services, such as those providing remote access to
network devices and information systems, which lack automated control
capabilities, increase risk and make remote user access management difficult at
best.

    Remote access is access to DoD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

    Ubuntu operating system functionality (e.g., RDP) must be capable of taking
enforcement action if the audit reveals unauthorized activity. Automated
control of remote access sessions allows organizations to ensure ongoing
compliance with remote access policies by enforcing connection rules of remote
access applications on a variety of information system components (e.g.,
servers, workstations, notebook computers, smartphones, and tablets).
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that the Uncomplicated Firewall is installed.

    Check that the Uncomplicated Firewall is installed with the following
command:

    # dpkg -l | grep ufw

    ii ufw 0.35-0Ubuntu2

    If the \"ufw\" package is not installed, ask the System Administrator is
another application firewall is installed. If no application firewall is
installed this is a finding.
  "
  desc  'fix', "
    Install the Uncomplicated Firewall by using the following command:

    # sudo apt-get install ufw
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag gid: 'V-219161'
  tag rid: 'SV-219161r508662_rule'
  tag stig_id: 'UBTU-18-010023'
  tag fix_id: 'F-20885r304812_fix'
  tag cci: ['SV-109653', 'V-100549', 'CCI-002314']
  tag nist: ['AC-17 (1)']

  describe service('ufw') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

