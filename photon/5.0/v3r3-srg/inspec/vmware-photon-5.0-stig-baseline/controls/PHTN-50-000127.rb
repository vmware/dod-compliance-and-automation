control 'PHTN-50-000127' do
  title 'The Photon operating system must install AIDE to detect changes to baseline configurations.'
  desc  "
    Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

    Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's IMO/ISSO and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following commands to verify AIDE is installed and used to monitor for file changes:

    # rpm -qa | grep '^aide'

    Example result:

    aide-0.17.4-5.ph5.x86_64

    If AIDE is not installed, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following command:

    # tdnf install aide
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag satisfies: ['SRG-OS-000446-GPOS-00200']
  tag gid: 'V-PHTN-50-000127'
  tag rid: 'SV-PHTN-50-000127'
  tag stig_id: 'PHTN-50-000127'
  tag cci: ['CCI-001744', 'CCI-002699']
  tag nist: ['CM-3 (5)', 'SI-6 b']

  describe command('rpm -qa | grep aide') do
    its('stdout.strip') { should match /^aide-/ }
  end
end
