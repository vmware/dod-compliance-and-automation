control 'PHTN-50-000237' do
  title 'The Photon operating system must configure AIDE to detect changes to baseline configurations.'
  desc  "
    Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

    Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's IMO/ISSO and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following commands to verify AIDE is configured and used to monitor for file changes:

    # grep -v '^#' /etc/aide.conf | grep -v '^$'

    Example result:

    STIG = p+i+n+u+g+s+m+S
    LOGS = p+n+u+g
    /boot   STIG
    /opt    STIG
    /usr    STIG
    /etc    STIG
    /var/log   LOGS

    If the AIDE configuration does not include the lines shown above, this is a finding.

    At the command line, run the following commands to verify an AIDE database is configured and used to monitor for file changes:

    # aide --check

    If the check command indicates there is no database available, this is a finding.
  "
  desc 'fix', "
    Update the /etc/aide.conf file with the template provided as a supplemental document.

    At the command line, run the following commands to generate an AIDE database to use for file monitoring:

    # aide --init
    # cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

    Note: It is recommended to run these fix steps after all other STIG configurations have been completed so that the AIDE database includes those updates.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag gid: 'V-PHTN-50-000237'
  tag rid: 'SV-PHTN-50-000237'
  tag stig_id: 'PHTN-50-000237'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']

  aidecontent = inspec.profile.file('aide.conf')
  describe file('/etc/aide.conf') do
    its('content') { should eq aidecontent }
  end
  describe command('aide --check') do
    its('stdout.strip') { should match /AIDE found/ }
    its('stdout.strip') { should_not match /Couldn't open file/ }
  end
end
