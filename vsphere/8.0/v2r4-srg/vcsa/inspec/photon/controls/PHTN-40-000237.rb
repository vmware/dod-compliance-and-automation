control 'PHTN-40-000237' do
  title 'The Photon operating system must configure AIDE to detect changes to baseline configurations.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's information system security manager (ISSM)/information system security officer (ISSO) and system administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item."
  desc 'check', "At the command line, run the following commands to verify AIDE is configured and used to monitor for file changes:

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

If the check command indicates there is no database available, this is a finding."
  desc 'fix', 'Update the /etc/aide.conf file with the template provided as a supplemental document.

At the command line, run the following commands to generate an AIDE database to use for file monitoring:

# aide --init
# cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

Note: It is recommended to run these fix steps after all other STIG configurations have been completed so that the AIDE database includes those updates.'
  impact 0.5
  tag check_id: 'C-69985r1003656_chk'
  tag severity: 'medium'
  tag gid: 'V-266062'
  tag rid: 'SV-266062r1003658_rule'
  tag stig_id: 'PHTN-40-000237'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-69888r1003657_fix'
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
