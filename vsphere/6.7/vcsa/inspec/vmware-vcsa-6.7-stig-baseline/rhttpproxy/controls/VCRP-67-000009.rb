control 'VCRP-67-000009' do
  title "The rhttpproxy log files must be moved to a permanent repository in
accordance with site policy."
  desc  "The rhttpproxy produces a handful of logs that must be offloaded from
the originating system. This information can then be used for diagnostic,
forensic, or other purposes relevant to ensuring the availability and integrity
of the hosted application."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep -v \"^#\" /etc/vmware-syslog/stig-services-rhttpproxy.conf

    Expected result:

    input(type=\"imfile\"
          File=\"/var/log/vmware/rhttpproxy/rhttpproxy.log\"
          Tag=\"rhttpproxy-main\"
          Severity=\"info\"
          Facility=\"local0\")

    If the file does not exist, this is a finding.

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc 'fix', "
    Navigate to and open /etc/vmware-syslog/stig-services-rhttpproxy.conf.

    Create the file if it does not exist.

    Set the contents of the file as follows:

    input(type=\"imfile\"
          File=\"/var/log/vmware/rhttpproxy/rhttpproxy.log\"
          Tag=\"rhttpproxy-main\"
          Severity=\"info\"
          Facility=\"local0\")
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-WSR-000063'
  tag gid: 'V-240724'
  tag rid: 'SV-240724r679685_rule'
  tag stig_id: 'VCRP-67-000009'
  tag fix_id: 'F-43916r679684_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  describe file('/etc/vmware-syslog/stig-services-rhttpproxy.conf') do
    it { should exist }
  end

  describe command('grep -v "^#" /etc/vmware-syslog/stig-services-rhttpproxy.conf') do
    its('stdout') { should match "input(type=\"imfile\"\n      File=\"/var/log/vmware/rhttpproxy/rhttpproxy.log\"\n      Tag=\"rhttpproxy-main\"\n      Severity=\"info\"\n      Facility=\"local0\")\n" }
  end
end
