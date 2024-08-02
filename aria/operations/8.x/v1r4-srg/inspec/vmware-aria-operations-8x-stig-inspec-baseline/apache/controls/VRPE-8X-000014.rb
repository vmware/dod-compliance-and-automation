control 'VRPE-8X-000014' do
  title 'Anonymous user access to the VMware Aria Operations Apache server application directories must be prohibited.'
  desc  "
    In order to properly monitor the changes to the web server and the hosted applications, logging must be enabled. Along with logging being enabled, each record must properly contain the changes made and the names of those who made the changes.

    Allowing anonymous users the capability to change the web server or the hosted application will not generate proper log information that can then be used for forensic reporting in the case of a security issue. Allowing anonymous users to make changes will also grant change capabilities to anybody without forcing a user to authenticate before the changes can be made.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following commands:

    # find /etc/httpd -xdev -type f -a '(' -perm /o+w,o+x ')' -exec stat -c %n:%a:%U:%G {} \\;

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands for each <file> returned in the check:

    # chmod o-w <file>
    # chmod o-x <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-WSR-000031'
  tag satisfies: ['SRG-APP-000380-WSR-000072']
  tag gid: 'V-VRPE-8X-000014'
  tag rid: 'SV-VRPE-8X-000014'
  tag stig_id: 'VRPE-8X-000014'
  tag cci: ['CCI-001082', 'CCI-001813']
  tag nist: ['CM-5 (1) (a)', 'SC-2']

  describe command("find /etc/httpd -xdev -type f -a '(' -perm /o+w,o+x ')'") do
    its('stdout.strip') { should cmp '' }
  end
end
