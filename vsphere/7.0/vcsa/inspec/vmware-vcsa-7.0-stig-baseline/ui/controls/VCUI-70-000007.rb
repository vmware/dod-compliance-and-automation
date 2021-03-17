# encoding: UTF-8

control 'VCUI-70-000007' do
  title 'vSphere UI log files must only be accessible by privileged users.'
  desc  "Log data is essential in the investigation of events. If log data were
to become compromised, then competent forensic analysis and discovery of the
true source of potentially malicious system activity would be difficult, if not
impossible, to achieve. In addition, access to log records provides information
an attacker could potentially use to their advantage since each event record
might contain communication ports, protocols, services, trust relationships,
user names, etc. The vSphere UI restricts all access to log file by default but
this configuration must be verified."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /storage/log/vmware/vsphere-ui/logs/ -xdev -type f -a '(' -not -perm
600 -o -not -user vsphere-ui ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc  'fix', "
    At the command prompt, execute the following commands:

    # chmod 600 /storage/log/vmware/vsphere-ui/logs/<file>
    # chown vsphere-ui:users /storage/log/vmware/vsphere-ui/logs/<file>

    Note: Subsitute <file> with the listed file
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCUI-70-000007'
  tag fix_id: nil
  tag cci: 'CCI-000162'
  tag nist: ['AU-9']

  command("find '#{input('logPath')}' -type f -xdev").stdout.split.each do | fname |
    describe file(fname) do
      it { should_not be_more_permissive_than('0640') }
      its('owner') {should eq 'vsphere-ui'}
      its('group') {should eq 'users'}
    end
  end

end

