control "VCFL-67-000011" do
  title "vSphere Client log files must only be accessible by privileged users."
  desc  "Log data is essential in the investigation of events. If log data were
to become compromised, then competent forensic analysis and discovery of the
true source of potentially malicious system activity would be difficult, if not
impossible, to achieve. In addition, access to log records provides information
an attacker could potentially use to their advantage since each event record
might contain communication ports, protocols, services, trust relationships,
user names, etc. The vSphere Client restricts all access to log file by default
but this configuration must be verified."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000118-WSR-000068"
  tag gid: nil
  tag rid: "VCFL-67-000011"
  tag stig_id: "VCFL-67-000011"
  tag cci: "CCI-000162"
  tag nist: ["AU-9", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# find /storage/log/vmware/vsphere-client/logs/ -xdev -type f -a '(' -not -perm
600 -o -not -user vsphere-client ')' -exec ls -ld {} \\;

If any files are returned, this is a finding.
"
  desc 'fix', "At the command prompt, execute the following commands:

# chmod 600 /storage/log/vmware/vsphere-client/logs/<file>
# chown vsphere-client:users /storage/log/vmware/vsphere-client/logs/<file>

Note: Subsitute <file> with the listed file"

  command('find /storage/log/vmware/vsphere-client/logs/ -maxdepth 1 -type f').stdout.split.each do | fname |
    describe file(fname) do
      it { should_not be_more_permissive_than('0600') }
      its('owner') {should eq 'vsphere-client'}
      its('group') {should eq 'users'}
    end
  end

end