control 'PHTN-40-000030' do
  title 'The Photon operating system must allow only authorized users to configure the auditd service.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'At the command line, run the following command to verify permissions on auditd configuration and rules files:

# find /etc/audit/* -type f -exec stat -c "%n %U:%G %a" {} $1\\;

If any files are returned with permissions more permissive than "0640", this is a finding.
If any files are returned not owned by root, this is a finding.
If any files are returned not group owned by root, this is a finding.'
  desc 'fix', 'At the command line, run the following commands:

#  chmod 0640 <audit file>
#  chown root:root <audit file>

Replace <audit file> with the target file.'
  impact 0.5
  tag check_id: 'C-62552r933495_chk'
  tag severity: 'medium'
  tag gid: 'V-258812'
  tag rid: 'SV-258812r958444_rule'
  tag stig_id: 'PHTN-40-000030'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-62461r933496_fix'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']

  auditfiles = command('find /etc/audit/ -type f').stdout
  if !auditfiles.empty?
    auditfiles.split.each do |fname|
      describe file(fname) do
        it { should_not be_more_permissive_than('0640') }
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
      end
    end
  else
    describe 'No auditd configuration files found. Is auditd installed?' do
      skip 'No auditd configuration files found. Is auditd installed?'
    end
  end
end
