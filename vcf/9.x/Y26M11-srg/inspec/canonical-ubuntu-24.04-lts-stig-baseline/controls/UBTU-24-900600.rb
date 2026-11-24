control 'UBTU-24-900600' do
  title 'Ubuntu 24.04 LTS must generate audit records for the /var/run/utmp file.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify Ubuntu 24.04 LTS generates audit records showing start and stop times for user access to the system via the "/var/run/utmp" file with the following command:

$ sudo auditctl -l | grep '/var/run/utmp'
-w /var/run/utmp -p wa -k logins

If the command does not return a line matching the example or the line is commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.)
  desc 'fix', 'Configure the audit system to generate audit events showing start and stop times for user access via the "/var/run/utmp" file.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-w /var/run/utmp -p wa -k logins

To reload the rules file, issue the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74844r1066920_chk'
  tag severity: 'medium'
  tag gid: 'V-270811'
  tag rid: 'SV-270811r1066922_rule'
  tag stig_id: 'UBTU-24-900600'
  tag gtitle: 'SRG-OS-000472-GPOS-00217'
  tag fix_id: 'F-74745r1066921_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  @audit_file = '/var/run/utmp'

  audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
  if audit_lines_exist
    describe auditd.file(@audit_file) do
      its('permissions') { should_not cmp [] }
      its('action') { should_not include 'never' }
    end

    @perms = auditd.file(@audit_file).permissions

    @perms.each do |perm|
      describe perm do
        it { should include 'w' }
        it { should include 'a' }
      end
    end
  else
    describe("Audit line(s) for #{@audit_file} exist") do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end
