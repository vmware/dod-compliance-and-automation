control 'V-219216' do
  title "The Ubuntu operating system must generate audit records for privileged
activities or other system-level access."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system audits privileged activities.

    Check the currently configured audit rules with the following command:

    # sudo auditctl -l | grep sudo.log

    -w /var/log/sudo.log -p wa -k priv_actions

    If the command does not return lines that match the example or the lines
are commented out, this is a finding.

    Notes: The '-k' allows for specifying an arbitrary identifier and the
string after it does not need to match the example output above.
  "
  desc 'fix', "
    Configure the Ubuntu operating system to audit privileged activities.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\"
file:

    -w /var/log/sudo.log -p wa -k actions

    Note:
    The \"root\" account must be used to view/edit any files in the
/etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag gid: 'V-219216'
  tag rid: 'SV-219216r508662_rule'
  tag stig_id: 'UBTU-18-010237'
  tag fix_id: 'F-20940r304977_fix'
  tag cci: %w(SV-109763 V-100659 CCI-000172)
  tag nist: ['AU-12 c']

  @audit_file = '/var/log/sudo.log'

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
    describe('Audit line(s) for ' + @audit_file + ' exist') do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end
