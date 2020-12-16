# encoding: UTF-8

control 'V-219219' do
  title "The Ubuntu operating system must generate audit records for the
/var/log/btmp file."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system generates audit records showing start
and stop times for user access to the system via /var/log/btmp file.

    Check the currently configured audit rules with the following command:

    # sudo auditctl -l | grep '/var/log/btmp'

    -w /var/log/btmp -p wa -k logins

    If the command does not return a line matching the example or the line is
commented out, this is a finding.

    Note: The '-k' allows for specifying an arbitrary identifier and the string
after it does not need to match the example output above.
  "
  desc  'fix', "
    Configure the audit system to generate audit events showing start and stop
times for user access via the /var/log/btmp file.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\"
file:

    -w /var/log/btmp -p wa -k logins

    Note:
    The \"root\" account must be used to view/edit any files in the
/etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000472-GPOS-00217'
  tag gid: 'V-219219'
  tag rid: 'SV-219219r508662_rule'
  tag stig_id: 'UBTU-18-010240'
  tag fix_id: 'F-20943r304986_fix'
  tag cci: ['V-100665', 'SV-109769', 'CCI-000172']
  tag nist: ['AU-12 c']

  @audit_file = "/var/log/btmp"

  audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
  if audit_lines_exist
    describe auditd.file(@audit_file) do
      its("permissions") { should_not cmp [] }
      its("action") { should_not include "never" }
    end

    @perms = auditd.file(@audit_file).permissions

    @perms.each do |perm|
      describe perm do
        it { should include "w" }
        it { should include "a" }
      end
    end
  else
    describe ("Audit line(s) for " + @audit_file + " exist") do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end

