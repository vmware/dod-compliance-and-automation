control 'UBTU-24-200270' do
  title 'Ubuntu 24.04 LTS must audit any script or executable called by cron as root or by any privileged user.'
  desc 'Any script or executable called by cron as root or by any privileged user must be owned by that user, must have the permissions 755 or more restrictive, and should have no extended rights that allow any nonprivileged user to modify the script or executable.'
  desc 'check', 'Verify Ubuntu 24.04 LTS is configured to audit the execution of any system call made by cron as root or as any privileged user.

$ sudo auditctl -l | grep /etc/cron.d
-w /etc/cron.d -p wa -k cronjobs

$ sudo auditctl -l | grep /var/spool/cron
-w /var/spool/cron -p wa -k cronjobs

If either of these commands does not return the expected output, or the lines are commented out, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to audit the execution of any system call made by cron as root or as any privileged user.

Add or update the following file system rules to "/etc/audit/rules.d/audit.rules":
-w /etc/cron.d/ -p wa -k cronjobs
-w /var/spool/cron/ -p wa -k cronjobs

To load the rules to the kernel immediately, use the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-78971r1155225_chk'
  tag severity: 'medium'
  tag gid: 'V-274870'
  tag rid: 'SV-274870r1155243_rule'
  tag stig_id: 'UBTU-24-200270'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-78876r1155226_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  @audit_files = ['/etc/cron.d', '/var/spool/cron']

  @audit_files.each do |audit_file|
    audit_lines_exist = !auditd.lines.index { |line| line.include?(audit_file) }.nil?

    if audit_lines_exist
      describe auditd.file(audit_file) do
        its('permissions') { should_not cmp [] }
        its('action') { should_not include 'never' }
      end

      @perms = auditd.file(audit_file).permissions

      @perms.each do |perm|
        describe perm do
          it { should include 'w' }
          it { should include 'a' }
        end
      end
    else
      describe("Audit line(s) for #{audit_file} exist") do
        subject { audit_lines_exist }
        it { should be true }
      end
    end
  end
end
