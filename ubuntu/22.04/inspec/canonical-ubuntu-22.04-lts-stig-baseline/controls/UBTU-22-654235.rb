control 'UBTU-22-654235' do
  title 'Ubuntu 22.04 LTS must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions and other system-level access.'
  desc 'If events associated with nonlocal administrative access or diagnostic sessions are not logged, a major tool for assessing and investigating attacks would not be available.

This requirement addresses auditing-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system, for example, the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch.

'
  desc 'check', 'Verify Ubuntu 22.04 LTS audits activities performed during nonlocal maintenance and diagnostic sessions by using the following command:

     $ sudo auditctl -l | grep sudo.log
     -w /var/log/sudo.log -p wa -k maintenance

If the command does not return lines that match the example or the lines are commented out, this is a finding.

Note: The "-k" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to audit activities performed during nonlocal maintenance and diagnostic sessions.

Add or modify the following line in the "/etc/audit/rules.d/stig.rules" file:

-w /var/log/sudo.log -p wa -k maintenance

To reload the rules file, issue the following command:

     $ sudo augenrules --load

Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64378r953758_chk'
  tag severity: 'medium'
  tag gid: 'V-260649'
  tag rid: 'SV-260649r986298_rule'
  tag stig_id: 'UBTU-22-654235'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-64286r953759_fix'
  tag satisfies: ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-002884', 'CCI-004188']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)', 'MA-3 (5)']

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
    describe("Audit line(s) for #{@audit_file} exist") do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end
