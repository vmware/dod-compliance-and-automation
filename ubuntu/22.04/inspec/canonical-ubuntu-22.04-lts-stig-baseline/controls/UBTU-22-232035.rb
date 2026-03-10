control 'UBTU-22-232035' do
  title 'Ubuntu 22.04 LTS must configure audit tools with a mode of "755" or less permissive.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

'
  desc 'check', 'Verify Ubuntu 22.04 LTS configures the audit tools to have a file permission of "755" or less to prevent unauthorized access by using the following command:

     $ stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules
     /sbin/auditctl 755
     /sbin/aureport 755
     /sbin/ausearch 755
     /sbin/autrace 755
     /sbin/auditd 755
     /sbin/audispd-zos-remote 755
     /sbin/augenrules 755

If any of the audit tools have a mode more permissive than "0755", this is a finding.'
  desc 'fix', 'Configure the audit tools on Ubuntu 22.04 LTS to be protected from unauthorized access by setting the correct permissive mode using the following command:

     $ sudo chmod 755 <audit_tool_name>

Replace "<audit_tool_name>" with the audit tool that does not have the correct permissions.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64221r953287_chk'
  tag severity: 'medium'
  tag gid: 'V-260492'
  tag rid: 'SV-260492r991557_rule'
  tag stig_id: 'UBTU-22-232035'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-64129r953288_fix'
  tag satisfies: ['SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098']
  tag 'documentable'
  tag cci: ['CCI-001493', 'CCI-001494']
  tag nist: ['AU-9 a', 'AU-9']

  audit_tools = input('audit_tools')

  audit_tools.each do |tool|
    if file(tool).exist?
      describe file(tool) do
        it { should_not be_more_permissive_than('0755') }
      end
    else
      describe "Audit Tool: #{tool} does not exist." do
        skip "Audit Tool: #{tool} does not exist."
      end
    end
  end
end
