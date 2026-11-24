control 'UBTU-24-901250' do
  title 'Ubuntu 24.04 LTS must configure the audit tools to be group owned by root.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions, roles identifying the user accessing the tools, and the corresponding user rights to make decisions regarding access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

'
  desc 'check', 'Verify Ubuntu 24.04 LTS configures the audit tools to be group owned by root to prevent any unauthorized access with the following command:

$ stat -c "%n %G" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules
/sbin/auditctl root
/sbin/aureport root
/sbin/ausearch root
/sbin/autrace root
/sbin/auditd root
/sbin/augenrules root

If any of the audit tools are not group owned by root, this is a finding.'
  desc 'fix', 'Configure the audit tools on Ubuntu 24.04 LTS to be protected from unauthorized access by setting the file group as root using the following command:

$ sudo chown :root [audit_tool]

Replace "[audit_tool]" with each audit tool not group owned by root.'
  impact 0.5
  tag check_id: 'C-74856r1134822_chk'
  tag severity: 'medium'
  tag gid: 'V-270823'
  tag rid: 'SV-270823r1134824_rule'
  tag stig_id: 'UBTU-24-901250'
  tag gtitle: 'SRG-OS-000257-GPOS-00098'
  tag fix_id: 'F-74757r1134823_fix'
  tag satisfies: ['SRG-OS-000257-GPOS-00098', 'SRG-OS-000256-GPOS-00097']
  tag 'documentable'
  tag cci: ['CCI-001494', 'CCI-001493']
  tag nist: ['AU-9', 'AU-9 a']

  audit_tools = input('audit_tools')

  audit_tools.each do |tool|
    if file(tool).exist?
      describe file(tool) do
        its('group') { should cmp 'root' }
      end
    else
      impact 0.0
      describe 'No Audit Tool found' do
        skip "Audit Tool #{tool} does not exist"
      end
    end
  end
end
