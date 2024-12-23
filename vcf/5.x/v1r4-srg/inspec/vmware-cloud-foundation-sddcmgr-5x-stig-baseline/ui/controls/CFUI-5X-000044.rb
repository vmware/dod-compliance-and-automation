control 'CFUI-5X-000044' do
  title 'The SDDC Manager UI service directory tree must be secured.'
  desc  "As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled. Only the system administrator needs access to all the system's capabilities, while the web administrator and associated staff require access and control of the web content and web server configuration files."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /opt/vmware/vcf/sddc-manager-ui-app/ -xdev -type f -a '(' -perm -o+w -o -not -user vcf_sddc_manager_ui_app -o -not -group vcf ')' -exec ls -ld {} \\;

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # chmod o-w <file>
    # chmod vcf_sddc_manager_ui_app:vcf <file>

    Repeat the command for each file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag satisfies: ['SRG-APP-000380-WSR-000072']
  tag gid: 'V-CFUI-5X-000044'
  tag rid: 'SV-CFUI-5X-000044'
  tag stig_id: 'CFUI-5X-000044'
  tag cci: ['CCI-001082', 'CCI-001813']
  tag nist: ['CM-5 (1) (a)', 'SC-2']

  describe command('find /opt/vmware/vcf/sddc-manager-ui-app/ -xdev -type f -a \'(\' -perm -o+w -o -not -user vcf_sddc_manager_ui_app -o -not -group vcf \')\' -exec ls -ld {} \\;') do
    its('stdout') { should cmp '' }
    its('stderr') { should cmp '' }
    its('exit_status') { should cmp 0 }
  end
end
