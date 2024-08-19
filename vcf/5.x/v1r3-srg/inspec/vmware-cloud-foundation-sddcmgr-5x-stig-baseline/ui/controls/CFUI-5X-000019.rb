control 'CFUI-5X-000019' do
  title 'The SDDC Manager UI service log files must only be accessible by privileged users.'
  desc  "
    Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

    The web server must protect the log data from unauthorized read, write, copy, etc. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from access by non-privileged users.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /var/log/vmware/vcf/sddc-manager-ui-app/ -xdev -type f -a '(' -perm -o+w -o -not -user vcf_sddc_manager_ui_app -o -not -group vcf ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # chmod 640 <file>
    # chown vcf_sddc_manager_ui_app:vcf <file>

    Note: Substitute <file> with the listed file
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag satisfies: ['SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag gid: 'V-CFUI-5X-000019'
  tag rid: 'SV-CFUI-5X-000019'
  tag stig_id: 'CFUI-5X-000019'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9']

  describe command('find /var/log/vmware/vcf/sddc-manager-ui-app -xdev -type f -a \'(\' -perm -o+w -o -not -user vcf_sddc_manager_ui_app -o -not -group vcf \')\' -exec ls -ld {} \\;') do
    its('stdout') { should cmp '' }
    its('stderr') { should cmp '' }
    its('exit_status') { should cmp 0 }
  end
end
