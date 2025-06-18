control 'UBTU-22-654055' do
  title 'Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the kmod command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify Ubuntu 22.04 LTS is configured to audit the execution of the module management program "kmod" by using the following command:

     $ sudo auditctl -l | grep kmod
     -w /bin/kmod -p x -k module

If the command does not return a line, or the line is commented out, this is a finding.

Note: The "-k" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to audit the execution of the module management program "kmod".

Add or modify the following line in the "/etc/audit/rules.d/stig.rules" file:

-w /bin/kmod -p x -k modules

To reload the rules file, issue the following command:

     $ sudo augenrules --load

Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64342r953650_chk'
  tag severity: 'medium'
  tag gid: 'V-260613'
  tag rid: 'SV-260613r991586_rule'
  tag stig_id: 'UBTU-22-654055'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-64250r953651_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  @audit_file = '/bin/kmod'

  audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
  if audit_lines_exist
    describe auditd.file(@audit_file) do
      its('permissions') { should_not cmp [] }
      its('action') { should_not include 'never' }
    end

    @perms = auditd.file(@audit_file).permissions

    @perms.each do |perm|
      describe perm do
        it { should include 'x' }
      end
    end
  else
    describe("Audit line(s) for #{@audit_file} exist") do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end
