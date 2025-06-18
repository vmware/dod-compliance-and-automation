control 'UBTU-22-654060' do
  title 'Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use modprobe command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify if Ubuntu 22.04 LTS is configured to audit the execution of the module management program "modprobe" with the following command:

     $ sudo auditctl -l | grep /sbin/modprobe
     -w /sbin/modprobe -p x -k modules

If the command does not return a line, or the line is commented out, this is a finding.

Note: The "-k" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to audit the execution of the module management program "modprobe".

Add or modify the following line in the "/etc/audit/rules.d/stig.rules" file:

-w /sbin/modprobe -p x -k modules

To reload the rules file, issue the following command:

     $ sudo augenrules --load

Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64343r953653_chk'
  tag severity: 'medium'
  tag gid: 'V-260614'
  tag rid: 'SV-260614r991586_rule'
  tag stig_id: 'UBTU-22-654060'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-64251r953654_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  @audit_file = '/sbin/modprobe'

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
