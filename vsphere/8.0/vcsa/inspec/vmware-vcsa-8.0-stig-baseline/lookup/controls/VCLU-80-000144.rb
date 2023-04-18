control 'VCLU-80-000144' do
  title 'The vCenter Lookup service files must have permissions in an out-of-the-box state.'
  desc  'As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /usr/lib/vmware-lookupsvc/ -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # chmod o-w <file>
    # chown root:root <file>

    Note: Substitute <file> with the listed file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag gid: 'V-VCLU-80-000144'
  tag rid: 'SV-VCLU-80-000144'
  tag stig_id: 'VCLU-80-000144'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1)']

  command("find '#{input('appPath')}' -type f -xdev").stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_writable.by('others') }
      its('owner') { should eq 'root' }
      its('group') { should eq 'root' }
    end
  end
end
