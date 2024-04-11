control 'VRPI-8X-000144' do
  title 'The VMware Aria Operations API service files must have permissions in an out-of-the-box state.'
  desc  'As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /usr/lib/vmware-vcops/tomcat-enterprise/conf -xdev -type f -a '(' -perm -o+w -o -not -user admin -o -not -group admin ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # chmod o-w <file>
    # chown admin:admin<file>

    Note: Substitute <file> with each of the listed files.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag gid: 'V-VRPI-8X-000144'
  tag rid: 'SV-VRPI-8X-000144'
  tag stig_id: 'VRPI-8X-000144'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1)']

  command("find '#{input('api-tcInstance')}/conf' -type f -xdev").stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_writable.by('others') }
      its('owner') { should eq 'admin' }
      its('group') { should eq 'admin' }
    end
  end
end
