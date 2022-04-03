control 'VCEM-67-000008' do
  title "ESX Agent Manager application files must be verified for their
integrity."
  desc  "Verifying that ESX Agent Manager application code is unchanged from
its shipping state is essential for file validation and non-repudiation of the
ESX Agent Manager. There is no reason that the MD5 hash of the rpm original
files should be changed after installation, excluding configuration files."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V vmware-eam|grep \"^..5......\"|grep -E
\"\\.war|\\.jar|\\.sh|\\.py\"

    If there is any output, this is a finding.
  "
  desc 'fix', "Reinstall the VCSA or roll back to a snapshot. Modifying the
EAM installation files manually is not supported by VMware."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag satisfies: ['SRG-APP-000131-WSR-000051', 'SRG-APP-000357-WSR-000150']
  tag gid: 'V-239379'
  tag rid: 'SV-239379r674631_rule'
  tag stig_id: 'VCEM-67-000008'
  tag fix_id: 'F-42571r674630_fix'
  tag cci: ['CCI-001749', 'CCI-001849']
  tag nist: ['CM-5 (3)', 'AU-4']

  describe command('rpm -V vmware-eam|grep "^..5......"|grep -E "\.war|\.jar|\.sh|\.py"') do
    its('stdout.strip') { should eq '' }
  end
end
