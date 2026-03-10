control 'VCFK-9X-000043' do
  title "The VMware Cloud Foundation vCenter Envoy service's configuration must be protected from unauthorized modification."
  desc  "As a rule, accounts on a server are to be kept to a minimum. The resources to which these accounts have access must also be closely monitored and controlled. Only the system administrator needs access to all the system's capabilities and the server configuration files."
  desc  'rationale', ''
  desc  'check', "
    At a command prompt, validate the vCenter Envoy service's configuration is secure by running the following:

    # find /etc/vmware-envoy/ /etc/vmware-envoy-hgw/ /etc/vmware-envoy-sidecar/ /etc/vmware-envoy-system-proxy/ -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, correct permissions for Envoy configuration files by running the following:

    # chmod o-w <file>
    # chown root:root <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag satisfies: ['SRG-APP-000211-WSR-000031', 'SRG-APP-000340-WSR-000029', 'SRG-APP-000380-WSR-000072']
  tag gid: 'V-VCFK-9X-000043'
  tag rid: 'SV-VCFK-9X-000043'
  tag stig_id: 'VCFK-9X-000043'
  tag cci: ['CCI-001082', 'CCI-001813', 'CCI-002235']
  tag nist: ['AC-6 (10)', 'CM-5 (1) (a)', 'SC-2']

  conffilesenvoy = command('find /etc/vmware-envoy/ /etc/vmware-envoy-hgw/ /etc/vmware-envoy-sidecar/ /etc/vmware-envoy-system-proxy/ -type f -xdev').stdout
  if !conffilesenvoy.empty?
    conffilesenvoy.split.each do |fname|
      describe file(fname) do
        it { should_not be_writable.by('others') }
        its('owner') { should eq 'root' }
        its('group') { should eq 'root' }
      end
    end
  else
    describe 'No log files found...skipping.' do
      skip 'No log files found...skipping.'
    end
  end
end
