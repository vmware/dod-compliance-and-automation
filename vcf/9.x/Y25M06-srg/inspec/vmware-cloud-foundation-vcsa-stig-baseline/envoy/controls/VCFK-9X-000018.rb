control 'VCFK-9X-000018' do
  title 'The VMware Cloud Foundation vCenter Envoy services must protect log files from unauthorized access, modification, and deletion.'
  desc  "
    Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

    The web server must protect the log data from unauthorized read, write, copy, etc. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from access by non-privileged users.
  "
  desc  'rationale', ''
  desc  'check', "
    At a command prompt, validate the vCenter Envoy services logs are secure by running the following:

    # find /var/log/vmware/envoy/ -xdev -type f -a '(' -perm -o+w -o -not -user envoy -o -not -group envoy ')' -exec ls -ld {} \\;
    # find /var/log/vmware/envoy-hgw/ -xdev -type f -a '(' -perm -o+w -o -not -user envoy-hgw -o -not -group envoy-hgw ')' -exec ls -ld {} \\;
    # find /var/log/vmware/envoy-sidecar/ -xdev -type f -a '(' -perm -o+w -o -not -user envoy-sidecar -o -not -group envoy-sidecar ')' -exec ls -ld {} \\;
    # find /var/log/vmware/envoy-system-proxy/ -xdev -type f -a '(' -perm -o+w -o -not -user envoy-system-proxy -o -not -group envoy-system-proxy ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, correct permissions for Envoy log files in /var/log/vmware/envoy/ by running the following:

    # chmod o-w <file>
    # chown envoy:envoy <file>

    or

    At the command prompt, correct permissions for Envoy log files in /var/log/vmware/envoy-hgw/ by running the following:

    # chmod o-w <file>
    # chown envoy-hgw:envoy-hgw <file>

    or

    At the command prompt, correct permissions for Envoy log files in /var/log/vmware/envoy-sidecar/ by running the following:

    # chmod o-w <file>
    # chown envoy-sidecar:envoy-sidecar <file>

    or

    At the command prompt, correct permissions for Envoy log files in /var/log/vmware/envoy-system-proxy/ by running the following:

    # chmod o-w <file>
    # chown envoy-system-proxy:envoy-system-proxy <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag satisfies: ['SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag gid: 'V-VCFK-9X-000018'
  tag rid: 'SV-VCFK-9X-000018'
  tag stig_id: 'VCFK-9X-000018'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a']

  logfilesenvoy = command('find /var/log/vmware/envoy/ -type f -xdev').stdout
  if !logfilesenvoy.empty?
    logfilesenvoy.split.each do |fname|
      describe file(fname) do
        it { should_not be_writable.by('others') }
        its('owner') { should eq 'envoy' }
        its('group') { should eq 'envoy' }
      end
    end
  else
    describe 'No log files found...skipping.' do
      skip 'No log files found...skipping.'
    end
  end
  logfilesenvoyhgw = command('find /var/log/vmware/envoy-hgw/ -type f -xdev').stdout
  if !logfilesenvoyhgw.empty?
    logfilesenvoyhgw.split.each do |fname|
      describe file(fname) do
        it { should_not be_writable.by('others') }
        its('owner') { should eq 'envoy-hgw' }
        its('group') { should eq 'envoy-hgw' }
      end
    end
  else
    describe 'No log files found...skipping.' do
      skip 'No log files found...skipping.'
    end
  end
  logfilesenvoysc = command('find /var/log/vmware/envoy-sidecar/ -type f -xdev').stdout
  if !logfilesenvoysc.empty?
    logfilesenvoysc.split.each do |fname|
      describe file(fname) do
        it { should_not be_writable.by('others') }
        its('owner') { should eq 'envoy-sidecar' }
        its('group') { should eq 'envoy-sidecar' }
      end
    end
  else
    describe 'No log files found...skipping.' do
      skip 'No log files found...skipping.'
    end
  end
  logfilesenvoysp = command('find /var/log/vmware/envoy-system-proxy/ -type f -xdev').stdout
  if !logfilesenvoysp.empty?
    logfilesenvoysp.split.each do |fname|
      describe file(fname) do
        it { should_not be_writable.by('others') }
        its('owner') { should eq 'envoy-system-proxy' }
        its('group') { should eq 'envoy-system-proxy' }
      end
    end
  else
    describe 'No log files found...skipping.' do
      skip 'No log files found...skipping.'
    end
  end
end
