control 'CFSS-4X-000001' do
  title 'The SDDC Manager SOS service log files must only be accessible by privileged users.'
  desc  'Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command(s):

    # find /var/log/sos* -xdev -type f -a '(' -not -perm 640 -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    # find /var/log/vmware/vcf/sddc-support/*.* -xdev -type f -a '(' -not -perm 640 -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.

    At the command prompt, run the following command:

    # find /var/log/vmware/vcf/sddc-support/*/* -xdev -type f -a '(' -not -perm 640 -o -not -user vcf -o -not -group vcf ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s):

    # chmod 640 <file>
    # chown root:root <file>

    If files are from a support bundle for example in this path /var/log/vmware/vcf/sddc-support/sos-2020-10-14-13-17-57-2080/* run the following command(s):

    # chmod 640 <file>
    # chown vcf:vcf <file>

    Note: Substitute <file> with the listed file.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag satisfies: ['SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFSS-4X-000001'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9', 'AU-9', 'AU-9']

  command('find /var/log/sos* -xdev -type f').stdout.split.each do |fname|
    describe file(fname) do
      its('group') { should cmp 'root' }
      its('owner') { should cmp 'root' }
      it { should_not be_more_permissive_than('0640') }
    end
  end
  command('find /var/log/vmware/vcf/sddc-support/*.* -xdev -type f').stdout.split.each do |fname|
    describe file(fname) do
      its('group') { should cmp 'root' }
      its('owner') { should cmp 'root' }
      it { should_not be_more_permissive_than('0640') }
    end
  end
  command('find /var/log/vmware/vcf/sddc-support/*/* -xdev -type f').stdout.split.each do |fname|
    describe file(fname) do
      its('group') { should cmp 'vcf' }
      its('owner') { should cmp 'vcf' }
      it { should_not be_more_permissive_than('0640') }
    end
  end
end
