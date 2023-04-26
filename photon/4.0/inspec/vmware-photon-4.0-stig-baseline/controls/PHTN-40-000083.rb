control 'PHTN-40-000083' do
  title 'The Photon operating system must protect the auditd configuration from unauthorized modification.'
  desc  "
    Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

    Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has in order to make access decisions regarding the modification of audit tools.

    Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify permissions on the auditd.conf file:

    # stat -c \"%n is owned by %U and group owned by %G and permissions are %a\" /etc/audit/auditd.conf

    Expected result:

    /etc/audit/auditd.conf is owned by root and group owned by root and permissions are 640

    If the auditd.conf file is not owned by root or group owned by root or permissions are not 0640, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following commands:

    # chown root:root /etc/audit/auditd.conf
    # chmod 640 /etc/audit/auditd.conf
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000257-GPOS-00098'
  tag gid: 'V-PHTN-40-000083'
  tag rid: 'SV-PHTN-40-000083'
  tag stig_id: 'PHTN-40-000083'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']

  describe file('/etc/audit/auditd.conf') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    its('mode') { should cmp '0640' }
  end
end
