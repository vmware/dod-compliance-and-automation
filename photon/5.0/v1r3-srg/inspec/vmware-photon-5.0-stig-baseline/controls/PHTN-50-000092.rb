control 'PHTN-50-000092' do
  title 'The Photon operating system must use cryptographic mechanisms to protect the integrity of audit tools.'
  desc  "
    Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

    Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

    It is not uncommon for attackers to replace the audit tools or inject code into the existing tools with the purpose of providing the capability to hide or erase system activity from the audit logs.

    To address this risk, audit tools must be cryptographically signed in order to provide the capability to identify when the audit tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.
  "
  desc  'rationale', ''
  desc  'check', "
    Use the verification capability of rpm to check the MD5 hashes of the audit files on disk versus the expected ones from the installation package.

    At the command line, run the following command:

    # rpm -V audit | grep \"^..5\"

    Example output:

    S.5....T.  c /etc/audit/auditd.conf

    If there is any output for files that are not configuration files, this is a finding.
  "
  desc 'fix', "
    If the audit system binaries have been altered investigate the cause and then re-install the audit package to restore the integrity of the package.

    If performed on a VMware re-installing the audit tools is not supported. The appliance should be restored from a backup or redeployed once the root cause is remediated.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag gid: 'V-PHTN-50-000092'
  tag rid: 'SV-PHTN-50-000092'
  tag stig_id: 'PHTN-50-000092'
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']

  describe command('rpm -V audit | grep "^..5" | grep -v /etc/audit/auditd.conf') do
    its('stdout.strip') { should cmp '' }
    its('stderr') { should cmp '' }
  end
end
