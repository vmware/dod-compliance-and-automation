control 'PHTN-30-000051' do
  title 'The Photon operating system package files must not be modified.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Without confidence in the integrity of the auditing system and tools, the information it provides cannot be trusted.'
  desc 'check', 'Use the verification capability of rpm to check the MD5 hashes of the audit files on disk versus the expected ones from the installation package.

At the command line, run the following command:

# rpm -V audit | grep "^..5" | grep -v "^...........c"

If there is any output, this is a finding.'
  desc 'fix', 'If the audit system binaries have been altered, the system must be taken offline and the information system security manager (ISSM) notified immediately.

Reinstalling the audit tools is not supported. The appliance should be restored from a backup or redeployed once the root cause is remediated.'
  impact 0.5
  tag check_id: 'C-60200r887247_chk'
  tag severity: 'medium'
  tag gid: 'V-256525'
  tag rid: 'SV-256525r887249_rule'
  tag stig_id: 'PHTN-30-000051'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag fix_id: 'F-60143r887248_fix'
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']

  describe command('rpm -V audit | grep "^..5" | grep -v "^...........c"') do
    its('stdout') { should eq '' }
  end
end
