control 'UBTU-24-400370' do
  title 'Ubuntu 24.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Verify that authenticated certificates are mapped to the appropriate user group in the "/etc/sssd/sssd.conf" file with the following command:

$ grep -i ldap_user_certificate /etc/sssd/sssd.conf
ldap_user_certificate=userCertificate;binary'
  desc 'fix', 'Configure sssd to map authenticated certificates to the appropriate user group by adding the following line to the "/etc/sssd/sssd.conf" file:

ldap_user_certificate=userCertificate;binary'
  impact 0.7
  tag check_id: 'C-74769r1066695_chk'
  tag severity: 'high'
  tag gid: 'V-270736'
  tag rid: 'SV-270736r1066697_rule'
  tag stig_id: 'UBTU-24-400370'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag fix_id: 'F-74670r1066696_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']

  sssd_conf_path = input('sssd_conf_path')

  if file(sssd_conf_path).exist?
    describe file(sssd_conf_path) do
      its('content') { should match(/^\s*ldap_user_certificate\s*=\s*userCertificate;binary\s*$/i) }
    end
  else
    describe file(sssd_conf_path) do
      it { should exist }
    end
  end
end
