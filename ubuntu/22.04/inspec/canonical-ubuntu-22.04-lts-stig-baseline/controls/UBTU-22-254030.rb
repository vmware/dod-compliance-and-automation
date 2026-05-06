control 'UBTU-22-254030' do
  title 'Ubuntu 22.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Verify that authenticated certificates are mapped to the appropriate user group in the "/etc/sssd/sssd.conf" file with the following command:

$ grep -i ldap_user_certificate /etc/sssd/sssd.conf
ldap_user_certificate=userCertificate;binary'
  desc 'fix', 'Configure sssd to map authenticated certificates to the appropriate user group by adding the following line to the "/etc/sssd/sssd.conf" file:

ldap_user_certificate=userCertificate;binary'
  impact 0.5
  tag check_id: 'C-78966r1101729_chk'
  tag severity: 'medium'
  tag gid: 'V-274865'
  tag rid: 'SV-274865r1101731_rule'
  tag stig_id: 'UBTU-22-254030'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-78871r1101730_fix'
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
