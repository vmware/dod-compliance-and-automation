control 'UBTU-24-600060' do
  title 'Ubuntu 24.04 LTS must use DOD PKI-established certificate authorities (CAs) for verification of the establishment of protected sessions.'
  desc 'Untrusted CAs can issue certificates, but they may be issued by organizations or individuals that seek to compromise DOD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DOD-approved CA, trust of this CA has not been established.

The DOD will only accept PKI-certificates obtained from a DOD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.'
  desc 'check', 'Verify the directory containing the root certificates for Ubuntu 24.04 LTS contains certificate files for DOD PKI-established CAs by iterating over all files in the "/etc/ssl/certs" directory and checking if, at least one, has the subject matching "DOD ROOT CA".

$ grep -ir DOD /etc/ssl/certs
DOD_PKE_CA_chain.pem

If no root certificate is found, this is a finding.'
  desc 'fix', %q(Configure Ubuntu 24.04 LTS to use of DOD PKI-established CAs for verification of the establishment of protected sessions.

Edit the "/etc/ca-certificates.conf" file, adding the character "!" to the beginning of all uncommented lines that do not start with the "!" character with the following command:

$ sudo sed -i -E 's/^([^!#]+)/!\1/' /etc/ca-certificates.conf

Add at least one CA to the "/usr/local/share/ca-certificates" directory in the PEM format.

Update the "/etc/ssl/certs" directory with the following command:

$ sudo update-ca-certificates)
  impact 0.5
  tag check_id: 'C-74778r1066722_chk'
  tag severity: 'medium'
  tag gid: 'V-270745'
  tag rid: 'SV-270745r1066724_rule'
  tag stig_id: 'UBTU-24-600060'
  tag gtitle: 'SRG-OS-000403-GPOS-00182'
  tag fix_id: 'F-74679r1066723_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']

  cert_files = command('find /etc/ssl/certs -type f').stdout.split
  cert_subjects = []
  if cert_files.any?
    cert_files.each do |cert|
      cert_info = x509_certificate(cert)
      if cert_info&.subject&.CN
        cert_subjects.push(cert_info.subject.CN)
      end
    end
    describe 'Root Certificates' do
      it 'should have at least one DOD root certificate' do
        expect(cert_subjects.any? { |subj| subj =~ /dod root ca (\d+)|dod root ca/i }).to be true
      end
    end
  else
    describe cert_files.count do
      it { should_not be 0 }
    end
  end
end
