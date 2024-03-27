control 'CNTR-K8-003340' do
  title 'The Kubernetes PKI keys must have file permissions set to 600 or more restrictive.'
  desc 'The Kubernetes PKI directory contains all certificate key files supporting secure network communications in the Kubernetes Control Plane. If these files can be modified, data traversing within the architecture components would become unsecure and compromised.'
  desc 'check', "Review the permissions of the Kubernetes PKI key files by using the command:

find /etc/kubernetes/pki -name \"*.key\" | xargs stat -c '%n %a'

If any of the files are have permissions more permissive than \"600\", this is a finding."
  desc 'fix', "Change the ownership of the cert files to \"600\" by executing the command:

chmod -R 600 /etc/kubernetes/pki/*.key"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'V-242467'
  tag rid: 'SV-242467r712757_rule'
  tag stig_id: 'CNTR-K8-003340'
  tag fix_id: 'F-45700r712756_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  pki_path = input('pki_path')
  pki_files = command("find #{pki_path}/ -name \"*.key\"").stdout.split

  if pki_files.empty?
    desc 'caveat', "Kubernetes PKI files not present of the target at specified path #{pki_path}."
    describe "Kubernetes PKI files not present of the target at specified path #{pki_path}." do
      skip
    end
  end

  pki_files.each do |file_name|
    describe file(file_name) do
      it { should_not be_more_permissive_than('0600') }
    end
  end
end
