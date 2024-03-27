control 'CNTR-K8-003160' do
  title 'The Kubernetes Kubelet certificate authority file must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes kubelet certificate authority file contains settings for the Kubernetes Node TLS certificate authority. Any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate. If this file can be changed, the Kubernetes architecture could be compromised. The scheduler will implement the changes immediately. Many of the security settings within the document are implemented through this file.'
  desc 'check', "Change to the /etc/sysconfig/ directory on the Kubernetes Control Plane. Run command:
more kubelet
--client-ca-file argument
Note certificate location

If the ca-file argument location file has permissions more permissive than \"644\", this is a finding."
  desc 'fix', "Change the permissions of the --client-ca-file to \"644\" by executing the command:

chmod 644 &lt;kubelet --client--ca-file argument location&gt;."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-242449'
  tag rid: 'SV-242449r864021_rule'
  tag stig_id: 'CNTR-K8-003160'
  tag fix_id: 'F-45682r821613_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  kubelet_conf_path = input('kubelet_conf_path')

  client_ca_file = if kubelet_conf_path
                     kubelet_config_file(kubelet_conf_path).params.dig('authentication', 'x509', 'clientCAFile')
                   else
                     kubelet_config_file.params.dig('authentication', 'x509', 'clientCAFile')
                   end

  describe.one do
    describe kubelet do
      its('client_ca_file') { should_not be_nil }
      its('client_ca_file') { should_not be_more_permissive_than('0644') }
    end
    describe file(client_ca_file) do
      it { should_not be_more_permissive_than('0644') }
    end
  end
end
