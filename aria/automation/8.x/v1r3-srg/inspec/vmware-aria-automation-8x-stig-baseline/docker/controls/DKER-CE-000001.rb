control 'DKER-CE-000001' do
  title 'Docker CE must not use insecure registries.'
  desc 'The authenticity and integrity of the container image during the container image lifecycle is part of the overall security posture of the container platform. This begins with the container image creation and pull of a base image from a trusted source for child container image creation and the instantiation of the new image into a running service. If an insecure protocol is used during transmission of container images at any step of the lifecycle, a bad actor may inject nefarious code into the container image. The container image, when instantiated, then becomes a security risk to the container platform, the host server, and other containers within the container platform.'
  desc 'rationale', ''
  desc 'check', "
    At the command prompt, execute the following command:

    # docker info

    Examine the Insecure Registries section, for example:

    Insecure Registries:
      127.0.0.0/8

    If there are any insecure registries configured that are not local to the host, this is a finding.
  "
  desc 'fix', "
    To remove an insecure registry, do the following:

    Navigate to and open:

    /etc/docker/daemon.json

    Find the \"insecure-registries\" line and remove any non-local insecure registries.

    Restart the docker daemon by running the following command:

    # systemctl restart docker.service

    Note: Insecure registries may also be specified as an arguement to the Docker daemon service and must be removed there if specified in that manner.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-CTR-000035'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'DKER-CE-000001'
  tag fix_id: nil
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  val = ['127.0.0.0/8']

  if !docker.info.RegistryConfig.empty?
    docker.info.RegistryConfig do |conf|
      conf.IndexConfigs.each_value do |reg|
        if reg.Secure
          describe "Checking registry: #{reg.Name}" do
            it '{ Registry should be secure }' do
              expect(reg.Secure).to be true
            end
          end
        else
          describe "Checking registry: #{reg.Name}" do
            skip "Manual check - { #{reg.Name} } - insecure registry must be local"
          end
        end
      end

      conf.InsecureRegistryCIDRs.each do |insecure|
        describe "Checking registry CIDR: #{insecure}" do
          it '{ Registry should be local }' do
            expect(insecure).to be_in val
          end
        end
      end
    end
  else
    describe 'Registry Config empty' do
      skip 'Registry Config empty...skipping tests'
    end
  end
end
