control 'CNTR-K8-000430' do
  title 'Kubernetes Kubectl cp command must give expected access and results.'
  desc 'One of the tools heavily used to interact with containers in the Kubernetes cluster is kubectl. The command is the tool System Administrators used to create, modify, and delete resources. One of the capabilities of the tool is to copy files to and from running containers (i.e., kubectl cp). The command uses the "tar" command of the container to copy files from the container to the host executing the "kubectl cp" command. If the "tar" command on the container has been replaced by a malicious user, the command can copy files anywhere on the host machine. This flaw has been fixed in later versions of the tool. It is recommended to use kubectl versions newer than 1.12.9.'
  desc 'check', "From the Control Plane and each Worker node, check the version of kubectl by executing the command:

kubectl version --client

If the Control Plane or any Worker nodes are not using kubectl version 1.12.9 or newer, this is a finding."
  desc 'fix', 'Upgrade the Control Plane and Worker nodes to the latest version of kubectl.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag gid: 'V-242396'
  tag rid: 'SV-242396r863972_rule'
  tag stig_id: 'CNTR-K8-000430'
  tag fix_id: 'F-45629r863789_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  kubectl = command(input('kubectl_path'))

  kubectl_minversion = input('kubectl_minversion')

  unless kubectl.exist?
    impact 0.0
    desc 'caveat', 'kubectl command not available on target.'
  end

  if kubectl.exist?
    describe json(command: "#{input('kubectl_path')} version --client --output=json") do
      its(['clientVersion', 'gitVersion']) { should cmp >= kubectl_minversion }
    end
  end
end
