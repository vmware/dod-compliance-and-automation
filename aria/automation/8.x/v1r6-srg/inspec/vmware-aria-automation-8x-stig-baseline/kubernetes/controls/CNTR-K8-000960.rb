control 'CNTR-K8-000960' do
  title 'The Kubernetes cluster must use non-privileged host ports for user pods.'
  desc 'Privileged ports are those ports below 1024 and that require system privileges for their use. If containers can use these ports, the container must be run as a privileged user. Kubernetes must stop containers that try to map to these ports directly. Allowing non-privileged ports to be mapped to the container-privileged port is the allowable method when a certain port is needed. An example is mapping port 8080 externally to port 80 in the container.'
  desc 'check', 'On the Control Plane, run the command:
kubectl get pods --all-namespaces

The list returned is all pods running within the Kubernetes cluster. For those pods running within the user namespaces (System namespaces are kube-system, kube-node-lease and kube-public), run the command:
kubectl get pod podname -o yaml | grep -i port

Note: In the above command, "podname" is the name of the pod. For the command to work correctly, the current context must be changed to the namespace for the pod. The command to do this is:

kubectl config set-context --current --namespace=namespace-name
(Note: "namespace-name" is the name of the namespace.)

Review the ports that are returned for the pod.

If any host-privileged ports are returned for any of the pods, this is a finding.'
  desc 'fix', 'For any of the pods that are using host-privileged ports, reconfigure the pod to use a service to map a host non-privileged port to the pod port or reconfigure the image to use non-privileged ports.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45689r863835_chk'
  tag severity: 'medium'
  tag gid: 'V-242414'
  tag rid: 'SV-242414r879588_rule'
  tag stig_id: 'CNTR-K8-000960'
  tag gtitle: 'SRG-APP-000142-CTR-000330'
  tag fix_id: 'F-45647r717032_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  kubeconfig = input('kubectl_conf_path')
  pods = json({ command: "kubectl get pods --all-namespaces --kubeconfig=#{kubeconfig} -o=json" })['items']
  if pods.nil?
    impact 0.0
    describe 'No Pods found' do
      skip 'No Pods Found!'
    end
  else
    pods.each do |pod|
      next unless pod['metadata']['namespace'] != 'kube-system' && pod['metadata']['namespace'] != 'kube-public' && pod['metadata']['namespace'] != 'kube-node-lease'
      name = pod['metadata']['name']
      if pod['spec']['containers'].nil?
        describe 'No Containers found' do
          skip "No Containers Found for Pod: #{name}!"
        end
      else
        pod['spec']['containers'].each do |container|
          cname = container['name']
          if container['ports'].nil?
            describe 'No Container Ports Found' do
              skip "No Container Ports Found for Pod: #{name} Container: #{cname}!"
            end
          else
            container['ports'].each do |port|
              p = port['containerPort'].to_i
              describe 'Pod:' do
                it "#{name} Container: #{cname} --> Port #{p} should be greater than 1024" do
                  expect(p).to be > 1024
                end
              end
            end
          end
        end
      end
    end
  end
end
