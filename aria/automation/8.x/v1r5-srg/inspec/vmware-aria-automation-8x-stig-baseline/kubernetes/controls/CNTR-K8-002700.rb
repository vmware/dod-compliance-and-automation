control 'CNTR-K8-002700' do
  title 'Kubernetes must remove old components after updated versions have been installed.'
  desc 'Previous versions of Kubernetes components that are not removed after updates have been installed may be exploited by adversaries by allowing the vulnerabilities to still exist within the cluster. It is important for Kubernetes to remove old pods when newer pods are created using new images to always be at the desired security state.'
  desc 'check', "To view all pods and the images used to create the pods, from the Control Plane, run the following command:
kubectl get pods --all-namespaces -o jsonpath=\"{..image}\" | \\
tr -s '[[:space:]]' '\\n' | \\
sort | \\
uniq -c

Review the images used for pods running within Kubernetes.

If there are multiple versions of the same image, this is a finding."
  desc 'fix', "Remove any old pods that are using older images. On the Control Plane, run the command:
kubectl delete pod podname
(Note: \"podname\" is the name of the pod to delete.)"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000454-CTR-001110'
  tag gid: 'V-242442'
  tag rid: 'SV-242442r864014_rule'
  tag stig_id: 'CNTR-K8-002700'
  tag fix_id: 'F-45675r863906_fix'
  tag cci: ['CCI-002647']
  tag nist: ['SI-4 d']

  describe 'Verify old images are not used to create pods.' do
    skip 'This is a manual check.'
  end
end
