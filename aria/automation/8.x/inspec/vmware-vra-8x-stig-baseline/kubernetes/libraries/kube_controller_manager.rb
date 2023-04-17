require 'kubeprocess_baseresource'

class KubeControllerManager < KubeProcessBaseResource
  name 'kube_controller_manager'
  desc 'Custom resource to validate kube-controller-manager configs'
  example "
    describe kube_controller_manager do
      its('root-ca-file') { should_not be_nil }
    end

    describe kube_controller_manager('kube-controller-manager') do
      its('root-ca-file') { should_not be_nil }
    end
  "

  def initialize(process = nil)
    @process = process || inspec.kubernetes.controllermanager_bin

    # Component flag is used to identify component in K3S
    @component_flag = 'kube-controller-manager-arg' if @process.match(/k3s/)
    return skip_resource "Process #{@process} does not exist on the target node." unless inspec.processes(@process).exist?
  end
end
