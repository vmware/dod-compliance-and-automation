require 'kubeprocess_baseresource'

class Kubelet < KubeProcessBaseResource
  name 'kubelet'
  desc 'Custom resource to validate kubelet configs'
  example "
    describe kubelet do
      its('anonymous-auth') { should cmp 'false' }
    end

    describe kubelet('kubelet') do
      its('network-plugin') { should cmp 'cni' }
    end
  "

  def initialize(process = nil)
    @process = process || inspec.kubernetes.kubelet_bin

    # Component flag is used to identify component in K3S
    @component_flag = 'kubelet-arg' if @process.match(/k3s/)
    return skip_resource "Process #{@process} does not exist on the target node." unless inspec.processes(@process).exist?
  end

  def config_file
    inspec.file(params['config'].join) if params['config']
  end

  def kubeconfig_file
    inspec.file(params['kubeconfig'].join) if params['kubeconfig']
  end

  def client_ca_file
    inspec.file(params['client-ca-file'].join) if params['client-ca-file']
  end
end
