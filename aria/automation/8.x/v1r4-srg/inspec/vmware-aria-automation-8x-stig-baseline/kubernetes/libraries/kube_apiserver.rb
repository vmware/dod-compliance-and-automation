require 'kubeprocess_baseresource'

class KubeAPIServer < KubeProcessBaseResource
  name 'kube_apiserver'
  desc 'Custom resource to validate kube-apiserver configs'
  example "
    describe kube_apiserver do
      its('allow-privileged') { should cmp 'true' }
    end

    describe kube_apiserver('kube-apiserver') do
      its('insecure-port') { should cmp 0 }
    end
  "

  def initialize(process = nil)
    @process = process || inspec.kubernetes.apiserver_bin

    # Component flag is used to identify component in K3S
    @component_flag = 'kube-apiserver-arg' if @process.match(/k3s/)
    return skip_resource "Process #{@process} does not exist on the target node." unless inspec.processes(@process).exist?
  end

  def tls_cipher_suites
    suites = params['tls-cipher-suites']
    suites.nil? ? [] : suites.join.split(',')
  end
end
