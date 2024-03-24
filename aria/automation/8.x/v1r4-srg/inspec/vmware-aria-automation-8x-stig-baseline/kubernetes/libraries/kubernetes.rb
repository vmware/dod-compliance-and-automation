# source: https://github.com/dev-sec/cis-kubernetes-benchmark

class Kubernetes < Inspec.resource(1)
  name 'kubernetes'
  desc 'Custom resource which abstracts the various kubernetes runtimes like k3s'

  def initialize
    @is_k3s = inspec.file('/usr/local/bin/k3s').file?
  end

  def apiserver_bin
    @is_k3s ? 'k3s server' : 'kube-apiserver'
  end

  def scheduler_bin
    @is_k3s ? 'k3s server' : 'kube-scheduler'
  end

  def controllermanager_bin
    @is_k3s ? 'k3s server' : 'kube-controller-manager'
  end

  def kubelet_bin
    @is_k3s ? 'k3s*' : 'kubelet'
  end

  def kube_proxy_bin
    @is_k3s ? 'k3s*' : 'kube-proxy'
  end
end
