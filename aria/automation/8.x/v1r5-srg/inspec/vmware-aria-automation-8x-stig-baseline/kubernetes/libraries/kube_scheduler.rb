require 'kubeprocess_baseresource'

class KubeScheduler < KubeProcessBaseResource
  name 'kube_scheduler'
  desc 'Custom resource to validate kube-scheduler configs'
  example "
    describe kube_scheduler do
      its('allow-privileged') { should cmp 'true' }
    end

    describe kube_scheduler('kube-scheduler') do
      its('port') { should cmp 0 }
    end
  "

  def initialize(process = nil)
    @process = process || inspec.kubernetes.scheduler_bin

    # Component flag is used to identify component in K3S
    @component_flag = 'kube-scheduler-arg' if @process.match(/k3s/)
    return skip_resource "Process #{@process} does not exist on the target node." unless inspec.processes(@process).exist?
  end
end
