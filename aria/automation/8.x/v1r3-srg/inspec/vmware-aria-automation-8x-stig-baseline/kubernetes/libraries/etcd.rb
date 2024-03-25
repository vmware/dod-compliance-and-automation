require 'kubeprocess_baseresource'

class Etcd < KubeProcessBaseResource
  # class Etcd < Inspec.resource(1)
  name 'etcd'
  desc 'Custom resource to validate etcd configs'
  example "
    describe etcd do
      its('allow-privileged') { should cmp 'true' }
    end

    describe etcd('etcd') do
      its('port') { should cmp 0 }
    end
  "

  def initialize(process = nil)
    @process = process || 'etcd'
    return skip_resource "Process #{@process} does not exist on the target node." unless inspec.processes(@process).exist?
  end
end
