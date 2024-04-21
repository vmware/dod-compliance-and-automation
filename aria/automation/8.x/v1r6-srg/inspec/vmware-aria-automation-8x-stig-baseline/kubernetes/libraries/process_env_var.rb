# source: https://github.com/dev-sec/cis-kubernetes-benchmark

class ProcessEnvVar < Inspec.resource(1)
  name 'process_env_var'
  desc 'Custom resource to lookup environment variables for a process'
  example "
    describe process_env_var('etcd') do
      its(:ETCD_DATA_DIR) { should match(%r{/var/lib/etcd2}) }
    end
  "

  def initialize(process)
    @process = inspec.processes(process)
    return skip_resource "Process #{@process} does not exist on the target node." unless @process.exist?
  end

  def method_missing(name)
    read_params[name.to_s] || nil
  end

  def params
    @params ||= read_params
  end

  def read_params
    return @params if defined?(@params)

    @file = inspec.file("/proc/#{@process.pids.first}/environ")
    unless @file.file?
      skip_resource "Can't find environ file for #{@process}"
      return @params = {}
    end

    @content = @file.content
    if @content.empty? && !@file.empty?
      skip_resource "Can't read environ file for #{@process}"
      return @params = {}
    end

    @params = @content.split("\0").map { |i| i.split('=', 2) }.to_h
  end

  def to_s
    "Environment variables for #{@process}"
  end
end
