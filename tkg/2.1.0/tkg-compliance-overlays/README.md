# TKG Compliance Configs
Formerly TKG Compliance Overlays for pre TKG 2.1 please see the [legacy](tkg/README.md) folder or if you are deploying TKG 2.1 with legacy enabled.
1

## STIG
Starting with TKG 2.1 STIG compliance can be handled by simply adding the contents of [stig.conf](clusterconfigs/stig.conf) to your clusterconfig file or vice versa.

Alternatively you can export the below:

```bash
export ETCD_EXTRA_ARGS="auto-tls=false;peer-auto-tls=false;cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384"
export KUBE_CONTROLLER_MANAGER_EXTRA_ARGS="tls-min-version=VersionTLS12;profiling=false;tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384"
export WORKER_KUBELET_EXTRA_ARGS="streaming-connection-idle-timeout=5m;tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384;protect-kernel-defaults=true"
export APISERVER_EXTRA_ARGS="tls-min-version=VersionTLS12;tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384"
export KUBE_SCHEDULER_EXTRA_ARGS="tls-min-version=VersionTLS12;tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384"
export CONTROLPLANE_KUBELET_EXTRA_ARGS="streaming-connection-idle-timeout=5m;tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384;protect-kernel-defaults=true"
export ENABLE_AUDIT_LOGGING=true
```

### Results

* [Management Cluster](https://heimdall.k8s.pcfpci.io/results/619,616)
* [Workload Cluster](https://heimdall.k8s.pcfpci.io/results/618,617)
## CIS
Starting with TKG 2.1 CIS Compliance can be ostly accomplished with using environment variables or by appending the contents of [cis.conf](clusterconfigs/cis.conf) to your clusterconfig file.

The env vars can be set as follows:


```bash
export ETCD_EXTRA_ARGS="auto-tls=false;peer-auto-tls=false;cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256"
export KUBE_CONTROLLER_MANAGER_EXTRA_ARGS="profiling=false;terminated-pod-gc-threshold=500;tls-min-version=VersionTLS12;profiling=false;tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256"
export WORKER_KUBELET_EXTRA_ARGS="read-only-port=0;authorization-mode=Webhook;client-ca-file=/etc/kubernetes/pki/ca.crt;event-qps=0;make-iptables-util-chains=true;streaming-connection-idle-timeout=5m;tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256;protect-kernel-defaults=true"
export APISERVER_EXTRA_ARGS="enable-admission-plugins=AlwaysPullImages,NodeRestriction;profiling=false;service-account-lookup=true;tls-min-version=VersionTLS12;tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256"
export KUBE_SCHEDULER_EXTRA_ARGS="profiling=false;tls-min-version=VersionTLS12;tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256"
export CONTROLPLANE_KUBELET_EXTRA_ARGS="read-only-port=0;authorization-mode=Webhook;client-ca-file=/etc/kubernetes/pki/ca.crt;event-qps=0;make-iptables-util-chains=true;streaming-connection-idle-timeout=5m;tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256;protect-kernel-defaults=true"
export ENABLE_AUDIT_LOGGING=true
export APISERVER_EVENT_RATE_LIMIT_CONF_BASE64="YXBpVmVyc2lvbjogZXZlbnRyYXRlbGltaXQuYWRtaXNzaW9uLms4cy5pby92MWFscGhhMQpraW5kOiBDb25maWd1cmF0aW9uCmxpbWl0czoKLSB0eXBlOiBOYW1lc3BhY2UKICBxcHM6IDUwCiAgYnVyc3Q6IDEwMAogIGNhY2hlU2l6ZTogMjAwMAotIHR5cGU6IFVzZXIKICBxcHM6IDEwCiAgYnVyc3Q6IDUwCg=="

```


## Event Rate limit
The [cis.conf](clusterconfigs/cis.conf) and env vars above have the base64 encoded contents of this [config.yaml]((clusterconfigs/config.yaml)). If these defaults are not sufficient the base64 variable in cis.conf will need to be updated or the environment variable will need to be set.

In order to set the event rate limit run the below commands and edit the contents of the yaml below if they are not to the customers needs.
```bash
cat <<EOF > config.yaml
apiVersion: eventratelimit.admission.k8s.io/v1alpha1
kind: Configuration
limits:
- type: Namespace
  qps: 50
  burst: 100
  cacheSize: 2000
- type: User
  qps: 10
  burst: 50
EOF
```

On a mac:
```bash 
export APISERVER_EVENT_RATE_LIMIT_CONF_BASE64=$(base64 -b 0 config.yaml)
```
On linux:
```bash 
export APISERVER_EVENT_RATE_LIMIT_CONF_BASE64=$(base64 -w 0 config.yaml)
```

If you would like to edit the [config.yaml](clusterconfigs/config.yaml) directly to get the base64 value run:

On a mac:
```bash 
base64 -b 0 config.yaml
```

On linux:
```bash
base64 -w 0 config.yaml
```

## Encryption Config

The encryption configuration can not be set via ENV Var and a workaround is not available yet. The encyrption configuration for management clusters can not be set but a [custom cluster class] (https://docs.vmware.com/en/VMware-Tanzu-Kubernetes-Grid/2.1/using-tkg-21/workload-clusters-cclass.html) could be utilized for workload clusters to apply this.

### Results

* [Management Cluster](https://heimdall.k8s.pcfpci.io/results/624,625)
* [Workload Cluster](https://heimdall.k8s.pcfpci.io/results/626,627)

# Explanations/Exceptions

A new explanation and exception document has not been created yet for TKG 2.X.

# Serving Certs
A soltuion for serving certs is in progress as there is a bug with feature gates or any extra argument that has an equal sign in it such as feature-gates=RotateServerCertificates.

https://jira.eng.vmware.com/browse/TKG-17292

And 

https://jira.eng.vmware.com/browse/TKG-17405

