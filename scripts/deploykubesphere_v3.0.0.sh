#!/bin/bash
echo $(date) " - ############## Starting Script ####################"

export CloudName=$1
export ResourceGroup=$2
export resourceName=$3



function install_azure_cli(){
  apt-get update
  sudo apt-get install -y jq
  sudo apt-get install unzip

  TF_VERSION=$(curl -s https://checkpoint-api.hashicorp.com/v1/check/terraform | jq -r -M ".current_version")
  wget -O terraform.zip https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_amd64.zip
  wget -O terraform.sha256 https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_SHA256SUMS
  wget -O terraform.sha256.sig https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_SHA256SUMS.sig
  curl -s https://keybase.io/hashicorp/pgp_keys.asc | gpg --import
  gpg --verify terraform.sha256.sig terraform.sha256
  echo $(grep -Po "[[:xdigit:]]{64}(?=\s+terraform_${TF_VERSION}_linux_amd64.zip)" terraform.sha256) terraform.zip | sha256sum -c
  unzip terraform.zip
  mv terraform /usr/local/bin
  rm -f terraform terraform.zip terraform.sha256 terraform.sha256.sig
  unset TF_VERSION

  echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ wheezy main" | sudo tee /etc/apt/sources.list.d/azure-cli.list
  sudo curl -L https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
  sudo apt-get install apt-transport-https
  sudo apt-get update && sudo apt-get install azure-cli
}

 function login_azure(){
  if [[ "$CloudName" == AzureChinaCloud ]];then
    az cloud set -n AzureChinaCloud
  fi
  az login --identity
  if [ $? -eq 0 ];then
      echo "azure cloud login succeed"
  else
      echo "azure cloud login failed,please check MSI status."
  fi
 }

function get_kubeconfig(){
  az aks install-cli
  az aks get-credentials --resource-group "$ResourceGroup" --name "$resourceName"
}

function check_kubernetes_status(){
  echo $(date) " - Deploy KubeSphere"
  for i in $(seq 10 -1 1)
  do
    sudo kubectl get nodes
    if [ $? -eq 0 ];then
        echo "KubeSphere installing..."
        break
    else
      echo "$i"
      get_kubeconfig
      sleep 5
    fi
  done
}

# install Azure CLI
echo $(date) " - Install Azure-cli"
install_azure_cli
echo $(date) " - Install Azure-cli Complete"

# login Azure
echo $(date) " - Login Azure"
login_azure
echo $(date) " - Login Azure complete"

# get kubeconfig
echo $(date) " - Get kubeconfig"
get_kubeconfig
echo $(date) " - Get kubeconfig complete"

# check kubernetes status
echo $(date) " - check kubernetes status"
check_kubernetes_status
echo $(date) " - check kubernetes status complete"



## deploy KubeSphere
cat >>/tmp/kubesphere-installer.yaml<<EOF
---
apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  name: clusterconfigurations.installer.kubesphere.io
spec:
  group: installer.kubesphere.io
  versions:
  - name: v1alpha1
    served: true
    storage: true
  scope: Namespaced
  names:
    plural: clusterconfigurations
    singular: clusterconfiguration
    kind: ClusterConfiguration
    shortNames:
    - cc

---
apiVersion: v1
kind: Namespace
metadata:
  name: kubesphere-system

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ks-installer
  namespace: kubesphere-system

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ks-installer
rules:
- apiGroups:
  - ""
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - apps
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - extensions
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - batch
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - apiregistration.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - apiextensions.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - tenant.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - certificates.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - devops.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - monitoring.coreos.com
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - logging.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - jaegertracing.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - storage.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - admissionregistration.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - policy
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - autoscaling
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - networking.istio.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - config.istio.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - iam.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - notification.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - auditing.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - events.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - core.kubefed.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - installer.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - storage.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'

---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: ks-installer
subjects:
- kind: ServiceAccount
  name: ks-installer
  namespace: kubesphere-system
roleRef:
  kind: ClusterRole
  name: ks-installer
  apiGroup: rbac.authorization.k8s.io

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ks-installer
  namespace: kubesphere-system
  labels:
    app: ks-install
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ks-install
  template:
    metadata:
      labels:
        app: ks-install
    spec:
      serviceAccountName: ks-installer
      containers:
      - name: installer
        image: kubesphere/ks-installer:v3.0.0
        imagePullPolicy: "Always"
        volumeMounts:
        - mountPath: /etc/localtime
          name: host-time
      volumes:
      - hostPath:
          path: /etc/localtime
          type: ""
        name: host-time
EOF

cat >>/tmp/cluster-configuration.yaml<<EOF
---
apiVersion: installer.kubesphere.io/v1alpha1
kind: ClusterConfiguration
metadata:
  name: ks-installer
  namespace: kubesphere-system
  labels:
    version: v3.0.0
spec:
  persistence:
    storageClass: ""        # If there is not a default StorageClass in your cluster, you need to specify an existing StorageClass here.
  authentication:
    jwtSecret: ""           # Keep the jwtSecret consistent with the host cluster. Retrive the jwtSecret by executing "kubectl -n kubesphere-system get cm kubesphere-config -o yaml | grep -v "apiVersion" | grep jwtSecret" on the host cluster.
  etcd:
    monitoring: false       # Whether to enable etcd monitoring dashboard installation. You have to create a secret for etcd before you enable it.
    endpointIps: localhost  # etcd cluster EndpointIps, it can be a bunch of IPs here.
    port: 2379              # etcd port
    tlsEnable: true
  common:
    mysqlVolumeSize: 20Gi # MySQL PVC size.
    minioVolumeSize: 20Gi # Minio PVC size.
    etcdVolumeSize: 20Gi  # etcd PVC size.
    openldapVolumeSize: 2Gi   # openldap PVC size.
    redisVolumSize: 2Gi # Redis PVC size.
    es:   # Storage backend for logging, events and auditing.
      # elasticsearchMasterReplicas: 1   # total number of master nodes, it's not allowed to use even number
      # elasticsearchDataReplicas: 1     # total number of data nodes.
      elasticsearchMasterVolumeSize: 4Gi   # Volume size of Elasticsearch master nodes.
      elasticsearchDataVolumeSize: 20Gi    # Volume size of Elasticsearch data nodes.
      logMaxAge: 7                     # Log retention time in built-in Elasticsearch, it is 7 days by default.
      elkPrefix: logstash              # The string making up index names. The index name will be formatted as ks-<elk_prefix>-log.
  console:
    enableMultiLogin: true  # enable/disable multiple sing on, it allows an account can be used by different users at the same time.
    port: 30880
  alerting:                # (CPU: 0.3 Core, Memory: 300 MiB) Whether to install KubeSphere alerting system. It enables Users to customize alerting policies to send messages to receivers in time with different time intervals and alerting levels to choose from.
    enabled: false
  auditing:                # Whether to install KubeSphere audit log system. It provides a security-relevant chronological set of records，recording the sequence of activities happened in platform, initiated by different tenants.
    enabled: false
  devops:                  # (CPU: 0.47 Core, Memory: 8.6 G) Whether to install KubeSphere DevOps System. It provides out-of-box CI/CD system based on Jenkins, and automated workflow tools including Source-to-Image & Binary-to-Image.
    enabled: false
    jenkinsMemoryLim: 2Gi      # Jenkins memory limit.
    jenkinsMemoryReq: 1500Mi   # Jenkins memory request.
    jenkinsVolumeSize: 8Gi     # Jenkins volume size.
    jenkinsJavaOpts_Xms: 512m  # The following three fields are JVM parameters.
    jenkinsJavaOpts_Xmx: 512m
    jenkinsJavaOpts_MaxRAM: 2g
  events:                  # Whether to install KubeSphere events system. It provides a graphical web console for Kubernetes Events exporting, filtering and alerting in multi-tenant Kubernetes clusters.
    enabled: false
    ruler:
      enabled: true
      replicas: 2
  logging:                 # (CPU: 57 m, Memory: 2.76 G) Whether to install KubeSphere logging system. Flexible logging functions are provided for log query, collection and management in a unified console. Additional log collectors can be added, such as Elasticsearch, Kafka and Fluentd.
    enabled: false
    logsidecarReplicas: 2
  metrics_server:                    # (CPU: 56 m, Memory: 44.35 MiB) Whether to install metrics-server. IT enables HPA (Horizontal Pod Autoscaler).
    enabled: false
  monitoring:
    # prometheusReplicas: 1            # Prometheus replicas are responsible for monitoring different segments of data source and provide high availability as well.
    prometheusMemoryRequest: 400Mi   # Prometheus request memory.
    prometheusVolumeSize: 20Gi       # Prometheus PVC size.
    # alertmanagerReplicas: 1          # AlertManager Replicas.
  multicluster:
    clusterRole: none  # host | member | none  # You can install a solo cluster, or specify it as the role of host or member cluster.
  networkpolicy:       # Network policies allow network isolation within the same cluster, which means firewalls can be set up between certain instances (Pods).
    # Make sure that the CNI network plugin used by the cluster supports NetworkPolicy. There are a number of CNI network plugins that support NetworkPolicy, including Calico, Cilium, Kube-router, Romana and Weave Net.
    enabled: false
  notification:        # Email Notification support for the legacy alerting system, should be enabled/disabled together with the above alerting option.
    enabled: false
  openpitrix:          # (2 Core, 3.6 G) Whether to install KubeSphere Application Store. It provides an application store for Helm-based applications, and offer application lifecycle management.
    enabled: false
  servicemesh:         # (0.3 Core, 300 MiB) Whether to install KubeSphere Service Mesh (Istio-based). It provides fine-grained traffic management, observability and tracing, and offer visualization for traffic topology.
    enabled: false
EOF


function deploy_kubesphere(){
  sudo kubectl apply -f /tmp/kubesphere-installer.yaml
  sudo kubectl apply -f  /tmp/cluster-configuration.yaml
  if [ $? -eq 0 ];then
      echo "cc deployed"
  else
      echo "KubeSphere install failed,please check the network status or execute the command:"
  fi
}

function check_installer_ok(){
    echo "waiting for ks-installer pod ready"
    sudo kubectl -n kubesphere-system wait --timeout=180s --for=condition=Ready $(sudo kubectl -n kubesphere-system get pod -l app=ks-install -oname)
    echo "waiting for KubeSphere ready"
    while IFS= read -r line; do
        echo $line
        if [[ $line =~ "Welcome to KubeSphere" ]]
            then
                return
        fi
    done < <(sudo timeout 1200 kubectl logs -n kubesphere-system deploy/ks-installer -f)
    echo "ks-install not output 'Welcome to KubeSphere'"
}

function wait_status_ok(){
    for ((n=0;n<30;n++))
    do
        OK=`sudo kubectl get pod -A| grep -E 'Running|Completed' | wc | awk '{print $1}'`
        Status=`sudo kubectl get pod -A | sed '1d' | wc | awk '{print $1}'`
        echo "Success rate: ${OK}/${Status}"
        if [[ $OK == $Status ]]
        then
            n=$((n+1))
        else
            n=0
            sudo kubectl get pod -A | grep -vE 'Running|Completed'
        fi
        sleep 1
    done
}

function set_kubernetes_lb(){
  sudo kubectl get svc ks-console -n kubesphere-system -o yaml | sed "s/NodePort/LoadBalancer/g" | sudo kubectl apply -f -
  if [ $? -eq 0 ];then
    echo $(date) " - set KubeSphere loadbalance Complete"
  else
    echo $(date) " - set KubeSphere loadbalance failed"
  fi
  sudo kubectl rollout restart deployments ks-console -n kubesphere-system
}

function set_user_kubeconfig(){
  User=`users`
  cp -rp /root/.kube /home/${User}/
  chown -R ${User}.${User} /home/${User}/.kube
}

# deploy kubesphere
echo $(date) " - Deploy KubeSphere"
deploy_kubesphere
echo $(date) " - Deploy KubeSphere Complete"

# check kubesphere status
echo $(date) " - Check KubeSphere status"
export -f wait_status_ok

timeout 1800 bash -c wait_status_ok

check_installer_ok
echo $(date) " - ks-installer Complete"



# set loadbalance
echo $(date) " - set KubeSphere loadbalance"
set_kubernetes_lb
echo $(date) " - set KubeSphere loadbalance Complete"

# set admin user kubeconfig
set_user_kubeconfig

# message of login kubesphere
PIP=`sudo kubectl get svc ks-console -n kubesphere-system|grep "LoadBalancer"|awk '{print $4}'`
echo "欢迎使用kubesphere"
echo "登陆地址为: http://$PIP"
echo "默认管理员用户为: admin"
echo "默认密码为: P@88w0rd"
echo ""
echo "登陆后请修改默认密码。"
echo "登陆后请在集群管理中检查服务状态，直到所有服务状态为Ready。"