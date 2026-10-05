# OneEgress

单一共享出口，断线不回落。项目：[zylimit/OneEgress](https://github.com/zylimit/OneEgress)。

所有工作壳（包括不同 Linux 用户）共用一个出口节点。`switch` 全局生效，`shell` 只选用户。出口不可用时联网请求失败；SSH 管理网络保留原路线。唯一出口节点不等于固定公网 IP，运营商 NAT 可能为不同目标分配不同地址。

v0.1.1 起，同一内部端口 `10.200.0.1:1055` 同时支持 HTTP/CONNECT 和 SOCKS5。工作壳自动将 `HTTP_PROXY` / `HTTPS_PROXY`（含小写）设为 `http://10.200.0.1:1055`，`ALL_PROXY` 保留 SOCKS。[Claude Code 不支持 SOCKS](https://code.claude.com/docs/en/network-config)，因此使用 HTTP/CONNECT；不解密 HTTPS，不安装额外证书，两种协议都复用同一受隔离保护的隧道连接函数。代理仅面向受信任的本机工作壳，不是公开代理。

## 首版支持范围

Ubuntu 24.04、systemd、管理默认网卡 `eth0`、`/dev/net/tun`，管理员已确认宿主机 IPv4 转发策略（`net.ipv4.ip_forward=1`）。不是整机 VPN，也不会把普通 SSH 窗口自动改成工作出口。root / sudo 主动绕过隔离不在保证范围内；程序已经失败的请求是否自动重试由程序决定。

依赖：Tailscale、curl、jq、iproute2、iptables（含 IPv6）、Python 3、util-linux。Tailscale 请按[官方安装说明](https://tailscale.com/docs/install)安装；本项目不运行远程安装脚本、不自动安装依赖。

v0.1.3 起，系统 `tailscaled` 可以运行并承担 Peer Relay，WireGuard 可保留独立私网。宿主机不得选择 Tailscale 出口或启用路由导入；IPv4 管理默认路由必须唯一且走 `eth0`，其他策略表和 IPv6 也不得将公共流量导向其他接口。检查同时验证普通管理流量和隔离路由器传输的实际路由。安装器只检查，不停止系统服务、不擅自修改管理路由或其他组件防火墙。旧版本仍要求系统 Tailscale 停用，不可直接按新版本规则放行旧代码。

## 下载与安装

从 [Releases](https://github.com/zylimit/OneEgress/releases) 下载指定版本和校验文件。推荐固定版本，不执行 `curl | sudo bash`。

```bash
curl -fLO https://github.com/zylimit/OneEgress/releases/download/v0.1.3/oneegress-v0.1.3.tar.gz
curl -fLO https://github.com/zylimit/OneEgress/releases/download/v0.1.3/SHA256SUMS
sha256sum -c SHA256SUMS
tar -xzf oneegress-v0.1.3.tar.gz
cd oneegress-0.1.3
sudo ./install.sh --check
sudo ./install.sh
egress --version
```

现有机器升级使用相同命令。安装/升级保留 `/var/lib/tailscale-egress/config.json` 和 Tailscale 登录状态，不自动切换出口、不重启共享服务。新功能涉及代理服务时，需在维护窗口手动切换/重建后验收，不能把“更新文件”当作运行中进程已经更新。

升级至 v0.1.3 后，在管理窗口执行 `egress repair` 迁移私有 DNS：会中断所有工作壳的当前代理连接、重启隔离 Tailscale 和应用代理，但不停止宿主机中继、不改 WireGuard/Docker、不改路由和防火墙、不切换出口、不关闭工作壳。仅支持已有隔离服务和可确认的唯一出口；失败时保持代理不可用，不尝试其他设备。两个服务的私有 `/etc` 使用只读 DNS/NSS 文件和必要运行文件，不跟随宿主机 `resolv.conf` 的改写或软链接替换。普通 `reload` 不能迁移旧挂载；检查不合格时会明确要求 `repair`。

v0.1.1 升至 v0.1.2 只改公网探测策略，安装即生效，无需 `egress reload`、重新进壳或重启服务。SOCKS/HTTP 公网探测每次握手期限 15 秒、总期限 20 秒；仅 curl `28`（超时）在同一出口重试一次。连接拒绝、SOCKS 失败、证书错误、HTTP 错误、无效响应不会因此重试或被当作成功。三个公网探测最坏合计约 120 秒，另有宿主机与隔离检查耗时。重试不代表自动重试应用请求，也不切换/回落其他出口；完整验收条件不变。

从 v0.1.0 升至 v0.1.1，安装后在普通 SSH 管理窗口执行 `egress reload`，只重启共享应用代理并验收，保留 Tailscale、当前节点、工作壳与防火墙；已有代理连接会中断。此命令要求现有服务与硬隔离已经就绪，不负责重新配置网络。已开的工作壳环境不会随文件更新：在旧工作壳 `exit`，然后 `egress shell` 再执行 `claude`。也可以在旧工作壳只刷新代理环境而不退出：

```bash
export HTTPS_PROXY=http://10.200.0.1:1055 https_proxy=http://10.200.0.1:1055
export HTTP_PROXY="$HTTPS_PROXY" http_proxy="$HTTPS_PROXY"
claude
```

不要仅修改代理 URL 而不更新/重载服务；v0.1.0 的服务不会处理 HTTP。不要为了兼容而取消代理或退出工作隔离后运行应用。

## 新机器首次配置

安装器只创建全局空配置；不会复制作者的出口地址或账号。工作壳默认使用安装时的已有登录用户，必要时安装用 `--user ubuntu` 指定已有用户。每个用户不需要另外配置。

```bash
# 首次只启动隔离登录服务，不启动应用 SOCKS，不选出口。
egress init
sudo tailscale --socket=/run/tailscale-egress/tailscaled.sock up \
  --hostname=egress-proxy --accept-dns=false --netfilter-mode=off --advertise-exit-node=false

# 填入你自己的 Tailscale IPv4，不是公网 IP；以下 100.x.y.z 必须替换。
egress config node iphone 100.x.y.z
egress config node ipad 100.x.y.z
egress config node mudi 100.x.y.z
egress config switch iphone
egress switch iphone
```

出口设备须同一尾网、联网、宣告 exit node 并在 Tailscale 后台获准。不要运行省略 `--socket` 的出口设置命令：那会操作宿主机 Tailscale，而不是 OneEgress。Peer Relay 的配置与工作出口选择是两回事。

## 日常命令

```bash
egress check                  # 只读：当前节点、公网 IP、运营商、隔离
egress reload                 # 升级后仅重载共享代理；已有网络连接会中断
egress repair                 # 迁移/修复私有 DNS，重建隔离服务，保留当前节点
egress test                   # 短暂阻断代理隧道，影响所有工作壳联网；自动恢复并验收
egress switch ipad            # 全局切换；所有工作壳的后续连接使用此出口
egress shell                  # 默认用户，当前共享出口
egress shell ubuntu           # 只改变登录用户，不创建私有出口
egress config                 # 唯一全局配置
egress config switch ipad     # 下次 switch 的默认目标，不立即切换
egress config shell ubuntu    # 下次 shell 的默认用户
exit                          # 离开本工作壳；清理其后台进程，保留共享代理
```

管理命令从普通 SSH 窗口执行，不在 `[work:...]` 壳内执行。多个管理窗口同时写配置/切换时，第二次操作返回 `75`，不会排队执行一个过时切换。`check` 返回 `0` 已确认、`1` 不安全、`2` 无法确认。

紧急停止：在管理窗口执行 `sudo egress down`，它会停止共享服务并关闭**全部**工作壳。不要用它代替普通 `exit`。兼容的 `enter` 只进入当前共享出口；v0.1.3 的旧 `up/start` 等价于 `switch`，不再自动尝试候选，旧 mudi/phone/home 偏好命令已停用。

`egress test` 先验收正常出口，在独立路由器的代理 UID 隔离链临时加入 IPv4/IPv6 隧道 REJECT，以固定 IP 测试 SOCKS、HTTP、绕过代理直连均失败，再删除本工具的临时规则、核对原硬隔离并验收同一节点。不关闭 TUN、不改路由、不阻断 root Tailscale 的控制/中继传输。全局锁防止其他窗口同时切换；正常退出和 INT/TERM/HUP 会尝试清理。SIGKILL、断电无法执行清理：最坏保持断网，可在管理窗口 `egress repair` 清理已知测试阻断并重建服务；不自动切换出口。该测试不是实际手机断网、设备掉电、账号登录或所有目标网站的完整证明。

目前服务/命名空间仍由显式命令创建，使用临时 systemd 单元；不要把本次运行验收当作整机重启后自动恢复保障。暂不自动添加开机切换或出口回退。宿主机控制 socket 对工作用户的进一步收口、长期连接超时和防火墙归属梳理是后续独立验收项。sudo/root/docker/lxd 等有权绕过隔离的管理员不在防误用保证范围内。

## 每次部署的手动验收

在同一个工作壳重复：

```bash
curl -4 -fsS --max-time 15 https://ipinfo.io/json
```

1. 联网时：核对设备和预期供应商；不能是宿主机出口。
2. 手动关闭出口设备网络：必须失败，不能回落宿主机。
3. 恢复设备网络：同一工作壳的新请求恢复，无需重新进入。
4. 另一个管理窗口 `egress switch ipad` 验收通过后，原工作壳的新请求使用新出口。
5. `egress check` 的固定 IP 直连测试必须失败；只看到 DNS 失败不足以证明无泄漏。

## 持续迭代

```bash
python3 tests/test_project.py
bash scripts/build.sh
```

源码只在 `bin/egress` 维护，安装路径 `/usr/local/sbin/egress` 是部署产物。测试使用临时目录、模拟状态，不停本机服务、不测试作者的设备。人工验收不替代自动测试，自动测试也不替代真实设备断线验收。

修改代码后更新 `ONEEGRESS_VERSION`、CHANGELOG 和测试；提交至 `main` 触发 CI；测试通过再创建并推送相同版本标签（如 `v0.1.1`）。标签工作流再次测试、打包并发布带 SHA256 的下载资产。不使用强推或移动已经发布的版本标签，不上传本机配置、状态、密钥。
