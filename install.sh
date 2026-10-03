#!/bin/bash
# Offline, configuration-preserving install/upgrade. Never starts services or changes routes.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
INSTALL_ARGS=("$@")
DESTDIR= CHECK=false CONFIG_SOURCE= DEFAULT_USER=${SUDO_USER:-${USER:-ubuntu}}
[[ $DEFAULT_USER != root ]] || DEFAULT_USER=ubuntu
fail() { echo "OneEgress install: $*" >&2; exit 1; }
usage() {
  echo '用法: sudo ./install.sh [--check] [--config FILE] [--user USER] [--destdir ABSOLUTE_DIR]'
  echo '安装/升级仅写入程序和首次配置；保留已有配置与登录状态，不启停服务、不改变路由。'
}
while (($#)); do
  case "$1" in
    --check) CHECK=true; shift ;;
    --config|--user|--destdir)
      (($# >= 2)) || fail "$1 需要参数"
      case "$1" in --config) CONFIG_SOURCE=$2 ;; --user) DEFAULT_USER=$2 ;; --destdir) DESTDIR=$2 ;; esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "未知参数: $1" ;;
  esac
done
[[ ${EGRESS_WORK_SHELL:-} != 1 ]] || fail '请先 exit 返回 SSH 管理窗口，不能在工作壳中安装。'
if [[ -n $DESTDIR ]]; then
  [[ $DESTDIR == /* && $DESTDIR != / && -d $DESTDIR && ! -L $DESTDIR ]] || fail '--destdir 必须是已有的非根绝对目录（只做文件打包，不管理账号或网络）。'
elif [[ $(id -u) != 0 ]]; then
  exec sudo -n -- /bin/bash "$PROJECT_DIR/install.sh" "${INSTALL_ARGS[@]}"
fi
[[ -n $DESTDIR || $(id -u) == 0 ]] || fail '请使用 sudo ./install.sh。'
for dependency in bash jq python3 install mktemp flock; do
  command -v "$dependency" >/dev/null || fail "缺少依赖 $dependency"
done
SOURCE=$PROJECT_DIR/bin/egress
TARGET=$DESTDIR/usr/local/sbin/egress
STATE_DIR=$DESTDIR/var/lib/tailscale-egress
CONFIG=$STATE_DIR/config.json
[[ -f $SOURCE ]] || fail '缺少 bin/egress；请解压完整发布包。'
bash -n "$SOURCE"
if [[ -z $DESTDIR ]]; then
  for dependency in tailscale tailscaled ip iptables ip6tables curl systemctl systemd-run getent useradd; do
    command -v "$dependency" >/dev/null || fail "缺少依赖 $dependency；见 README 安装前准备。"
  done
  [[ -c /dev/net/tun ]] || fail '缺少 /dev/net/tun'
  [[ $(systemctl is-enabled tailscaled 2>/dev/null || true) == masked ]] || fail '系统 tailscaled 必须已 masked；安装器不会自动修改管理网络。'
  [[ $(systemctl is-active tailscaled 2>/dev/null || true) == inactive ]] || fail '系统 tailscaled 必须 inactive。'
  [[ $(ip -4 route show default | awk '{print $5; exit}') == eth0 ]] || fail 'v0.1.0 仅支持管理默认网卡 eth0；不改当前路由。'
  [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]] || fail '隔离路由器需要宿主机 net.ipv4.ip_forward=1；请先由管理员确认转发策略，安装器不自动开启。'
  [[ $DEFAULT_USER =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$ ]] || fail '用户名无效'
  getent passwd "$DEFAULT_USER" >/dev/null || fail "工作壳用户不存在: $DEFAULT_USER；用 --user 指定已有用户。"
  if getent passwd egress >/dev/null; then
    [[ $(id -u egress) != 0 ]] || fail 'egress 不能是 uid 0'
    getent group egress >/dev/null || fail '已有 egress 用户缺少同名组；请先人工确认账号用途。'
  fi
fi
if [[ -f $CONFIG ]]; then
  [[ -z $CONFIG_SOURCE ]] || fail '已有配置时不接受 --config 覆盖；用 egress config 修改全局配置。'
  candidate=$(jq -c . "$CONFIG")
else
  if [[ -n $CONFIG_SOURCE ]]; then
    candidate=$(jq -c . "$CONFIG_SOURCE")
  else
    candidate=$(jq -c --arg user "$DEFAULT_USER" '.default_user=$user' "$PROJECT_DIR/config.example.json")
  fi
fi
# Share the application's validation rather than maintaining a second schema.
export ONEEGRESS_CONFIG_CANDIDATE=$candidate
bash -c 'source <(awk '\''/^# 只供受限 systemd 服务使用/{exit} {print}'\'' "$1"); validate_configuration "$ONEEGRESS_CONFIG_CANDIDATE"' -- "$SOURCE"
unset ONEEGRESS_CONFIG_CANDIDATE
$CHECK && { echo '安装预检通过；未写文件、未启停服务、未改变网络。'; exit 0; }
if [[ -z $DESTDIR ]]; then
  install -d -m 700 /run/tailscale-egress
  exec {install_lock}>>/run/tailscale-egress/control.lock
  chmod 600 /run/tailscale-egress/control.lock
  flock -n "$install_lock" || { echo '全局出口操作忙，未安装；请稍后重试。' >&2; exit 75; }
fi
if [[ -z $DESTDIR ]] && ! getent passwd egress >/dev/null; then
  if getent group egress >/dev/null; then
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid egress egress
  else
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --user-group egress
  fi
fi
install -d -m 755 "$DESTDIR/usr/local/sbin"
install -d -m 700 "$STATE_DIR"
program_temp=$(mktemp "$DESTDIR/usr/local/sbin/.oneegress.XXXXXX")
config_temp=
cleanup() {
  [[ -z ${program_temp:-} ]] || rm -f -- "$program_temp"
  [[ -z ${config_temp:-} ]] || rm -f -- "$config_temp"
}
trap cleanup EXIT
install -m 755 "$SOURCE" "$program_temp"
mv -f -- "$program_temp" "$TARGET"
program_temp=
if [[ ! -f $CONFIG ]]; then
  config_temp=$(mktemp "$STATE_DIR/.config.XXXXXX")
  jq . <<< "$candidate" > "$config_temp"
  chmod 600 "$config_temp"
  mv -n -- "$config_temp" "$CONFIG"
else
  echo '已有全局配置与 Tailscale 登录状态已保留。'
fi
"$TARGET" --version
echo '安装完成；未改变当前出口，未重启服务。首次使用见 README。'
