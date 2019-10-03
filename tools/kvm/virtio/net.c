#include "kvm/virtio-pci-dev.h"
#include "kvm/virtio-net.h"
#include "kvm/virtio.h"
#include "kvm/types.h"
#include "kvm/mutex.h"
#include "kvm/util.h"
#include "kvm/kvm.h"
#include "kvm/irq.h"
#include "kvm/uip.h"
#include "kvm/guest_compat.h"
#include "kvm/iovec.h"

#include <linux/vhost.h>
#include <linux/virtio_net.h>
#include <linux/if_tun.h>
#include <linux/types.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/eventfd.h>

#define VIRTIO_NET_QUEUE_SIZE		256
#define VIRTIO_NET_NUM_QUEUES		8

struct net_dev;

struct net_dev_operations {
	int (*rx)(struct iovec *iov, u16 in, struct net_dev *ndev);
	int (*tx)(struct iovec *iov, u16 in, struct net_dev *ndev);
};

struct pthread_data {
	pthread_t			thread;
	struct mutex			lock;
	pthread_cond_t			cond;
} __attribute__((aligned(128)));


struct net_dev {
	struct mutex			mutex;
	struct virtio_device		vdev;
	struct list_head		list;

	struct virt_queue		vqs[VIRTIO_NET_NUM_QUEUES * 2 + 1];
	struct virtio_net_config	config;
	u32				features, rx_vqs, tx_vqs, queue_pairs;

	struct pthread_data		io[VIRTIO_NET_NUM_QUEUES * 2 + 1];

	int				vhost_fd;
	int				tap_fd;
	char				tap_name[IFNAMSIZ];

	int				mode;

	struct uip_info			info;
	struct net_dev_operations	*ops;
	struct kvm			*kvm;

	struct virtio_net_params	*params;
};

static LIST_HEAD(ndevs);
static int compat_id = -1;

#define MAX_PACKET_SIZE 65550

static bool has_virtio_feature(struct net_dev *ndev, u32 feature)
{
	return ndev->features & (1 << feature);
}

static void virtio_net_fix_tx_hdr(struct virtio_net_hdr *hdr, struct net_dev *ndev)
{
	hdr->hdr_len		= virtio_guest_to_host_u16(&ndev->vdev, hdr->hdr_len);
	hdr->gso_size		= virtio_guest_to_host_u16(&ndev->vdev, hdr->gso_size);
	hdr->csum_start		= virtio_guest_to_host_u16(&ndev->vdev, hdr->csum_start);
	hdr->csum_offset	= virtio_guest_to_host_u16(&ndev->vdev, hdr->csum_offset);
}

static void virtio_net_fix_rx_hdr(struct virtio_net_hdr_mrg_rxbuf *hdr, struct net_dev *ndev)
{
	hdr->hdr.hdr_len	= virtio_host_to_guest_u16(&ndev->vdev, hdr->hdr.hdr_len);
	hdr->hdr.gso_size	= virtio_host_to_guest_u16(&ndev->vdev, hdr->hdr.gso_size);
	hdr->hdr.csum_start	= virtio_host_to_guest_u16(&ndev->vdev, hdr->hdr.csum_start);
	hdr->hdr.csum_offset	= virtio_host_to_guest_u16(&ndev->vdev, hdr->hdr.csum_offset);
	if (has_virtio_feature(ndev, VIRTIO_NET_F_MRG_RXBUF))
		hdr->num_buffers	= virtio_host_to_guest_u16(&ndev->vdev, hdr->num_buffers);
}

static void *virtio_net_rx_thread(void *p)
{
	struct iovec iov[VIRTIO_NET_QUEUE_SIZE];
	struct virt_queue *vq;
	struct kvm *kvm;
	struct net_dev *ndev = p;
	u16 out, in;
	u16 head;
	int len, copied;
	u32 id;

	mutex_lock(&ndev->mutex);
	id = ndev->rx_vqs++ * 2;
	mutex_unlock(&ndev->mutex);

	kvm__set_thread_name("virtio-net-rx");

	kvm = ndev->kvm;
	vq = &ndev->vqs[id];

	while (1) {
		mutex_lock(&ndev->io[id].lock);
		if (!virt_queue__available(vq)) {
			pthread_cond_wait(&ndev->io[id].cond, &ndev->io[id].lock.mutex);
		}
		mutex_unlock(&ndev->io[id].lock);

		while (virt_queue__available(vq)) {
			unsigned char buffer[MAX_PACKET_SIZE + sizeof(struct virtio_net_hdr_mrg_rxbuf)];
			struct iovec dummy_iov = {
				.iov_base = buffer,
				.iov_len  = sizeof(buffer),
			};
			struct virtio_net_hdr_mrg_rxbuf *hdr;
			int i;

			len = ndev->ops->rx(&dummy_iov, 1, ndev);
			if (len < 0) {
				pr_warning("%s: rx on vq %u failed (%d), exiting thread\n",
						__func__, id, len);
				goto out_err;
			}

			copied = i = 0;
			head = virt_queue__get_iov(vq, iov, &out, &in, kvm);
			hdr = iov[0].iov_base;
			while (copied < len) {
				size_t iovsize = min_t(size_t, len - copied, iov_size(iov, in));

				memcpy_toiovec(iov, buffer + copied, iovsize);
				copied += iovsize;
				if (i++ == 0)
					virtio_net_fix_rx_hdr(hdr, ndev);
				if (has_virtio_feature(ndev, VIRTIO_NET_F_MRG_RXBUF)) {
					u16 num_buffers = virtio_guest_to_host_u16(vq, hdr->num_buffers);
					hdr->num_buffers = virtio_host_to_guest_u16(vq, num_buffers + 1);
				}
				virt_queue__set_used_elem(vq, head, iovsize);
				if (copied == len)
					break;
				while (!virt_queue__available(vq))
					sleep(0);
				head = virt_queue__get_iov(vq, iov, &out, &in, kvm);
			}
			/* We should interrupt guest right now, otherwise latency is huge. */
			if (virtio_queue__should_signal(vq))
				ndev->vdev.ops->signal_vq(kvm, &ndev->vdev, id);
		}
	}

out_err:
	pthread_exit(NULL);
	return NULL;

}

static void *virtio_net_tx_thread(void *p)
{
	struct iovec iov[VIRTIO_NET_QUEUE_SIZE];
	struct virt_queue *vq;
	struct kvm *kvm;
	struct net_dev *ndev = p;
	u16 out, in;
	u16 head;
	int len;
	u32 id;

	mutex_lock(&ndev->mutex);
	id = ndev->tx_vqs++ * 2 + 1;
	mutex_unlock(&ndev->mutex);

	kvm__set_thread_name("virtio-net-tx");

	kvm = ndev->kvm;
	vq = &ndev->vqs[id];

	while (1) {
		mutex_lock(&ndev->io[id].lock);
		if (!virt_queue__available(vq))
			pthread_cond_wait(&ndev->io[id].cond, &ndev->io[id].lock.mutex);
		mutex_unlock(&ndev->io[id].lock);

		while (virt_queue__available(vq)) {
			struct virtio_net_hdr *hdr;
			head = virt_queue__get_iov(vq, iov, &out, &in, kvm);
			hdr = iov[0].iov_base;
			virtio_net_fix_tx_hdr(hdr, ndev);
			len = ndev->ops->tx(iov, out, ndev);
			if (len < 0) {
				pr_warning("%s: tx on vq %u failed (%d)\n",
						__func__, id, errno);
				goto out_err;
			}

			virt_queue__set_used_elem(vq, head, len);
		}

		if (virtio_queue__should_signal(vq))
			ndev->vdev.ops->signal_vq(kvm, &ndev->vdev, id);
	}

out_err:
	pthread_exit(NULL);
	return NULL;
}

static virtio_net_ctrl_ack virtio_net_handle_mq(struct kvm* kvm, struct net_dev *ndev, struct virtio_net_ctrl_hdr *ctrl)
{
	/* Not much to do here */
	return VIRTIO_NET_OK;
}

static void *virtio_net_ctrl_thread(void *p)
{
	struct iovec iov[VIRTIO_NET_QUEUE_SIZE];
	u16 out, in, head;
	struct net_dev *ndev = p;
	struct kvm *kvm = ndev->kvm;
	u32 id = ndev->queue_pairs * 2;
	struct virt_queue *vq = &ndev->vqs[id];
	struct virtio_net_ctrl_hdr *ctrl;
	virtio_net_ctrl_ack *ack;

	kvm__set_thread_name("virtio-net-ctrl");

	while (1) {
		mutex_lock(&ndev->io[id].lock);
		if (!virt_queue__available(vq))
			pthread_cond_wait(&ndev->io[id].cond, &ndev->io[id].lock.mutex);
		mutex_unlock(&ndev->io[id].lock);

		while (virt_queue__available(vq)) {
			head = virt_queue__get_iov(&ndev->vqs[id], iov, &out, &in, kvm);
			ctrl = iov[0].iov_base;
			ack = iov[out].iov_base;

			switch (ctrl->class) {
			case VIRTIO_NET_CTRL_MQ:
				*ack = virtio_net_handle_mq(kvm, ndev, ctrl);
				break;
			default:
				*ack = VIRTIO_NET_ERR;
				break;
			}
			virt_queue__set_used_elem(&ndev->vqs[id], head, iov[out].iov_len);
		}

		if (virtio_queue__should_signal(&ndev->vqs[id]))
			ndev->vdev.ops->signal_vq(kvm, &ndev->vdev, id);
	}

	pthread_exit(NULL);

	return NULL;
}

static void virtio_net_handle_callback(struct kvm *kvm, struct net_dev *ndev, int queue)
{
	if ((u32)queue >= (ndev->queue_pairs * 2 + 1)) {
		pr_warning("Unknown queue index %u", queue);
		return;
	}

	mutex_lock(&ndev->io[queue].lock);
	pthread_cond_signal(&ndev->io[queue].cond);
	mutex_unlock(&ndev->io[queue].lock);
}

static bool virtio_net__tap_init(struct net_dev *ndev)
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	int pid, status, offload, hdr_len;
	struct sockaddr_in sin = {0};
	struct ifreq ifr;
	const struct virtio_net_params *params = ndev->params;
	bool skipconf = !!params->tapif;

	/* Did the user already gave us the FD? */
	if (params->fd) {
		ndev->tap_fd = params->fd;
		return 1;
	}

	ndev->tap_fd = open("/dev/net/tun", O_RDWR);
	if (ndev->tap_fd < 0) {
		pr_warning("Unable to open /dev/net/tun");
		goto fail;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
	if (params->tapif)
		strncpy(ifr.ifr_name, params->tapif, sizeof(ifr.ifr_name));
	if (ioctl(ndev->tap_fd, TUNSETIFF, &ifr) < 0) {
		pr_warning("Config tap device error. Are you root?");
		goto fail;
	}

	strncpy(ndev->tap_name, ifr.ifr_name, sizeof(ndev->tap_name));

	if (ioctl(ndev->tap_fd, TUNSETNOCSUM, 1) < 0) {
		pr_warning("Config tap device TUNSETNOCSUM error");
		goto fail;
	}

	hdr_len = has_virtio_feature(ndev, VIRTIO_NET_F_MRG_RXBUF) ?
			sizeof(struct virtio_net_hdr_mrg_rxbuf) :
			sizeof(struct virtio_net_hdr);
	if (ioctl(ndev->tap_fd, TUNSETVNETHDRSZ, &hdr_len) < 0)
		pr_warning("Config tap device TUNSETVNETHDRSZ error");

	offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_UFO;
	if (ioctl(ndev->tap_fd, TUNSETOFFLOAD, offload) < 0) {
		pr_warning("Config tap device TUNSETOFFLOAD error");
		goto fail;
	}

	if (strcmp(params->script, "none")) {
		pid = fork();
		if (pid == 0) {
			execl(params->script, params->script, ndev->tap_name, NULL);
			_exit(1);
		} else {
			waitpid(pid, &status, 0);
			if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
				pr_warning("Fail to setup tap by %s", params->script);
				goto fail;
			}
		}
	} else if (!skipconf) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ndev->tap_name, sizeof(ndev->tap_name));
		sin.sin_addr.s_addr = inet_addr(params->host_ip);
		memcpy(&(ifr.ifr_addr), &sin, sizeof(ifr.ifr_addr));
		ifr.ifr_addr.sa_family = AF_INET;
		if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
			pr_warning("Could not set ip address on tap device");
			goto fail;
		}
	}

	if (!skipconf) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ndev->tap_name, sizeof(ndev->tap_name));
		ioctl(sock, SIOCGIFFLAGS, &ifr);
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0)
			pr_warning("Could not bring tap device up");
	}

	close(sock);

	return 1;

fail:
	if (sock >= 0)
		close(sock);
	if (ndev->tap_fd >= 0)
		close(ndev->tap_fd);

	return 0;
}

static inline int tap_ops_tx(struct iovec *iov, u16 out, struct net_dev *ndev)
{
	return writev(ndev->tap_fd, iov, out);
}

static inline int tap_ops_rx(struct iovec *iov, u16 in, struct net_dev *ndev)
{
	return readv(ndev->tap_fd, iov, in);
}

static inline int uip_ops_tx(struct iovec *iov, u16 out, struct net_dev *ndev)
{
	return uip_tx(iov, out, &ndev->info);
}

static inline int uip_ops_rx(struct iovec *iov, u16 in, struct net_dev *ndev)
{
	return uip_rx(iov, in, &ndev->info);
}

static struct net_dev_operations tap_ops = {
	.rx	= tap_ops_rx,
	.tx	= tap_ops_tx,
};

static struct net_dev_operations uip_ops = {
	.rx	= uip_ops_rx,
	.tx	= uip_ops_tx,
};

static u8 *get_config(struct kvm *kvm, void *dev)
{
	struct net_dev *ndev = dev;

	return ((u8 *)(&ndev->config));
}

static u32 get_host_features(struct kvm *kvm, void *dev)
{
	struct net_dev *ndev = dev;

	return 1UL << VIRTIO_NET_F_MAC
		| 1UL << VIRTIO_NET_F_CSUM
		| 1UL << VIRTIO_NET_F_HOST_UFO
		| 1UL << VIRTIO_NET_F_HOST_TSO4
		| 1UL << VIRTIO_NET_F_HOST_TSO6
		| 1UL << VIRTIO_NET_F_GUEST_UFO
		| 1UL << VIRTIO_NET_F_GUEST_TSO4
		| 1UL << VIRTIO_NET_F_GUEST_TSO6
		| 1UL << VIRTIO_RING_F_EVENT_IDX
		| 1UL << VIRTIO_RING_F_INDIRECT_DESC
		| 1UL << VIRTIO_NET_F_CTRL_VQ
		| 1UL << VIRTIO_NET_F_MRG_RXBUF
		| 1UL << (ndev->queue_pairs > 1 ? VIRTIO_NET_F_MQ : 0);
}

static int virtio_net__vhost_set_features(struct net_dev *ndev)
{
	u64 features = 1UL << VIRTIO_RING_F_EVENT_IDX;
	u64 vhost_features;

	if (ioctl(ndev->vhost_fd, VHOST_GET_FEATURES, &vhost_features) != 0)
		die_perror("VHOST_GET_FEATURES failed");

	/* make sure both side support mergable rx buffers */
	if (vhost_features & 1UL << VIRTIO_NET_F_MRG_RXBUF &&
			has_virtio_feature(ndev, VIRTIO_NET_F_MRG_RXBUF))
		features |= 1UL << VIRTIO_NET_F_MRG_RXBUF;

	return ioctl(ndev->vhost_fd, VHOST_SET_FEATURES, &features);
}

static void set_guest_features(struct kvm *kvm, void *dev, u32 features)
{
	struct net_dev *ndev = dev;
	struct virtio_net_config *conf = &ndev->config;

	ndev->features = features;

	conf->status = virtio_host_to_guest_u16(&ndev->vdev, conf->status);
	conf->max_virtqueue_pairs = virtio_host_to_guest_u16(&ndev->vdev,
							     conf->max_virtqueue_pairs);

	if (ndev->mode == NET_MODE_TAP) {
		if (!virtio_net__tap_init(ndev))
			die_perror("You have requested a TAP device, but creation of one has failed because");
		if (ndev->vhost_fd &&
				virtio_net__vhost_set_features(ndev) != 0)
			die_perror("VHOST_SET_FEATURES failed");
	} else {
		ndev->info.vnet_hdr_len = has_virtio_feature(ndev, VIRTIO_NET_F_MRG_RXBUF) ?
						sizeof(struct virtio_net_hdr_mrg_rxbuf) :
						sizeof(struct virtio_net_hdr);
		uip_init(&ndev->info);
	}
}

static bool is_ctrl_vq(struct net_dev *ndev, u32 vq)
{
	return vq == (u32)(ndev->queue_pairs * 2);
}

static int init_vq(struct kvm *kvm, void *dev, u32 vq, u32 page_size, u32 align,
		   u32 pfn)
{
	struct vhost_vring_state state = { .index = vq };
	struct vhost_vring_addr addr;
	struct net_dev *ndev = dev;
	struct virt_queue *queue;
	void *p;
	int r;

	compat__remove_message(compat_id);

	queue		= &ndev->vqs[vq];
	queue->pfn	= pfn;
	p		= virtio_get_vq(kvm, queue->pfn, page_size);

	vring_init(&queue->vring, VIRTIO_NET_QUEUE_SIZE, p, align);
	virtio_init_device_vq(&ndev->vdev, queue);

	mutex_init(&ndev->io[vq].lock);
	pthread_cond_init(&ndev->io[vq].cond, NULL);
	if (is_ctrl_vq(ndev, vq)) {
		pthread_create(&ndev->io[vq].thread, NULL, virtio_net_ctrl_thread, ndev);

		return 0;
	} else if (ndev->vhost_fd == 0 ) {
		if (vq & 1)
			pthread_create(&ndev->io[vq].thread, NULL, virtio_net_tx_thread, ndev);
		else
			pthread_create(&ndev->io[vq].thread, NULL, virtio_net_rx_thread, ndev);

		return 0;
	}

	if (queue->endian != VIRTIO_ENDIAN_HOST)
		die_perror("VHOST requires VIRTIO_ENDIAN_HOST");

	state.num = queue->vring.num;
	r = ioctl(ndev->vhost_fd, VHOST_SET_VRING_NUM, &state);
	if (r < 0)
		die_perror("VHOST_SET_VRING_NUM failed");
	state.num = 0;
	r = ioctl(ndev->vhost_fd, VHOST_SET_VRING_BASE, &state);
	if (r < 0)
		die_perror("VHOST_SET_VRING_BASE failed");

	addr = (struct vhost_vring_addr) {
		.index = vq,
		.desc_user_addr = (u64)(unsigned long)queue->vring.desc,
		.avail_user_addr = (u64)(unsigned long)queue->vring.avail,
		.used_user_addr = (u64)(unsigned long)queue->vring.used,
	};

	r = ioctl(ndev->vhost_fd, VHOST_SET_VRING_ADDR, &addr);
	if (r < 0)
		die_perror("VHOST_SET_VRING_ADDR failed");

	return 0;
}

static void notify_vq_gsi(struct kvm *kvm, void *dev, u32 vq, u32 gsi)
{
	struct net_dev *ndev = dev;
	struct kvm_irqfd irq;
	struct vhost_vring_file file;
	int r;

	if (ndev->vhost_fd == 0)
		return;

	irq = (struct kvm_irqfd) {
		.gsi	= gsi,
		.fd	= eventfd(0, 0),
	};
	file = (struct vhost_vring_file) {
		.index	= vq,
		.fd	= irq.fd,
	};

	r = ioctl(kvm->vm_fd, KVM_IRQFD, &irq);
	if (r < 0)
		die_perror("KVM_IRQFD failed");

	r = ioctl(ndev->vhost_fd, VHOST_SET_VRING_CALL, &file);
	if (r < 0)
		die_perror("VHOST_SET_VRING_CALL failed");
	file.fd = ndev->tap_fd;
	r = ioctl(ndev->vhost_fd, VHOST_NET_SET_BACKEND, &file);
	if (r != 0)
		die("VHOST_NET_SET_BACKEND failed %d", errno);

}

static void notify_vq_eventfd(struct kvm *kvm, void *dev, u32 vq, u32 efd)
{
	struct net_dev *ndev = dev;
	struct vhost_vring_file file = {
		.index	= vq,
		.fd	= efd,
	};
	int r;

	if (ndev->vhost_fd == 0 || is_ctrl_vq(ndev, vq))
		return;

	r = ioctl(ndev->vhost_fd, VHOST_SET_VRING_KICK, &file);
	if (r < 0)
		die_perror("VHOST_SET_VRING_KICK failed");
}

static int notify_vq(struct kvm *kvm, void *dev, u32 vq)
{
	struct net_dev *ndev = dev;

	virtio_net_handle_callback(kvm, ndev, vq);

	return 0;
}

static int get_pfn_vq(struct kvm *kvm, void *dev, u32 vq)
{
	struct net_dev *ndev = dev;

	return ndev->vqs[vq].pfn;
}

static int get_size_vq(struct kvm *kvm, void *dev, u32 vq)
{
	/* FIXME: dynamic */
	return VIRTIO_NET_QUEUE_SIZE;
}

static int set_size_vq(struct kvm *kvm, void *dev, u32 vq, int size)
{
	/* FIXME: dynamic */
	return size;
}

static struct virtio_ops net_dev_virtio_ops = (struct virtio_ops) {
	.get_config		= get_config,
	.get_host_features	= get_host_features,
	.set_guest_features	= set_guest_features,
	.init_vq		= init_vq,
	.get_pfn_vq		= get_pfn_vq,
	.get_size_vq		= get_size_vq,
	.set_size_vq		= set_size_vq,
	.notify_vq		= notify_vq,
	.notify_vq_gsi		= notify_vq_gsi,
	.notify_vq_eventfd	= notify_vq_eventfd,
};

static void virtio_net__vhost_init(struct kvm *kvm, struct net_dev *ndev)
{
	struct kvm_mem_bank *bank;
	struct vhost_memory *mem;
	int r, i;

	ndev->vhost_fd = open("/dev/vhost-net", O_RDWR);
	if (ndev->vhost_fd < 0)
		die_perror("Failed openning vhost-net device");

	mem = calloc(1, sizeof(*mem) + kvm->mem_slots * sizeof(struct vhost_memory_region));
	if (mem == NULL)
		die("Failed allocating memory for vhost memory map");

	i = 0;
	list_for_each_entry(bank, &kvm->mem_banks, list) {
		mem->regions[i] = (struct vhost_memory_region) {
			.guest_phys_addr = bank->guest_phys_addr,
			.memory_size	 = bank->size,
			.userspace_addr	 = (unsigned long)bank->host_addr,
		};
		i++;
	}
	mem->nregions = i;

	r = ioctl(ndev->vhost_fd, VHOST_SET_OWNER);
	if (r != 0)
		die_perror("VHOST_SET_OWNER failed");

	r = ioctl(ndev->vhost_fd, VHOST_SET_MEM_TABLE, mem);
	if (r != 0)
		die_perror("VHOST_SET_MEM_TABLE failed");

	ndev->vdev.use_vhost = true;

	free(mem);
}

static inline void str_to_mac(const char *str, char *mac)
{
	sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		mac, mac+1, mac+2, mac+3, mac+4, mac+5);
}
static int set_net_param(struct kvm *kvm, struct virtio_net_params *p,
			const char *param, const char *val)
{
	if (strcmp(param, "guest_mac") == 0) {
		str_to_mac(val, p->guest_mac);
	} else if (strcmp(param, "mode") == 0) {
		if (!strncmp(val, "user", 4)) {
			int i;

			for (i = 0; i < kvm->cfg.num_net_devices; i++)
				if (kvm->cfg.net_params[i].mode == NET_MODE_USER)
					die("Only one usermode network device allowed at a time");
			p->mode = NET_MODE_USER;
		} else if (!strncmp(val, "tap", 3)) {
			p->mode = NET_MODE_TAP;
		} else if (!strncmp(val, "none", 4)) {
			kvm->cfg.no_net = 1;
			return -1;
		} else
			die("Unknown network mode %s, please use user, tap or none", kvm->cfg.network);
	} else if (strcmp(param, "script") == 0) {
		p->script = strdup(val);
	} else if (strcmp(param, "guest_ip") == 0) {
		p->guest_ip = strdup(val);
	} else if (strcmp(param, "host_ip") == 0) {
		p->host_ip = strdup(val);
	} else if (strcmp(param, "trans") == 0) {
		p->trans = strdup(val);
	} else if (strcmp(param, "tapif") == 0) {
		p->tapif = strdup(val);
	} else if (strcmp(param, "vhost") == 0) {
		p->vhost = atoi(val);
	} else if (strcmp(param, "fd") == 0) {
		p->fd = atoi(val);
	} else if (strcmp(param, "mq") == 0) {
		p->mq = atoi(val);
	} else
		die("Unknown network parameter %s", param);

	return 0;
}

int netdev_parser(const struct option *opt, const char *arg, int unset)
{
	struct virtio_net_params p;
	char *buf = NULL, *cmd = NULL, *cur = NULL;
	bool on_cmd = true;
	struct kvm *kvm = opt->ptr;

	if (arg) {
		buf = strdup(arg);
		if (buf == NULL)
			die("Failed allocating new net buffer");
		cur = strtok(buf, ",=");
	}

	p = (struct virtio_net_params) {
		.guest_ip	= DEFAULT_GUEST_ADDR,
		.host_ip	= DEFAULT_HOST_ADDR,
		.script		= DEFAULT_SCRIPT,
		.mode		= NET_MODE_TAP,
	};

	str_to_mac(DEFAULT_GUEST_MAC, p.guest_mac);
	p.guest_mac[5] += kvm->cfg.num_net_devices;

	while (cur) {
		if (on_cmd) {
			cmd = cur;
		} else {
			if (set_net_param(kvm, &p, cmd, cur) < 0)
				goto done;
		}
		on_cmd = !on_cmd;

		cur = strtok(NULL, ",=");
	};

	kvm->cfg.num_net_devices++;

	kvm->cfg.net_params = realloc(kvm->cfg.net_params, kvm->cfg.num_net_devices * sizeof(*kvm->cfg.net_params));
	if (kvm->cfg.net_params == NULL)
		die("Failed adding new network device");

	kvm->cfg.net_params[kvm->cfg.num_net_devices - 1] = p;

done:
	free(buf);
	return 0;
}

static int virtio_net__init_one(struct virtio_net_params *params)
{
	int i, err;
	struct net_dev *ndev;
	struct virtio_ops *ops;

	ndev = calloc(1, sizeof(struct net_dev));
	if (ndev == NULL)
		return -ENOMEM;

	ops = malloc(sizeof(*ops));
	if (ops == NULL) {
		err = -ENOMEM;
		goto err_free_ndev;
	}

	list_add_tail(&ndev->list, &ndevs);

	ndev->kvm = params->kvm;
	ndev->params = params;

	mutex_init(&ndev->mutex);
	ndev->queue_pairs = max(1, min(VIRTIO_NET_NUM_QUEUES, params->mq));
	ndev->config.status = VIRTIO_NET_S_LINK_UP;
	if (ndev->queue_pairs > 1)
		ndev->config.max_virtqueue_pairs = ndev->queue_pairs;

	for (i = 0 ; i < 6 ; i++) {
		ndev->config.mac[i]		= params->guest_mac[i];
		ndev->info.guest_mac.addr[i]	= params->guest_mac[i];
		ndev->info.host_mac.addr[i]	= params->host_mac[i];
	}

	ndev->mode = params->mode;
	if (ndev->mode == NET_MODE_TAP) {
		ndev->ops = &tap_ops;
	} else {
		ndev->info.host_ip		= ntohl(inet_addr(params->host_ip));
		ndev->info.guest_ip		= ntohl(inet_addr(params->guest_ip));
		ndev->info.guest_netmask	= ntohl(inet_addr("255.255.255.0"));
		ndev->info.buf_nr		= 20,
		ndev->ops = &uip_ops;
		uip_static_init(&ndev->info);
	}

	*ops = net_dev_virtio_ops;
	if (params->trans && strcmp(params->trans, "mmio") == 0)
		virtio_init(params->kvm, ndev, &ndev->vdev, ops, VIRTIO_MMIO,
			    PCI_DEVICE_ID_VIRTIO_NET, VIRTIO_ID_NET, PCI_CLASS_NET);
	else
		virtio_init(params->kvm, ndev, &ndev->vdev, ops, VIRTIO_PCI,
			    PCI_DEVICE_ID_VIRTIO_NET, VIRTIO_ID_NET, PCI_CLASS_NET);

	if (params->vhost)
		virtio_net__vhost_init(params->kvm, ndev);

	if (compat_id == -1)
		compat_id = virtio_compat_add_message("virtio-net", "CONFIG_VIRTIO_NET");

	return 0;

err_free_ndev:
	free(ndev);
	return err;
}

int virtio_net__init(struct kvm *kvm)
{
	int i;

	for (i = 0; i < kvm->cfg.num_net_devices; i++) {
		kvm->cfg.net_params[i].kvm = kvm;
		virtio_net__init_one(&kvm->cfg.net_params[i]);
	}

	if (kvm->cfg.num_net_devices == 0 && kvm->cfg.no_net == 0) {
		static struct virtio_net_params net_params;

		net_params = (struct virtio_net_params) {
			.guest_ip	= kvm->cfg.guest_ip,
			.host_ip	= kvm->cfg.host_ip,
			.kvm		= kvm,
			.script		= kvm->cfg.script,
			.mode		= NET_MODE_USER,
		};
		str_to_mac(kvm->cfg.guest_mac, net_params.guest_mac);
		str_to_mac(kvm->cfg.host_mac, net_params.host_mac);

		virtio_net__init_one(&net_params);
	}

	return 0;
}
virtio_dev_init(virtio_net__init);

int virtio_net__exit(struct kvm *kvm)
{
	return 0;
}
virtio_dev_exit(virtio_net__exit);
