#include "kvm/devices.h"
#include "kvm/pci.h"
#include "kvm/ioport.h"
#include "kvm/irq.h"
#include "kvm/util.h"
#include "kvm/kvm.h"

#include <linux/err.h>
#include <assert.h>

#define PCI_BAR_OFFSET(b)		(offsetof(struct pci_device_header, bar[b]))

static u32 pci_config_address_bits;

/* This is within our PCI gap - in an unused area.
 * Note this is a PCI *bus address*, is used to assign BARs etc.!
 * (That's why it can still 32bit even with 64bit guests-- 64bit
 * PCI isn't currently supported.)
 */
static u32 io_space_blocks		= KVM_PCI_MMIO_AREA;

/*
 * BARs must be naturally aligned, so enforce this in the allocator.
 */
u32 pci_get_io_space_block(u32 size)
{
	u32 block = ALIGN(io_space_blocks, size);
	io_space_blocks = block + size;
	return block;
}

void pci__assign_irq(struct device_header *dev_hdr)
{
	struct pci_device_header *pci_hdr = dev_hdr->data;

	/*
	 * PCI supports only INTA#,B#,C#,D# per device.
	 *
	 * A#,B#,C#,D# are allowed for multifunctional devices so stick
	 * with A# for our single function devices.
	 */
	pci_hdr->irq_pin	= 1;
	pci_hdr->irq_line	= irq__alloc_line();
}

static void *pci_config_address_ptr(u16 port)
{
	unsigned long offset;
	void *base;

	offset	= port - PCI_CONFIG_ADDRESS;
	base	= &pci_config_address_bits;

	return base + offset;
}

static bool pci_config_address_out(struct ioport *ioport, struct kvm_cpu *vcpu, u16 port, void *data, int size)
{
	void *p = pci_config_address_ptr(port);

	memcpy(p, data, size);

	return true;
}

static bool pci_config_address_in(struct ioport *ioport, struct kvm_cpu *vcpu, u16 port, void *data, int size)
{
	void *p = pci_config_address_ptr(port);

	memcpy(data, p, size);

	return true;
}

static struct ioport_operations pci_config_address_ops = {
	.io_in	= pci_config_address_in,
	.io_out	= pci_config_address_out,
};

static bool pci_device_exists(u8 bus_number, u8 device_number, u8 function_number)
{
	union pci_config_address pci_config_address;

	pci_config_address.w = ioport__read32(&pci_config_address_bits);

	if (pci_config_address.bus_number != bus_number)
		return false;

	if (pci_config_address.function_number != function_number)
		return false;

	return !IS_ERR_OR_NULL(device__find_dev(DEVICE_BUS_PCI, device_number));
}

static bool pci_config_data_out(struct ioport *ioport, struct kvm_cpu *vcpu, u16 port, void *data, int size)
{
	union pci_config_address pci_config_address;

	pci_config_address.w = ioport__read32(&pci_config_address_bits);
	/*
	 * If someone accesses PCI configuration space offsets that are not
	 * aligned to 4 bytes, it uses ioports to signify that.
	 */
	pci_config_address.reg_offset = port - PCI_CONFIG_DATA;

	pci__config_wr(vcpu->kvm, pci_config_address, data, size);

	return true;
}

static bool pci_config_data_in(struct ioport *ioport, struct kvm_cpu *vcpu, u16 port, void *data, int size)
{
	union pci_config_address pci_config_address;

	pci_config_address.w = ioport__read32(&pci_config_address_bits);
	/*
	 * If someone accesses PCI configuration space offsets that are not
	 * aligned to 4 bytes, it uses ioports to signify that.
	 */
	pci_config_address.reg_offset = port - PCI_CONFIG_DATA;

	pci__config_rd(vcpu->kvm, pci_config_address, data, size);

	return true;
}

static struct ioport_operations pci_config_data_ops = {
	.io_in	= pci_config_data_in,
	.io_out	= pci_config_data_out,
};

void pci__config_wr(struct kvm *kvm, union pci_config_address addr, void *data, int size)
{
	u8 dev_num;

	dev_num	= addr.device_number;

	if (pci_device_exists(0, dev_num, 0)) {
		unsigned long offset;

		offset = addr.w & 0xff;
		if (offset < sizeof(struct pci_device_header)) {
			void *p = device__find_dev(DEVICE_BUS_PCI, dev_num)->data;
			struct pci_device_header *hdr = p;
			u8 bar = (offset - PCI_BAR_OFFSET(0)) / (sizeof(u32));
			u32 sz = cpu_to_le32(PCI_IO_SIZE);

			if (bar < 6 && hdr->bar_size[bar])
				sz = hdr->bar_size[bar];

			/*
			 * If the kernel masks the BAR it would expect to find the
			 * size of the BAR there next time it reads from it.
			 * When the kernel got the size it would write the address
			 * back.
			 */
			if (*(u32 *)(p + offset)) {
				/* See if kernel tries to mask one of the BARs */
				if ((offset >= PCI_BAR_OFFSET(0)) &&
				    (offset <= PCI_BAR_OFFSET(6)) &&
				    (ioport__read32(data)  == 0xFFFFFFFF))
					memcpy(p + offset, &sz, sizeof(sz));
				    else
					memcpy(p + offset, data, size);
			}
		}
	}
}

void pci__config_rd(struct kvm *kvm, union pci_config_address addr, void *data, int size)
{
	u8 dev_num;

	dev_num	= addr.device_number;

	if (pci_device_exists(0, dev_num, 0)) {
		unsigned long offset;

		offset = addr.w & 0xff;
		if (offset < sizeof(struct pci_device_header)) {
			void *p = device__find_dev(DEVICE_BUS_PCI, dev_num)->data;

			memcpy(data, p + offset, size);
		} else {
			memset(data, 0x00, size);
		}
	} else {
		memset(data, 0xff, size);
	}
}

static void pci_config_mmio_access(struct kvm_cpu *vcpu, u64 addr, u8 *data,
				   u32 len, u8 is_write, void *kvm)
{
	union pci_config_address cfg_addr;

	addr			-= KVM_PCI_CFG_AREA;
	cfg_addr.w		= (u32)addr;
	cfg_addr.enable_bit	= 1;

	if (is_write)
		pci__config_wr(kvm, cfg_addr, data, len);
	else
		pci__config_rd(kvm, cfg_addr, data, len);
}

struct pci_device_header *pci__find_dev(u8 dev_num)
{
	struct device_header *hdr = device__find_dev(DEVICE_BUS_PCI, dev_num);

	if (IS_ERR_OR_NULL(hdr))
		return NULL;

	return hdr->data;
}

int pci__init(struct kvm *kvm)
{
	int r;

	r = ioport__register(kvm, PCI_CONFIG_DATA + 0, &pci_config_data_ops, 4, NULL);
	if (r < 0)
		return r;

	r = ioport__register(kvm, PCI_CONFIG_ADDRESS + 0, &pci_config_address_ops, 4, NULL);
	if (r < 0)
		goto err_unregister_data;

	r = kvm__register_mmio(kvm, KVM_PCI_CFG_AREA, PCI_CFG_SIZE, false,
			       pci_config_mmio_access, kvm);
	if (r < 0)
		goto err_unregister_addr;

	return 0;

err_unregister_addr:
	ioport__unregister(kvm, PCI_CONFIG_ADDRESS);
err_unregister_data:
	ioport__unregister(kvm, PCI_CONFIG_DATA);
	return r;
}
dev_base_init(pci__init);

int pci__exit(struct kvm *kvm)
{
	ioport__unregister(kvm, PCI_CONFIG_DATA);
	ioport__unregister(kvm, PCI_CONFIG_ADDRESS);

	return 0;
}
dev_base_exit(pci__exit);
