#include "capture_source.h"

#include <iostream>

#ifdef HAVE_LIBPCAP
#include <pcap/pcap.h>
#endif

namespace DPI {

// ============================================================================
// FileCapture
// ============================================================================

bool FileCapture::open(const std::string& filename, std::string& error) {
    if (!reader_.open(filename)) {
        error = "Cannot open pcap file: " + filename;
        return false;
    }
    name_ = filename;
    global_header_ = reader_.getGlobalHeader();
    return true;
}

bool FileCapture::readNextPacket(CapturePacket& packet) {
    PacketAnalyzer::RawPacket raw;
    if (!reader_.readNextPacket(raw)) {
        return false;  // End of file
    }
    packet.header = raw.header;
    packet.data = std::move(raw.data);
    return true;
}

const PacketAnalyzer::PcapGlobalHeader* FileCapture::globalHeader() const {
    return &global_header_;
}

// ============================================================================
// LiveCapture
// ============================================================================

LiveCapture::~LiveCapture() {
#ifdef HAVE_LIBPCAP
    if (handle_) {
        pcap_close(static_cast<pcap_t*>(handle_));
        handle_ = nullptr;
    }
#endif
}

bool LiveCapture::open(const std::string& iface_name, std::string& error) {
#ifdef HAVE_LIBPCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* p = pcap_create(iface_name.c_str(), errbuf);
    if (!p) {
        error = "pcap_create(" + iface_name + ") failed: " + std::string(errbuf);
        return false;
    }

    // Configure before activate so the capture buffer is settable.
    if (pcap_set_snaplen(p, 65535) != 0) {
        error = "pcap_set_snaplen failed on " + iface_name;
        pcap_close(p);
        return false;
    }
    if (pcap_set_promisc(p, 1) != 0) {  // Promiscuous: see traffic not addressed to us
        error = "pcap_set_promisc failed on " + iface_name;
        pcap_close(p);
        return false;
    }
    pcap_set_timeout(p, 100);        // read timeout (ms)
    pcap_set_buffer_size(p, static_cast<int>(buffer_size_));

    if (pcap_activate(p) != 0) {
        error = "pcap_activate(" + iface_name + ") failed: " +
                std::string(pcap_geterr(p)) +
                " (needs admin/root for raw socket access; on Windows install Npcap)";
        pcap_close(p);
        return false;
    }

    handle_ = p;
    name_ = iface_name;
    fatal_error_ = false;

    // Build a synthetic pcap global header for optional output writing.
    global_header_.magic_number = 0xa1b2c3d4;
    global_header_.version_major = 2;
    global_header_.version_minor = 4;
    global_header_.thiszone = 0;
    global_header_.sigfigs = 0;
    global_header_.snaplen = 65535;
    global_header_.network = static_cast<uint32_t>(pcap_datalink(p));

    pcap_setnonblock(p, 1, errbuf);
    return true;
#else
    error = "Live capture requires libpcap. Rebuild with -Dlive_capture=true "
            "(Linux: install libpcap-dev and run as root/CAP_NET_RAW; "
            "Windows: Npcap driver + SDK).";
    (void)iface_name;
    return false;
#endif
}

bool LiveCapture::readNextPacket(CapturePacket& packet) {
#ifdef HAVE_LIBPCAP
    if (!handle_) {
        return false;
    }

    pcap_t* p = static_cast<pcap_t*>(handle_);
    struct pcap_pkthdr* hdr = nullptr;
    const u_char* data = nullptr;

    int rc = pcap_next_ex(p, &hdr, &data);
    if (rc == 1) {
        packet.header.ts_sec = hdr->ts.tv_sec;
        packet.header.ts_usec = hdr->ts.tv_usec;
        packet.header.incl_len = hdr->caplen;
        packet.header.orig_len = hdr->len;
        packet.data.assign(data, data + hdr->caplen);
        return true;
    }
    if (rc == 0) {
        // Timeout - no packet yet. Signal caller to keep polling.
        packet.data.clear();
        return true;
    }
    // rc == -1 (error) or -2 (savefile EOF): stop the capture loop.
    return false;
#else
    (void)packet;
    return false;
#endif
}

const PacketAnalyzer::PcapGlobalHeader* LiveCapture::globalHeader() const {
#ifdef HAVE_LIBPCAP
    if (handle_) {
        return &global_header_;
    }
#endif
    return nullptr;
}

bool LiveCapture::captureStats(CaptureStats& out) const {
#ifdef HAVE_LIBPCAP
    if (!handle_) {
        return false;
    }
    struct pcap_stat ps;
    if (pcap_stats(static_cast<pcap_t*>(handle_), &ps) != 0) {
        return false;
    }
    out.received = static_cast<uint64_t>(ps.ps_recv);
    out.dropped = static_cast<uint64_t>(ps.ps_drop);
    out.if_dropped = static_cast<uint64_t>(ps.ps_ifdrop);
    out.available = true;
    return true;
#else
    (void)out;
    return false;
#endif
}

std::vector<std::string> LiveCapture::listInterfaces() {
    std::vector<std::string> result;
#ifdef HAVE_LIBPCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return result;
    }
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        if ((dev->flags & PCAP_IF_LOOPBACK) == 0 && dev->name != nullptr) {
            result.emplace_back(dev->name);
        }
    }
    pcap_freealldevs(alldevs);
#endif
    return result;
}

} // namespace DPI