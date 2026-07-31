#include "test_common.hpp"

#include <cstring>

#include <openvpn/buffer/bufstr.hpp>
#include <openvpn/frame/frame_init.hpp>
#include <openvpn/ssl/psid_cookie_impl.hpp>

using namespace openvpn;


TEST(PsidCookie, Setup)
{
    PsidCookieImpl::pre_threading_setup();

    ASSERT_TRUE(true);
}

// The following uland_addr46 type is a userland adaptation of an unpublished
// ovpn_addr46 type from James Yonan's kernel work.  The main idea is to create
// a reliably hashable representation of an IP address, be it IPv4 or IPv6
/* Discriminated union for IPv4/v6 addresses that should replace
   ovpn_addr.  The advantage of this approach over ovpn_addr is
   better alignment/packing and potential use as an rhashtable key. */
union uland_addr46 {
    /* IPv4 */
    struct
    {
        /* treat as IPv4-mapped IPv6 addresses */
        uint64_t a4_pre64; /* 0 */
        uint32_t a4_pre32; /* htonl(0xFFFF) */
        struct in_addr a4; /* the IPv4 address */
    };

    /* IPv6 */
    struct in6_addr a6;
    uint64_t a6_64[2];
};

class ClientAddressMock : public PsidCookieAddrInfoBase
{
  public:
    ClientAddressMock(RandomAPI &prng)
    {
        prng.rand_fill(addrport_);
    }
    const unsigned char *get_abstract_cli_addrport(size_t &slab_size) const override
    {
        slab_size = slab_size_;
        return addrport_.c;
    }
    // unused for these tests
    const void *get_impl_info() const override
    {
        return nullptr;
    }

    virtual ~ClientAddressMock() = default;

  private:
    // the detail here is not used; the slab is just randomly filled with data for the
    // hmac; this segment is here to show the motivation for slab_size_
    static constexpr size_t slab_size_ = sizeof(union uland_addr46) + sizeof(std::uint16_t);
    union {
        unsigned char c[slab_size_];
        struct
        {
            union uland_addr46 oaddr46;
            std::uint16_t port;
        } s;
    } addrport_;
};

class PsidCookieTest : public testing::Test
{
    openvpn_io::io_context dummy_io_context;
    Time now;
    ProtoContext::ProtoConfig::Ptr pcfg;
    ServerProto::Factory::Ptr spf;

  protected:
    PsidCookieTest()
        : dummy_io_context(1), pcfg(new ProtoContext::ProtoConfig())
    {
        const std::string tls_key_fn = UNITTEST_SOURCE_DIR "/input/psid_cookie_tls.key";
        pcfg->tls_auth_key.parse_from_file(tls_key_fn);
        pcfg->tls_auth_factory.reset(new CryptoOvpnHMACFactory<SSLLib::CryptoAPI>());
        pcfg->set_tls_auth_digest(CryptoAlgs::lookup("SHA256"));
        pcfg->now = &now;
        pcfg->handshake_window = Time::Duration::seconds(60);
        pcfg->key_direction = 0;
        pcfg->rng.reset(new SSLLib::RandomAPI());
        pcfg->prng.reset(new MTRand(2020303));

        spf.reset(new ServerProto::Factory(dummy_io_context, *pcfg));
        spf->proto_context_config = pcfg;

        pcookie_impl.reset(new PsidCookieImpl(spf.get()));
    }

    Time set_clock(Time setting)
    {
        now = setting;
        return setting;
    }

    Time advance_clock(uint64_t binary_ms)
    {
        now += Time::Duration::binary_ms(binary_ms);
        return now;
    }

    void SetUp() override
    {
    }

    void TearDown() override
    {
    }

    std::unique_ptr<PsidCookieImpl> pcookie_impl;
};


TEST_F(PsidCookieTest, CheckSetup)
{
    const PsidCookieImpl *pci_dut = pcookie_impl.get();
    ASSERT_NE(pci_dut, nullptr);

    // check test clock's equivalence to the PsidCookieImpl clock
    const Time start(set_clock(Time::now()));
    EXPECT_TRUE(start == *pci_dut->now_);

    // spot check other aspects of successful pci_dut creation
    EXPECT_TRUE(pci_dut->pcfg_.tls_auth_key.defined());
}

TEST_F(PsidCookieTest, ValidTime)
{
    PsidCookieImpl &pci_dut(*pcookie_impl.get());
    const ClientAddressMock cli_addr(*pci_dut.pcfg_.prng);
    ProtoSessionID cli_psid;
    ProtoSessionID srv_psid;
    // interval duplicates the computation in calculate_session_id_hmac()
    const uint64_t interval = (pci_dut.pcfg_.handshake_window.raw() + 1) / 2;
    bool hmac_ok;

    cli_psid.randomize(*pci_dut.pcfg_.rng);

    set_clock(Time::now());
    srv_psid = pci_dut.calculate_session_id_hmac(cli_psid, cli_addr, 0);

    // server is in the same interval in which it offered the hmac
    hmac_ok = pci_dut.check_session_id_hmac(srv_psid, cli_psid, cli_addr);
    EXPECT_TRUE(hmac_ok);

    advance_clock(interval);
    // server is in the next interval after which it offered the hmac
    hmac_ok = pci_dut.check_session_id_hmac(srv_psid, cli_psid, cli_addr);
    EXPECT_TRUE(hmac_ok);

    advance_clock(interval);
    // server is two intervals after which it offered the hmac
    hmac_ok = pci_dut.check_session_id_hmac(srv_psid, cli_psid, cli_addr);
    EXPECT_FALSE(hmac_ok);
}


// Tests that exercise PsidCookieImpl::intercept() against crafted third
// packets of the OpenVPN 3-way handshake (the client reply to the server's
// HARD_RESET).  The cookie code only ever sees this packet when no peer
// state exists yet, so it must positively identify the packet as the
// handshake-completing one before letting the caller create state.
class PsidCookieInterceptTest : public PsidCookieTest
{
  protected:
    // Build a complete third-packet (tls-auth path) suitable for intercept().
    // Each on-the-wire field is parameterized so that individual tests can
    // perturb exactly one field while leaving everything else valid.
    BufferAllocated build_third_packet_tls_auth(const ProtoSessionID &cli_psid,
                                                const ProtoSessionID &cookie_psid,
                                                std::uint32_t acked_pktid_be,
                                                std::uint32_t own_pktid_be,
                                                unsigned char ack_count,
                                                unsigned char op_field)
    {
        PsidCookieImpl &pci = *pcookie_impl;
        // The server validates the incoming HMAC with ta_hmac_recv_; with
        // pcfg_.key_direction == 0 that key differs from ta_hmac_send_'s, so
        // we must sign the synthetic client packet with the recv key here.
        const size_t hmac_size = pci.ta_hmac_recv_->output_size();

        BufferAllocated buf;
        buf.reset(/*headroom=*/256, /*capacity=*/512, BufAllocFlags::GROW);

        // Fields are prepended in reverse on-the-wire order, mirroring how
        // process_clients_initial_reset_tls_auth() builds the server reply.
        buf.prepend(&own_pktid_be, sizeof(own_pktid_be));
        cookie_psid.prepend(buf);
        buf.prepend(&acked_pktid_be, sizeof(acked_pktid_be));
        buf.push_front(ack_count);

        PacketIDControlSend pid;
        pid.write_next(buf, /*prepend=*/true, pci.now_->seconds_since_epoch());

        buf.prepend_alloc(hmac_size);
        cli_psid.prepend(buf);
        buf.push_front(op_field);

        pci.ta_hmac_recv_->ovpn_hmac_gen(buf.data(),
                                         buf.size(),
                                         PsidCookieImpl::OPCODE_SIZE + PsidCookieImpl::SID_SIZE,
                                         hmac_size,
                                         PacketIDControl::idsize);
        return buf;
    }

    struct Fixture
    {
        ClientAddressMock cli_addr;
        ProtoSessionID cli_psid;
        ProtoSessionID cookie_psid;
    };

    Fixture make_fixture()
    {
        PsidCookieImpl &pci = *pcookie_impl;
        set_clock(Time::now());

        Fixture f{ClientAddressMock(*pci.pcfg_.prng), {}, {}};
        f.cli_psid.randomize(*pci.pcfg_.rng);
        f.cookie_psid = pci.calculate_session_id_hmac(f.cli_psid, f.cli_addr, 0);
        return f;
    }
};

TEST_F(PsidCookieInterceptTest, ThirdPacketValid)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);
    EXPECT_TRUE(pcookie_impl->get_cookie_psid().match(f.cookie_psid));
}

TEST_F(PsidCookieInterceptTest, ThirdPacketAcceptsAckedPktidOne)
{
    // Both acked-pktid 0 (default) and 1 are tolerated as part of the early
    // handshake; only > 1 is treated as mid-session.  This mirrors OpenVPN 2.
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/htonl(1),
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketRejectsAckedPktidAboveOne)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/htonl(2),
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::DROP_2ND);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketAcceptsOwnPktidOne)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/htonl(1),
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketRejectsOwnPktidAboveOne)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/htonl(2),
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::DROP_2ND);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketRejectsAckCountNotOne)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/2,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::DROP_2ND);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketAcceptsAckV1)
{
    // P_ACK_V1 has no own message-id on the wire; intercept() must accept
    // it and skip the message-id check.  The packet builder still writes 4
    // bytes for own_pktid into the buffer, but the validator's reqd_size is
    // 4 bytes shorter for ACK_V1 so those bytes are simply ignored.
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::ACK_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketRejectsNonZeroKeyId)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 1));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::EARLY_DROP);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketRejectsBadCookie)
{
    auto f = make_fixture();
    // Tamper with the cookie psid: still valid HMAC over the packet, but
    // the embedded server psid does not match what calculate_session_id_hmac
    // would produce for this client.
    ProtoSessionID bogus;
    bogus.randomize(*pcookie_impl->pcfg_.rng);

    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      bogus,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::DROP_2ND);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketRejectsBadHmac)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));
    // Flip a byte in the HMAC field (right after the opcode + own session id).
    pkt.data()[PsidCookieImpl::OPCODE_SIZE + PsidCookieImpl::SID_SIZE] ^= 0x01;

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::DROP_2ND);
}

//! Records what unwrap_tls_crypt_wkc() handed the hook, and answers with @p accept
class MetadataRecorder : public TLSCryptMetadata
{
  public:
    explicit MetadataRecorder(bool accept)
        : accept_(accept)
    {
    }

    bool verify(int type, Buffer &metadata) const override
    {
        ++n_calls;
        type_seen = type;
        payload_seen = buf_to_string(metadata);
        return accept_;
    }

    mutable unsigned int n_calls = 0;
    mutable int type_seen = -2; //!< -1 would mean "WKc carried no metadata"
    mutable std::string payload_seen;

  private:
    const bool accept_; //!< what verify() returns
};

/**
 * @brief The hook an embedder installs, standing in for PG's
 *
 * Keeps the recorders it makes reachable from the test: @c n_created counts how many
 * records were put to the hook at all, which is what says whether a packet reached it that
 * should not have, and @c last holds the verdict and payload of the most recent one.
 */
class MetadataRecorderFactory : public TLSCryptMetadataFactory
{
  public:
    TLSCryptMetadata::Ptr new_obj() override
    {
        ++n_created;
        last = new MetadataRecorder(accept);
        return last;
    }

    bool accept = true; //!< verify() verdict handed to the recorders produced here
    unsigned int n_created = 0;
    RCPtr<MetadataRecorder> last;
};

/**
 * @brief Tests for the tls-crypt-v2 arm of intercept()
 *
 * The client's third packet (CONTROL_WKC_V1) carries the WKc, and unwrap_tls_crypt_wkc()
 * strips it there, so this is the only place its metadata can be parsed; the handler that
 * parsed the cookie layer judges it before a session exists.
 *
 * The server this configures holds a tls-auth key as well, which is what PG deploys and the
 * case reset_tls_wrap_mode() resolves to TLS_AUTH.
 */
class PsidCookieTlsCryptV2Test : public PsidCookieInterceptTest
{
  protected:
    PsidCookieTlsCryptV2Test()
    {
        ProtoContext::ProtoConfig &pcfg = pcookie_impl->pcfg_;

        // server key IDs, the way PG deploys it: the WKc names its server key by
        // K_id, loaded from tls_crypt_v2_serverkey_dir as <2 hex digits>/<K_id>.key
        pcfg.tls_crypt_factory.reset(new CryptoTLSCryptFactory<SSLLib::CryptoAPI>());
        pcfg.set_tls_crypt_algs();
        pcfg.tls_crypt_ = ProtoContext::ProtoConfig::TLSCrypt::V2;
        pcfg.tls_crypt_v2_serverkey_id = true;
        pcfg.tls_crypt_v2_serverkey_dir = UNITTEST_SOURCE_DIR "/../ssl";
        pcfg.frame = frame_init_simple(2048);

        // our own copy of that key, to wrap with; unwrap overwrites pcfg.tls_crypt_key
        TLSCryptV2ServerKey server_key;
        server_key.parse(read_text(UNITTEST_SOURCE_DIR "/../ssl/06/063FE634.key"));
        server_key.extract_key(server_key_);

        // The cookie code needs an ssl_factory for libctx() and, via mode(), for the
        // client key's direction. No handshake happens here, but a server-mode context
        // insists on a certificate.
        SSLLib::SSLAPI::Config::Ptr sslcfg(new SSLLib::SSLAPI::Config());
        sslcfg->set_mode(Mode(Mode::SERVER));
        sslcfg->set_frame(pcfg.frame);
        sslcfg->set_rng(pcfg.rng);
        sslcfg->load_ca(read_text(UNITTEST_SOURCE_DIR "/../ssl/ca.crt"), true);
        sslcfg->load_cert(read_text(UNITTEST_SOURCE_DIR "/../ssl/server.crt"));
        sslcfg->load_private_key(read_text(UNITTEST_SOURCE_DIR "/../ssl/server.key"));
        pcfg.ssl_factory = sslcfg->new_factory();

        meta_factory.reset(new MetadataRecorderFactory());
        pcfg.tls_crypt_metadata_factory = meta_factory;

        // Kc, the client key the WKc wraps. Kept as raw bytes to write into the
        // WKc plaintext, and mirrored into a static key to key the client-side
        // tls-crypt instance with the same material.
        pcfg.prng->rand_bytes(client_key_raw_, sizeof(client_key_raw_));
        std::memcpy(client_key_.raw_alloc(), client_key_raw_, sizeof(client_key_raw_));
    }

    /**
     * @brief Build the WKc a client appends to its handshake packets.
     *
     * @code
     *   T   = HMAC-SHA256(Ka, len || K_id || Kc || metadata)
     *   WKc = T || AES-256-CTR(Ke, IV = T, Kc || metadata) || K_id || len
     * @endcode
     *
     * @param metadata       Metadata payload; empty for a WKc carrying none.
     * @param metadata_type  Type byte prefixed to @p metadata: 0x00 for user metadata,
     *                       0x01 for the timestamp stock tls-crypt-v2-genkey emits.
     */
    BufferAllocated make_wkc(const std::string &metadata, int metadata_type = 0x00)
    {
        ProtoContext::ProtoConfig &pcfg = pcookie_impl->pcfg_;
        const size_t hmac_size = pcfg.tls_crypt_context->digest_size();

        // a single key set, so sliced without direction or mode, as unwrap does
        TLSCryptInstance::Ptr wrap = pcfg.tls_crypt_context->new_obj_send();
        wrap->init(pcfg.ssl_factory->libctx(),
                   server_key_.slice(OpenVPNStaticKey::HMAC),
                   server_key_.slice(OpenVPNStaticKey::CIPHER));

        // the encrypted part: Kc, then the metadata behind its type byte
        BufferAllocated inner(OpenVPNStaticKey::KEY_SIZE + 1 + metadata.size(), BufAllocFlags::GROW);
        inner.write(client_key_raw_, sizeof(client_key_raw_));
        if (!metadata.empty())
        {
            inner.push_back(static_cast<unsigned char>(metadata_type));
            inner.write(metadata.c_str(), metadata.size());
        }

        // the trailing length counts itself, the tag, the ciphertext and K_id
        const std::uint32_t k_id_be = htonl(SERVER_KEY_ID);
        const std::uint16_t wkc_len = static_cast<std::uint16_t>(sizeof(std::uint16_t) + hmac_size
                                                                 + inner.size() + sizeof(k_id_be));
        const std::uint16_t wkc_len_be = htons(wkc_len);

        // the tag covers the length prefix and K_id as well as the plaintext
        BufferAllocated hmac_input(sizeof(wkc_len_be) + sizeof(k_id_be) + inner.size(), BufAllocFlags::GROW);
        hmac_input.write(&wkc_len_be, sizeof(wkc_len_be));
        hmac_input.write(&k_id_be, sizeof(k_id_be));
        hmac_input.write(inner.c_data(), inner.size());

        BufferAllocated wkc(wkc_len, BufAllocFlags::GROW);
        unsigned char *tag = wkc.write_alloc(hmac_size);
        wrap->hmac_gen(tag, 0, hmac_input.c_data(), hmac_input.size());

        // the tag doubles as the CTR IV, as on the server's decrypt
        const size_t ciphertext_bytes = wrap->encrypt(tag,
                                                      wkc.data() + hmac_size,
                                                      wkc.max_size() - hmac_size,
                                                      inner.c_data(),
                                                      inner.size());
        wkc.inc_size(ciphertext_bytes);
        wkc.write(&k_id_be, sizeof(k_id_be));
        wkc.write(&wkc_len_be, sizeof(wkc_len_be));

        return wkc;
    }

    /**
     * @brief Build the tls-crypt-v2 third packet of the 3-way handshake: a
     *        CONTROL_WKC_V1 wrapped with Kc, ACKing the server's HARD_RESET and
     *        echoing the cookie psid back, with the WKc appended.
     */
    BufferAllocated build_third_packet_tls_crypt_v2(const ProtoSessionID &cli_psid,
                                                    const ProtoSessionID &cookie_psid,
                                                    const BufferAllocated &wkc,
                                                    unsigned char op_field)
    {
        ProtoContext::ProtoConfig &pcfg = pcookie_impl->pcfg_;
        const size_t hmac_size = pcfg.tls_crypt_context->digest_size();

        // ENCRYPT|INVERSE, as a client slices it: the server's DECRYPT|NORMAL key set
        TLSCryptInstance::Ptr send = pcfg.tls_crypt_context->new_obj_send();
        send->init(pcfg.ssl_factory->libctx(),
                   client_key_.slice(OpenVPNStaticKey::HMAC | OpenVPNStaticKey::ENCRYPT | OpenVPNStaticKey::INVERSE),
                   client_key_.slice(OpenVPNStaticKey::CIPHER | OpenVPNStaticKey::ENCRYPT | OpenVPNStaticKey::INVERSE));

        // the layout validate_3whs_ack_payload() walks
        BufferAllocated payload;
        pcfg.frame->prepare(Frame::WRITE_SSL_INIT, payload);
        payload.push_back(1); // ACK count
        const std::uint32_t acked_pktid_be = 0;
        payload.write(&acked_pktid_be, sizeof(acked_pktid_be));
        cookie_psid.write(payload);
        const std::uint32_t own_pktid_be = 0;
        payload.write(&own_pktid_be, sizeof(own_pktid_be));

        // header fields, prepended in reverse on-the-wire order
        BufferAllocated work;
        pcfg.frame->prepare(Frame::ENCRYPT_WORK, work);
        work.prepend_alloc(hmac_size);
        PacketIDControlSend pid;
        pid.write_next(work, /*prepend=*/true, pcookie_impl->now_->seconds_since_epoch());
        cli_psid.prepend(work);
        work.push_front(op_field);

        send->hmac_gen(work.data(), TLSCryptContext::hmac_offset, payload.c_data(), payload.size());

        const size_t data_offset = TLSCryptContext::hmac_offset + hmac_size;
        const size_t encrypt_bytes = send->encrypt(work.c_data() + TLSCryptContext::hmac_offset,
                                                   work.data() + data_offset,
                                                   work.max_size() - data_offset,
                                                   payload.c_data(),
                                                   payload.size());
        work.inc_size(encrypt_bytes);

        // the WKc rides at the very end of the packet
        work.write(wkc.c_data(), wkc.size());

        return work;
    }

    //! the opcode of the third packet, the one whose WKc keys the session behind it
    static unsigned char wkc_v1_op_field()
    {
        return ProtoContext::op_compose(ProtoContext::CONTROL_WKC_V1, 0);
    }

    //! K_id of test/ssl/06/063FE634.key, the server key the WKc names
    static constexpr std::uint32_t SERVER_KEY_ID = 0x063FE634;

    RCPtr<MetadataRecorderFactory> meta_factory;
    unsigned char client_key_raw_[OpenVPNStaticKey::KEY_SIZE];
    OpenVPNStaticKey client_key_; //!< Kc, as the client keys its tls-crypt instance
    OpenVPNStaticKey server_key_; //!< Ka/Ke, used here to wrap the WKc
};


// The session created for this client strips the WKc itself, uniformly for this copy and
// the retransmissions that follow, so intercept() must hand the packet on as it arrived.
TEST_F(PsidCookieTlsCryptV2Test, ThirdPacketIsForwardedIntact)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc("v=1,type=external"),
                                                          wkc_v1_op_field());

    const size_t wire_size = pkt.size();
    const std::string wire(reinterpret_cast<const char *>(pkt.c_data()), pkt.size());

    ASSERT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);

    EXPECT_EQ(pkt.size(), wire_size);
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(pkt.c_data()), pkt.size()), wire);
    // ... and the session takes the WKc off it
    EXPECT_TRUE(ProtoContext::KeyContext::strip_resent_wkc(pkt, pcookie_impl->pcfg_));
    EXPECT_LT(pkt.size(), wire_size);
}
