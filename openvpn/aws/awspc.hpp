//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

// Get AWS info such as instanceId, region, and privateIp.

#pragma once

#include <string>
#include <utility>

#include <openvpn/aws/awscreds.hpp>
#include <openvpn/ws/httpcliset.hpp>
#include <openvpn/common/jsonhelper.hpp>
#include <openvpn/common/enumdir.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/frame/frame_init.hpp>
#include <openvpn/openssl/sign/pkcs7verify.hpp>

namespace openvpn::AWS {

class PCQuery : public RC<thread_unsafe_refcount>
{
  public:
    typedef RCPtr<PCQuery> Ptr;

    OPENVPN_EXCEPTION(awspc_query_error);

    struct Info
    {
        std::string instanceId;
        std::string region;
        std::string az;
        std::string privateIp;

        Creds creds;

        std::string error;

        bool is_error() const
        {
            return !error.empty();
        }

        bool instance_data_defined() const
        {
            return !instanceId.empty() && !region.empty() && !privateIp.empty();
        }

        // example: [instanceId=i-ae91d23e region=us-east-1 privateIp=10.0.0.218]
        std::string to_string() const
        {
            std::string ret = "[instanceId=" + instanceId + " region=" + region;
            if (!privateIp.empty())
                ret += " privateIp=" + privateIp;
            if (!error.empty())
                ret += " error='" + error + '\'';
            ret += ']';
            return ret;
        }
    };

    PCQuery(WS::ClientSet::Ptr cs_arg,
            const int debug_level_arg)
        : cs(std::move(cs_arg)),
          frame(frame_init_simple(1024)),
          debug_level(debug_level_arg)
    {
    }

    PCQuery(WS::ClientSet::Ptr cs_arg,
            const std::string &role_for_credentials_arg,
            const std::string &certs_dir_arg)
        : cs(std::move(cs_arg)),
          frame(frame_init_simple(1024)),
          debug_level(0),
          role_for_credentials(role_for_credentials_arg),
          certs_dir(certs_dir_arg)
    {
    }

    WS::ClientSet::TransactionSet::Ptr prepare_transaction_set()
    {
        // make HTTP context
        WS::Client::Config::Ptr http_config(new WS::Client::Config());
        http_config->frame = frame;
        http_config->connect_timeout = 15;
        http_config->general_timeout = 30;

        // make transation set
        WS::ClientSet::TransactionSet::Ptr ts = new WS::ClientSet::TransactionSet;
        ts->host.host = "169.254.169.254";
        ts->host.port = "80";
        ts->http_config = http_config;
        ts->max_retries = 3;
        ts->debug_level = debug_level;

        return ts;
    }

    void start(std::function<void(Info info)> completion_arg)
    {
        // make sure we are not in a pending state
        if (pending)
            throw awspc_query_error("request pending");
        pending = true;

        // save completion method
        completion = std::move(completion_arg);

        // init return object
        info = Info();

        try
        {
            auto ts = prepare_transaction_set();

            {
                std::unique_ptr<WS::ClientSet::Transaction> t(new WS::ClientSet::Transaction);
                t->req.method = "PUT";
                t->req.uri = "/latest/api/token";
                t->ci.extra_headers.emplace_back("X-aws-ec2-metadata-token-ttl-seconds: 60");
                ts->transactions.push_back(std::move(t));
            }

            // completion handler
            ts->completion = [self = Ptr(this)](WS::ClientSet::TransactionSet &ts)
            {
                self->token_query_complete(ts);
            };

            // do the request
            cs->new_request(ts);
        }
        catch (const std::exception &e)
        {
            done(e.what());
        }
    }

    void stop()
    {
        if (cs)
            cs->stop();
    }

  private:
    void done(std::string error)
    {
        pending = false;
        info.error = std::move(error);
        if (completion)
            completion(std::move(info));
    }

    void local_query_complete(WS::ClientSet::TransactionSet &lts)
    {
        try
        {
            // get transactions and check that they succeeded
            WS::ClientSet::Transaction &ident_trans = *lts.transactions.at(0);
            if (!ident_trans.request_status_success())
            {
                done("could not fetch AWS identity document: " + ident_trans.format_status(lts));
                return;
            }

            WS::ClientSet::Transaction &sig_trans = *lts.transactions.at(1);
            if (!sig_trans.request_status_success())
            {
                done("could not fetch AWS identity document signature: " + sig_trans.format_status(lts));
                return;
            }

            // get identity document and signature
            const std::string ident = ident_trans.content_in.to_string();
            const std::string sig = "-----BEGIN PKCS7-----\n"
                                    + sig_trans.content_in.to_string()
                                    + "\n-----END PKCS7-----\n";

            if (debug_level >= 3)
            {
                OPENVPN_LOG("IDENT\n"
                            << ident);
                OPENVPN_LOG("SIG\n"
                            << sig);
            }

            // verify signature on identity document
            {
                std::list<OpenSSLPKI::X509> certs;
                if (certs_dir.empty())
                    certs.emplace_back(awscert(), "AWS Cert");
                else
                {
                    enum_dir(certs_dir, [&certs, certs_dir = certs_dir](const std::string &file)
                             { certs.emplace_back(read_text(certs_dir + "/" + file), "AWS Cert"); });
                }
                OpenSSLSign::verify_pkcs7(certs, sig, ident);
            }

            // parse the identity document (JSON)
            {
                const std::string title = "identity-document";
                const Json::Value root = json::parse(ident, title);
                info.region = json::get_string(root, "region", title);
                info.az = json::get_string(root, "availabilityZone", title);
                info.instanceId = json::get_string(root, "instanceId", title);
                info.privateIp = json::get_string(root, "privateIp", title);
            }

            if (!role_for_credentials.empty())
            {
                WS::ClientSet::Transaction &cred_trans = *lts.transactions.at(2);
                if (cred_trans.request_status_success())
                {
                    const std::string creds = cred_trans.content_in.to_string();
                    const Json::Value root = json::parse(creds);
                    info.creds.access_key = json::get_string(root, "AccessKeyId");
                    info.creds.secret_key = json::get_string(root, "SecretAccessKey");
                    info.creds.token = json::get_string(root, "Token");
                    done("");
                }
                else
                    done("could not fetch role credentials: " + cred_trans.format_status(lts));
            }
            else
                done("");
        }
        catch (const std::exception &e)
        {
            done(e.what());
        }
    }

    void token_query_complete(WS::ClientSet::TransactionSet &lts)
    {
        try
        {
            // get transaction and check that they succeeded
            WS::ClientSet::Transaction &token_trans = *lts.transactions.at(0);
            if (!token_trans.request_status_success())
            {
                done("could not fetch AWS session token: " + token_trans.format_status(lts));
                return;
            }
            const std::string token = token_trans.content_in.to_string();

            auto ts = prepare_transaction_set();

            // transaction #1
            {
                std::unique_ptr<WS::ClientSet::Transaction> t(new WS::ClientSet::Transaction);
                t->req.method = "GET";
                t->req.uri = "/latest/dynamic/instance-identity/document";
                t->ci.extra_headers.emplace_back("X-aws-ec2-metadata-token: " + token);
                ts->transactions.push_back(std::move(t));
            }

            // transaction #2
            {
                std::unique_ptr<WS::ClientSet::Transaction> t(new WS::ClientSet::Transaction);
                t->req.method = "GET";
                t->req.uri = "/latest/dynamic/instance-identity/pkcs7";
                t->ci.extra_headers.emplace_back("X-aws-ec2-metadata-token: " + token);
                ts->transactions.push_back(std::move(t));
            }

            // transaction #3
            if (!role_for_credentials.empty())
            {
                std::unique_ptr<WS::ClientSet::Transaction> t(new WS::ClientSet::Transaction);
                t->req.method = "GET";
                t->req.uri = "/latest/meta-data/iam/security-credentials/" + role_for_credentials;
                t->ci.extra_headers.emplace_back("X-aws-ec2-metadata-token: " + token);
                ts->transactions.push_back(std::move(t));
            }

            // completion handler
            ts->completion = [self = Ptr(this)](WS::ClientSet::TransactionSet &ts)
            {
                self->local_query_complete(ts);
            };

            // do the request
            cs->new_request(ts);
        }
        catch (const std::exception &e)
        {
            done(e.what());
        }
    }

    // The AWS cert for PKCS#7 validation of AWS identity document
    static std::string awscert()
    {
        return std::string(
            "-----BEGIN CERTIFICATE-----\n"
            "MIIC7TCCAq0CCQCWukjZ5V4aZzAJBgcqhkjOOAQDMFwxCzAJBgNVBAYTAlVTMRkw\n"
            "FwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD\n"
            "VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0xMjAxMDUxMjU2MTJaFw0z\n"
            "ODAxMDUxMjU2MTJaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9u\n"
            "IFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNl\n"
            "cnZpY2VzIExMQzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQCjkvcS2bb1VQ4yt/5e\n"
            "ih5OO6kK/n1Lzllr7D8ZwtQP8fOEpp5E2ng+D6Ud1Z1gYipr58Kj3nssSNpI6bX3\n"
            "VyIQzK7wLclnd/YozqNNmgIyZecN7EglK9ITHJLP+x8FtUpt3QbyYXJdmVMegN6P\n"
            "hviYt5JH/nYl4hh3Pa1HJdskgQIVALVJ3ER11+Ko4tP6nwvHwh6+ERYRAoGBAI1j\n"
            "k+tkqMVHuAFcvAGKocTgsjJem6/5qomzJuKDmbJNu9Qxw3rAotXau8Qe+MBcJl/U\n"
            "hhy1KHVpCGl9fueQ2s6IL0CaO/buycU1CiYQk40KNHCcHfNiZbdlx1E9rpUp7bnF\n"
            "lRa2v1ntMX3caRVDdbtPEWmdxSCYsYFDk4mZrOLBA4GEAAKBgEbmeve5f8LIE/Gf\n"
            "MNmP9CM5eovQOGx5ho8WqD+aTebs+k2tn92BBPqeZqpWRa5P/+jrdKml1qx4llHW\n"
            "MXrs3IgIb6+hUIB+S8dz8/mmO0bpr76RoZVCXYab2CZedFut7qc3WUH9+EUAH5mw\n"
            "vSeDCOUMYQR7R9LINYwouHIziqQYMAkGByqGSM44BAMDLwAwLAIUWXBlk40xTwSw\n"
            "7HX32MxXYruse9ACFBNGmdX2ZBrVNGrN9N2f6ROk0k9K\n"
            "-----END CERTIFICATE-----\n");
    }

    WS::ClientSet::Ptr cs;
    Frame::Ptr frame;
    const int debug_level;
    std::string role_for_credentials;
    std::string certs_dir;

    std::function<void(Info info)> completion;
    Info info;
    bool pending = false;
};
} // namespace openvpn::AWS
