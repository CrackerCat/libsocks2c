#pragma once

struct EndPointHash {
    size_t operator()(boost::asio::ip::udp::endpoint const &ep_in) const
    {
        size_t seed = 0;
		//printf("hashing %s:%d\n", ep_in.address().to_string(), ep_in.port());
        //boost::hash_combine(seed, ep_in.address().to_string());
        boost::hash_combine(seed, ep_in.port());
        return seed;
    }
};

struct tcp_session_src_tuple
{
    uint32_t src_ip;
    uint16_t  src_port;
};

struct udp_ep_tuple
{
    uint32_t src_ip;
    uint16_t  src_port;
    uint32_t dst_ip;
    uint16_t  dst_port;
};
struct TCPSrcTupleHash {
    size_t operator()(tcp_session_src_tuple const &ep_tuple) const
    {
        size_t seed = 0;
        //printf("hashing %s:%d\n", ep_in.address().to_string(), ep_in.port());
        //boost::hash_combine(seed, ep_in.address().to_string());
        boost::hash_combine(seed, ep_tuple.src_ip);
        boost::hash_combine(seed, ep_tuple.src_port);
        return seed;
    }
};
class TCPSrcTupleEQ
{
public:
    bool operator() (tcp_session_src_tuple const& t1, tcp_session_src_tuple const& t2) const
    {

        bool res = (t1.src_port == t2.src_port) && (t1.src_ip == t2.src_ip);

        return res;
    }
};


struct UdpEndPointTupleHash {
    size_t operator()(udp_ep_tuple const &ep_tuple) const
    {
        size_t seed = 0;
        //printf("hashing %s:%d\n", ep_in.address().to_string(), ep_in.port());
        //boost::hash_combine(seed, ep_in.address().to_string());
        boost::hash_combine(seed, ep_tuple.src_ip);
        boost::hash_combine(seed, ep_tuple.src_port);
        //boost::hash_combine(seed, ep_tuple.dst_ip);
        //boost::hash_combine(seed, ep_tuple.dst_port);

        return seed;
    }
};

class UdpEndPointTupleEQ
{
public:
    bool operator() (udp_ep_tuple const& t1, udp_ep_tuple const& t2) const
    {

        bool res = (t1.src_port == t2.src_port) && (t1.src_ip == t2.src_ip);

        return res;
    }
};

