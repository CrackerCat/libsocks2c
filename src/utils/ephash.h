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

struct udp2raw_session_ep_tuple
{
    uint32_t src_ip;
    uint8_t  src_port;
};

struct udp_ep_tuple
{
    uint32_t src_ip;
    uint8_t  src_port;
    uint32_t dst_ip;
    uint8_t  dst_port;
};
struct EndPointTupleHash {
    size_t operator()(udp2raw_session_ep_tuple const &ep_tuple) const
    {
        size_t seed = 0;
        //printf("hashing %s:%d\n", ep_in.address().to_string(), ep_in.port());
        //boost::hash_combine(seed, ep_in.address().to_string());
        boost::hash_combine(seed, ep_tuple.src_ip);
        boost::hash_combine(seed, ep_tuple.src_port);
        return seed;
    }
};
struct EndPointTupleHash {
    size_t operator()(udp_ep_tuple const &ep_tuple) const
    {
        size_t seed = 0;
        //printf("hashing %s:%d\n", ep_in.address().to_string(), ep_in.port());
        //boost::hash_combine(seed, ep_in.address().to_string());
        boost::hash_combine(seed, ep_tuple.src_ip);
        boost::hash_combine(seed, ep_tuple.src_port);
        boost::hash_combine(seed, ep_tuple.dst_ip);
        boost::hash_combine(seed, ep_tuple.dst_port);

        return seed;
    }
};


