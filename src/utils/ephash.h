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