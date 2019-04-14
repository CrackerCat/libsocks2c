#pragma once

#include "../src/utils/logger.h"
#include "../src/utils/singleton.h"
#include "../src/factory/client_factory.h"

#include <unordered_map>
#include <mutex>

template <class Protocol>
class ClientProxyMap : public Singleton<ClientProxyMap<Protocol>> {


public:


    bool IsProxyExist(int port)
    {
        std::lock_guard<std::mutex> lg(map_mutex);

        auto cit = client_map.find(port);
        if (cit != client_map.end()) return true;

        return false;
    }


    bool Insert(int port, ClientProxy<Protocol> handle)
    {
        std::lock_guard<std::mutex> lg(map_mutex);

        return client_map.insert({port, handle}).second;
    }


    bool StopProxy(int port)
    {
        std::lock_guard<std::mutex> lg(map_mutex);

        auto cit = client_map.find(port);

        if (cit == client_map.end()) return false;

        if (cit != client_map.end())
        {
            std::get<0>(cit->second)->StopProxy();
            std::get<1>(cit->second)->StopProxy();
            client_map.erase(cit);
            return true;
        }

        return false;
    }

private:
    std::mutex map_mutex;
    std::unordered_map<int, ClientProxy<Protocol>> client_map;
};


