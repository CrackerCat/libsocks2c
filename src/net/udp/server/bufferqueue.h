#pragma once

#include <queue>
#include <cstring>
#include <memory>

class BufferQueue
{

public:

    struct buffer_data
    {

        buffer_data(size_t size, void* src, boost::asio::ip::udp::endpoint& ep)
        {
            size_ = size;
            payload_ = new char[size];
            memcpy(payload_, src, size);
            remote_ep_ = ep;

        }

        size_t size_;
        char* payload_;
        boost::asio::ip::udp::endpoint remote_ep_;
    };
    using PBufferData = std::shared_ptr<buffer_data>;


    PBufferData Enqueue(size_t size, void* src, boost::asio::ip::udp::endpoint ep)
    {
        //printf("enqueue size: %zu\n", size);
        data_queue_.emplace(std::make_shared<buffer_data>(buffer_data(size, src, ep)));
        //auto front = data_queue_.front();
        return data_queue_.back();
    }

    void Dequeue()
    {
        auto front = data_queue_.front();
        data_queue_.pop();
        delete [] front->payload_;
    }

    PBufferData GetFront()
    {
        if (data_queue_.empty()) return nullptr;
        return data_queue_.front();
    }

    bool Empty()
    {
        //printf("data queue empty? %d\n", data_queue_.empty());
        return data_queue_.empty();
    }

    auto GetQueueSize()
    {
        return data_queue_.size();
    }
private:
    std::queue<PBufferData> data_queue_;

};