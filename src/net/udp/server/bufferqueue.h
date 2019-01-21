#pragma once

#include <queue>
#include <cstring>

class BufferQueue
{

public:
    struct buffer_data
    {

        buffer_data(size_t size, void* src, boost::asio::ip::udp::endpoint& ep)
        {
            size = size;
            payload_ = malloc(size);
            memcpy(payload_, src, size);
            remote_ep_ = ep;
        }

        ~buffer_data()
        {
            free(payload_);
        }

        size_t size_;
        void* payload_;
        boost::asio::ip::udp::endpoint remote_ep_;
    };


    buffer_data& Enqueue(size_t size, void* src, boost::asio::ip::udp::endpoint ep)
    {
        data_queue_.push(buffer_data(size, src, ep));
        return data_queue_.back();
    }

    buffer_data Dequeue()
    {
        auto data = data_queue_.front();
        data_queue_.pop();
        return data;
    }

    buffer_data* GetFront()
    {
        if (data_queue_.empty()) return nullptr;
        return &data_queue_.front();
    }

    bool IsEmpty()
    {
        return data_queue_.empty();
    }

private:

    std::queue<buffer_data> data_queue_;

};