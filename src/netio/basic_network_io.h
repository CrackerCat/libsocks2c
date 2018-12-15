#pragma once

#include <boost/asio/io_context.hpp>

class BasicNetworkIO {

    using IO_CONTEXT = boost::asio::io_context;
    using PIO_CONTEXT = IO_CONTEXT*;

public:

    BasicNetworkIO(){
        pio_context_ = new IO_CONTEXT();
    }

    /*
     *  you can pass a specific context if you don't want to use the build in one
     *  all io operation will attach on that context
     */
    void SetIOContext(IO_CONTEXT* io_context)
    {
        if (pio_context_ && this->use_buildin_context)
        {
            delete pio_context_;
            use_buildin_context = false;
            pio_context_ = io_context;
        }
    }

protected:

    void RunIO()
    {
        if (use_buildin_context)
        {
            pio_context_->run();
        }
    }


    void StopIO()
    {
        if (use_buildin_context)
        {
            pio_context_->stop();
        }
    }

protected:

    IO_CONTEXT& GetIOContext()
    {
        return *pio_context_;
    }

private:

    bool use_buildin_context = true;
    PIO_CONTEXT pio_context_;

};


