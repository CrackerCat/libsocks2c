#pragma once

#include <memory>

template <class T>
class Singleton
{

public:
    template<typename... Args>
    static std::shared_ptr<T> GetInstance(Args&&... args)
    {

        static std::shared_ptr<T> instance(new T(std::forward(args)...));

        return instance;
    }

};
