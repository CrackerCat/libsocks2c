#pragma once

#include <memory>
template<class T>
class Singleton
{
public:
#ifdef SINGLETON_RAW_POINTER
    template<typename... Args>
	static T* GetInstance(Args&&... args)
	{
		static T* instance = new T(std::forward<Args>(args)...);
		return instance;
	}
#else
    template<typename... Args>
    static std::shared_ptr<T> GetInstance(Args&&... args)
    {
        static std::shared_ptr<T> instance(std::make_shared<T>(std::forward<Args>(args)...));
        return instance;
    }
#endif
};
