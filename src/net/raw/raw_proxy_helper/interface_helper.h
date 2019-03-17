#pragma once
#include "../../../utils/singleton.h"
#include <string>

class InterfaceHelper : public Singleton<InterfaceHelper>
{

public:

    std::string GetDefaultInterface();

private:

    std::string default_interface_str;

};