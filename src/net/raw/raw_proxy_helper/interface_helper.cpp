#include "interface_helper.h"

#ifdef __APPLE__
#include "../../../utils/system/system_exec.h"
std::string InterfaceHelper::GetDefaultInterface()
{
    const std::string default_if_str = "route -n get default | grep 'interface' | awk '{print $2}'";



}

#endif
